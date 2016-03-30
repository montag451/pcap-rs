extern crate byteorder;

use std::io::{self, Read, ErrorKind};
use std::result;

use byteorder::{NativeEndian, ReadBytesExt};

const MAGIC_NUMBER: u32 = 0xa1b2c3d4;
const MAGIC_NUMBER_SWAPPED: u32 = 0xd4c3b2a1;
const MAGIC_NUMBER_NANO_RES: u32 = 0xa1b23c4d;
const MAGIC_NUMBER_NANO_RES_SWAPPED: u32 = 0x4d3cb2a1;

const GLOBAL_HEADER_SIZE: usize = 24;
const PACKET_HEADER_SIZE: usize = 16;

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    BadMagicNumber(u32),
    ShortRead(usize, usize),
}

pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

pub struct GlobalHeader {
    pub magic_number: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub network: u32,
}

pub struct PacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

pub struct Reader<R> {
    r: R,
    pub global_header: GlobalHeader,
    need_swap: bool,
}

fn read_u16(buf: &mut &[u8], swap: bool) -> u16 {
    assert!(buf.len() >= 2);
    let i = buf.read_u16::<NativeEndian>().unwrap();
    if swap { i.swap_bytes() } else { i }
}

fn read_u32(buf: &mut &[u8], swap: bool) -> u32 {
    assert!(buf.len() >= 4);
    let i = buf.read_u32::<NativeEndian>().unwrap();
    if swap { i.swap_bytes() } else { i }
}

fn read_i32(buf: &mut &[u8], swap: bool) -> i32 {
    assert!(buf.len() >= 4);
    let i = buf.read_i32::<NativeEndian>().unwrap();
    if swap { i.swap_bytes() } else { i }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let len = buf.len();
    let mut rd = 0;
    while rd < len {
        rd += match r.read(&mut buf[rd..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::from(e)),
        }
    }
    if rd < len {
        Err(Error::ShortRead(len, rd))
    } else {
        Ok(())
    }
}

impl<R: Read> Reader<R> {
    pub fn new(mut r: R) -> Result<Reader<R>> {
        let mut hdr = [0; GLOBAL_HEADER_SIZE];
        try!(read_exact(&mut r, &mut hdr));
        let mut hdr_ptr: &[u8] = &hdr;
        let magic_number = read_u32(&mut hdr_ptr, false);
        let need_swap = match magic_number {
            MAGIC_NUMBER | MAGIC_NUMBER_NANO_RES => false,
            MAGIC_NUMBER_SWAPPED | MAGIC_NUMBER_NANO_RES_SWAPPED => true,
            e => return Err(Error::BadMagicNumber(e)),
        };
        let magic_number = if need_swap { magic_number.swap_bytes() } else { magic_number };
        let version_major = read_u16(&mut hdr_ptr, need_swap);
        let version_minor = read_u16(&mut hdr_ptr, need_swap);
        let thiszone = read_i32(&mut hdr_ptr, need_swap);
        let sigfigs = read_u32(&mut hdr_ptr, need_swap);
        let snaplen = read_u32(&mut hdr_ptr, need_swap);
        let network = read_u32(&mut hdr_ptr, need_swap);
        Ok(Reader {
            r: r,
            global_header: GlobalHeader {
                magic_number: magic_number,
                version_major: version_major,
                version_minor: version_minor,
                thiszone: thiszone,
                sigfigs: sigfigs,
                snaplen: snaplen,
                network: network,
            },
            need_swap: need_swap,
        })
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<(PacketHeader, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut hdr = [0; PACKET_HEADER_SIZE];
        match read_exact(&mut self.r, &mut hdr) {
            Ok(_) => {},
            Err(Error::ShortRead(_, rd)) if rd == 0 => return None,
            Err(e) => return Some(Err(e)),
        }
        let mut hdr_ptr: &[u8] = &hdr;
        let ts_sec = read_u32(&mut hdr_ptr, self.need_swap);
        let ts_usec = read_u32(&mut hdr_ptr, self.need_swap);
        let incl_len = read_u32(&mut hdr_ptr, self.need_swap);
        let orig_len = read_u32(&mut hdr_ptr, self.need_swap);
        let mut pkt = vec![0; incl_len as usize];
        match read_exact(&mut self.r, &mut pkt) {
            Ok(_) => {},
            Err(e) => return Some(Err(e)),
        }
        let hdr = PacketHeader {
            ts_sec: ts_sec,
            ts_usec: ts_usec,
            incl_len: incl_len,
            orig_len: orig_len,
        };
        Some(Ok((hdr, pkt)))
    }
}

#[test]
fn test_one_packet() {
    let buf: &[u8] = &[
        0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x56, 0xfb, 0x98, 0xfb, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x61,
    ];
    let mut reader = Reader::new(buf).unwrap();
    assert_eq!(reader.global_header.magic_number, 0xa1b2c3d4);
    assert_eq!(reader.global_header.version_major, 2);
    assert_eq!(reader.global_header.version_minor, 4);
    assert_eq!(reader.global_header.thiszone, 0);
    assert_eq!(reader.global_header.sigfigs, 0);
    assert_eq!(reader.global_header.snaplen, 262144);
    assert_eq!(reader.global_header.network, 1);
    match reader.next() {
        Some(res) => {
            let (hdr, pkt) = res.unwrap();
            assert_eq!(hdr.ts_sec, 1459329275);
            assert_eq!(hdr.ts_usec, 0);
            assert_eq!(hdr.incl_len, 1);
            assert_eq!(hdr.orig_len, 1);
            assert_eq!(pkt.len(), 1);
            assert_eq!(pkt[0], 0x61);
        },
        None => panic!("no packet found"),
    }
    match reader.next() {
        Some(res) => panic!("only one packet should have been found"),
        None => {}
    }
}

#[test]
fn test_one_packet_2() {
    let buf: &[u8] = &[
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xfb, 0x98, 0xfb, 0x56, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x61,
    ];
    let mut reader = Reader::new(buf).unwrap();
    assert_eq!(reader.global_header.magic_number, 0xa1b2c3d4);
    assert_eq!(reader.global_header.version_major, 2);
    assert_eq!(reader.global_header.version_minor, 4);
    assert_eq!(reader.global_header.thiszone, 0);
    assert_eq!(reader.global_header.sigfigs, 0);
    assert_eq!(reader.global_header.snaplen, 262144);
    assert_eq!(reader.global_header.network, 1);
    match reader.next() {
        Some(res) => {
            let (hdr, pkt) = res.unwrap();
            assert_eq!(hdr.ts_sec, 1459329275);
            assert_eq!(hdr.ts_usec, 0);
            assert_eq!(hdr.incl_len, 1);
            assert_eq!(hdr.orig_len, 1);
            assert_eq!(pkt.len(), 1);
            assert_eq!(pkt[0], 0x61);
        },
        None => panic!("no packet found"),
    }
    match reader.next() {
        Some(res) => panic!("only one packet should have been found"),
        None => {}
    }
}
