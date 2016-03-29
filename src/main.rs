extern crate pcap;
extern crate byteorder;

use std::fs::File;
use std::env::args;
use std::fmt;

use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug)]
enum EthernetType {
    IPv4,
    ARP,
    VLAN,
    IPv6,
    Unknown(u16),
}

impl From<u16> for EthernetType {
    fn from(_type: u16) -> Self {
        match _type {
            0x0800 => EthernetType::IPv4,
            0x0806 => EthernetType::ARP,
            0x8100 => EthernetType::VLAN,
            0x86DD => EthernetType::IPv6,
            t => EthernetType::Unknown(t),
        }
    }
}

struct EthernetPacket<'a> {
    dst: &'a [u8],
    src: &'a [u8],
    _type: EthernetType, // type is a reserved keyword
    payload: &'a [u8],
}

impl<'a> fmt::Debug for EthernetPacket<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let src: Vec<_> = self.src.iter().map(|x| format!("{:02x}", x)).collect();
        let dst: Vec<_> = self.dst.iter().map(|x| format!("{:02x}", x)).collect();
        fmt.debug_struct("EthernetPacket")
            .field("src", &src.join(":"))
            .field("dst", &dst.join(":"))
            .field("type", &self._type)
            .field("payload", &self.payload)
            .finish()
    }
}

#[derive(Debug)]
struct IPv4Packet;

#[derive(Debug)]
struct IPv6Packet;

#[derive(Debug)]
enum IPPacket {
    IPv4(IPv4Packet),
    IPv6(IPv6Packet),
}

fn ethernet_decode(pkt: &[u8]) -> EthernetPacket {
    let _type = (&pkt[12..14]).read_u16::<BigEndian>().unwrap();
    EthernetPacket {
        dst: &pkt[0..6],
        src: &pkt[6..12],
        _type: EthernetType::from(_type),
        payload: &pkt[14..],
    }
}

fn ip_decode(pkt: &[u8]) -> IPPacket {
    let version = (pkt[0] & 0xf0) >> 4;
    if version == 4 {
        IPPacket::IPv4(IPv4Packet)
    } else {
        IPPacket::IPv6(IPv6Packet)
    }
}

fn main() {
    let f = File::open(args().nth(1).unwrap()).unwrap();
    let reader = pcap::Reader::new(f).unwrap();
    println!("magic: 0x{:x}", reader.global_header.magic_number);
    println!("version major: {}", reader.global_header.version_major);
    println!("version minor: {}", reader.global_header.version_minor);
    println!("snaplen: {}", reader.global_header.snaplen);
    println!("network: {}", reader.global_header.network);
    let mut count = 0;
    for pkt in reader {
        match pkt {
            Ok((hdr, pkt)) => {
                count += 1;
                let eth_pkt = ethernet_decode(&pkt);
                // if let EthernetType::IPv4 = eth_pkt._type {
                //     let ip_pkt = ip_decode(eth_pkt.payload);
                //     println!("{:?}", ip_pkt);
                // }
                if let EthernetType::ARP = eth_pkt._type {
                    println!("{:?}", eth_pkt);
                }
                //println!("{:?}", eth_pkt);
            },
            Err(e) => println!("{:?}", e),
        }
    }
    println!("number of packets: {}", count);
}
