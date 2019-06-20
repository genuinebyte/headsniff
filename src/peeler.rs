use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;

pub enum Layer3<'p> {
	Ipv4(Ipv4Packet<'p>),
	Ipv6(Ipv6Packet<'p>),
}

impl<'p> Layer3<'p> {
	pub fn new(buf: &[u8]) -> Option<Layer3> {
		let version = buf[0].to_be() & 0b1111_0000;
		return match version {
			0x40 => match Ipv4Packet::new(buf) {
				Some(pack) => Some(Layer3::Ipv4(pack)),
				None => None,
			},
			0x60 => match Ipv6Packet::new(buf) {
				Some(pack) => Some(Layer3::Ipv6(pack)),
				None => None,
			},
			_ => None,
		};
	}

	pub fn source(&self) -> IpAddr {
		match self {
			Layer3::Ipv4(pack) => IpAddr::V4(pack.get_source()),
			Layer3::Ipv6(pack) => IpAddr::V6(pack.get_source()),
		}
	}

	pub fn destination(&self) -> IpAddr {
		match self {
			Layer3::Ipv4(pack) => IpAddr::V4(pack.get_destination()),
			Layer3::Ipv6(pack) => IpAddr::V6(pack.get_destination()),
		}
	}
}
