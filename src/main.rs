mod peeler;

#[macro_use]
use clap::{Arg, App};
use peeler::Layer3;
use pnet::datalink;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

fn main() {
	let matches = App::new("metasniff")
		.version(clap::crate_version!())
		.author(clap::crate_authors!(", "))
		.about(clap::crate_description!())
		.arg(
			Arg::with_name("INTERFACE")
				.help("Sets the interface to listen on")
				.required(true)
				.index(1),
		)
		.get_matches();

	let iface_name = matches.value_of("INTERFACE").unwrap();
	let iface_name_match = |iface: &NetworkInterface| iface.name == iface_name;

	let ifaces = datalink::interfaces();
	let iface = if let Some(iface) = ifaces.into_iter().filter(iface_name_match).next() {
		iface
	} else {
		panic!("The interface provided is invalid");
	};

	let mut rx = match datalink::channel(&iface, Default::default()) {
		Ok(Channel::Ethernet(_, rx)) => rx,
		Ok(_) => panic!("Unhandled channel type!"),
		Err(e) => panic!("Failed to open interface: {}", e),
	};

	println!("Listening for traffic on {}...", iface_name);
	loop {
		match rx.next() {
			Ok(buffer) => process_raw(buffer),
			Err(_) => println!("Packet dropped!"),
		}
	}
}

fn process_raw(buffer: &[u8]) {
	match EthernetPacket::new(buffer) {
		Some(pack) => process_ethframe(pack),
		None => println!("Couldn't parse raw receive!"),
	}
}

fn process_ethframe(ethpack: EthernetPacket) {
	match Layer3::new(ethpack.payload()) {
		Some(l3) => process_layer3(l3),
		None => println!("Couldn't process eth frame"),
	}
}

fn process_layer3(l3: Layer3) {
	println!("{}\t=>\t{}", l3.source(), l3.destination());
}
