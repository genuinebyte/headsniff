mod peeler;

#[macro_use]
use clap::{Arg, App};
use peeler::Layer3;
use pnet::datalink;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

struct Options<'s> {
    macignore: Option<&'s str>,
    maclisten: Option<&'s str>,
    ipignore: Option<&'s str>,
    iplisten: Option<&'s str>,
}

impl<'s> Options<'s> {
    fn new(
        macignore: Option<&'s str>,
        maclisten: Option<&'s str>,
        ipignore: Option<&'s str>,
        iplisten: Option<&'s str>,
    ) -> Self {
        Options {
            macignore,
            maclisten,
            ipignore,
            iplisten,
        }
    }
}

fn main() {
    //rustfmt is consitently removing the Arg::with_name from macignore, thus:
    #[rustfmt::skip]
	let matches = App::new("metasniff")
		.version(clap::crate_version!())
		.author(clap::crate_authors!(", "))
		.about(clap::crate_description!())
		.arg(
			Arg::with_name("INTERFACE")
				.help("Sets the interface to listen on")
				.required(true)
				.index(1)
		)
        .arg(
            Arg::with_name("macignore")
                .long("mac-ignore")
                .value_name("MAC_ADDRESS")
                .takes_value(true)
        )
        .arg (
            Arg::with_name("maclisten")
                .long("mac-listen")
                .value_name("MAC_LISTEN")
                .takes_value(true)
                .conflicts_with("macignore")
        )
        .arg(
            Arg::with_name("ipignore")
                .long("ip-ignore")
                .value_name("IP_ADDRESS")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("iplisten")
                .long("ip-listen")
                .value_name("IP_LISTEN")
                .takes_value(true)
                .conflicts_with("ipignore")
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

    let options = Options::new(
        matches.value_of("macignore"),
        matches.value_of("maclisten"),
        matches.value_of("ipignore"),
        matches.value_of("iplisten"),
    );

    if let Some(val) = options.macignore {
        println!("Ignoring packets with source/dest MAC '{}'", val);
    } else if let Some(val) = options.maclisten {
        println!("Listening for packets with source/dest MAC '{}'", val);
    }

    if let Some(val) = options.ipignore {
        println!("Ignoring packets with source/dest IP '{}'", val);
    } else if let Some(val) = options.iplisten {
        println!("Listening for packets with source/dest IP '{}'", val);
    }

    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type!"),
        Err(e) => panic!("Failed to open interface: {}", e),
    };

    println!("Listening for traffic on {}...", iface_name);
    loop {
        match rx.next() {
            Ok(buffer) => process_raw(buffer, &options),
            Err(_) => println!("Packet dropped!"),
        }
    }
}

fn process_raw(buffer: &[u8], options: &Options) {
    match EthernetPacket::new(buffer) {
        Some(pack) => process_ethframe(pack, options),
        None => println!("Couldn't parse raw receive!"),
    }
}

fn process_ethframe(ethpack: EthernetPacket, options: &Options) {
    if let Some(val) = options.macignore {
        if ethpack.get_destination().to_string() == val.to_string()
            || ethpack.get_source().to_string() == val.to_string()
        {
            return;
        }
    } else if let Some(val) = options.maclisten {
        if ethpack.get_destination().to_string() != val.to_string()
            && ethpack.get_source().to_string() != val.to_string()
        {
            return;
        }
    }

    match Layer3::new(ethpack.payload()) {
        Some(l3) => process_layer3(l3, options),
        None => println!("Couldn't process eth frame"),
    }
}

fn process_layer3(l3: Layer3, options: &Options) {
    let source = l3.source();
    let destination = l3.destination();

    if let Some(val) = options.ipignore {
        let val = val.to_string();
        if source == val || destination == val {
            return;
        }
    } else if let Some(val) = options.iplisten {
        let val = val.to_string();
        if source != val || destination != val {
            return;
        }
    }

    println!("{}\t->\t{}", source, destination);
}
