mod peeler;

#[macro_use]
use clap::{Arg, App};
use peeler::Layer3;
use pnet::datalink;
use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::cell::RefCell;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

use std::ops::DerefMut;
use std::str::FromStr;
struct Options {
    mac_addrs: Vec<MacAddr>,
    mac_blacklisting: bool,
    mac_whitelisting: bool,
    ip_addrs: Vec<IpAddr>,
    ip_blacklisting: bool,
    ip_whitelisting: bool,
    debug: Option<RefCell<File>>,
}

impl Options {
    pub fn new(
        macignore: Option<&str>,
        maclisten: Option<&str>,
        ipignore: Option<&str>,
        iplisten: Option<&str>,
        debug: bool,
    ) -> Self {
        let mac_addrs: Vec<MacAddr> = if let Some(val) = macignore {
            Self::split_and_collect(val, ',', |x| MacAddr::from_str(x).unwrap())
        } else if let Some(val) = maclisten {
            Self::split_and_collect(val, ',', |x| MacAddr::from_str(x).unwrap())
        } else {
            Vec::new()
        };

        let ip_addrs = if let Some(val) = ipignore {
            Self::split_and_collect(val, ',', |x| IpAddr::from_str(x).unwrap())
        } else if let Some(val) = iplisten {
            Self::split_and_collect(val, ',', |x| IpAddr::from_str(x).unwrap())
        } else {
            Vec::new()
        };

        let debug_cell: Option<RefCell<File>> = if debug {
            Some(RefCell::new(
                File::create("debug.packets").expect("Failed to create debug file!"),
            ))
        } else {
            None
        };

        Options {
            mac_addrs,
            mac_blacklisting: macignore.is_some(),
            mac_whitelisting: maclisten.is_some(),
            ip_addrs,
            ip_blacklisting: ipignore.is_some(),
            ip_whitelisting: iplisten.is_some(),
            debug: debug_cell,
        }
    }

    fn split_and_collect<T, F: FnMut(&str) -> T>(string: &str, delim: char, func: F) -> Vec<T> {
        string.split(delim).map(func).collect()
    }

    /// Checks to see if the provided MAC is one we should be monitoring
    pub fn mac_match(&self, mac: &MacAddr) -> bool {
        self.mac_addrs.contains(mac)
    }

    /// Checks to see if the provided IP is one we should be monitoring
    pub fn ip_match(&self, ip: &IpAddr) -> bool {
        self.ip_addrs.contains(ip)
    }

    /// Write a buffer to the debug file
    pub fn debug(&self, buf: &[u8]) {
        if self.debug.is_none() {
            return;
        }

        let cell = self.debug.as_ref().unwrap();
        let mut file = cell.borrow_mut();
        file.deref_mut()
            .write_all(buf)
            .expect("Failed to write to file!");
        file.deref_mut()
            .write(b"@@@")
            .expect("Failed to write to file!");
    }
}

fn main() {
    //rustfmt is consitently removing the Arg::with_name from macignore, thus:
    #[rustfmt::skip]
	let matches = App::new("headsniff")
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
            Arg::with_name("macblacklist")
                .long("mac-blacklist")
                .value_name("MAC_BLACKLIST")
                .takes_value(true)
        )
        .arg (
            Arg::with_name("macwhitelist")
                .long("mac-whitelist")
                .value_name("MAC_WHITELIST")
                .takes_value(true)
                .conflicts_with("macblacklist")
        )
        .arg(
            Arg::with_name("ipblacklist")
                .long("ip-blacklist")
                .value_name("IP_BLACKLIST")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("ipwhitelist")
                .long("ip-whitelist")
                .value_name("IP_WHITELIST")
                .takes_value(true)
                .conflicts_with("ipblacklist")
        )
        .arg(
            Arg::with_name("debug")
                .short("D")
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
        matches.value_of("macblacklist"),
        matches.value_of("macwhitelist"),
        matches.value_of("ipblacklist"),
        matches.value_of("ipwhitelist"),
        matches.is_present("debug"),
    );

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
    options.debug(buffer);

    match EthernetPacket::new(buffer) {
        Some(pack) => process_ethframe(pack, options),
        None => println!("Couldn't parse raw receive!"),
    }
}

fn process_ethframe(ethpack: EthernetPacket, options: &Options) {
    let destination = ethpack.get_destination();
    let source = ethpack.get_source();
    let mac_match = options.mac_match(&destination) || options.mac_match(&source);

    if mac_match && options.mac_blacklisting {
        return;
    } else if !mac_match && options.mac_whitelisting {
        return;
    }

    match Layer3::new(ethpack.payload()) {
        Some(l3) => process_layer3(l3, options),
        None => println!("Couldn't process eth frame"),
    }
}

fn process_layer3(l3: Layer3, options: &Options) {
    let source = l3.source();
    let destination = l3.destination();
    let ip_match = options.ip_match(&source) || options.ip_match(&destination);

    if ip_match && options.ip_blacklisting {
        return;
    } else if !ip_match && options.ip_whitelisting {
        return;
    }

    println!("{}\t->\t{}", source, destination);
}
