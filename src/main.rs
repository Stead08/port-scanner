use std::{env, fs, process};
use std::net::Ipv4Addr;
use log::error;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpFlags;
use pnet::transport;

struct PacketInfo {
    my_ipaddr: Ipv4Addr,
    target_ipaddr: Ipv4Addr,
    my_port: u16,
    maximum_port: u16,
    scan_type: ScanType,
}

#[derive(Copy, Clone)]
enum ScanType {
    Syn = TcpFlags::SYN as isize,
    Fin = TcpFlags::FIN as isize,
    Xmas = (TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH) as isize,
    Null = 0,
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    dotenv::dotenv().ok();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Incorrect number of arguments. [ipaddr] [scantype]");
        process::exit(1);
    }
    // from command line
    let Ok(target_ipaddr) = args[1].parse::<Ipv4Addr>() else {
        error!("Invalid IP address format.");
        process::exit(1);
    };
    let scan_type = match args[2].as_str() {
        "sS" => ScanType::Syn,
        "sF" => ScanType::Fin,
        "sX" => ScanType::Xmas,
        "sN" => ScanType::Null,
        _ => {
            error!("Undefined scan method.");
            process::exit(1);
        }
    };
    // from .env
    let my_ipaddr = env::var("MY_IPADDR")
        .expect("MY_IPADDR is not set.")
        .parse()
        .expect("Invalid IP address format.");

    let my_port = env::var("MY_PORT")
        .expect("MY_PORT is not set.")
        .parse()
        .expect("Invalid port number format.");

    let maximum_port = env::var("MAXIMUM_PORT")
        .expect("MAXIMUM_PORT is not set.")
        .parse()
        .expect("Invalid port number format.");


    let packet_info = PacketInfo {
        my_ipaddr,
        target_ipaddr,
        my_port,
        maximum_port,
        scan_type,
    };

    // open a transport layer
    // 内部的にはソケット
    let (mut ts, mut tr) = transport::transport_channel(
        1024,
        transport::TransportChannelType::Layer4(transport::TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Tcp,
        )),
    ).expect("Failed to open channel.");




}
