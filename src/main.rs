use std::{env, net, process, thread, time};
use std::net::Ipv4Addr;
use log::error;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport;
use pnet::transport::TransportReceiver;

const TCP_SIZE: usize = 20;
const MAXIMUM_PORT_NUM: u16 = 1023;

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

    rayon::join(|| send_packet(&mut ts, &packet_info),
    || receive_packets(&mut tr, &packet_info));

}

/**
* パケット送信
 */
fn send_packet(ts: &mut transport::TransportSender, packet_info: &PacketInfo) {
    let mut packet = build_packet(packet_info);
    for i in 1..MAXIMUM_PORT_NUM+1 {
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet).unwrap();
        reregister_destination_port(i, &mut tcp_header, packet_info);
        thread::sleep(time::Duration::from_millis(5));
        ts.send_to(tcp_header, net::IpAddr::V4(packet_info.target_ipaddr))
            .expect("failed to send");
    }
}

/**
* パケットの構築
 */
fn build_packet(packet_info: &PacketInfo) -> [u8; TCP_SIZE] {
    //TCPヘッダの作成
    let mut tcp_buffer = [0u8; TCP_SIZE];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
    tcp_header.set_source(packet_info.my_port);

    // オプションを含まないので、20オクテットまでがTCPヘッダ。4オクテット単位で管理する
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(packet_info.scan_type as u16);
    let checksum = tcp::ipv4_checksum(
        &tcp_header.to_immutable(),
        &packet_info.my_ipaddr,
        &packet_info.target_ipaddr,
    );
    tcp_header.set_checksum(checksum);

    tcp_buffer
}

/**
* TCPヘッダの宛先ポート情報を書き換える
*　チェックサムを計算し直す必要がある
*/
fn reregister_destination_port(
    target: u16,
    tcp_header: &mut MutableTcpPacket,
    packet_info: &PacketInfo,
) {
    tcp_header.set_destination(target);
    let checksum = tcp::ipv4_checksum(
        &tcp_header.to_immutable(),
        &packet_info.my_ipaddr,
        &packet_info.target_ipaddr,
    );
    tcp_header.set_checksum(checksum);
}

/**
* パケットを受信してスキャン結果を出力する。
*/
fn receive_packets(
    tr: &mut TransportReceiver,
    packet_info: &PacketInfo,
) -> Result<(), anyhow::Error> {
    let mut reply_ports = Vec::new();
    let mut packet_iter = transport::tcp_packet_iter(tr);
    loop {
        // ターゲットからの返信パケット
        let tcp_packet = match packet_iter.next() {
            Ok((tcp_packet, _)) => {
                if tcp_packet.get_destination() == packet_info.my_port {
                    tcp_packet
                } else {
                    continue;
                }
            },
            Err(_) => continue,
        };

        let target_port = tcp_packet.get_source();
        match packet_info.scan_type {
            ScanType::Syn => {
                if tcp_packet.get_flags() == TcpFlags::SYN | TcpFlags::ACK {
                    println!("port {} is open", target_port);
                }
            }
            //SYN スキャン以外はレスポンスが帰ってきたポート（＝閉じているポート）を記録
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                reply_ports.push(target_port);
            }
        }

        /* スキャン対象の最後のポートに対する返信が返ってこれば終了 */

        if target_port != packet_info.maximum_port {
            continue;
        }

        match packet_info.scan_type {
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                for i in 1..=packet_info.maximum_port {
                    if !reply_ports.iter().any(|&x| x == i) {
                        println!("port {} is open", i);
                    }
                }
            },
            _ => {}
        }

        return Ok(())
    }
}