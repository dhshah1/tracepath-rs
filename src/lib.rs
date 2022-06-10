//use clap::{App, Arg};
//use libc;
use nix::cmsg_space;
use nix::errno::Errno;
use nix::sys::select::{select, FdSet};
use nix::sys::socket::setsockopt;
use nix::sys::socket::sockopt;
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use nix::sys::time::TimeVal;
use nix::sys::uio::IoVec;
use nix::Error;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, RawFd};

fn udp_socket() -> UdpSocket {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    return socket;
}

fn udp_socket_v6() -> UdpSocket {
    UdpSocket::bind("[::/0]:0").expect("Failed to bind socket")
}

fn set_sockopts(sock: RawFd) {
    setsockopt(sock, sockopt::IpRecvErr, &true).expect("sockopt failed");
    setsockopt(sock, sockopt::IpRecvTtl, &true).expect("sockopt failed");
    setsockopt(sock, sockopt::IpMtuDiscover, &true).expect("sockopt failed");
}

fn prepare_socket(sock: &UdpSocket, host: &String, ttl: u32) {
    let raw_fd: RawFd = sock.as_raw_fd();
    sock.connect(&host).expect("Error connecting");
    println!("Connecting {}", host);
    set_sockopts(raw_fd);
    sock.set_ttl(ttl + 1)
        .expect(format!("Failed to set ttl={} on socket", ttl).as_str());
}

fn send_datagram(sock: &UdpSocket) {
    let bytes = b"hello\0";
    match sock.send(bytes) {
        Ok(_nbytes) => {
            println!("Sent bytes: {}", _nbytes);
        }
        Err(_e) => {
            println!("Error in sending: {}", _e);
        }
    }
}

struct HopResult {
    addr: Option<String>,
    est_ttl: Option<u8>,
}

impl HopResult {
    fn new() -> Self {
        HopResult {
            addr: None,
            est_ttl: None,
        }
    }
}

fn recv_hop_cmsg(sock: &UdpSocket) -> Result<Box<HopResult>, Box<nix::Error>> {
    let raw_fd: RawFd = sock.as_raw_fd();
    sock.set_nonblocking(false);
    sock.set_read_timeout(None);
    loop {
        let mut data = [0; 65536];
        let iov = IoVec::from_mut_slice(&mut data);
        let mut cmsg = cmsg_space!([RawFd; 28]);

        let result = recvmsg(raw_fd, &[iov], Some(&mut cmsg), MsgFlags::MSG_ERRQUEUE);
        if let Err(e) = result {
            match e.as_errno() {
                Some(Errno::EAGAIN) => {
                    println!("recvmsg failed with: {}. Trying again", e);
                    continue;
                }
                _ => {
                    println!("recvmsg failed with: {}", e);
                }
            }
            return Err(Box::new(e));
        }

        let msg = result.unwrap();
        let mut hop_result = Box::new(HopResult::new());
        for cmsg in msg.cmsgs() {
            match cmsg {
                ControlMessageOwned::IpTtl(ip_ttl) => {
                    hop_result.est_ttl = Some(match ip_ttl {
                        ittl if ittl <= 64 => 64 - ip_ttl,
                        ittl if ittl <= 128 => 128 - ip_ttl,
                        ittl if ittl < 255 => 255 - ip_ttl,
                        _ => 0,
                    });
                }
                ControlMessageOwned::IpRecvErr(err) => {
                    hop_result.addr =
                        Some(Ipv4Addr::from(err.offender.sin_addr.s_addr.to_be()).to_string());
                }
                _ => {}
            };
        }
        return Ok(hop_result);
    }

    // let mut readset = FdSet::new();
    // readset.insert(raw_fd);

    // let mut timeout = TimeVal::from(libc::timeval {
    //     tv_sec: 1,
    //     tv_usec: 0,
    // });
    // if let Err(e) = select(None, Some(&mut readset), None, None, None) {
    //     println!("Select failed with: {}. Trying again", e);
    //     match e.as_errno() {
    //         Some(Errno::EAGAIN) => {
    //             println!("Select failed with: {}. Trying again", e);
    //         }
    //         _ => {
    //             println!("Select failed with: {}", e);
    //         }
    //     };
    // }
}

fn peer_ip(sock: &UdpSocket) -> String {
    let peer = sock.peer_addr().unwrap().to_string();
    let parts: Vec<&str> = peer.split(":").collect();
    assert_eq!(parts.len(), 2);

    parts[0].to_string()
}

fn traceroute(hostname: String, hops: u32) {
    println!("Trying {}", hostname);
    let mut trace_complete = false;
    let mut ip_addr: Option<String> = None;
    for ttl in 1..hops {
        let port = 33435 + ttl;
        println!("Trying TTL: {}", ttl);
        let mut success = false;
        for _retry in 0..3 {
            let sock = udp_socket();
            let host = match ip_addr {
                None => format!("{}:{}", hostname, port),
                Some(ref ip) => format!("{}:{}", ip, port),
            };
            prepare_socket(&sock, &host, ttl);

            if let None = ip_addr {
                ip_addr = Some(peer_ip(&sock));
            }

            send_datagram(&sock);

            match recv_hop_cmsg(&sock) {
                Err(_err) => {
                    success = false;
                    continue;
                }
                Ok(hop_result) => {
                    if let Some(addr) = hop_result.addr {
                        trace_complete = match ip_addr {
                            None => false,
                            Some(ref ip) => *ip == addr,
                        };
                    } else {
                        println!("{}: no reply :(", ttl + 1);
                    }
                    success = true;
                    break;
                }
            };
        }
        if !success {
            println!("{}: no reply", ttl + 1);
        }
        if trace_complete {
            break;
        }
    }
}

#[cfg_attr(target_os = "android", ndk_glue::main(backtrace = "on"))]
fn main() {
    let hostname = String::from("172.217.194.147");
    let hops: u32 = 255;
    traceroute(hostname, hops);
}
