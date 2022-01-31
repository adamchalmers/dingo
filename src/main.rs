use crate::message::{Message, MAX_UDP_BYTES};
use anyhow::{anyhow, Result as AResult};
use bitvec::prelude::*;
use std::{fmt, net::UdpSocket, time::Duration};

mod message;

// I asked some coworkers and they suggested this DNS resolver
const REMOTE_RESOLVER: &str = "1.1.1.1:53";

/// TTL             positive values of a signed 32 bit number.
const _MAX_TTL: isize = isize::MAX;

fn main() {
    let domain_name = "blog.adamchalmers.com".to_owned();
    let record_type = RecordType::A;
    let query_id = 33;
    println!("Resolving {record_type} records for {domain_name}");
    let msg = Message::new_query(query_id, domain_name, record_type).unwrap();
    let (resp, len) = send_req(msg).unwrap();
    print_resp(resp, len);
}

fn send_req(msg: Message) -> AResult<(Vec<u8>, usize)> {
    use std::net::SocketAddr;

    // Connect to the DNS resolver
    let local_addr = "0.0.0.0:0";
    let socket = UdpSocket::bind(local_addr).expect("couldn't bind to a local address");
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    println!(
        "Bound to :{}",
        match socket.local_addr()? {
            SocketAddr::V4(s4) => s4.port(),
            SocketAddr::V6(s6) => s6.port(),
        }
    );
    socket
        .connect(REMOTE_RESOLVER)
        .expect("couldn't connect to the DNS resolver");
    println!("Connected to {REMOTE_RESOLVER}");

    // Send the DNS resolver the message
    let body = msg.serialize_bytes()?;
    println!("Sending {} bytes", body.len());
    let bytes_sent = socket.send(&body).expect("couldn't send data");
    println!("Sent {bytes_sent} bytes");

    // Get the resolver's response.
    // Note, you have to actually allocate space to write into.
    // I was originally using an empty vector, but reading into an empty vector always
    // instantly succeeds (by writing nothing), so I was discarding the response.
    // See <https://users.rust-lang.org/t/empty-response-from-udp-recv-w-tokio-and-futures/20241/2>
    let mut response_buf = vec![0; MAX_UDP_BYTES];
    match socket.recv(&mut response_buf) {
        Ok(received) => Ok((response_buf, received)),
        Err(e) => Err(anyhow!("recv function failed: {:?}", e)),
    }
}

fn print_resp(resp: Vec<u8>, len: usize) {
    println!("received {} bytes {:?}", len, &resp[..len]);
}

enum RecordType {
    A,
    // TODO: Add more record types
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A => "A",
        };
        s.fmt(f)
    }
}

impl RecordType {
    fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::A => 1,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}

enum Class {
    IN,
}

impl Class {
    fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::IN => 1,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}
