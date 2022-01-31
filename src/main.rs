use crate::message::Message;
use anyhow::Result as AResult;
use bitvec::prelude::*;
use std::{net::UdpSocket, time::Duration};

mod message;

const REMOTE_RESOLVER: &str = "1.1.1.1:53";

// /// From the RFC: "Various objects and parameters in the DNS have size limits.""
// /// labels          63 octets or less
// const MAX_LABEL_BYTES: usize = 63;
// /// names           255 octets or less
// const MAX_NAME_BYTES: usize = 255;
// /// TTL             positive values of a signed 32 bit number.
// const MAX_TTL: isize = isize::MAX;

fn main() {
    let domain_name = "blog.adamchalmers.com".to_owned();
    let record_type = RecordType::A;
    let query_id = 33;
    let msg = Message::new_query(query_id, domain_name, record_type).unwrap();
    let resp = send_req(msg).unwrap();
    println!("{:?}", resp);
}

fn send_req(msg: Message) -> AResult<Vec<u8>> {
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

    // Get the resolver's response
    let mut response_buf = vec![0; 1024];
    match socket.recv(&mut response_buf) {
        Ok(received) => println!(
            "received {} bytes {:?}",
            received,
            &response_buf[..received]
        ),
        Err(e) => println!("recv function failed: {:?}", e),
    }
    Ok(response_buf)
}

enum RecordType {
    A,
    // TODO: Add more record types
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
