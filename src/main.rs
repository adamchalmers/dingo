use crate::message::Message;
use anyhow::Result as AResult;
use bitvec::prelude::*;
use std::net::UdpSocket;

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
    let socket = UdpSocket::bind("127.0.0.1:34254").expect("couldn't bind to address");
    socket
        .send_to(&msg.serialize_bytes()?, REMOTE_RESOLVER)
        .expect("couldn't send data");
    let mut buf = Vec::new();
    match socket.recv(&mut buf) {
        Ok(received) => println!("received {} bytes {:?}", received, &buf[..received]),
        Err(e) => println!("recv function failed: {:?}", e),
    }
    Ok(buf)
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
