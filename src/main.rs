use crate::message::{header::ResponseCode, Message, MAX_UDP_BYTES};
use anyhow::{anyhow, Result as AResult};
use bitvec::prelude::*;
use std::{fmt, net::UdpSocket, time::Duration};

mod message;
mod parse;
mod util;

// I asked some coworkers and they suggested this DNS resolver
const REMOTE_RESOLVER: &str = "1.1.1.1:53";

fn main() {
    let domain_name = "blog.adamchalmers.com.".to_owned();
    let record_type = RecordType::A;
    let query_id = 33;
    println!("Resolving {record_type} records for {domain_name}");
    let msg = Message::new_query(query_id, domain_name, record_type).unwrap();
    let (resp, len) = send_req(msg).unwrap();
    if let Err(e) = print_resp(resp, len, query_id) {
        println!("Error: {e}");
    }
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

fn print_resp(resp: Vec<u8>, len: usize, sent_query_id: u16) -> AResult<()> {
    println!("received {len} bytes");
    let (_remaining_input, response_msg) = match Message::deserialize_bytes(&resp[..len]) {
        Ok(msg) => msg,
        Err(e) => anyhow::bail!("Error parsing response: {e}"),
    };
    let received_query_id = response_msg.header.id;
    if sent_query_id != received_query_id {
        println!("Mismatch between query IDs. Client sent {sent_query_id} and received {received_query_id}")
    }
    match response_msg.header.rcode {
        ResponseCode::NoError => {}
        err => anyhow::bail!("Error from resolver: {err}"),
    };
    println!("Header\n{:?}", response_msg.header);
    if response_msg.question.len() > 1 {
        for (i, question) in response_msg.question.iter().enumerate() {
            println!("Question {i}:\n{question}");
        }
    } else {
        println!("{}", response_msg.question[0]);
    }
    if !response_msg.answer.is_empty() {
        println!("Answers:");
        for record in response_msg.answer {
            println!("{:?}", record);
        }
    }
    if !response_msg.authority.is_empty() {
        println!("Authority records:");
        for record in response_msg.authority {
            println!("{:?}", record);
        }
    }
    if !response_msg.additional.is_empty() {
        println!("Additional records:");
        for record in response_msg.additional {
            println!("{:?}", record);
        }
    }
    Ok(())
}

#[derive(Debug)]
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

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record_type = match value {
            1 => Self::A,
            other => anyhow::bail!("Invalid record type number {other}"),
        };
        Ok(record_type)
    }
}

#[derive(Debug)]
enum Class {
    IN,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IN => "IN",
        };
        s.fmt(f)
    }
}

impl Class {
    fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::IN => 1,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}

impl TryFrom<u16> for Class {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record_type = match value {
            1 => Self::IN,
            other => anyhow::bail!("Invalid class number {other}"),
        };
        Ok(record_type)
    }
}
