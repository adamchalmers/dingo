use crate::message::{header::ResponseCode, Message, MAX_UDP_BYTES};
use anyhow::{anyhow, Result as AResult};
use std::{net::UdpSocket, time::Duration};

// I asked some coworkers and they suggested this DNS resolver
const REMOTE_RESOLVER: &str = "1.1.1.1:53";

pub fn send_req(msg: Message) -> AResult<(Vec<u8>, usize)> {
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

pub fn print_resp(resp: Vec<u8>, len: usize, sent_query_id: u16) -> AResult<()> {
    println!("received {len} bytes");

    // Parse and validate the response.
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

    // Reprint the question, why not?
    if response_msg.question.len() > 1 {
        for (i, question) in response_msg.question.iter().enumerate() {
            println!("Question {i}:\n{question}");
        }
    } else {
        println!("{}", response_msg.question[0]);
    }

    // Print records sent by the resolver.
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
