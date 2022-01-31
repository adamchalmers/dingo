#[cfg(test)]
mod message;

// /// From the RFC: "Various objects and parameters in the DNS have size limits.""
// /// labels          63 octets or less
// const MAX_LABEL_BYTES: usize = 63;
// /// names           255 octets or less
// const MAX_NAME_BYTES: usize = 255;
// /// TTL             positive values of a signed 32 bit number.
// const MAX_TTL: isize = isize::MAX;
// /// UDP messages    512 octets or less
// const MAX_UDP_BYTES: usize = 512;

fn main() {
    let host = "blog.adamchalmers.com".to_owned();
    let record_type = "A".to_owned();
    let resp = send_req(host, record_type);
    println!("{:?}", resp);
}

fn send_req(_host: String, _resp: String) -> String {
    todo!();
}
