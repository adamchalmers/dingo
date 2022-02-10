use crate::{
    dns_types::{Class, RecordType},
    message::Message,
};

mod dns_types;
mod io;
mod message;
mod parse;
mod util;

fn main() {
    let domain_name = "blog.adamchalmers.com.".to_owned();
    let record_type = RecordType::A;
    let query_id = 33;
    let msg = Message::new_query(query_id, domain_name, record_type).unwrap();
    let (resp, len) = io::send_req(msg).unwrap();
    if let Err(e) = io::print_resp(resp, len, query_id) {
        println!("Error: {e}");
    }
}
