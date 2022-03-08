use crate::{
    cli::AppArgs,
    dns_types::{Class, RecordType},
    message::Message,
};
use rand::Rng;

mod cli;
mod dns_types;
mod io;
mod message;
mod parse;

const VERBOSE: bool = false;

fn main() {
    let AppArgs {
        name,
        record_type,
        resolver,
    } = AppArgs::parse().unwrap();
    let query_id = rand::thread_rng().gen();
    let msg = Message::new_query(query_id, name, record_type).unwrap();
    let (resp, len) = io::send_req(msg, resolver, VERBOSE).unwrap();
    if let Err(e) = io::print_resp(resp, len, query_id, VERBOSE) {
        println!("Error: {e}");
    }
}
