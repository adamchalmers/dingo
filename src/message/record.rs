use std::net::Ipv4Addr;

use crate::{Class, RecordType};
use ascii::AsciiString;

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Record {
    pub name: AsciiString,
    pub class: Class,
    pub ttl: u32,
    pub data: RecordData,
}

impl Record {
    pub fn as_dns_response(&self) -> String {
        let rdata = match &self.data {
            RecordData::A(ipv4) => ipv4.to_string(),
            RecordData::Cname(name) => name.to_string(),
        };
        format!("{rdata} (TTL {})", self.ttl)
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum RecordData {
    A(Ipv4Addr),
    Cname(AsciiString),
}

impl RecordData {
    #[allow(dead_code)]
    fn as_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Cname(_) => RecordType::Cname,
        }
    }
}
