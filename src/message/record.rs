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
        let (rtype, rdata) = match self.data {
            RecordData::A(ipv4) => ("A", ipv4.to_string()),
        };
        format!(
            "({}, {rtype}) for {} => {rdata} (TTL {})",
            self.class, self.name, self.ttl
        )
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum RecordData {
    A(Ipv4Addr),
}

impl From<RecordData> for RecordType {
    fn from(rd: RecordData) -> Self {
        match rd {
            RecordData::A(_) => Self::A,
        }
    }
}
