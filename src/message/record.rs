use std::{fmt, net::Ipv4Addr};

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

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!(
            "{} ({}) => {} (TTL {})",
            self.name, self.class, self.data, self.ttl
        );
        s.fmt(f)
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum RecordData {
    A(Ipv4Addr),
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A(ipv4) => format!("{ipv4}"),
        };
        s.fmt(f)
    }
}

impl From<RecordData> for RecordType {
    fn from(rd: RecordData) -> Self {
        match rd {
            RecordData::A(_) => Self::A,
        }
    }
}
