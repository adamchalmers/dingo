use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Class, RecordType};

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Record {
    pub name: String,
    pub class: Class,
    pub ttl: u32,
    pub data: RecordData,
}

impl Record {
    pub fn as_dns_response(&self) -> String {
        let rdata = match &self.data {
            RecordData::A(ipv4) => ipv4.to_string(),
            RecordData::Aaaa(ipv6) => ipv6.to_string(),
            RecordData::Cname(name) => name.to_string(),
            RecordData::Soa(soa) => format!("{soa:?}"),
            RecordData::Gpos(rr) => format!("{rr:?}"),
            RecordData::X25(rr) => format!("{rr:?}"),
        };
        format!("{rdata} (TTL {})", self.ttl)
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Soa(SoaData),
    X25(X25Data),
    Gpos(GposData),
}

impl RecordData {
    #[allow(dead_code)]
    fn as_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::Aaaa,
            Self::Cname(_) => RecordType::Cname,
            Self::Soa(_) => RecordType::Soa,
            Self::X25(_) => RecordType::X25,
            Self::Gpos(_) => RecordType::Gpos,
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct SoaData {
    /// name server that was the original or primary source of data for this zone.
    pub mname: String,
    /// mailbox of the person responsible for this zone.
    pub rname: String,
    /// The unsigned 32 bit version number of the original copy
    /// of the zone.  Zone transfers preserve this value.  This
    /// value wraps and should be compared using sequence space
    /// arithmetic.
    pub serial: u32,
    /// time interval before the zone should be refreshed.
    pub refresh: u32,
    /// time interval that should elapse before a failed refresh should be retried.
    pub retry: u32,
    /// upper limit on the time interval that can elapse before the zone is no longer authoritative.
    pub expire: u32,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct X25Data;

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct GposData;
