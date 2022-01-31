use std::net::Ipv4Addr;

use crate::{parse::BitInput, Class, RecordType};
use ascii::AsciiString;
use nom::IResult;

#[derive(Debug)]
pub struct Record {
    name: AsciiString,
    class: Class,
    ttl: u32,
    data: RecordData,
}

impl Record {
    pub fn deserialize(i: BitInput) -> IResult<BitInput, Self> {
        let name = AsciiString::new();
        let class = Class::IN;
        let ttl = 0;
        let data = RecordData::A(Ipv4Addr::new(0, 0, 0, 0));
        Ok((
            i,
            Record {
                name,
                class,
                ttl,
                data,
            },
        ))
    }
}

#[derive(Debug)]
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
