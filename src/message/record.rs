use std::{fmt, net::Ipv4Addr};

use crate::{
    parse::{parse_domain, take_le2_bytes, BitInput},
    util::join_asciis,
    Class, RecordType,
};
use nom::{
    bits::complete::take,
    combinator::{map, map_res},
    IResult,
};

/// TTL             positive values of a signed 32 bit number.
const MAX_TTL: isize = isize::MAX;
#[derive(Debug)]
pub struct Record {
    name: String,
    class: Class,
    ttl: u32,
    data: RecordData,
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

impl Record {
    pub fn deserialize(i: BitInput) -> IResult<BitInput, Self> {
        println!("Getting record: {i:?}");
        let (i, name) = map(parse_domain, |strs| join_asciis(&strs))(i)?;
        dbg!(&name);
        let (i, record_type) = map_res(take(16u8), |n: u16| match dbg!(RecordType::try_from(n)) {
            Ok(rt) => Ok(rt),
            Err(e) => Err(e),
        })(i)?;
        let (i, class) = map_res(|i| take_le2_bytes(i, 16), Class::try_from)(i)?;
        let (i, ttl) = map_res(take(32usize), |ttl| {
            if (ttl as isize) > MAX_TTL {
                Err(format!("TTL {ttl} is too large"))
            } else {
                Ok(ttl)
            }
        })(i)?;
        let mut parse_data = match (&record_type, &class) {
            (RecordType::A, Class::IN) => map(
                nom::sequence::tuple((take(8usize), take(8usize), take(8usize), take(8usize))),
                |(a, b, c, d)| RecordData::A(Ipv4Addr::new(a, b, c, d)),
            ),
        };
        let (i, data) = parse_data(i)?;
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
