use crate::{parse::parse_labels_then_zero, util::join_asciis, Class, RecordType};
use anyhow::{anyhow, Result as AResult};
use ascii::AsciiString;
use bitvec::prelude::*;
use nom::{combinator::map_res, number::complete::be_u16, IResult};
use std::fmt;

const LABEL_TOO_LONG: &str = "is too long (must be <64 chars)";

#[derive(Debug)]
pub struct Entry {
    labels: Vec<AsciiString>,
    record_type: RecordType,
    record_qclass: Class,
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!("{}: {}", self.record_type, join_asciis(&self.labels));
        s.fmt(f)
    }
}

impl Entry {
    pub(crate) fn new(labels: Vec<AsciiString>, record_type: RecordType) -> Self {
        Self {
            labels,
            record_type,
            record_qclass: Class::IN,
        }
    }

    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) -> AResult<()> {
        self.serialize_qname(bv)?;
        self.record_type.serialize(bv);
        self.record_qclass.serialize(bv);
        Ok(())
    }

    fn serialize_qname<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) -> AResult<()> {
        // QNAME   a domain name represented as a sequence of labels, where
        //         each label consists of a length octet followed by that
        //         number of octets.
        for label in &self.labels {
            // The mapping of domain names to labels is defined in RFC 1035:
            // 2.3.1. Preferred name syntax
            let len = label.len();
            let fmt = format!("Label {label} {LABEL_TOO_LONG}");
            let len = u8::try_from(len).map_err(|_| anyhow!("{fmt}"))?;
            if len >= 64 {
                anyhow::bail!("{fmt}")
            }
            bv.extend_from_bitslice(len.view_bits::<Msb0>());
            label
                .chars()
                .map(|ch| ch.as_byte())
                .for_each(|byte| bv.extend_from_bitslice(byte.view_bits::<Msb0>()));
        }
        Ok(())
    }

    pub fn deserialize(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, labels) = parse_labels_then_zero(i)?;
        let (i, record_type) = map_res(be_u16, RecordType::try_from)(i)?;
        let (i, record_qclass) = map_res(be_u16, Class::try_from)(i)?;
        Ok((
            i,
            Self {
                labels,
                record_type,
                record_qclass,
            },
        ))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::Read;

    #[test]
    fn test_serialize_entry() {
        let entry = Entry {
            labels: vec![
                AsciiString::from_ascii("adamchalmers").unwrap(),
                AsciiString::from_ascii("com").unwrap(),
                AsciiString::from_ascii("").unwrap(),
            ],
            record_type: RecordType::A,
            record_qclass: Class::IN,
        };
        let mut bv = BitVec::<u8, Msb0>::new();
        entry.serialize(&mut bv).unwrap();
        let mut buf = Vec::new();
        let expected_bytes_read = "adamchalmers".len() + 1 + // First label
        "com".len() + 1 // Second label
        + 1 // Last empty label
        + 2 // QCLASS is 16 bits
        + 2; // QTYPE is 16 bits
        let actual_bytes_read = bv.as_bitslice().read_to_end(&mut buf).unwrap();
        assert_eq!(expected_bytes_read, actual_bytes_read);
    }
}
