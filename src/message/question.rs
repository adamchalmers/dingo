use crate::{Class, RecordType};
use anyhow::{anyhow, Result as AResult};
use ascii::AsciiString;
use bitvec::prelude::*;

const LABEL_TOO_LONG: &str = "is too long (must be <64 chars)";

#[derive(Debug)]
pub struct Entry {
    labels: Vec<AsciiString>,
    record_type: RecordType,
    record_qclass: Class,
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
            let len = u8::try_from(len).map_err(|_| anyhow!("Label {label} {LABEL_TOO_LONG}"))?;
            if len >= 64 {
                anyhow::bail!("Label {label} {LABEL_TOO_LONG}")
            }
            bv.extend_from_bitslice(len.view_bits::<Msb0>());
            label
                .chars()
                .map(|ch| ch.as_byte())
                .for_each(|byte| bv.extend_from_bitslice(byte.view_bits::<Msb0>()));
        }
        // The domain name terminates with the zero length octet for the null label of the root.
        bv.extend_from_bitslice(0u8.view_bits::<Msb0>());
        Ok(())
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
