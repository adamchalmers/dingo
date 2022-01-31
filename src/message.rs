mod header;
mod question;

use std::io::Read;

use crate::RecordType;
use anyhow::Result as AResult;
use ascii::AsciiString;
use bitvec::prelude::*;
use header::Header;

use self::question::Entry;

/// Defined by the spec
/// UDP messages    512 octets or less
pub(crate) const MAX_UDP_BYTES: usize = 512;

/// Defined by the spec
/// labels          63 octets or less
const MAX_LABEL_BYTES: usize = 63;

/// Defined by the spec
/// names           255 octets or less
const MAX_NAME_BYTES: usize = 255;

#[allow(dead_code)] // Haven't yet implemented responses
pub struct Message {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    header: Header,
    // The question section contains fields that describe a
    // question to a name server.  These fields are a query type (QTYPE), a
    // query class (QCLASS), and a query domain name (QNAME).
    question: Vec<question::Entry>,
    // The last three
    // sections have the same format: a possibly empty list of concatenated
    // resource records (RRs).
    /// The answer section contains RRs that answer the question
    answer: (),
    /// the authority section contains RRs that point toward an
    /// authoritative name server;
    authority: (),
    /// the additional records section contains RRs
    /// which relate to the query, but are not strictly answers for the
    /// question.
    additional: (),
}

impl Message {
    pub(crate) fn new_query(
        id: u16,
        domain_name: String,
        record_type: RecordType,
    ) -> AResult<Self> {
        let name_len = domain_name.len();
        if name_len > MAX_NAME_BYTES {
            anyhow::bail!(
                "Domain name is {name_len} bytes, which is over the max of {MAX_NAME_BYTES}"
            );
        }
        let dn = AsciiString::from_ascii(domain_name)?;
        let labels: Vec<_> = dn
            .split(ascii::AsciiChar::Dot)
            .map(|a| a.to_owned())
            .collect();
        if labels.iter().any(|label| label.len() > MAX_LABEL_BYTES) {
            anyhow::bail!(
                "One of the labels in your domain is over the max of {MAX_LABEL_BYTES} bytes"
            );
        }
        let msg = Message {
            header: Header::new_query(id),
            question: vec![Entry::new(labels, record_type)],
            answer: (),
            authority: (),
            additional: (),
        };
        Ok(msg)
    }

    fn serialize_bits<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) -> AResult<()> {
        self.header.serialize(bv);
        for q in &self.question {
            q.serialize(bv)?;
        }
        Ok(())
    }

    pub fn serialize_bytes(&self) -> AResult<Vec<u8>> {
        let mut bv = BitVec::<usize, Msb0>::new();
        self.serialize_bits(&mut bv)?;
        let mut msg_bytes = Vec::with_capacity(MAX_UDP_BYTES);
        bv.as_bitslice().read_to_end(&mut msg_bytes).unwrap();
        Ok(msg_bytes)
    }
}
