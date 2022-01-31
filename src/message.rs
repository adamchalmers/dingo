pub mod header;
mod question;
pub mod record;

use std::io::Read;

use crate::{parse::BitInput, RecordType};
use anyhow::Result as AResult;
use ascii::AsciiString;
use bitvec::prelude::*;
use header::Header;
use nom::{multi::count, IResult};

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

#[derive(Debug)]
#[allow(dead_code)] // Haven't yet implemented responses
pub struct Message {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    pub header: Header,
    // The question section contains fields that describe a
    // question to a name server.  These fields are a query type (QTYPE), a
    // query class (QCLASS), and a query domain name (QNAME).
    question: Vec<question::Entry>,
    // The last three
    // sections have the same format: a possibly empty list of concatenated
    // resource records (RRs).
    /// The answer section contains RRs that answer the question
    answer: Vec<record::Record>,
    /// the authority section contains RRs that point toward an
    /// authoritative name server;
    authority: Vec<record::Record>,
    /// the additional records section contains RRs
    /// which relate to the query, but are not strictly answers for the
    /// question.
    additional: Vec<record::Record>,
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
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
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

    /// Parse a DNS message from a sequence of bytes
    pub fn deserialize_bytes(i: &[u8]) -> IResult<&[u8], Self> {
        // Convert the byte-offset input into a bit-offset input, then parse that.
        nom::bits::bits(Self::deserialize_bits)(i)
    }

    /// Parse a DNS message from a sequence of bits
    fn deserialize_bits(i: BitInput) -> IResult<BitInput, Self> {
        let (i, header) = Header::deserialize(i)?;
        let (i, question) = count(question::Entry::deserialize, header.qdcount.into())(i)?;
        let (i, answer) = count(record::Record::deserialize, header.ancount.into())(i)?;
        let (i, authority) = count(record::Record::deserialize, header.nscount.into())(i)?;
        let (i, additional) = count(record::Record::deserialize, header.arcount.into())(i)?;
        Ok((
            i,
            Self {
                header,
                question,
                answer,
                authority: Vec::new(),
                additional: Vec::new(),
            },
        ))
    }
}
