pub mod header;
mod parse_header;
mod question;
pub mod record;

use crate::{
    dns_types::Class,
    message::{question::Entry, record::Record},
    parse::parse_label,
    RecordType,
};
use anyhow::Result as AResult;
use ascii::AsciiString;
use bitvec::prelude::*;
use header::Header;
use nom::{
    combinator::{consumed, map, map_res, peek},
    error::Error,
    multi::{count, length_value},
    number::complete::{be_u16, be_u32, be_u8},
    sequence::tuple,
    IResult,
};
use std::{collections::HashMap, io::Read, net::Ipv4Addr};

use self::record::RecordData;

const LENGTH_OF_HEADER_SECTION: usize = 12;

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
pub struct Message {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    pub header: Header,
    // The question section contains fields that describe a
    // question to a name server.  These fields are a query type (QTYPE), a
    // query class (QCLASS), and a query domain name (QNAME).
    pub question: Vec<question::Entry>,
    // The last three
    // sections have the same format: a possibly empty list of concatenated
    // resource records (RRs).
    /// The answer section contains RRs that answer the question
    pub answer: Vec<Record>,
    /// the authority section contains RRs that point toward an
    /// authoritative name server;
    pub authority: Vec<Record>,
    /// the additional records section contains RRs
    /// which relate to the query, but are not strictly answers for the
    /// question.
    pub additional: Vec<Record>,
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

    pub fn deserialize(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, header) = nom::bits::bits(Header::deserialize)(i)?;

        // Parse the right number of question sections, and keep a reference back to
        // the bytes that were parsed for each one.
        let (i, question) = count(
            consumed(question::Entry::deserialize),
            header.qdcount.into(),
        )(i)?;

        // Add the domains parsed from the question as possible future domains that could be pointed to,
        // for DNS message compression.
        // See RFC 1035 part 4.1.4 for more about message compression.
        let mut q_section_offset = LENGTH_OF_HEADER_SECTION;
        let mut domains = HashMap::new();
        for (consumed, q) in &question {
            let labels_from_question = q
                .offsets()
                .into_iter()
                .map(|(offset, label)| (offset + q_section_offset, label));
            domains.extend(labels_from_question);
            q_section_offset += consumed.len();
        }
        let mut rp = RecordParser { domains };
        use nom::Parser;
        let (i, answer) = count(|i| rp.parse(i), header.ancount.into())(i)?;
        let (i, authority) = count(|i| rp.parse(i), header.nscount.into())(i)?;
        let (i, additional) = count(|i| rp.parse(i), header.arcount.into())(i)?;
        Ok((
            i,
            Message {
                header,
                question: question.into_iter().map(|(_, q)| q).collect(),
                answer,
                authority,
                additional,
            },
        ))
    }
}

#[derive(Default, Debug)]
pub struct RecordParser {
    domains: HashMap<usize, AsciiString>,
}

impl RecordParser {
    fn parse_rdata<'i>(
        &mut self,
        record_type: RecordType,
    ) -> impl FnMut(&'i [u8]) -> IResult<&'i [u8], RecordData> + '_ {
        move |i| {
            let record = match record_type {
                RecordType::A => map(tuple((be_u8, be_u8, be_u8, be_u8)), |(a, b, c, d)| {
                    RecordData::A(Ipv4Addr::new(a, b, c, d))
                })(i)?,
                RecordType::Cname => map(|i| self.parse_name(i), RecordData::Cname)(i)?,
            };
            Ok(record)
        }
    }
    fn parse_name<'i>(&mut self, mut input: &'i [u8]) -> IResult<&'i [u8], AsciiString> {
        let mut name = AsciiString::new();
        loop {
            let (i, first_byte) = peek(be_u8)(input)?;
            input = i;
            if first_byte >= 0b11000000 {
                // This label is a pointer, and it ends the sequence of labels.
                const POINTER_HEADER: u16 = 0b1100000000000000;
                // The remaining 14 bits are the offset that the pointer points at.
                let (i, pointer_offset) =
                    map(be_u16, |ptr| (ptr - POINTER_HEADER) as usize)(input)?;
                name += &self.domains[&pointer_offset];
                input = i;
                break;
            } else {
                // This label is a literal.
                let (i, label) = parse_label(input)?;
                input = i;
                name += &label;
                if label.is_empty() {
                    break;
                }
                name.push(ascii::AsciiChar::Dot);
            }
        }
        // TODO: update the domains list with the domains we got from parsing this name.
        Ok((input, name))
    }
}

impl<'i> nom::Parser<&'i [u8], Record, Error<&'i [u8]>> for RecordParser {
    fn parse(&mut self, input: &'i [u8]) -> IResult<&'i [u8], Record, Error<&'i [u8]>> {
        let (input, name) = self.parse_name(input)?;
        let (input, record_type) = map_res(be_u16, RecordType::try_from)(input)?;
        let (input, class) = map_res(be_u16, Class::try_from)(input)?;
        // RFC defines the max TTL as "positive values of a signed 32 bit number."
        let max_ttl: isize = i32::MAX.try_into().unwrap();
        let (input, ttl) = map_res(be_u32, |ttl| {
            if (ttl as isize) > max_ttl {
                Err(format!("TTL {ttl} is too large"))
            } else {
                Ok(ttl)
            }
        })(input)?;
        let (i, data) = length_value(be_u16, self.parse_rdata(record_type))(input)?;
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{
        dns_types::Class,
        message::record::{Record, RecordData},
    };

    use super::*;

    #[test]
    fn test_parse_msg() {
        let response_msg = vec![
            0, 33, 129, 128, 0, 1, 0, 2, 0, 0, 0, 0, // Header (12 bytes)
            4, 98, 108, 111, 103, // blog
            12, 97, 100, 97, 109, 99, 104, 97, 108, 109, 101, 114, 115, // adamchalmers
            3, 99, 111, 109, // com
            0,   // .
            0, 1, 0, 1, // class, type
            192, 12, // Answer #1: name, which is a pointer to byte 12.
            0, 1, 0, 1, // class, type
            0, 0, 0, 179, // TTL (u32)
            0, 4, // rdata length
            104, 19, 237, 120, // rdata, an IPv4
            192, 12, // Answer #1: name, which is a pointer to byte 12.
            0, 1, 0, 1, // class, type
            0, 0, 0, 179, // TTL (u32)
            0, 4, // rdata length
            104, 19, 238, 120, // IPv4
        ];

        // Try to parse it
        let r = Message::deserialize(&response_msg);
        let (_, actual_msg) = r.unwrap();

        // Was it correct?
        let name = AsciiString::from_ascii("blog.adamchalmers.com.").unwrap();
        let expected_answers = vec![
            Record {
                name: name.clone(),
                class: Class::IN,
                ttl: 179,
                data: RecordData::A(Ipv4Addr::new(104, 19, 237, 120)),
            },
            Record {
                name,
                class: Class::IN,
                ttl: 179,
                data: RecordData::A(Ipv4Addr::new(104, 19, 238, 120)),
            },
        ];
        let actual_answers = actual_msg.answer;
        assert_eq!(actual_answers, expected_answers)
    }
}
