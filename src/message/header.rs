use crate::message::parser_utils::*;
use bitvec::prelude::*;
use nom::IResult;

/// RFC 1035 defines DNS headers as 12 bytes long.
const EXPECTED_SIZE_BYTES: usize = 12;

/// All DNS messages start with a Header (both queries and responses!)
/// Structure is defined at <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
#[derive(Debug)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    pub id: u16,
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    is_query: bool,
    /// A four bit field that specifies kind of query in this message.  This value is set by the originator of a query and copied into the response.
    opcode: Opcode,
    /// This bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
    authoritative_answer: bool,
    /// Specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    truncation: bool,
    /// This bit may be set in a query and is copied into the response.  If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
    recursion_desired: bool,
    /// This be (sic) is set or cleared in a response, and denotes whether recursive query support is available in the name server.
    recursion_available: bool,
    pub resp_code: ResponseCode,
    /// Number of entries in the question section.
    pub question_count: u16,
    /// Number of resource records in the answer section.
    pub answer_count: u16,
    /// Number of name server resource records in the authority records section.
    pub name_server_count: u16,
    /// Number of resource records in the additional records section.
    pub additional_records_count: u16,
}

impl Header {
    /// Generate the header for a query with one question.
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            is_query: false,
            opcode: Opcode::Query,
            authoritative_answer: Default::default(),
            truncation: false,
            recursion_desired: true,
            recursion_available: Default::default(),
            resp_code: ResponseCode::NoError, // This doesn't matter for a query
            // In a query, there will be 1 question and no records.
            question_count: 1,
            answer_count: 0,
            name_server_count: 0,
            additional_records_count: 0,
        }
    }

    /// Serialize the Header and write it into the stream of bits.
    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let initial_length_bits = bv.len();
        bv.extend(self.id.view_bits::<Msb0>());
        bv.push(self.is_query);
        self.opcode.serialize(bv);
        bv.push(self.authoritative_answer);
        bv.push(self.truncation);
        bv.push(self.recursion_desired);
        bv.push(self.recursion_available);
        // the Z field, reserved for future use.
        // Must be zero in all queries and responses.
        bv.extend_from_bitslice(bits![0; 3]);
        self.resp_code.serialize(bv);
        bv.extend(self.question_count.view_bits::<Msb0>());
        bv.extend(self.answer_count.view_bits::<Msb0>());
        bv.extend(self.name_server_count.view_bits::<Msb0>());
        bv.extend(self.additional_records_count.view_bits::<Msb0>());
        let bits_written = bv.len() - initial_length_bits;
        assert_eq!(bits_written, 8 * EXPECTED_SIZE_BYTES);
    }

    pub fn deserialize(i: BitInput) -> IResult<BitInput, Self> {
        use nom::combinator::map_res;

        // From RFC 1035, section 4.1.1
        // The header contains the following fields:
        //
        //                               1  1  1  1  1  1
        // 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        let (i, id) = take_u16(i)?;
        let (i, qr) = take_bit(i)?;
        let (i, opcode) = map_res(take_nibble, Opcode::try_from)(i)?;
        let (i, aa) = take_bit(i)?;
        let (i, tc) = take_bit(i)?;
        let (i, rd) = take_bit(i)?;
        let (mut i, ra) = take_bit(i)?;
        for _ in 0..3 {
            let z;
            (i, z) = take_bit(i)?;
            assert!(!z);
        }
        let (i, rcode) = map_res(take_nibble, ResponseCode::try_from)(i)?;
        let (i, qdcount) = take_u16(i)?;
        let (i, ancount) = take_u16(i)?;
        let (i, nscount) = take_u16(i)?;
        let (i, arcount) = take_u16(i)?;
        let header = Header {
            id,
            is_query: qr,
            opcode,
            authoritative_answer: aa,
            truncation: tc,
            recursion_desired: rd,
            recursion_available: ra,
            resp_code: rcode,
            question_count: qdcount,
            answer_count: ancount,
            name_server_count: nscount,
            additional_records_count: arcount,
        };
        Ok((i, header))
    }
}

/// A four bit field that specifies kind of query in this message.
/// This value is set by the originator of a query and copied into the response.
#[derive(Debug)]
enum Opcode {
    /// 0: a standard query (QUERY)
    Query,
    /// 1: an inverse query (IQUERY)
    InverseQuery,
    /// 2: a server status request (STATUS)
    Status,
}

impl TryFrom<u8> for Opcode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let op = match value {
            0 => Self::Query,
            1 => Self::InverseQuery,
            2 => Self::Status,
            other => anyhow::bail!("Unknown opcode {other}"),
        };
        Ok(op)
    }
}

impl Opcode {
    fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        match self {
            Self::Query => bv.extend_from_bitslice(bits![u8, Msb0; 0; 4]),
            Self::InverseQuery => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 0, 1]),
            Self::Status => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 0]),
        }
    }
}

/// This field is set by the DNS resolver and indicates if the DNS query was successful or erroneous.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum ResponseCode {
    NoError,
    /// The name server was unable to interpret the query
    FormatError,
    /// The name server was unable to process this query due to a problem with the name server.
    ServerFailure,
    /// Meaningful only for
    /// responses from an authoritative name
    /// server, this code signifies that the
    /// domain name referenced in the query does
    /// not exist.
    NameError,
    /// The name server does not support the requested kind of query.
    NotImplemented,
    /// The name server refuses to
    /// perform the specified operation for
    /// policy reasons.  For example, a name
    /// server may not wish to provide the
    /// information to the particular requester,
    /// or a name server may not wish to perform
    /// a particular operation (e.g., zone
    Refused,
}

impl ResponseCode {
    fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        match self {
            Self::NoError => bv.extend_from_bitslice(bits![u8, Msb0; 0; 4]),
            Self::FormatError => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 0, 1]),
            Self::ServerFailure => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 0]),
            Self::NameError => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 1]),
            Self::NotImplemented => bv.extend_from_bitslice(bits![u8, Msb0; 0, 1, 0, 0]),
            Self::Refused => bv.extend_from_bitslice(bits![u8, Msb0; 0, 1, 0, 1]),
        };
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NoError => "No error condition",
            Self::FormatError => "The name server was unable to interpret the query",
            Self::ServerFailure => "The name server was unable to process this query due to a problem with the name server.",
            Self::NameError => "Domain name referenced in the query does not exist",
            Self::NotImplemented => "The name server does not support the requested kind of query",
            Self::Refused => "The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation"
        };
        s.fmt(f)
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let op = match value {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            other => anyhow::bail!("Unknown response code {other}"),
        };
        Ok(op)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::Read;

    #[test]
    fn test_serialize_header_for_query() {
        let test_id = 33;
        let h = Header::new_query(test_id);
        let mut bv = BitVec::<u8, Msb0>::new();
        h.serialize(&mut bv);
        let mut buf = [0; EXPECTED_SIZE_BYTES];
        bv.as_bitslice().read_exact(&mut buf).unwrap();
    }

    #[test]
    fn test_deserialize() {
        // This is a real response from a DNS resolver (1.1.1.1)
        let i = vec![
            0, 33, 128, 130, 0, 1, 0, 0, 0, 0, 0, 0, 4, 98, 108, 111, 103, 12, 97, 100, 97, 109,
            99, 104, 97, 108, 109, 101, 114, 115, 3, 99, 111, 109, 0, 0, 1, 0, 1,
        ];

        pub fn deser(i: &[u8]) -> IResult<&[u8], Header> {
            nom::bits::bits(Header::deserialize)(i)
        }
        let (_i, h): (&[u8], Header) = deser(&i).unwrap();
        assert_eq!(h.id, 33);
        assert_eq!(h.resp_code, ResponseCode::ServerFailure);
    }
}
