use bitvec::prelude::*;
use nom::IResult;

use crate::parse::{take_bit, take_le1_byte, take_le2_bytes, take_nibble, BitInput};

/// Headers should always be 6 bytes long.
const EXPECTED_SIZE_BYTES: usize = 2 * 6;

/// All DNS messages start with a Header (both queries and responses!)
/// Structure is defined at <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
#[derive(Debug)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    pub id: u16,
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    qr: bool,
    /// A four bit field that specifies kind of query in this message.  This value is set by the originator of a query and copied into the response.
    opcode: Opcode,
    /// Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
    aa: bool,
    /// TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    tc: bool,
    /// Recursion Desired - this bit may be set in a query and is copied into the response.  If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
    rd: bool,
    /// Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
    ra: bool,
    pub rcode: ResponseCode,
    /// Number of entries in the question section.
    qdcount: u16,
    /// Number of resource records in the answer section.
    ancount: u16,
    /// Number of name server resource records in the authority records section.
    nscount: u16,
    /// Number of resource records in the additional records section.
    arcount: u16,
}

impl Header {
    /// Generate the header for a query with one question.
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: Default::default(),
            tc: false,
            rd: false,
            ra: Default::default(),
            rcode: ResponseCode::NoError, // This doesn't matter for a query
            // In a query, there will be 1 question and no records.
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Serialize the Header and write it into the stream of bits.
    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let initial_length_bits = bv.len();
        bv.extend(self.id.view_bits::<Msb0>());
        bv.push(self.qr);
        self.opcode.serialize(bv);
        bv.push(self.aa);
        bv.push(self.tc);
        bv.push(self.rd);
        bv.push(self.ra);
        // the Z field, reserved for future use.
        // Must be zero in all queries and responses.
        bv.extend_from_bitslice(bits![0; 3]);
        self.rcode.serialize(bv);
        bv.extend(self.qdcount.view_bits::<Msb0>());
        bv.extend(self.ancount.view_bits::<Msb0>());
        bv.extend(self.nscount.view_bits::<Msb0>());
        bv.extend(self.arcount.view_bits::<Msb0>());
        let bits_written = bv.len() - initial_length_bits;
        assert_eq!(bits_written, 8 * EXPECTED_SIZE_BYTES);
    }

    pub fn deserialize(i: BitInput) -> IResult<BitInput, Self> {
        use nom::combinator::map_res;

        let (i, id) = take_le2_bytes(i, 16)?;
        let (i, qr) = take_bit(i)?;
        let (i, opcode) = map_res(take_nibble, Opcode::try_from)(i)?;
        let (i, aa) = take_bit(i)?;
        let (i, tc) = take_bit(i)?;
        let (i, rd) = take_bit(i)?;
        let (i, ra) = take_bit(i)?;
        let (i, z) = take_le1_byte(i, 3)?;
        assert_eq!(z, 0);
        let (i, rcode) = map_res(take_nibble, ResponseCode::try_from)(i)?;
        let (i, qdcount) = take_le2_bytes(i, 16)?;
        let (i, ancount) = take_le2_bytes(i, 16)?;
        let (i, nscount) = take_le2_bytes(i, 16)?;
        let (i, arcount) = take_le2_bytes(i, 16)?;
        let header = Header {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };
        Ok((i, header))
    }
}

#[derive(Debug)]
enum Opcode {
    // 0: a standard query (QUERY)
    Query,
    // 1: an inverse query (IQUERY)
    IQuery,
    // 2: a server status request (STATUS)
    Status,
}

impl TryFrom<u8> for Opcode {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let op = match value {
            0 => Self::Query,
            1 => Self::IQuery,
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
            Self::IQuery => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 0, 1]),
            Self::Status => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 0]),
        }
    }
}

#[derive(Debug)]
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
    fn test_header_for_query() {
        let test_id = 33;
        let h = Header::new_query(test_id);
        let mut bv = BitVec::<u8, Msb0>::new();
        h.serialize(&mut bv);
        let mut buf = [0; EXPECTED_SIZE_BYTES];
        bv.as_bitslice().read_exact(&mut buf).unwrap();
    }
}