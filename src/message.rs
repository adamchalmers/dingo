use bitvec::prelude::*;
struct Message {
    /// The header section is always present.  The header includes fields that
    /// specify which of the remaining sections are present, and also specify
    /// whether the message is a query or a response, a standard query or some
    /// other opcode, etc.
    header: Header,
    // The question section contains fields that describe a
    // question to a name server.  These fields are a query type (QTYPE), a
    // query class (QCLASS), and a query domain name (QNAME).
    question: (),
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

struct Header {
    /// A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    id: u16,
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
    rcode: ResponseCode,
    /// Number of entries in the question section.
    qdcount: u16,
    /// Number of resource records in the answer section.
    ancount: u16,
    /// Number of name server resource records in the authority records section.
    nscount: u16,
    /// Number of resource records in the additional records section.
    arcount: u16,
}

const HEADER_SIZE_BYTES: usize = 2 * 6;

impl Header {
    /// Generate the header for a query with one question.
    fn query() -> Self {
        Self {
            id: 33,
            qr: false,
            opcode: Opcode::Query,
            aa: Default::default(),
            tc: false,
            rd: false,
            ra: Default::default(),
            rcode: ResponseCode::NoError,
            qdcount: 1,
            ancount: Default::default(),
            nscount: Default::default(),
            arcount: Default::default(),
        }
    }
    fn serialize<T: BitStore>(self, bv: &mut BitVec<T, Msb0>) {
        bv.extend(self.id.view_bits::<Msb0>());
        bv.push(self.qr);
        self.opcode.serialize(bv);
        bv.push(self.aa);
        bv.push(self.tc);
        bv.push(self.rd);
        bv.push(self.ra);
        // the Z field, reserved for future use.
        // Must be zero in all queries and responses.
        bv.extend_from_bitslice(&bits![0; 3]);
        self.rcode.serialize(bv);
        bv.extend(self.qdcount.view_bits::<Msb0>());
        bv.extend(self.ancount.view_bits::<Msb0>());
        bv.extend(self.nscount.view_bits::<Msb0>());
        bv.extend(self.arcount.view_bits::<Msb0>());
    }
}

enum Opcode {
    // 0: a standard query (QUERY)
    Query,
    // 1: an inverse query (IQUERY)
    IQuery,
    // 2: a server status request (STATUS)
    Status,
}

impl Opcode {
    fn serialize<T: BitStore>(self, bv: &mut BitVec<T, Msb0>) {
        match self {
            Self::Query => bv.extend_from_bitslice(bits![u8, Msb0; 0; 4]),
            Self::IQuery => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 0, 1]),
            Self::Status => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 0]),
        }
    }
}

enum ResponseCode {
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
    fn serialize<T: BitStore>(self, bv: &mut BitVec<T, Msb0>) {
        match self {
            ResponseCode::NoError => bv.extend_from_bitslice(bits![u8, Msb0; 0; 4]),
            ResponseCode::FormatError => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 0, 1]),
            ResponseCode::ServerFailure => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 0]),
            ResponseCode::NameError => bv.extend_from_bitslice(bits![u8, Msb0; 0, 0, 1, 1]),
            ResponseCode::NotImplemented => bv.extend_from_bitslice(bits![u8, Msb0; 0, 1, 0, 0]),
            ResponseCode::Refused => bv.extend_from_bitslice(bits![u8, Msb0; 0, 1, 0, 1]),
        };
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_header_for_query() {
        let h = Header::query();
        let mut bv = BitVec::<u8, Msb0>::new();
        h.serialize(&mut bv);
        let vals: Vec<_> = bv.iter().collect();
        // let mut buf = Vec::new();
        // let bytes_read = bv.read_to_end(&mut buf).unwrap();
        assert_eq!(96, vals.len());
    }
}
