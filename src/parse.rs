use ascii::AsciiString;
use nom::{
    branch::alt,
    combinator::{map, map_res},
    multi::many1,
    number::complete::be_u16,
    sequence::pair,
    IResult,
};

pub fn parse_domain(i: &[u8]) -> IResult<&[u8], Vec<AsciiString>> {
    println!("Parsing domain");
    let ways_to_parse_domain = (
        parse_labels_then_zero,
        parse_pointer,
        parse_labels_then_pointer,
    );
    alt(ways_to_parse_domain)(i)
}

fn parse_labels_then_pointer(i: &[u8]) -> IResult<&[u8], Vec<AsciiString>> {
    map(
        pair(many1(parse_label), parse_pointer),
        |(mut names0, names1)| {
            names0.extend(names1);
            names0
        },
    )(i)
}

fn parse_pointer(i: &[u8]) -> IResult<&[u8], Vec<AsciiString>> {
    //     The pointer takes the form of a two octet sequence:
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     | 1  1|                OFFSET                   |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // The first two bits are ones.  This allows a pointer to be distinguished
    // from a label, since the label must begin with two zero bits because
    // labels are restricted to 63 octets or less.
    const POINTER_HEADER: u16 = 0b1100000000000000;
    let (i, pointer_offset) = map(be_u16, |ptr| ptr - POINTER_HEADER)(i)?;
    // TODO: Actually parse the name
    use std::str::FromStr;
    let name = AsciiString::from_str(&format!("name at {pointer_offset}")).unwrap();
    Ok((i, vec![dbg!(name)]))
}

/// Matches a sequence of labels, terminated by a zero-length label.
fn parse_labels_then_zero(mut i: &[u8]) -> IResult<&[u8], Vec<AsciiString>> {
    let mut labels = Vec::new();
    loop {
        let (new_i, label) = parse_label(i)?;
        i = new_i;
        let len = label.len();
        labels.push(label);
        if len == 0 {
            return Ok((i, labels));
        }
    }
}

/// Read one byte as a u8. Then read that many following bytes and output them, as ASCII.
fn parse_label(i: &[u8]) -> IResult<&[u8], AsciiString> {
    let parse_len = map_res(nom::number::complete::be_u8, |num| {
        if num >= 64 {
            Err(format!(
                "DNS name labels must be <=63 bytes but this one is {num}"
            ))
        } else {
            Ok(num)
        }
    });
    let parse_label = nom::multi::length_data(parse_len);
    map_res(parse_label, AsciiString::from_ascii)(i)
}
