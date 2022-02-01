use ascii::AsciiString;
use nom::{
    bits::complete::take,
    branch::alt,
    combinator::{map, map_res},
    multi::many1,
    sequence::pair,
    IResult,
};

/// Newtype around a very common type in Nom.
/// Represents a binary sequence which can be parsed one bit at a time.
/// Nom represents this as a sequence of bytes, and an offset tracking which number bit
/// is currently being read.
///
/// For example, you might start with 16 bits, pointing at the 0th bit:
///```
/// 1111000011001100
/// ^
/// ```
/// Nom represents this using the BitInput type as:
/// ```
/// ([0b11110000, 0b11001100], 0)
///     ^
/// ```
/// Lets say you parsed 3 bits from there. After that, the BitInput would be
///
/// ```
/// ([0b11110000, 0b11001100], 3)
///        ^
/// ```
/// After reading another six bits, the input would have advanced past the first byte:
///
/// ```
/// ([0b11110000, 0b11001100], 9)
///                  ^
/// ```
/// Because the first byte will never be used again, Nom optimizes by dropping the first byte
///
/// ```
///  ([0b11001100], 1)
///       ^
/// ```
pub type BitInput<'a> = (&'a [u8], usize);

/// Takes n bits from the BitInput, n <= 8
/// Returns the remaining BitInput and a number parsed the first n bits.
pub fn take_le1_byte(i: BitInput, n: u8) -> IResult<BitInput, u8> {
    take(n)(i)
}

/// Take 4 bits from the BitInput.
pub fn take_nibble(i: BitInput) -> IResult<BitInput, u8> {
    take_le1_byte(i, 4)
}

/// Takes n bits from the BitInput, n <= 16
/// Returns the remaining BitInput and a number parsed the first n bits.
pub fn take_le2_bytes(i: BitInput, n: u8) -> IResult<BitInput, u16> {
    take(n)(i)
}

/// Takes one bit from the BitInput.
pub fn take_bit(i: BitInput) -> IResult<BitInput, bool> {
    let (i, bit): (BitInput, u8) = take(1u8)(i)?;
    Ok((i, bit != 0))
}

pub fn parse_domain(i: BitInput) -> IResult<BitInput, Vec<AsciiString>> {
    println!("Parsing domain");
    let ways_to_parse_domain = (
        nom::bits::bytes(parse_labels_then_zero),
        parse_pointer,
        parse_labels_then_pointer,
    );
    alt(ways_to_parse_domain)(i)
}

fn parse_labels_then_pointer(i: BitInput) -> IResult<BitInput, Vec<AsciiString>> {
    map(
        pair(many1(nom::bits::bytes(parse_label)), parse_pointer),
        |(mut names0, names1)| {
            names0.extend(names1);
            names0
        },
    )(i)
}

fn parse_pointer(i: BitInput) -> IResult<BitInput, Vec<AsciiString>> {
    //     The pointer takes the form of a two octet sequence:
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     | 1  1|                OFFSET                   |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // The first two bits are ones.  This allows a pointer to be distinguished
    // from a label, since the label must begin with two zero bits because
    // labels are restricted to 63 octets or less.
    let (i, _) = map_res(take(2u8), |num: u8| {
        if num == 0b11 {
            Ok(())
        } else {
            Err(format!("{num:b} is not a pointer"))
        }
    })(i)?;
    let (i, offset) = take_le1_byte(i, 6)?;
    // TODO: Actually parse the name
    use std::str::FromStr;
    let name = AsciiString::from_str(&format!("name at {offset}")).unwrap();
    Ok((i, vec![name]))
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
