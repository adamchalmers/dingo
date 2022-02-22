use nom::{bits::complete::take, IResult};

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

/// Take 4 bits from the BitInput.
/// Parse into a uint with most significant bit first.
/// Add 0000 as padding to the most significant bits to the output number to make it
/// fit into a u8.
pub fn take_nibble(i: BitInput) -> IResult<BitInput, u8> {
    take(4u8)(i)
}

/// Take 16 bits from the BitInput, parse into a uint with most significant bit first..
pub fn take_u16(i: BitInput) -> IResult<BitInput, u16> {
    take_bits(i, 16)
}

/// Takes n bits from the BitInput, n <= 16
/// Returns the remaining BitInput and a number parsed the first n bits.
pub fn take_bits(i: BitInput, n: u8) -> IResult<BitInput, u16> {
    take(n)(i)
}

/// Takes one bit from the BitInput.
pub fn take_bit(i: BitInput) -> IResult<BitInput, bool> {
    let (i, bit): (BitInput, u8) = take(1u8)(i)?;
    Ok((i, bit != 0))
}
