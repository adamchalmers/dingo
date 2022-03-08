use nom::{combinator::map_res, IResult};

/// Matches a sequence of labels, terminated by a zero-length label.
pub fn parse_labels_then_zero(mut i: &[u8]) -> IResult<&[u8], Vec<String>> {
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
pub fn parse_label(i: &[u8]) -> IResult<&[u8], String> {
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
    map_res(parse_label, |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
    })(i)
}
