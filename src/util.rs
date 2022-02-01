use ascii::AsciiString;

pub fn join_asciis(asciis: &[AsciiString]) -> String {
    let v: Vec<_> = asciis.iter().map(|a| a.to_string()).collect();
    v.join(".")
}
