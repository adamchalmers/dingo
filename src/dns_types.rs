use bitvec::prelude::*;
use std::fmt;

#[derive(Debug)]
pub enum RecordType {
    A,
    // TODO: Add more record types
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A => "A",
        };
        s.fmt(f)
    }
}

impl RecordType {
    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::A => 1,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record_type = match value {
            1 => Self::A,
            other => anyhow::bail!("Invalid record type number {other:b}"),
        };
        Ok(record_type)
    }
}

#[derive(Debug)]
pub enum Class {
    IN,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IN => "IN",
        };
        s.fmt(f)
    }
}

impl Class {
    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::IN => 1,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}

impl TryFrom<u16> for Class {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record_type = match value {
            1 => Self::IN,
            other => anyhow::bail!("Invalid class number {other}"),
        };
        Ok(record_type)
    }
}
