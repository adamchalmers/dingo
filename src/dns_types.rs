//! Common DNS types that get used in several different parts of the codebase.
use bitvec::prelude::*;
use std::{fmt, str::FromStr};

#[derive(Debug)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Soa,
    Ns,
    // TODO: Add more record types
}

impl FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rt = match s.to_uppercase().as_str() {
            "A" => Self::A,
            "AAAA" => Self::Aaaa,
            "CNAME" => Self::Cname,
            "SOA" => Self::Soa,
            "NS" => Self::Ns,
            other => return Err(format!("{other} is not a valid DNS record type")),
        };
        Ok(rt)
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Ns => "NS",
        };
        s.fmt(f)
    }
}

impl RecordType {
    pub fn serialize<T: BitStore>(&self, bv: &mut BitVec<T, Msb0>) {
        let type_num: u16 = match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ns => 2,
        };
        bv.extend_from_bitslice(type_num.view_bits::<Msb0>())
    }
}

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let record_type = match value {
            1 => Self::A,
            28 => Self::Aaaa,
            5 => Self::Cname,
            6 => Self::Soa,
            2 => Self::Ns,
            other => anyhow::bail!("Invalid record type number {other:b}"),
        };
        Ok(record_type)
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
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
