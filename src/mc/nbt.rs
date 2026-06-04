use super::{
    Result,
    error::ProtoError,
    io::{read_i16_be, read_i32_be, read_i64_be, read_i8, read_u8, take, write_i16_be,
        write_i32_be, write_i64_be, write_i8},
};

const TAG_END: u8 = 0;
const TAG_BYTE: u8 = 1;
const TAG_SHORT: u8 = 2;
const TAG_INT: u8 = 3;
const TAG_LONG: u8 = 4;
const TAG_FLOAT: u8 = 5;
const TAG_DOUBLE: u8 = 6;
const TAG_BYTE_ARRAY: u8 = 7;
const TAG_STRING: u8 = 8;
const TAG_LIST: u8 = 9;
const TAG_COMPOUND: u8 = 10;
const TAG_INT_ARRAY: u8 = 11;
const TAG_LONG_ARRAY: u8 = 12;

/// Named Binary Tag — owned tree representation of Minecraft NBT data.
#[derive(Debug, Clone, PartialEq)]
pub enum NbtTag {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    ByteArray(Vec<u8>),
    String(String),
    List(Vec<NbtTag>),
    Compound(Vec<(String, NbtTag)>),
    IntArray(Vec<i32>),
    LongArray(Vec<i64>),
}

impl NbtTag {
    /// Reads a network-NBT root compound (tag type + empty name + content).
    pub fn read_network<'a>(input: &mut &'a [u8]) -> Result<Self> {
        let tag_type = read_u8(input)?;
        if tag_type != TAG_COMPOUND {
            let _ = read_nbt_string(input)?; // skip name even on mismatch
            return Err(ProtoError::NbtExpectedCompound(tag_type));
        }
        let _ = read_nbt_string(input)?; // root name (empty in network)
        read_compound_body(input).map(NbtTag::Compound)
    }

    /// Writes as network-NBT (compound header + empty name + content).
    pub fn write_network(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            NbtTag::Compound(pairs) => {
                out.push(TAG_COMPOUND);
                write_i16_be(out, 0); // empty root name
                for (name, value) in pairs {
                    out.push(tag_type(value));
                    write_nbt_string(out, name)?;
                    write_tag_body(value, out)?;
                }
                out.push(TAG_END);
                Ok(())
            }
            other => {
                let name = b"<root>";
                out.push(TAG_COMPOUND);
                write_i16_be(out, name.len() as i16);
                out.extend_from_slice(name);
                write_tag_body(other, out)?;
                out.push(TAG_END);
                Ok(())
            }
        }
    }
}

/// Reads one NBT key-value pair from a compound (type byte + name + body).
fn read_tag<'a>(input: &mut &'a [u8]) -> Result<Option<(String, NbtTag)>> {
    let tag_type = read_u8(input)?;
    if tag_type == TAG_END {
        return Ok(None);
    }
    let name = read_nbt_string(input)?;
    let value = read_tag_body(tag_type, input)?;
    Ok(Some((name, value)))
}

fn read_nbt_string<'a>(input: &mut &'a [u8]) -> Result<String> {
    let len = read_i16_be(input)?;
    if len < 0 {
        return Err(ProtoError::NegativeLength(len as i32));
    }
    let len = len as usize;
    if len == 0 {
        return Ok(String::new());
    }
    let bytes = take(input, len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| ProtoError::InvalidUtf8)
}

fn read_tag_body<'a>(tag_type: u8, input: &mut &'a [u8]) -> Result<NbtTag> {
    match tag_type {
        TAG_BYTE => read_i8(input).map(NbtTag::Byte),
        TAG_SHORT => read_i16_be(input).map(NbtTag::Short),
        TAG_INT => read_i32_be(input).map(NbtTag::Int),
        TAG_LONG => read_i64_be(input).map(NbtTag::Long),
        TAG_FLOAT => super::io::read_f32_be(input).map(NbtTag::Float),
        TAG_DOUBLE => super::io::read_f64_be(input).map(NbtTag::Double),
        TAG_BYTE_ARRAY => {
            let len = read_i32_be(input)?;
            if len < 0 {
                return Err(ProtoError::NegativeLength(len));
            }
            let data = take(input, len as usize)?;
            Ok(NbtTag::ByteArray(data.to_vec()))
        }
        TAG_STRING => {
            let s = read_nbt_string(input)?;
            Ok(NbtTag::String(s))
        }
        TAG_LIST => {
            let elem_type = read_u8(input)?;
            let len = read_i32_be(input)?;
            if len < 0 {
                return Err(ProtoError::NegativeLength(len));
            }
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                items.push(read_tag_body(elem_type, input)?);
            }
            Ok(NbtTag::List(items))
        }
        TAG_COMPOUND => {
            let pairs = read_compound_body(input)?;
            Ok(NbtTag::Compound(pairs))
        }
        TAG_INT_ARRAY => {
            let len = read_i32_be(input)?;
            if len < 0 {
                return Err(ProtoError::NegativeLength(len));
            }
            let mut values = Vec::with_capacity(len as usize);
            for _ in 0..len {
                values.push(read_i32_be(input)?);
            }
            Ok(NbtTag::IntArray(values))
        }
        TAG_LONG_ARRAY => {
            let len = read_i32_be(input)?;
            if len < 0 {
                return Err(ProtoError::NegativeLength(len));
            }
            let mut values = Vec::with_capacity(len as usize);
            for _ in 0..len {
                values.push(read_i64_be(input)?);
            }
            Ok(NbtTag::LongArray(values))
        }
        other => Err(ProtoError::UnknownTagType(other)),
    }
}

fn read_compound_body<'a>(input: &mut &'a [u8]) -> Result<Vec<(String, NbtTag)>> {
    let mut pairs = Vec::new();
    loop {
        match read_tag(input)? {
            Some((name, tag)) => pairs.push((name, tag)),
            None => return Ok(pairs),
        }
    }
}

fn write_tag_body(tag: &NbtTag, out: &mut Vec<u8>) -> Result<()> {
    match tag {
        NbtTag::Byte(v) => write_i8(out, *v),
        NbtTag::Short(v) => write_i16_be(out, *v),
        NbtTag::Int(v) => write_i32_be(out, *v),
        NbtTag::Long(v) => write_i64_be(out, *v),
        NbtTag::Float(v) => super::io::write_f32_be(out, *v),
        NbtTag::Double(v) => out.extend_from_slice(&v.to_be_bytes()),
        NbtTag::ByteArray(data) => {
            write_i32_be(out, data.len() as i32);
            out.extend_from_slice(data);
        }
        NbtTag::String(s) => {
            let bytes = s.as_bytes();
            let len = i16::try_from(bytes.len()).map_err(|_| ProtoError::LengthTooLarge {
                max: i16::MAX as usize,
                actual: bytes.len(),
            })?;
            write_i16_be(out, len);
            out.extend_from_slice(bytes);
        }
        NbtTag::List(items) => {
            if items.is_empty() {
                out.push(TAG_BYTE);
                write_i32_be(out, 0);
            } else {
                let elem_type = tag_type(&items[0]);
                out.push(elem_type);
                let len = i32::try_from(items.len()).map_err(|_| ProtoError::LengthTooLarge {
                    max: i32::MAX as usize,
                    actual: items.len(),
                })?;
                write_i32_be(out, len);
                for item in items {
                    write_tag_body(item, out)?;
                }
            }
        }
        NbtTag::Compound(pairs) => {
            for (name, value) in pairs {
                out.push(tag_type(value));
                write_nbt_string(out, name)?;
                write_tag_body(value, out)?;
            }
            out.push(TAG_END);
        }
        NbtTag::IntArray(values) => {
            let len = i32::try_from(values.len()).map_err(|_| ProtoError::LengthTooLarge {
                max: i32::MAX as usize,
                actual: values.len(),
            })?;
            write_i32_be(out, len);
            for v in values {
                write_i32_be(out, *v);
            }
        }
        NbtTag::LongArray(values) => {
            let len = i32::try_from(values.len()).map_err(|_| ProtoError::LengthTooLarge {
                max: i32::MAX as usize,
                actual: values.len(),
            })?;
            write_i32_be(out, len);
            for v in values {
                write_i64_be(out, *v);
            }
        }
    }
    Ok(())
}

fn write_nbt_string(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let len = i16::try_from(bytes.len()).map_err(|_| ProtoError::LengthTooLarge {
        max: i16::MAX as usize,
        actual: bytes.len(),
    })?;
    write_i16_be(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn tag_type(tag: &NbtTag) -> u8 {
    match tag {
        NbtTag::Byte(_) => TAG_BYTE,
        NbtTag::Short(_) => TAG_SHORT,
        NbtTag::Int(_) => TAG_INT,
        NbtTag::Long(_) => TAG_LONG,
        NbtTag::Float(_) => TAG_FLOAT,
        NbtTag::Double(_) => TAG_DOUBLE,
        NbtTag::ByteArray(_) => TAG_BYTE_ARRAY,
        NbtTag::String(_) => TAG_STRING,
        NbtTag::List(_) => TAG_LIST,
        NbtTag::Compound(_) => TAG_COMPOUND,
        NbtTag::IntArray(_) => TAG_INT_ARRAY,
        NbtTag::LongArray(_) => TAG_LONG_ARRAY,
    }
}

impl<'a> super::FieldRead<'a> for NbtTag {
    fn read_field(input: &mut &'a [u8]) -> Result<Self> {
        Self::read_network(input)
    }
}

impl super::FieldWrite for NbtTag {
    fn write_field(&self, out: &mut Vec<u8>) -> Result<()> {
        self.write_network(out)
    }
}
