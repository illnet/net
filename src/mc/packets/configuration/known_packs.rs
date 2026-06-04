use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result, ProtoError,
        types::{PacketDecode, PacketEncode}},
};

/// Clientbound Known Packs (S2C, 1.20.5+) — server advertises its known data packs.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x0E]
pub struct ClientBoundKnownPacksS2c<'a> {
    pub known_packs: crate::mc::LengthCountedVec<KnownPack<'a>>,
}

/// Serverbound Known Packs (C2S, 1.20.5+) — client reports which packs it already has.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x07]
pub struct ServerBoundKnownPacksC2s<'a> {
    pub known_packs: crate::mc::LengthCountedVec<KnownPack<'a>>,
}

impl<'a> PacketDecode<'a> for ClientBoundKnownPacksS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("known_packs.protocol_version"))
    }
}

impl PacketEncode for ClientBoundKnownPacksS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}

impl<'a> PacketDecode<'a> for ServerBoundKnownPacksC2s<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for ServerBoundKnownPacksC2s<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}

/// A single known pack entry (namespace, id, version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownPack<'a> {
    pub namespace: BoundedStr<'a, 32767>,
    pub id: BoundedStr<'a, 32767>,
    pub version: BoundedStr<'a, 32767>,
}

impl<'a> crate::mc::FieldRead<'a> for KnownPack<'a> {
    fn read_field(input: &mut &'a [u8]) -> Result<Self> {
        Ok(KnownPack {
            namespace: BoundedStr::read_field(input)?,
            id: BoundedStr::read_field(input)?,
            version: BoundedStr::read_field(input)?,
        })
    }
}

impl crate::mc::FieldWrite for KnownPack<'_> {
    fn write_field(&self, out: &mut Vec<u8>) -> Result<()> {
        self.namespace.write_field(out)?;
        self.id.write_field(out)?;
        self.version.write_field(out)
    }
}
