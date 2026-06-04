use crate::{
    VersionedPacket,
    mc::{NbtTag, ProtoError, Result,
        types::{PacketDecode, PacketEncode}},
};

/// Update Tags (S2C) — minecraft:update_tags in configuration state.
/// Body is an NBT compound mapping resource types to lists of tag values.
#[derive(VersionedPacket, Debug, Clone, PartialEq)]
#[packet_id = 0x09]
pub struct UpdateTagsS2c {
    pub data: NbtTag,
}

impl<'a> PacketDecode<'a> for UpdateTagsS2c {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("update_tags.protocol_version"))
    }
}

impl PacketEncode for UpdateTagsS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
