use crate::{
    VersionedPacket,
    mc::{Result, VarInt, types::{PacketDecode, PacketEncode}},
};

/// Set Center Chunk (S2C) — minecraft:set_chunk_cache_center.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x4E]
pub struct SetCenterChunkS2c {
    pub chunk_x: VarInt,
    pub chunk_z: VarInt,
}

impl<'a> PacketDecode<'a> for SetCenterChunkS2c {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for SetCenterChunkS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
