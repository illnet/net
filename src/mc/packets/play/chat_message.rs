use crate::{
    VersionedPacket,
    mc::{ByteSlice, Result, types::{PacketDecode, PacketEncode}},
};

/// Chat Message (C2S, 1.19+) — minecraft:chat. Uses signed chat chain.
/// Body structure is complex (message + signatures + timestamps).
/// We store raw data for forwarding.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x05]
pub struct ChatMessageC2s<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for ChatMessageC2s<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for ChatMessageC2s<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
