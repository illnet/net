use crate::{
    VersionedPacket,
    mc::{ByteSlice, Result,
        types::PacketDecode},
};

/// Chat Command (C2S, 1.19+) — minecraft:chat_command. Uses signed command chain.
/// Body structure is complex (command string + signatures + timestamps).
/// We store raw data for forwarding.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x04]
pub struct ChatCommandC2s<'a> {
    pub command: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for ChatCommandC2s<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
