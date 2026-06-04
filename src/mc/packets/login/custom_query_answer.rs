use crate::{
    VersionedPacket,
    mc::{
        ByteSlice, Result, VarInt,
        types::PacketDecode,
    },
};

/// Custom Query Answer (C2S) in Login state — minecraft:custom_query_answer.
/// Client's response to a server's custom query before login.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x02]
pub struct CustomQueryAnswerC2s<'a> {
    pub message_id: VarInt,
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for CustomQueryAnswerC2s<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
