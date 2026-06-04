use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result,
        types::{PacketDecode, PacketEncode}},
};

/// System Chat Message (S2C, 1.19+) — minecraft:system_chat.
/// Overlay=true renders as action bar; false renders in chat.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x6F]
pub struct SystemChatMessageS2c<'a> {
    pub message: BoundedStr<'a, 32767>,
    pub overlay: bool,
}

impl<'a> PacketDecode<'a> for SystemChatMessageS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for SystemChatMessageS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
