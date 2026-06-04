use crate::{
    VersionedPacket,
    mc::{BoundedStr, ByteSlice, Result,
        types::{PacketDecode, PacketEncode}},
};

/// Play Plugin Message (S2C) — minecraft:custom_payload in play state.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x18]
pub struct PlayPluginMessageS2c<'a> {
    pub channel: BoundedStr<'a, 32767>,
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for PlayPluginMessageS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for PlayPluginMessageS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
