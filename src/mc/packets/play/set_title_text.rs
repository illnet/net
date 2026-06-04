use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result, types::PacketEncode},
};

/// Set Title Text (S2C) — minecraft:set_title_text.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x5E]
pub struct SetTitleTextS2c<'a> {
    pub text: BoundedStr<'a, 32767>,
}

impl PacketEncode for SetTitleTextS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
