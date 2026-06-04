use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result, types::PacketEncode},
};

/// Set Action Bar Text (S2C) — minecraft:set_action_bar_text.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x5D]
pub struct SetActionBarTextS2c<'a> {
    pub text: BoundedStr<'a, 32767>,
}

impl PacketEncode for SetActionBarTextS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
