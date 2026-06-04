use crate::{
    VersionedPacket,
    mc::{BEi32, Result, types::PacketEncode},
};

/// Set Title Animation (S2C) — minecraft:set_titles_animation: fade-in, stay, fade-out.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x5C]
pub struct SetTitlesAnimationS2c {
    pub fade_in: BEi32,
    pub stay: BEi32,
    pub fade_out: BEi32,
}

impl PacketEncode for SetTitlesAnimationS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
