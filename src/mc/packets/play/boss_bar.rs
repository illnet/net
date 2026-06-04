use crate::{mc::Result, mc::types::PacketDecode};

/// Boss Bar (S2C) — minecraft:boss_event. Complex action-based structure. Stored raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BossBarS2c<'a> {
    pub data: &'a [u8],
}

impl<'a> BossBarS2c<'a> {
    pub const ID: i32 = 0x0D;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let data = *input;
        *input = &[];
        Ok(Self { data })
    }
}

impl<'a> PacketDecode<'a> for BossBarS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body(input)
    }
}
