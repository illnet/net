use crate::{
    VersionedPacket,
    mc::{Result, types::PacketDecode},
};

/// Legacy Set Title (S2C, pre-1.17) — minecraft:title with action enum.
/// 1.17+ split title into individual packets. Raw trailing for compatibility.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x5B]
pub struct LegacySetTitleS2c<'a> {
    pub data: &'a [u8],
}

impl<'a> PacketDecode<'a> for LegacySetTitleS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let data = *input;
        *input = &[];
        Ok(Self { data })
    }
}
