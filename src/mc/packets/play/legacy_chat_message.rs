use crate::{
    VersionedPacket,
    mc::{Result, types::PacketDecode},
};

/// Legacy Chat Message (S2C, pre-1.19) — minecraft:chat or minecraft:legacy_chat_message.
/// Versions prior to 1.19 use a different format. Raw trailing for simplicity.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x0F]
pub struct LegacyChatMessageS2c<'a> {
    pub data: &'a [u8],
}

impl<'a> PacketDecode<'a> for LegacyChatMessageS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let data = *input;
        *input = &[];
        Ok(Self { data })
    }
}
