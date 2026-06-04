use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result, types::PacketDecode},
};

/// Play Disconnect (S2C) — minecraft:disconnect in play state.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x1A]
pub struct PlayDisconnectS2c<'a> {
    pub reason: BoundedStr<'a, 32767>,
}

impl<'a> PacketDecode<'a> for PlayDisconnectS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
