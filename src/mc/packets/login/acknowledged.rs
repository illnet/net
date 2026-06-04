use crate::{VersionedPacket, mc::Result, mc::types::PacketDecode};

/// Login Acknowledged (C2S) — sent by client after receiving LoginSuccess/GameProfile in >= 1.20.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x03]
pub struct LoginAcknowledgedC2s;

impl<'a> PacketDecode<'a> for LoginAcknowledgedC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
