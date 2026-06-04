use crate::{
    VersionedPacket,
    mc::{ByteSlice, ProtoError, Result,
        types::PacketDecode},
};

/// Player Info Update (S2C, 1.19.3+) — minecraft:player_info_update.
/// Action-based structure with variable entries per action.
/// Store raw for forwarding.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x3C]
pub struct PlayerInfoUpdateS2c<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for PlayerInfoUpdateS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("player_info_update.protocol_version"))
    }
}
