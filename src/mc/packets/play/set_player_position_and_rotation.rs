use crate::{
    VersionedPacket,
    mc::{ByteSlice, Result,
        types::PacketDecode},
};

/// Set Player Position and Rotation (C2S) — minecraft:move_player_pos_rot.
/// Body structure varies by version. Store raw.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x13]
pub struct SetPlayerPositionAndRotationC2s<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for SetPlayerPositionAndRotationC2s<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
