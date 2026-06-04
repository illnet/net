use crate::{
    VersionedPacket,
    mc::{Result, types::PacketDecode},
};

/// Set Default Spawn Position (S2C) — minecraft:set_default_spawn_position.
/// Body is version-dependent (BlockPos encoding + optional angle). Stored raw.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x52]
pub struct SetDefaultSpawnPositionS2c<'a> {
    pub data: &'a [u8],
}

impl<'a> PacketDecode<'a> for SetDefaultSpawnPositionS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
