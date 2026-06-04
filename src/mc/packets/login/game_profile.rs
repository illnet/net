use crate::{
    VersionedPacket,
    mc::{
        BoundedStr, LengthCountedVec, ProtoError, Result,
        types::{PacketDecode, PacketEncode},
    },
};

use super::super::data::Property;

/// Game Profile (S2C) in Login state — minecraft:game_profile (1.19+).
/// Delivers the player's signed profile data after authentication completes.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x02]
pub struct GameProfileS2c<'a> {
    pub uuid: crate::mc::Uuid,
    pub username: BoundedStr<'a, 16>,
    pub properties: LengthCountedVec<Property<'a>>,
}

impl<'a> PacketDecode<'a> for GameProfileS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("game_profile.protocol_version"))
    }
}

impl PacketEncode for GameProfileS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
