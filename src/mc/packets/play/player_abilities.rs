use crate::{
    VersionedPacket,
    mc::{Result,
        types::{PacketDecode, PacketEncode}},
};

/// Clientbound Player Abilities (S2C) — minecraft:player_abilities.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq)]
#[packet_id = 0x34]
pub struct ClientBoundPlayerAbilitiesS2c {
    pub flags: u8,
    pub flying_speed: f32,
    pub walking_speed: f32,
}

impl<'a> PacketDecode<'a> for ClientBoundPlayerAbilitiesS2c {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for ClientBoundPlayerAbilitiesS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}

/// Serverbound Player Abilities (C2S) — minecraft:player_abilities.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x1D]
pub struct ServerBoundPlayerAbilitiesC2s {
    pub flags: u8,
}

impl<'a> PacketDecode<'a> for ServerBoundPlayerAbilitiesC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for ServerBoundPlayerAbilitiesC2s {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
