use crate::{
    VersionedPacket,
    mc::{Result, types::PacketEncode},
};

/// Game Event (S2C) — minecraft:game_event, e.g. change game mode, rain level, etc.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq)]
#[packet_id = 0x1B]
pub struct GameEventS2c {
    pub event: u8,
    pub value: f32,
}

impl PacketEncode for GameEventS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
