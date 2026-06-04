use crate::{
    VersionedPacket,
    mc::{BEi64, Result,
        types::{PacketDecode, PacketEncode}},
};

/// Keep Alive (C2S) — minecraft:keep_alive response from client.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x18]
pub struct KeepAliveC2s {
    pub id: BEi64,
}

impl<'a> PacketDecode<'a> for KeepAliveC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

/// Keep Alive (S2C) — minecraft:keep_alive sent from server.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x26]
pub struct KeepAliveS2c {
    pub id: BEi64,
}

impl PacketEncode for KeepAliveS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
