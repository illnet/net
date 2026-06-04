use crate::{
    VersionedPacket,
    mc::{BEi64, Result, types::{PacketDecode, PacketEncode}},
};

/// Update Time (S2C) — minecraft:set_time.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x65]
pub struct UpdateTimeS2c {
    pub world_age: BEi64,
    pub time_of_day: BEi64,
}

impl<'a> PacketDecode<'a> for UpdateTimeS2c {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for UpdateTimeS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
