use crate::{
    VersionedPacket,
    mc::{BEi64, PacketDecode, PacketEncode, Result},
};

/// Status pong (S2C) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x01]
pub struct StatusPongS2c {
    pub payload: BEi64,
}

impl<'a> PacketDecode<'a> for StatusPongS2c {
    const ID: i32 = StatusPongS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for StatusPongS2c {
    const ID: i32 = StatusPongS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
