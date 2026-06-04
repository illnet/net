use crate::{
    VersionedPacket,
    mc::{BEi64, PacketDecode, PacketEncode, Result},
};

/// Status ping (C2S) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x01]
pub struct StatusPingC2s {
    pub payload: BEi64,
}

impl<'a> PacketDecode<'a> for StatusPingC2s {
    const ID: i32 = StatusPingC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for StatusPingC2s {
    const ID: i32 = StatusPingC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
