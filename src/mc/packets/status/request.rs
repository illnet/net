use crate::{VersionedPacket, mc::{PacketDecode, PacketEncode, Result}};

/// Status request (C2S) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x00]
pub struct StatusRequestC2s;

impl<'a> PacketDecode<'a> for StatusRequestC2s {
    const ID: i32 = StatusRequestC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for StatusRequestC2s {
    const ID: i32 = StatusRequestC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
