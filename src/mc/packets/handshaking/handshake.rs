use crate::{
    VersionedPacket,
    mc::{BEu16, BoundedStr, HandshakeNextState, PacketDecode, PacketEncode, Result, VarInt},
};

/// Handshake (C2S) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x00]
pub struct HandshakeC2s<'a> {
    pub protocol_version: VarInt,
    pub server_address: BoundedStr<'a, 255>,
    pub server_port: BEu16,
    pub next_state: HandshakeNextState,
}

impl<'a> PacketDecode<'a> for HandshakeC2s<'a> {
    const ID: i32 = HandshakeC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for HandshakeC2s<'_> {
    const ID: i32 = HandshakeC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
