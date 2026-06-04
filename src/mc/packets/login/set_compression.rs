use crate::{VersionedPacket, mc::{PacketDecode, Result, VarInt}};

/// Set Compression (S2C) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x03]
pub struct SetCompressionS2c {
    pub threshold: VarInt,
}

impl<'a> PacketDecode<'a> for SetCompressionS2c {
    const ID: i32 = SetCompressionS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
