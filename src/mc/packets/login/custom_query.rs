use crate::{
    VersionedPacket,
    mc::{
        ByteSlice, ProtoError, Result, VarInt,
        types::PacketDecode,
    },
};

/// Custom Query (S2C) in Login state — minecraft:custom_query.
/// Asks the client to respond to a plugin message before login completes.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x04]
pub struct CustomQueryS2c<'a> {
    pub message_id: VarInt,
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for CustomQueryS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("custom_query.protocol_version"))
    }
}
