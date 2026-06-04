use crate::{
    VersionedPacket,
    mc::{ByteSlice, ProtoError, Result,
        types::PacketDecode},
};

/// Commands (S2C) — minecraft:commands. Tree of command nodes.
/// Body structure is complex. Store raw for forwarding.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x11]
pub struct CommandsS2c<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for CommandsS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("commands.protocol_version"))
    }
}
