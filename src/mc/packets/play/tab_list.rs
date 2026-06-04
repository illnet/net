use crate::{
    VersionedPacket,
    mc::{ByteSlice, ProtoError, Result,
        types::PacketDecode},
};

/// Tab List / Player List (S2C, pre-1.19.3) — minecraft:tab_list.
/// Player list with display names and ping. Store raw.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x3D]
pub struct TabListS2c<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for TabListS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("tab_list.protocol_version"))
    }
}
