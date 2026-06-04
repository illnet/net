use crate::{
    VersionedPacket,
    mc::{ByteSlice, ProtoError, Result,
        types::PacketDecode},
};

/// Set Entity Metadata / Set Entity Data (S2C) — minecraft:set_entity_data.
/// Complex metadata structure varying by entity type. Store raw.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x56]
pub struct SetEntityMetadataS2c<'a> {
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for SetEntityMetadataS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("set_entity_metadata.protocol_version"))
    }
}
