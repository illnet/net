use crate::{
    VersionedPacket,
    mc::{NbtTag, ProtoError, Result,
        types::{PacketDecode, PacketEncode}},
};

/// Registry Data (S2C, 1.19+) — minecraft:registry_data in configuration state.
/// Body is an NBT compound tag containing dimension types, biomes, etc.
#[derive(VersionedPacket, Debug, Clone, PartialEq)]
#[packet_id = 0x07]
pub struct RegistryDataS2c {
    pub data: NbtTag,
}

impl<'a> PacketDecode<'a> for RegistryDataS2c {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("registry_data.protocol_version"))
    }
}

impl PacketEncode for RegistryDataS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
