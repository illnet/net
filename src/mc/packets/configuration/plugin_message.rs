use crate::{
    VersionedPacket,
    mc::{BoundedStr, ByteSlice, ProtoError, Result,
        types::{PacketDecode, PacketEncode}},
};

/// Configuration Plugin Message (S2C) — minecraft:custom_payload in configuration state.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x01]
pub struct ConfigurationPluginMessageS2c<'a> {
    pub channel: BoundedStr<'a, 32767>,
    pub data: ByteSlice<'a>,
}

impl<'a> PacketDecode<'a> for ConfigurationPluginMessageS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("config_plugin_message.protocol_version"))
    }
}

impl PacketEncode for ConfigurationPluginMessageS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
