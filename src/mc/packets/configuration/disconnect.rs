use crate::{
    VersionedPacket,
    mc::{BoundedStr, Result, types::PacketDecode},
};

/// Configuration Disconnect (S2C) — server disconnects client during configuration.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x02]
pub struct ConfigurationDisconnectS2c<'a> {
    pub reason: BoundedStr<'a, 32767>,
}

impl<'a> PacketDecode<'a> for ConfigurationDisconnectS2c<'a> {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
