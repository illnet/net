use crate::{VersionedPacket, mc::Result, mc::types::PacketDecode};

/// Acknowledge Configuration (C2S) — client confirms it has applied configuration.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x02]
pub struct AcknowledgeConfigurationC2s;

impl<'a> PacketDecode<'a> for AcknowledgeConfigurationC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}
