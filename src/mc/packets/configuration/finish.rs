use crate::{VersionedPacket, mc::Result, mc::types::PacketEncode};

/// Finish Configuration (S2C) — server indicates configuration phase is done.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x03]
pub struct FinishConfigurationS2c;

impl PacketEncode for FinishConfigurationS2c {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
