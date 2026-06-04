use crate::{
    VersionedPacket,
    mc::{Result, types::PacketEncode},
};

/// Transfer in Play state (S2C, 1.20.5+) — minecraft:transfer.
/// Structure is identical to TransferConfigS2c (host + port).
/// This type alias is kept in play for backward compat.
#[derive(VersionedPacket, Debug, Clone, PartialEq, Eq)]
#[packet_id = 0x1D]
pub struct TransferS2c<'a> {
    pub host: crate::mc::BoundedStr<'a, 255>,
    pub port: crate::mc::BEu16,
}

impl PacketEncode for TransferS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}

/// Backward-compat alias — TransferConfigS2c is the same as TransferS2c.
pub type TransferConfigS2c<'a> = TransferS2c<'a>;
