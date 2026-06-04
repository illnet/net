use crate::{
    VersionedPacket,
    mc::{BoundedStr, PacketDecode, PacketEncode, Result},
};

/// Login disconnect (S2C) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x00]
pub struct LoginDisconnectS2c<'a> {
    pub reason: BoundedStr<'a, 32767>,
}

impl<'a> PacketDecode<'a> for LoginDisconnectS2c<'a> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body_with_version(input, 0)
    }
}

impl PacketEncode for LoginDisconnectS2c<'_> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_body_with_version(out, 0)
    }
}
