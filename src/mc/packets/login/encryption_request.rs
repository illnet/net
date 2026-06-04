use crate::{
    VersionedPacket,
    mc::{Bool, BoundedStr, ByteSlice, ProtoError, Result},
};

/// Encryption Request (S2C) packet.
#[derive(VersionedPacket, Debug, Clone, Copy, PartialEq, Eq)]
#[packet_id = 0x01]
pub struct EncryptionRequestS2c<'a> {
    pub server_id: BoundedStr<'a, 20>,
    pub public_key: ByteSlice<'a>,
    pub verify_token: ByteSlice<'a>,
    /// Present in modern protocol versions where encryption can be requested without online auth.
    #[pvn(766..)]
    pub should_authenticate: Option<Bool>,
}

impl<'a> crate::mc::PacketDecode<'a> for EncryptionRequestS2c<'a> {
    const ID: i32 = EncryptionRequestS2c::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField(
            "encryption_request.protocol_version",
        ))
    }
}
