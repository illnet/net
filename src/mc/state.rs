/// Protocol state used to select packet IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketState {
    Handshaking,
    Status,
    Login,
    Configuration,
    Play,
}

/// Next state value in the handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeNextState {
    Status,
    Login,
}

impl<'a> super::types::FieldRead<'a> for HandshakeNextState {
    fn read_field(input: &mut &'a [u8]) -> super::error::Result<Self> {
        let raw = super::varint::read_varint(input)?;
        match raw {
            1 => Ok(HandshakeNextState::Status),
            2 => Ok(HandshakeNextState::Login),
            other => Err(super::error::ProtoError::InvalidHandshakeState(other)),
        }
    }
}

impl super::types::FieldWrite for HandshakeNextState {
    fn write_field(&self, out: &mut Vec<u8>) -> super::error::Result<()> {
        let raw = match self {
            HandshakeNextState::Status => 1,
            HandshakeNextState::Login => 2,
        };
        super::varint::write_varint(out, raw);
        Ok(())
    }
}

/// Packet direction label used by stream metadata and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    C2s,
    S2c,
}

/// Authentication mode inferred from the login exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthMode {
    Unknown,
    Offline,
    OnlineRequested,
    OfflineEncryption,
}

/// Encryption progress inferred by the stream parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSecurity {
    Plain,
    EncryptionRequested,
    EncryptionResponseSeen,
    Encrypted,
}
