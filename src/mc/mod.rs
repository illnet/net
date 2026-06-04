//! Minimal Minecraft protocol framing for handshake, status, and login start.

mod error;
mod io;
mod nbt;
mod packets;
mod state;
mod stream;
mod types;
mod varint;

#[cfg(test)]
mod tests;

pub use error::{ProtoError, Result};
pub use packets::{
    AcknowledgeConfigurationC2s, BossBarS2c, ChatCommandC2s, ChatMessageC2s,
    ClientBoundKnownPacksS2c, ClientboundPacket, ClientBoundPlayerAbilitiesS2c, CommandsS2c,
    ConfigurationDisconnectS2c, ConfigurationPluginMessageS2c, CustomQueryAnswerC2s,
    CustomQueryS2c, EncryptionRequestS2c, EncryptionResponseC2s, FinishConfigurationS2c,
    GameEventS2c, GameProfileS2c, HandshakeC2s, JoinGameS2c, KeepAliveC2s, KeepAliveS2c,
    LegacyChatMessageS2c, LegacySetTitleS2c, LoginAcknowledgedC2s, LoginDisconnectS2c,
    LoginStartC2s, LoginStartSigData, LoginSuccessS2c, PacketKind, PlayDisconnectS2c,
    PlayerInfoUpdateS2c, PlayerPositionS2c, PlayPluginMessageS2c, RegistryDataS2c, RespawnS2c,
    ServerBoundKnownPacksC2s, ServerBoundPlayerAbilitiesC2s, ServerboundPacket,
    SetActionBarTextS2c, SetCenterChunkS2c, SetCompressionS2c, SetDefaultSpawnPositionS2c,
    SetEntityMetadataS2c, SetPlayerPositionAndRotationC2s, SetPlayerPositionC2s,
    SetSubtitleTextS2c, SetTitleTextS2c, SetTitlesAnimationS2c, StatusPingC2s, StatusPongS2c,
    StatusRequestC2s, StatusResponseS2c, SystemChatMessageS2c, TabListS2c, TransferConfigS2c,
    TransferS2c, UpdateTagsS2c, UpdateTimeS2c, packet_kind_for,
};
pub use nbt::NbtTag;
pub use state::{HandshakeNextState, PacketDirection, PacketState, StreamAuthMode, StreamSecurity};
pub use stream::{MinecraftStreamParser, PacketEvent, PacketHook, PacketMeta, ParsedPacket};
pub use types::{
    BEi32, BEi64, BEu16, BEu64, Bool, BoundedStr, ByteSlice, FieldRead, FieldWrite,
    LengthCountedVec, MAX_PACKET_SIZE, PacketDecode, PacketDecoder, PacketEncode, PacketEncoder,
    PacketFrame, Uuid, VarInt, encode_packet, encode_raw_packet,
};
