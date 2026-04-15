use std::{
    error::Error,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use net::mc::{
    HandshakeNextState, PacketDecoder, PacketEncoder, PacketFrame, PacketState, ServerboundPacket,
    StatusPongS2c, StatusResponseS2c,
};

const STATUS_JSON: &str = concat!(
    r#"{"version":{"name":"net-compat","protocol":772},"#,
    r#""players":{"max":20,"online":1,"sample":["#,
    r#"{"name":"stdpi","id":"caca2faa-3969-3937-95d3-79bc619b6353"}"#,
    r#"]},"description":{"text":"net compat pong"},"enforcesSecureChat":false}"#,
);

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    println!("PORT {port}");
    std::io::stdout().flush()?;

    let (mut stream, _) = listener.accept()?;
    let mut decoder = PacketDecoder::new();

    let handshake_frame = read_frame(&mut stream, &mut decoder)?;
    let handshake = handshake_frame.decode_serverbound(PacketState::Handshaking, 0)?;
    let protocol_version = match handshake {
        ServerboundPacket::Handshake(packet) => {
            if packet.next_state != HandshakeNextState::Status {
                return Err("expected status handshake".into());
            }
            packet.protocol_version
        }
        other => return Err(format!("expected handshake, got {other:?}").into()),
    };

    let request_frame = read_frame(&mut stream, &mut decoder)?;
    match request_frame.decode_serverbound(PacketState::Status, protocol_version)? {
        ServerboundPacket::StatusRequest(_) => {}
        other => return Err(format!("expected status request, got {other:?}").into()),
    }

    write_packet(&mut stream, &StatusResponseS2c { json: STATUS_JSON })?;

    let ping_frame = read_frame(&mut stream, &mut decoder)?;
    let payload = match ping_frame.decode_serverbound(PacketState::Status, protocol_version)? {
        ServerboundPacket::StatusPing(packet) => packet.payload,
        other => return Err(format!("expected status ping, got {other:?}").into()),
    };

    write_packet(&mut stream, &StatusPongS2c { payload })?;
    Ok(())
}

fn read_frame(
    stream: &mut TcpStream,
    decoder: &mut PacketDecoder,
) -> Result<PacketFrame, Box<dyn Error>> {
    let mut buf = [0u8; 1024];
    loop {
        if let Some(frame) = decoder.try_next_packet()? {
            return Ok(frame);
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err("unexpected eof while reading packet".into());
        }
        decoder.queue_slice(&buf[..n]);
    }
}

fn write_packet<P: net::mc::PacketEncode>(
    stream: &mut TcpStream,
    packet: &P,
) -> Result<(), Box<dyn Error>> {
    let mut encoder = PacketEncoder::new();
    encoder.write_packet(packet)?;
    stream.write_all(&encoder.take())?;
    stream.flush()?;
    Ok(())
}
