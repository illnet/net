import json
import socket
import struct
import subprocess
import unittest
from pathlib import Path


PROTOCOL_VERSION = 772
HOST = "compat.local"
PING_PAYLOAD = 0x0102030405060708


class MinecraftStatusCompatTest(unittest.TestCase):
    def test_python_pinger_accepts_net_status_response_and_pong(self) -> None:
        server = start_fake_status_server()
        try:
            port = read_server_port(server)
            response, pong_payload = ping_status_server(port)
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            close_pipe(server.stdout)
            close_pipe(server.stderr)

        self.assertEqual(response["version"], {"name": "net-compat", "protocol": 772})
        self.assertEqual(response["players"]["online"], 1)
        self.assertEqual(response["players"]["sample"][0]["name"], "stdpi")
        self.assertEqual(response["description"], {"text": "net compat pong"})
        self.assertIs(response["enforcesSecureChat"], False)
        self.assertEqual(pong_payload, PING_PAYLOAD)


def start_fake_status_server() -> subprocess.Popen[str]:
    crate_root = Path(__file__).resolve().parents[2]
    return subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "mc_status_compat_server"],
        cwd=crate_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def read_server_port(server: subprocess.Popen[str]) -> int:
    assert server.stdout is not None
    line = server.stdout.readline().strip()
    if not line.startswith("PORT "):
        stderr = server.stderr.read() if server.stderr is not None else ""
        raise AssertionError(f"server did not publish port, stdout={line!r}, stderr={stderr!r}")
    return int(line.split()[1])


def close_pipe(pipe) -> None:
    if pipe is not None and not pipe.closed:
        pipe.close()


def ping_status_server(port: int) -> tuple[dict, int]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(handshake_packet(PROTOCOL_VERSION, HOST, port, next_state=1))
        sock.sendall(packet(0x00, b""))

        response_packet_id, response_body = read_packet(sock)
        if response_packet_id != 0x00:
            raise AssertionError(f"expected status response packet 0x00, got {response_packet_id}")
        response_json, rest = read_string(response_body)
        if rest:
            raise AssertionError(f"status response had trailing bytes: {rest.hex()}")

        sock.sendall(packet(0x01, struct.pack(">q", PING_PAYLOAD)))
        pong_packet_id, pong_body = read_packet(sock)
        if pong_packet_id != 0x01:
            raise AssertionError(f"expected pong packet 0x01, got {pong_packet_id}")
        if len(pong_body) != 8:
            raise AssertionError(f"expected 8-byte pong body, got {len(pong_body)} bytes")
        (pong_payload,) = struct.unpack(">q", pong_body)

    return json.loads(response_json), pong_payload


def handshake_packet(protocol: int, host: str, port: int, next_state: int) -> bytes:
    body = b"".join(
        [
            write_varint(protocol),
            write_string(host),
            struct.pack(">H", port),
            write_varint(next_state),
        ]
    )
    return packet(0x00, body)


def packet(packet_id: int, body: bytes) -> bytes:
    payload = write_varint(packet_id) + body
    return write_varint(len(payload)) + payload


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    packet_len = read_varint_from_socket(sock)
    payload = read_exact(sock, packet_len)
    packet_id, body = read_varint(payload)
    return packet_id, body


def write_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return write_varint(len(encoded)) + encoded


def read_string(data: bytes) -> tuple[str, bytes]:
    length, rest = read_varint(data)
    raw = rest[:length]
    if len(raw) != length:
        raise AssertionError("truncated string")
    return raw.decode("utf-8"), rest[length:]


def write_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def read_varint(data: bytes) -> tuple[int, bytes]:
    value = 0
    for index, byte in enumerate(data[:5]):
        value |= (byte & 0x7F) << (7 * index)
        if byte & 0x80 == 0:
            if value & (1 << 31):
                value -= 1 << 32
            return value, data[index + 1 :]
    raise AssertionError("varint too long or truncated")


def read_varint_from_socket(sock: socket.socket) -> int:
    data = bytearray()
    for _ in range(5):
        chunk = read_exact(sock, 1)
        data.extend(chunk)
        if chunk[0] & 0x80 == 0:
            value, rest = read_varint(bytes(data))
            if rest:
                raise AssertionError("socket varint reader left unexpected bytes")
            return value
    raise AssertionError("socket varint too long")


def read_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise AssertionError("unexpected eof")
        data.extend(chunk)
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
