from __future__ import annotations

import socket
import time
from typing import Any

from bkzs_guard.adapters.base import SignalSourceAdapter


class UdpTcpAdapter(SignalSourceAdapter):
    def __init__(
        self,
        protocol: str = "udp",
        host: str = "127.0.0.1",
        port: int = 9000,
        timeout_seconds: float = 0.5,
        recv_buffer_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self.protocol = protocol.lower()
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.recv_buffer_bytes = recv_buffer_bytes
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        if self.protocol == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buffer_bytes)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(self.timeout_seconds)
            return
        if self.protocol == "tcp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.sock.settimeout(self.timeout_seconds)
            return
        raise ValueError(f"Unsupported protocol: {self.protocol}")

    def read_packet_with_meta(self) -> tuple[str | None, dict[str, Any] | None]:
        if self.sock is None:
            raise RuntimeError("Adapter not connected.")
        if self.protocol == "udp":
            try:
                payload, remote = self.sock.recvfrom(8192)
                return payload.decode("utf-8"), {
                    "remote_ip": remote[0],
                    "remote_port": int(remote[1]),
                    "protocol": self.protocol,
                }
            except (TimeoutError, socket.timeout):
                return None, None
        try:
            conn, remote = self.sock.accept()
        except (TimeoutError, socket.timeout):
            return None, None
        with conn:
            conn.settimeout(self.timeout_seconds)
            chunks: list[bytes] = []
            while True:
                try:
                    data = conn.recv(4096)
                except (TimeoutError, socket.timeout):
                    break
                if not data:
                    break
                chunks.append(data)
            payload = b"".join(chunks).decode("utf-8").strip()
            return (payload or None), {
                "remote_ip": remote[0],
                "remote_port": int(remote[1]),
                "protocol": self.protocol,
            }

    def read_packet(self) -> str | None:
        payload, _ = self.read_packet_with_meta()
        return payload

    def listen_batch(self, max_packets: int = 20) -> list[str]:
        if self.sock is None:
            self.connect()
        packets: list[str] = []
        deadline = time.monotonic() + self.timeout_seconds
        while len(packets) < max_packets and time.monotonic() < deadline:
            packet = self.read_packet()
            if packet is not None:
                packets.append(packet)
        return packets

    def listen_batch_with_meta(self, max_packets: int = 20) -> list[tuple[str, dict[str, Any] | None]]:
        if self.sock is None:
            self.connect()
        packets: list[tuple[str, dict[str, Any] | None]] = []
        deadline = time.monotonic() + self.timeout_seconds
        while len(packets) < max_packets and time.monotonic() < deadline:
            packet, meta = self.read_packet_with_meta()
            if packet is not None:
                packets.append((packet, meta))
        return packets

    def drain_ready_packets_with_meta(self, max_packets: int = 64) -> list[tuple[str, dict[str, Any] | None]]:
        if self.sock is None:
            raise RuntimeError("Adapter not connected.")
        if max_packets <= 0:
            return []
        if self.protocol == "tcp":
            return []

        packets: list[tuple[str, dict[str, Any] | None]] = []
        original_timeout = self.sock.gettimeout()
        try:
            self.sock.setblocking(False)
            while len(packets) < max_packets:
                try:
                    payload, remote = self.sock.recvfrom(8192)
                except BlockingIOError:
                    break
                packets.append(
                    (
                        payload.decode("utf-8"),
                        {
                            "remote_ip": remote[0],
                            "remote_port": int(remote[1]),
                            "protocol": self.protocol,
                        },
                    )
                )
        finally:
            self.sock.settimeout(original_timeout)
        return packets

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
