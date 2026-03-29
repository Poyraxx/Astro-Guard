from __future__ import annotations

from collections import deque

from bkzs_guard.adapters.base import SignalSourceAdapter


class PeerFeedAdapter(SignalSourceAdapter):
    def __init__(self, initial_packets: list[str] | None = None) -> None:
        self.buffer: deque[str] = deque(initial_packets or [])

    def connect(self) -> None:
        return None

    def load_packets(self, packets: list[str]) -> None:
        self.buffer.extend(packets)

    def read_packet(self) -> str | None:
        return self.buffer.popleft() if self.buffer else None

    def drain(self) -> list[str]:
        packets = list(self.buffer)
        self.buffer.clear()
        return packets

    def close(self) -> None:
        self.buffer.clear()
