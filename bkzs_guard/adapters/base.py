from __future__ import annotations

from abc import ABC, abstractmethod


class SignalSourceAdapter(ABC):
    @abstractmethod
    def connect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def read_packet(self) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError
