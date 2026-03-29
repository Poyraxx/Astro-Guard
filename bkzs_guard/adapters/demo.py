from __future__ import annotations

from collections import deque

from bkzs_guard.adapters.base import SignalSourceAdapter
from bkzs_guard.attack_lab.scenarios import AttackLab


class DemoAdapter(SignalSourceAdapter):
    def __init__(self, attack_lab: AttackLab | None = None) -> None:
        self.attack_lab = attack_lab or AttackLab()
        self.buffer: deque[str] = deque()
        self.last_truth: list[dict] = []
        self.last_metadata: dict = {}

    def connect(self) -> None:
        return None

    def load_normal(self, count: int = 5) -> None:
        self.last_truth = []
        self.last_metadata = {}
        self.buffer.extend(self.attack_lab.generate_normal_batch(count=count))

    def load_stage(self, stage: int, count: int = 6) -> None:
        self.last_truth = []
        self.last_metadata = {}
        self.buffer.extend(self.attack_lab.generate_stage_batch(stage=stage, count=count))

    def load_chain(self) -> None:
        self.last_truth = []
        self.last_metadata = {}
        self.buffer.extend(self.attack_lab.generate_chain_batch())

    def load_real_scenario(self, base_count: int = 6) -> dict:
        packets, truth, metadata = self.attack_lab.generate_real_scenario_batch(base_count=base_count)
        self.buffer.extend(packets)
        self.last_truth = truth
        self.last_metadata = metadata
        return metadata

    def load_counter_intel_tour(self, base_count: int = 4) -> dict:
        packets, truth, metadata = self.attack_lab.generate_counter_intel_tour(base_count=base_count)
        self.buffer.extend(packets)
        self.last_truth = truth
        self.last_metadata = metadata
        return metadata

    def read_packet(self) -> str | None:
        return self.buffer.popleft() if self.buffer else None

    def drain(self) -> list[str]:
        packets = list(self.buffer)
        self.buffer.clear()
        return packets

    def consume_last_truth(self) -> list[dict]:
        truth = list(self.last_truth)
        self.last_truth = []
        return truth

    def consume_last_metadata(self) -> dict:
        metadata = dict(self.last_metadata)
        self.last_metadata = {}
        return metadata

    def close(self) -> None:
        self.buffer.clear()
