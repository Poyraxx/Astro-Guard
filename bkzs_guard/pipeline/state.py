from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from bkzs_guard.config import AppConfig
from bkzs_guard.models import DecisionRecord, SignalPacket
from bkzs_guard.utils import build_packet_chain_hash, initial_clean_hash, utc_now


@dataclass(slots=True)
class PipelineState:
    max_history_packets: int
    max_packet_id_cache: int
    history_by_source: dict[str, deque[SignalPacket]] = field(init=False)
    accepted_history_by_source: dict[str, deque[SignalPacket]] = field(init=False)
    packet_id_window: deque[str] = field(init=False)
    packet_id_index: set[str] = field(init=False)
    accepted_proof_by_packet_id: dict[str, str] = field(init=False)
    source_strikes: dict[str, int] = field(init=False)
    locked_sources_until: dict[str, datetime] = field(init=False)
    clean_hash_by_source: dict[str, str] = field(init=False)
    epoch_chain_failures_by_source: dict[str, int] = field(init=False)

    def __post_init__(self) -> None:
        self.history_by_source = defaultdict(lambda: deque(maxlen=self.max_history_packets))
        self.accepted_history_by_source = defaultdict(lambda: deque(maxlen=self.max_history_packets))
        self.packet_id_window = deque(maxlen=self.max_packet_id_cache)
        self.packet_id_index = set()
        self.accepted_proof_by_packet_id = {}
        self.source_strikes = defaultdict(int)
        self.locked_sources_until = {}
        self.clean_hash_by_source = {}
        self.epoch_chain_failures_by_source = defaultdict(int)

    def get_history(self, source: str) -> list[SignalPacket]:
        return list(self.history_by_source[source])

    def get_peer_packets(self, source: str) -> list[SignalPacket]:
        peers: list[SignalPacket] = []
        for peer_source, history in self.accepted_history_by_source.items():
            if peer_source == source or not history:
                continue
            peers.append(history[-1])
        return peers

    def has_packet_id(self, packet_id: str) -> bool:
        return packet_id in self.packet_id_index

    def get_accepted_proof(self, packet_id: str) -> str | None:
        return self.accepted_proof_by_packet_id.get(packet_id)

    def get_previous_clean_hash(self, source: str, config: AppConfig) -> str:
        return self.clean_hash_by_source.get(source, initial_clean_hash(source, config.security.session_nonce))

    def get_epoch_chain_failures(self, source: str) -> int:
        return int(self.epoch_chain_failures_by_source[source])

    def get_source_status(self, source: str, now: datetime | None = None) -> tuple[bool, int, float]:
        now = now or utc_now()
        locked_until = self.locked_sources_until.get(source)
        if locked_until is not None and locked_until <= now:
            self.locked_sources_until.pop(source, None)
            locked_until = None
        remaining_seconds = (locked_until - now).total_seconds() if locked_until is not None else 0.0
        return locked_until is not None, int(self.source_strikes[source]), max(0.0, remaining_seconds)

    def active_locked_sources(self, now: datetime | None = None) -> dict[str, float]:
        now = now or utc_now()
        active: dict[str, float] = {}
        for source in list(self.locked_sources_until):
            locked, _, remaining = self.get_source_status(source, now)
            if locked:
                active[source] = round(remaining, 1)
        return active

    def register_verdict(self, packet: SignalPacket | None, decision: DecisionRecord, config: AppConfig) -> None:
        if packet is None:
            return

        source = packet.source
        attack_meta = packet.payload.get("attack_meta", {}) if isinstance(packet.payload, dict) else {}
        simulation_role = str(attack_meta.get("simulation_role", "")).lower() if isinstance(attack_meta, dict) else ""
        stage_hint = attack_meta.get("stage_hint") if isinstance(attack_meta, dict) else None
        trusted_clean_peer = (
            source in config.security.trusted_sources
            and simulation_role != "attack"
            and not bool(attack_meta.get("secret_compromised", False))
            and stage_hint in {None, 0}
        )
        if decision.decision == "accepted":
            if simulation_role != "attack":
                self.clean_hash_by_source[source] = build_packet_chain_hash(packet.raw)
                self.accepted_proof_by_packet_id[packet.packet_id] = packet.challenge_proof
                self.source_strikes[source] = max(0, self.source_strikes[source] - 1)
                self.epoch_chain_failures_by_source[source] = 0
                if trusted_clean_peer:
                    self.accepted_history_by_source[source].append(packet)
            return

        failed = next((item for item in decision.trace if not item.passed), None)
        trusted_normal_like = (
            source in config.security.trusted_sources
            and not bool(attack_meta.get("secret_compromised", False))
            and stage_hint in {None, 0}
        )
        if trusted_normal_like and failed is not None and failed.layer_id == 6 and failed.reason_code == "epoch_chain_broken":
            self.epoch_chain_failures_by_source[source] += 1
            if self.epoch_chain_failures_by_source[source] >= 2:
                self.clean_hash_by_source.pop(source, None)
                self.source_strikes[source] = 0
                self.locked_sources_until.pop(source, None)
                self.epoch_chain_failures_by_source[source] = 0
            return

        self.epoch_chain_failures_by_source[source] = 0
        weight = 2 if decision.classification in {
            "spoof_suspect",
            "credential_compromise_suspect",
            "signal_tamper",
            "jam_suspect",
            "mesh_divergence_suspect",
            "leak_trap_triggered",
            "shadow_contact_suspect",
        } else 1
        self.source_strikes[source] += weight
        if self.source_strikes[source] >= config.thresholds.adaptive_lock_threshold:
            self.locked_sources_until[source] = utc_now() + timedelta(seconds=config.thresholds.adaptive_lock_seconds)

    def observe(self, packet: SignalPacket) -> None:
        if len(self.packet_id_window) == self.packet_id_window.maxlen:
            expired = self.packet_id_window.popleft()
            self.packet_id_index.discard(expired)
            self.accepted_proof_by_packet_id.pop(expired, None)
        self.packet_id_window.append(packet.packet_id)
        self.packet_id_index.add(packet.packet_id)
        self.history_by_source[packet.source].append(packet)
