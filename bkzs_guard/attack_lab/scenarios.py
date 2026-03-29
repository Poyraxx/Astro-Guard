from __future__ import annotations

import json
import random
from datetime import timedelta
from typing import Any
from uuid import uuid4

from bkzs_guard.config import AppConfig, load_app_config
from bkzs_guard.models import AttackScenario
from bkzs_guard.policy import sample_trust_bulletin
from bkzs_guard.satellites import build_satellite_payload, get_satellite_profile
from bkzs_guard.utils import (
    build_challenge_proof,
    build_flow_tag,
    build_packet_chain_hash,
    epoch_id_from_timestamp,
    frame_signal_payload,
    initial_clean_hash,
    packet_flow_tag_view,
    parse_timestamp,
    split_signal_secret,
    stable_checksum,
    utc_now,
)


class AttackLab:
    def __init__(self, config: AppConfig | None = None, seed: int = 42) -> None:
        self.config = config or load_app_config()
        self.random = random.Random(seed)
        self.base_latitude = 41.0082
        self.base_longitude = 28.9784
        self.clean_hash_by_source: dict[str, str] = {}

    def default_scenario(self, stage: int) -> AttackScenario:
        profiles = {
            1: AttackScenario(1, "Gurultu ve Cop Trafik", 4.0, 0.0, False, 0.0),
            2: AttackScenario(2, "Yapisal Sahtecilik", 6.0, 0.2, False, 0.0, deception_ratio=0.1),
            3: AttackScenario(3, "Replay ve Zaman Kaydirma", 6.0, 0.3, False, 0.8),
            4: AttackScenario(4, "Basit Spoof", 8.0, 0.5, False, 0.0),
            5: AttackScenario(5, "Gelismis Spoof", 8.0, 0.7, False, 0.2, holdover_pressure=0.6, mission_breach_ratio=0.35),
            6: AttackScenario(6, "Secret Ele Gecirilmis Kombinasyon", 8.0, 0.9, True, 0.4, deception_ratio=0.35, bulletin_conflict_ratio=0.45),
        }
        return profiles[stage]

    def signal_halves(self) -> tuple[str, str]:
        return split_signal_secret(self.config.security.signal_secret)

    def unwrap_packet_text(self, framed_packet: str) -> str:
        prefix, suffix = self.signal_halves()
        end_index = len(framed_packet) - len(suffix) if suffix else len(framed_packet)
        return framed_packet[len(prefix):end_index]

    def generate_normal_batch(self, count: int = 5, source: str = "bkzs-core", start_seq: int = 1) -> list[str]:
        now = utc_now() - timedelta(seconds=count + 5)
        packets = []
        for offset in range(count):
            packet = self._build_packet(
                source=source,
                seq=start_seq + offset,
                timestamp=now + timedelta(seconds=offset),
                latitude=self.base_latitude + offset * 0.00002,
                longitude=self.base_longitude + offset * 0.00002,
                commit_clean=True,
            )
            packets.append(self._frame_packet(packet))
        return packets

    def generate_stage_batch(self, stage: int, count: int = 6) -> list[str]:
        if stage == 1:
            return self._stage_one(count)
        if stage == 2:
            return self._stage_two(count)
        if stage == 3:
            return self._stage_three(count)
        if stage == 4:
            return self._stage_four(count)
        if stage == 5:
            return self._stage_five(count)
        if stage == 6:
            return self._stage_six(count)
        raise ValueError(f"Unsupported stage: {stage}")

    def generate_chain_batch(self) -> list[str]:
        chain = self.generate_normal_batch(count=5, start_seq=1)
        for stage in range(1, 7):
            chain.extend(self.generate_stage_batch(stage, count=5))
        return chain

    def generate_real_scenario_batch(
        self,
        base_count: int = 6,
    ) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
        selected_stage_count = self.random.randint(2, 4)
        selected_stages = self.random.sample(list(range(1, 7)), k=selected_stage_count)
        seq_tracker = {source: self.random.randint(50, 150) for source in self.config.security.trusted_sources}
        time_tracker = {source: utc_now() - timedelta(seconds=self.random.randint(8, 12)) for source in self.config.security.trusted_sources}
        packets: list[str] = []
        truth: list[dict[str, Any]] = []
        segments: list[dict[str, Any]] = []

        def add_normal_segment(count: int) -> None:
            source = self.random.choice(self.config.security.trusted_sources)
            batch = self._build_normal_segment(source, seq_tracker, time_tracker, count)
            packets.extend(batch)
            truth.extend({"label": "normal", "stage": 0, "profile": "Normal Operasyonel Akis", "family": "normal"} for _ in batch)
            segments.append({"kind": "normal", "stage": 0, "profile": "Normal Operasyonel Akis", "source": source, "packet_count": len(batch)})

        def add_attack_segment(stage: int, count: int) -> None:
            batch = self.generate_stage_batch(stage=stage, count=count)
            self._sync_trackers_from_batch(batch, seq_tracker, time_tracker)
            profile = self.default_scenario(stage).profile
            packets.extend(batch)
            truth.extend({"label": "attack", "stage": stage, "profile": profile, "family": f"stage_{stage}"} for _ in batch)
            segments.append({"kind": "attack", "stage": stage, "profile": profile, "packet_count": len(batch)})

        add_normal_segment(max(3, base_count // 2))
        for stage in selected_stages:
            if self.random.random() > 0.35:
                add_normal_segment(self.random.randint(1, max(2, base_count // 2)))
            attack_count = self.random.randint(max(2, base_count // 2), max(3, base_count))
            add_attack_segment(stage, attack_count)
            if self.random.random() > 0.45:
                add_normal_segment(self.random.randint(1, max(3, base_count // 2)))

        metadata = {
            "mode": "real_scenario",
            "selected_stages": selected_stages,
            "segment_order": segments,
            "profile": "Rastgele saha turu",
            "packet_count": len(packets),
        }
        return packets, truth, metadata

    def generate_counter_intel_tour(
        self,
        base_count: int = 4,
    ) -> tuple[list[str], list[dict[str, Any]], dict[str, Any]]:
        seq_tracker = {source: self.random.randint(200, 400) for source in self.config.security.trusted_sources}
        time_tracker = {source: utc_now() - timedelta(seconds=self.random.randint(8, 12)) for source in self.config.security.trusted_sources}
        bulletin_payload = sample_trust_bulletin(self.config.bulletin.signing_key)
        packets: list[str] = []
        truth: list[dict[str, Any]] = []
        segments: list[dict[str, Any]] = []

        def add_normal(count: int) -> None:
            source = self.random.choice(self.config.security.trusted_sources)
            batch = self._build_normal_segment(source, seq_tracker, time_tracker, count)
            packets.extend(batch)
            truth.extend({"label": "normal", "stage": 0, "profile": "Normal Operasyonel Akis", "family": "normal"} for _ in batch)
            segments.append({"kind": "normal", "family": "normal", "source": source, "packet_count": len(batch)})

        def add_attack(family: str, batch: list[str], profile: str) -> None:
            self._sync_trackers_from_batch(batch, seq_tracker, time_tracker)
            packets.extend(batch)
            truth.extend({"label": "attack", "stage": 0, "profile": profile, "family": family} for _ in batch)
            segments.append({"kind": "attack", "family": family, "profile": profile, "packet_count": len(batch)})

        add_normal(max(3, base_count))
        families = [
            ("classic_replay", self._stage_three(max(3, base_count // 2))),
            ("secret_leak_after_spoof", self._secret_leak_without_shadow(max(2, base_count // 2))),
            ("shadow_lane_contact", self._shadow_lane_contact(max(2, base_count // 2))),
            ("mesh_divergence", self._mesh_divergence(max(2, base_count // 2))),
            ("holdover_break_attempt", self._holdover_break_attempt(max(2, base_count // 2))),
            ("mission_envelope_break", self._mission_envelope_break(max(2, base_count // 2))),
            ("bulletin_conflict", self._bulletin_conflict(max(2, base_count // 2))),
        ]
        self.random.shuffle(families)

        for family, batch in families:
            if self.random.random() > 0.3:
                add_normal(self.random.randint(1, max(2, base_count // 2)))
            add_attack(family, batch, family.replace("_", " ").title())

        metadata = {
            "mode": "counter_intel_tour",
            "profile": "Counter-Intel Tour",
            "packet_count": len(packets),
            "segment_order": segments,
            "families": [family for family, _ in families],
            "trust_bulletin": bulletin_payload,
        }
        return packets, truth, metadata

    def _stage_one(self, count: int) -> list[str]:
        batch: list[str] = []
        for index in range(count):
            if index % 3 == 0:
                batch.append('{"packet_id":"broken"')
            elif index % 3 == 1:
                batch.append(self._frame_text('{"packet_id":"noise","source":"bkzs-core"'))
            else:
                packet = self._build_packet(
                    source="bkzs-core",
                    seq=100 + index,
                    timestamp=utc_now(),
                    stage_hint=1,
                )
                batch.append(json.dumps(packet))
        return batch

    def _stage_two(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            if offset % 2 == 0:
                packet = self._build_packet(
                    source="bkzs-core",
                    seq=200 + offset,
                    timestamp=now + timedelta(seconds=offset),
                    stage_hint=2,
                    op_code="BKZS-LEAKED",
                    commit_clean=False,
                )
                packet["checksum"] = "deadbeefdeadbeef"
            elif offset % 3 == 0:
                packet = self._build_packet(
                    source="bkzs-core",
                    seq=200 + offset,
                    timestamp=now + timedelta(seconds=offset),
                    stage_hint=2,
                    session_nonce="stale-session-seal",
                    commit_clean=False,
                )
            else:
                packet = self._build_packet(
                    source="spoofed-edge",
                    seq=200 + offset,
                    timestamp=now + timedelta(seconds=offset),
                    stage_hint=2,
                    commit_clean=False,
                )
            packet["flow_tag"] = self._flow_tag(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _stage_three(self, count: int) -> list[str]:
        warmup = self.generate_normal_batch(count=3, source="bkzs-edge-1", start_seq=300)
        replay_packets = list(warmup[: min(count, len(warmup))])
        if count > len(replay_packets) and replay_packets:
            replay_packets.extend(replay_packets[-1:] * (count - len(replay_packets)))
        return warmup + replay_packets

    def _stage_four(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            packet = self._build_packet(
                source="bkzs-edge-1",
                seq=400 + offset,
                timestamp=now + timedelta(seconds=offset),
                stage_hint=4,
                commit_clean=False,
            )
            packet["metrics"]["cn0"] = 18.0 + offset * 0.5
            packet["metrics"]["power"] = -74.0 + offset * 0.2
            packet["metrics"]["doppler"] = 2600.0 + offset * 150.0
            packet["metrics"]["sat_count"] = 3
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _stage_five(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            latitude = self.base_latitude + 0.00028 * offset
            longitude = self.base_longitude + 0.00028 * offset
            packet = self._build_packet(
                source="bkzs-edge-2",
                seq=500 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=latitude,
                longitude=longitude,
                stage_hint=5,
                commit_clean=False,
                holdover_state=self._holdover_state(latitude, longitude, 12.0 + offset * 4.0),
            )
            packet["metrics"]["clock_bias"] = 10.0 + (offset * 65.0)
            packet["metrics"]["clock_drift"] = 0.5 + (offset * 1.1)
            packet["metrics"]["doppler"] = 1220.0 + offset * 25.0
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _stage_six(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            latitude = self.base_latitude + 0.00030 * offset
            longitude = self.base_longitude + 0.00024 * offset
            packet = self._build_packet(
                source="bkzs-core",
                seq=600 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=latitude,
                longitude=longitude,
                stage_hint=6,
                secret_compromised=True,
                commit_clean=False,
                holdover_state=self._holdover_state(latitude, longitude, 12.0 + offset * 5.0),
            )
            packet["metrics"]["clock_bias"] = 12.0 + (offset * 80.0)
            packet["metrics"]["clock_drift"] = 0.7 + (offset * 1.25)
            packet["payload"]["attack_meta"]["replay_ratio"] = 0.4
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _secret_leak_without_shadow(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        stale_hash = initial_clean_hash("bkzs-core", self.config.security.session_nonce)
        for offset in range(count):
            packet = self._build_packet(
                source="bkzs-core",
                seq=700 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                stage_hint=6,
                secret_compromised=True,
                commit_clean=False,
                previous_clean_hash_override=stale_hash,
            )
            packets.append(self._frame_packet(packet))
        return packets

    def _shadow_lane_contact(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            packet = self._build_packet(
                source="bkzs-core",
                seq=760 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                stage_hint=6,
                secret_compromised=True,
                commit_clean=False,
                proof_lane="shadow",
            )
            packets.append(self._frame_packet(packet))
        return packets

    def _mesh_divergence(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            latitude = self.base_latitude + 0.00004 * offset
            longitude = self.base_longitude + 0.00003 * offset
            packet = self._build_packet(
                source="bkzs-edge-1",
                seq=820 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=latitude,
                longitude=longitude,
                stage_hint=5,
                commit_clean=False,
                peer_observations={
                    "peer_count": 2,
                    "position_delta_m": 240.0 + offset * 6.0,
                    "clock_bias_delta": 165.0 + offset * 5.0,
                    "clock_drift_delta": 5.8,
                    "time_delta_seconds": 1.9,
                    "receiver_baseline_delta_m": 150.0 + offset * 5.0,
                },
                holdover_state=self._holdover_state(latitude, longitude, 14.0),
            )
            packets.append(self._frame_packet(packet))
        return packets

    def _holdover_break_attempt(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            latitude = self.base_latitude + 0.00032 * offset
            longitude = self.base_longitude + 0.00025 * offset
            packet = self._build_packet(
                source="bkzs-edge-2",
                seq=880 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=latitude,
                longitude=longitude,
                stage_hint=5,
                commit_clean=False,
                holdover_state=self._holdover_state(latitude, longitude, 18.0, confidence=0.91),
            )
            packet["metrics"]["clock_bias"] = 35.0 + offset * 90.0
            packet["metrics"]["clock_drift"] = 8.5 + offset * 1.45
            packet["metrics"]["doppler"] = 1440.0 + offset * 44.0
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _mission_envelope_break(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        profile = get_satellite_profile(self.config.mission.satellite_profile_id)
        for offset in range(count):
            latitude = self.base_latitude + 0.012 + (offset * 0.0004)
            longitude = self.base_longitude + 0.012 + (offset * 0.0004)
            satellite_overrides: dict[str, Any] | None = None
            if profile.mission_domain == "communications":
                satellite_overrides = {
                    "orbital_slot_deg_e": (profile.orbital_slot_deg_e or 0.0) + 7.0,
                    "downlink_band": "X-Band",
                }
            elif profile.mission_domain == "earth_observation":
                satellite_overrides = {
                    "downlink_band": "Ka-Band",
                    "protocol_family": "unknown-protocol",
                }
            packet = self._build_packet(
                source="bkzs-edge-1",
                seq=940 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=latitude,
                longitude=longitude,
                stage_hint=5,
                commit_clean=False,
                speed=34.0,
                satellite_overrides=satellite_overrides,
            )
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _bulletin_conflict(self, count: int) -> list[str]:
        packets: list[str] = []
        now = utc_now() - timedelta(seconds=count)
        for offset in range(count):
            packet = self._build_packet(
                source="bkzs-edge-2",
                seq=980 + offset,
                timestamp=now + timedelta(seconds=offset + 1),
                latitude=self.base_latitude + 0.00005 * offset,
                longitude=self.base_longitude + 0.00005 * offset,
                stage_hint=6,
                secret_compromised=True,
                commit_clean=False,
                speed=56.0 + offset,
            )
            packet = self._finalize_packet(packet)
            packets.append(self._frame_packet(packet))
        return packets

    def _build_normal_segment(
        self,
        source: str,
        seq_tracker: dict[str, int],
        time_tracker: dict[str, Any],
        count: int,
    ) -> list[str]:
        batch: list[str] = []
        current_time = time_tracker[source]
        latitude = self.base_latitude + self.random.uniform(-0.0001, 0.0001)
        longitude = self.base_longitude + self.random.uniform(-0.0001, 0.0001)
        for _ in range(count):
            current_time += timedelta(seconds=1)
            latitude += self.random.uniform(0.00001, 0.00003)
            longitude += self.random.uniform(0.00001, 0.00003)
            packet = self._build_packet(
                source=source,
                seq=seq_tracker[source],
                timestamp=current_time,
                latitude=latitude,
                longitude=longitude,
                commit_clean=True,
            )
            seq_tracker[source] += 1
            batch.append(self._frame_packet(packet))
        time_tracker[source] = current_time
        return batch

    def _build_packet(
        self,
        *,
        source: str,
        seq: int,
        timestamp,
        latitude: float | None = None,
        longitude: float | None = None,
        stage_hint: int | None = None,
        secret_compromised: bool = False,
        trust_lane: str = "primary",
        proof_lane: str = "primary",
        commit_clean: bool = False,
        op_code: str | None = None,
        session_nonce: str | None = None,
        peer_observations: dict[str, Any] | None = None,
        holdover_state: dict[str, Any] | None = None,
        previous_clean_hash_override: str | None = None,
        advance_chain: bool = False,
        channel: str | None = None,
        speed: float | None = None,
        mission_phase: str | None = None,
        satellite_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        latitude = latitude if latitude is not None else self.base_latitude + self.random.uniform(-0.00005, 0.00005)
        longitude = longitude if longitude is not None else self.base_longitude + self.random.uniform(-0.00005, 0.00005)
        session_nonce = session_nonce or self.config.security.session_nonce
        previous_clean_hash = previous_clean_hash_override or self.clean_hash_by_source.get(
            source,
            initial_clean_hash(source, self.config.security.session_nonce),
        )
        satellite_payload = build_satellite_payload(self.config.mission.satellite_profile_id)
        if satellite_overrides:
            satellite_payload.update(dict(satellite_overrides))
        epoch_id = epoch_id_from_timestamp(timestamp, self.config.thresholds.challenge_epoch_seconds)
        packet = {
            "packet_id": uuid4().hex[:12],
            "source": source,
            "ts": timestamp.isoformat(),
            "seq": seq,
            "epoch_id": epoch_id,
            "challenge_proof": build_challenge_proof(
                self.config.security.signal_secret,
                self.config.security.session_nonce,
                self.config.security.shadow_lane_salt,
                source,
                epoch_id,
                previous_clean_hash,
                lane=proof_lane,
            ),
            "session_nonce": session_nonce,
            "trust_lane": trust_lane,
            "peer_observations": dict(peer_observations or {}),
            "holdover_state": dict(holdover_state or {}),
            "op_code": op_code or self.config.security.expected_op_code,
            "payload": {
                "channel": channel or self.config.mission.allowed_channel,
                "mission_phase": mission_phase or self.config.mission.mission_phase,
                "confidence": round(self.random.uniform(0.96, 0.999), 3),
                **satellite_payload,
                "attack_meta": {
                    "stage_hint": stage_hint,
                    "secret_compromised": secret_compromised,
                },
            },
            "metrics": {
                "cn0": round(self.random.uniform(41.0, 47.0), 2),
                "power": round(self.random.uniform(-113.0, -107.0), 2),
                "doppler": round(self.random.uniform(1100.0, 1300.0), 2),
                "sat_count": self.random.randint(8, 12),
                "clock_bias": round(self.random.uniform(8.0, 16.0), 2),
                "clock_drift": round(self.random.uniform(0.1, 1.2), 2),
                "latitude": round(latitude, 7),
                "longitude": round(longitude, 7),
                "altitude": round(self.random.uniform(14.0, 22.0), 2),
                "speed": round(speed if speed is not None else self.random.uniform(9.0, 16.0), 2),
            },
        }
        packet = self._finalize_packet(packet)
        if (commit_clean or advance_chain) and trust_lane == "primary" and proof_lane == "primary":
            self.clean_hash_by_source[source] = build_packet_chain_hash(packet)
        return packet

    def _finalize_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        packet["flow_tag"] = self._flow_tag(packet)
        packet["checksum"] = stable_checksum({k: v for k, v in packet.items() if k not in {"checksum", "flow_tag"}})
        return packet

    def _holdover_state(
        self,
        latitude: float,
        longitude: float,
        predicted_clock_bias: float,
        confidence: float = 0.88,
    ) -> dict[str, Any]:
        return {
            "confidence": confidence,
            "predicted_latitude": round(latitude + self.random.uniform(-0.00003, 0.00003), 7),
            "predicted_longitude": round(longitude + self.random.uniform(-0.00003, 0.00003), 7),
            "predicted_clock_bias": round(predicted_clock_bias, 2),
        }

    def _frame_packet(self, packet: dict[str, Any]) -> str:
        return self._frame_text(json.dumps(packet))

    def _frame_text(self, raw_json: str) -> str:
        return frame_signal_payload(raw_json, self.config.security.signal_secret)

    def _flow_tag(self, packet: dict[str, Any]) -> str:
        return build_flow_tag(
            packet_flow_tag_view(packet),
            self.config.security.signal_secret,
            str(packet.get("session_nonce", self.config.security.session_nonce)),
        )

    def _sync_trackers_from_batch(
        self,
        batch: list[str],
        seq_tracker: dict[str, int],
        time_tracker: dict[str, Any],
    ) -> None:
        for framed_packet in batch:
            try:
                raw_packet = json.loads(self.unwrap_packet_text(framed_packet))
            except Exception:
                continue
            source = str(raw_packet.get("source", ""))
            if source not in seq_tracker:
                continue
            try:
                seq_tracker[source] = max(seq_tracker[source], int(raw_packet["seq"]) + 1)
                parsed_ts = parse_timestamp(str(raw_packet["ts"]))
                if parsed_ts > time_tracker[source]:
                    time_tracker[source] = parsed_ts
            except (KeyError, TypeError, ValueError):
                continue
