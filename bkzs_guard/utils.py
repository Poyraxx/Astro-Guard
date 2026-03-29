from __future__ import annotations

import hashlib
import json
import math
import secrets
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def stable_digest(payload: Any, length: int = 24) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:length]


def stable_checksum(payload: dict[str, Any]) -> str:
    return stable_digest(payload, length=16)


def packet_checksum_view(raw_packet: dict[str, Any]) -> dict[str, Any]:
    clone = dict(raw_packet)
    clone.pop("checksum", None)
    clone.pop("flow_tag", None)
    return clone


def packet_flow_tag_view(raw_packet: dict[str, Any]) -> dict[str, Any]:
    clone = dict(raw_packet)
    clone.pop("checksum", None)
    clone.pop("flow_tag", None)
    return clone


def packet_chain_view(raw_packet: dict[str, Any]) -> dict[str, Any]:
    clone = dict(raw_packet)
    clone.pop("checksum", None)
    clone.pop("flow_tag", None)
    return clone


def build_flow_tag(payload: dict[str, Any], signal_secret: str, session_nonce: str) -> str:
    material = {
        "signal_secret": signal_secret,
        "session_nonce": session_nonce,
        "payload": payload,
    }
    return stable_digest(material, length=24)


def initial_clean_hash(source: str, session_nonce: str) -> str:
    return stable_digest({"source": source, "session_nonce": session_nonce, "lane": "genesis"}, length=24)


def build_packet_chain_hash(raw_packet: dict[str, Any]) -> str:
    return stable_digest(packet_chain_view(raw_packet), length=24)


def epoch_id_from_timestamp(value: datetime, epoch_seconds: int = 1) -> str:
    seconds = max(1, epoch_seconds)
    slot = int(value.timestamp()) // seconds
    return str(slot)


def build_challenge_proof(
    signal_secret: str,
    session_nonce: str,
    shadow_lane_salt: str,
    source: str,
    epoch_id: str,
    previous_clean_hash: str,
    lane: str = "primary",
) -> str:
    material = {
        "lane": lane,
        "seed": shadow_lane_salt if lane == "shadow" else signal_secret,
        "session_nonce": session_nonce,
        "source": source,
        "epoch_id": epoch_id,
        "previous_clean_hash": previous_clean_hash,
    }
    return stable_digest(material, length=24)


def split_signal_secret(signal_secret: str) -> tuple[str, str]:
    midpoint = len(signal_secret) // 2
    if midpoint == 0:
        return signal_secret, ""
    return signal_secret[:midpoint], signal_secret[midpoint:]


def frame_signal_payload(payload: str, signal_secret: str) -> str:
    prefix, suffix = split_signal_secret(signal_secret)
    return f"{prefix}{payload}{suffix}"


def unwrap_signal_payload(raw_input: str, signal_secret: str) -> tuple[str | None, str | None]:
    prefix, suffix = split_signal_secret(signal_secret)
    if prefix and not raw_input.startswith(prefix):
        return None, "signal_prefix_missing"
    if suffix and not raw_input.endswith(suffix):
        return None, "signal_suffix_missing"
    end_index = len(raw_input) - len(suffix) if suffix else len(raw_input)
    payload = raw_input[len(prefix):end_index]
    if not payload.strip():
        return None, "signal_envelope_empty"
    return payload, None


def haversine_meters(
    latitude_a: float,
    longitude_a: float,
    latitude_b: float,
    longitude_b: float,
) -> float:
    radius_m = 6_371_000.0
    lat_a = math.radians(latitude_a)
    lon_a = math.radians(longitude_a)
    lat_b = math.radians(latitude_b)
    lon_b = math.radians(longitude_b)
    delta_lat = lat_b - lat_a
    delta_lon = lon_b - lon_a
    term = math.sin(delta_lat / 2) ** 2 + math.cos(lat_a) * math.cos(lat_b) * math.sin(delta_lon / 2) ** 2
    return 2 * radius_m * math.asin(math.sqrt(term))


def generate_session_nonce(length: int = 12) -> str:
    return secrets.token_hex(max(1, length // 2))
