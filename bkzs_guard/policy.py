from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from bkzs_guard.utils import parse_timestamp, stable_digest, utc_now


@dataclass(slots=True)
class BulletinRiskZone:
    name: str
    center_latitude: float
    center_longitude: float
    radius_m: float
    severity: str = "high"


@dataclass(slots=True)
class TrustBulletin:
    bulletin_id: str
    valid_from: datetime
    valid_to: datetime
    risk_zones: list[BulletinRiskZone] = field(default_factory=list)
    source_risk: dict[str, int] = field(default_factory=dict)
    threshold_overrides: dict[str, float] = field(default_factory=dict)
    signature: str = ""

    def is_active(self, at: datetime | None = None) -> bool:
        now = at or utc_now()
        return self.valid_from <= now <= self.valid_to

    @property
    def risk_zone_count(self) -> int:
        return len(self.risk_zones)


@dataclass(slots=True)
class ForensicCase:
    case_id: str
    created_at: datetime
    packet_id: str
    source: str
    classification: str
    failed_layer: int | None
    defense_mechanism: str
    service_mode: str
    mission_breach: bool
    trust_bulletin_id: str | None
    quorum_result: str
    evidence_vector: list[str] = field(default_factory=list)
    attacker_profile: dict[str, Any] = field(default_factory=dict)
    summary: str = ""


def build_bulletin_signature(payload: dict[str, Any], signing_key: str) -> str:
    material = {
        "signing_key": signing_key,
        "payload": payload,
    }
    return stable_digest(material, length=32)


def verify_bulletin_signature(payload: dict[str, Any], signing_key: str, signature: str) -> bool:
    return build_bulletin_signature(payload, signing_key) == signature


def load_trust_bulletin(raw_bulletin: str | dict[str, Any], signing_key: str) -> TrustBulletin:
    payload = json.loads(raw_bulletin) if isinstance(raw_bulletin, str) else dict(raw_bulletin)
    signature = str(payload.get("signature", ""))
    body = {key: value for key, value in payload.items() if key != "signature"}
    if not verify_bulletin_signature(body, signing_key, signature):
        raise ValueError("Trust bulletin imzasi gecersiz.")

    zones = [
        BulletinRiskZone(
            name=str(item["name"]),
            center_latitude=float(item["center_latitude"]),
            center_longitude=float(item["center_longitude"]),
            radius_m=float(item["radius_m"]),
            severity=str(item.get("severity", "high")),
        )
        for item in payload.get("risk_zones", [])
    ]
    return TrustBulletin(
        bulletin_id=str(payload["bulletin_id"]),
        valid_from=parse_timestamp(str(payload["valid_from"])),
        valid_to=parse_timestamp(str(payload["valid_to"])),
        risk_zones=zones,
        source_risk={str(key): int(value) for key, value in dict(payload.get("source_risk", {})).items()},
        threshold_overrides={str(key): float(value) for key, value in dict(payload.get("threshold_overrides", {})).items()},
        signature=signature,
    )


def sample_trust_bulletin(signing_key: str) -> dict[str, Any]:
    now = utc_now().replace(microsecond=0)
    body = {
        "bulletin_id": f"bulletin-{uuid4().hex[:8]}",
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "valid_to": (now + timedelta(hours=6)).isoformat(),
        "risk_zones": [
            {
                "name": "elevated-east",
                "center_latitude": 41.0184,
                "center_longitude": 29.0118,
                "radius_m": 180.0,
                "severity": "high",
            }
        ],
        "source_risk": {"bkzs-edge-2": 2},
        "threshold_overrides": {
            "mission_max_speed_mps": 48.0,
            "mission_max_route_drift_m": 160.0,
            "max_peer_position_delta_m": 120.0,
        },
    }
    body["signature"] = build_bulletin_signature(body, signing_key)
    return body
