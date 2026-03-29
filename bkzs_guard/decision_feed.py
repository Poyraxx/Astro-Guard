from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bkzs_guard.config import DecisionFeedConfig
from bkzs_guard.models import DecisionRecord
from bkzs_guard.utils import stable_digest, utc_now


@dataclass(slots=True)
class DecisionFeedEvent:
    event_id: str
    created_at: datetime
    protocol: str
    host: str
    port: int
    channel_name: str
    packet_id: str
    source: str
    decision: str
    classification: str
    failed_layer: int | None
    status: str
    twin_engaged: bool = False
    mission_breach: bool = False
    service_mode: str = "normal"
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class DecisionFeedPublisher:
    def __init__(self, config: DecisionFeedConfig) -> None:
        self.config = config
        self._sequence = 0

    def publish_record(self, record: DecisionRecord) -> DecisionFeedEvent:
        payload = {
            "packet_id": record.packet_id or "unknown-packet",
            "source": record.source or "-",
            "decision": record.decision,
            "classification": record.classification,
            "failed_layer": record.failed_layer,
            "service_mode": record.service_mode,
            "defense_mechanism": record.defense_mechanism,
            "anomaly_signature": record.anomaly_signature,
            "twin_engaged": record.twin_engaged,
            "mission_breach": record.mission_breach,
            "credential_leak_suspect": record.credential_leak_suspect,
            "deception_triggered": record.deception_triggered,
            "threat_intel_score": record.threat_intel_score,
            "processed_at": record.processed_at.isoformat() if record.processed_at else utc_now().isoformat(),
        }
        status = self._dispatch(payload)
        self._sequence += 1
        return DecisionFeedEvent(
            event_id=f"df-{stable_digest({'seq': self._sequence, 'packet_id': payload['packet_id']}, length=10)}",
            created_at=utc_now(),
            protocol=self.config.protocol,
            host=self.config.host,
            port=self.config.port,
            channel_name=self.config.channel_name,
            packet_id=str(payload["packet_id"]),
            source=str(payload["source"]),
            decision=str(payload["decision"]),
            classification=str(payload["classification"]),
            failed_layer=payload["failed_layer"] if isinstance(payload["failed_layer"], int) else None,
            status=status,
            twin_engaged=bool(payload["twin_engaged"]),
            mission_breach=bool(payload["mission_breach"]),
            service_mode=str(payload["service_mode"]),
            summary=self._summary_for(payload),
            details=payload,
        )

    def _dispatch(self, payload: dict[str, Any]) -> str:
        if not self.config.enabled:
            return "dry_run"
        protocol = self.config.protocol.lower()
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        try:
            if protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(encoded, (self.config.host, self.config.port))
                return "sent"
            if protocol == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    sock.connect((self.config.host, self.config.port))
                    sock.sendall(encoded)
                return "sent"
        except OSError as exc:
            return f"dispatch_error:{exc.__class__.__name__}"
        return "unsupported_protocol"

    @staticmethod
    def _summary_for(payload: dict[str, Any]) -> str:
        base = f"{payload['source']} -> {payload['decision']} / {payload['classification']}"
        flags: list[str] = []
        if payload.get("twin_engaged"):
            flags.append("digital-twin")
        if payload.get("mission_breach"):
            flags.append("mission-breach")
        if payload.get("credential_leak_suspect"):
            flags.append("credential-leak")
        if payload.get("deception_triggered"):
            flags.append("trap")
        return f"{base} ({', '.join(flags)})" if flags else base
