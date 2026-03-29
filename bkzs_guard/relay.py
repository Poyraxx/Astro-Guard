from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bkzs_guard.config import RelayPlaneConfig
from bkzs_guard.models import DecisionRecord
from bkzs_guard.utils import stable_digest, utc_now


@dataclass(slots=True)
class PlaneRelayEvent:
    relay_id: str
    created_at: datetime
    plane: str
    channel_name: str
    protocol: str
    host: str
    port: int
    source: str
    packet_id: str
    action: str
    status: str
    used_fallback: bool = False
    payload_digest: str = ""
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class SplitPlaneRelay:
    def __init__(self, secure_plane: RelayPlaneConfig, shadow_plane: RelayPlaneConfig, dispatch_enabled: bool = False) -> None:
        self.secure_plane = secure_plane
        self.shadow_plane = shadow_plane
        self.dispatch_enabled = dispatch_enabled
        self._sequence = 0

    def route_record(
        self,
        record: DecisionRecord,
        trusted_payload: str | None = None,
    ) -> list[PlaneRelayEvent]:
        events: list[PlaneRelayEvent] = []
        if record.decision == "accepted":
            payload = record.payload_view or "{}"
            events.append(self._build_real_event(record, payload, used_fallback=False, action="accepted_forward"))
            return events

        if record.twin_engaged:
            if trusted_payload:
                events.append(self._build_real_event(record, trusted_payload, used_fallback=True, action="continuity_forward"))
            events.append(self._build_shadow_event(record))
        return events

    def _build_real_event(
        self,
        record: DecisionRecord,
        payload: str,
        used_fallback: bool,
        action: str,
    ) -> PlaneRelayEvent:
        status = self._dispatch(self.secure_plane, payload)
        summary = (
            "Temiz veri guvenli hatta aktarildi."
            if not used_fallback
            else "Saldiri sirasinda son temiz veri guvenli hatta devamlilik icin aktarildi."
        )
        return self._build_event(
            plane="real",
            target=self.secure_plane,
            source=record.source or "-",
            packet_id=record.packet_id or "relay-packet",
            action=action,
            status=status,
            used_fallback=used_fallback,
            payload=payload,
            summary=summary,
            details={
                "service_mode": record.service_mode,
                "classification": record.classification,
                "shadow_session_id": record.shadow_session_id,
            },
        )

    def _build_shadow_event(self, record: DecisionRecord) -> PlaneRelayEvent:
        payload = record.synthetic_response or "BKZS Shadow Twin ACK"
        status = self._dispatch(self.shadow_plane, payload)
        summary = (
            "Saldirgan gercek sistemden ayrildi. Shadow plane uzerinden sentetik kabul akisi devam ediyor."
        )
        return self._build_event(
            plane="shadow",
            target=self.shadow_plane,
            source=record.source or "-",
            packet_id=record.packet_id or "shadow-packet",
            action="deception_ack",
            status=status,
            used_fallback=False,
            payload=payload,
            summary=summary,
            details={
                "classification": record.classification,
                "threat_intel_score": record.threat_intel_score,
                "shadow_session_id": record.shadow_session_id,
            },
        )

    def _build_event(
        self,
        plane: str,
        target: RelayPlaneConfig,
        source: str,
        packet_id: str,
        action: str,
        status: str,
        used_fallback: bool,
        payload: str,
        summary: str,
        details: dict[str, Any],
    ) -> PlaneRelayEvent:
        self._sequence += 1
        return PlaneRelayEvent(
            relay_id=f"relay-{stable_digest({'seq': self._sequence, 'plane': plane, 'packet_id': packet_id}, length=10)}",
            created_at=utc_now(),
            plane=plane,
            channel_name=target.channel_name,
            protocol=target.protocol,
            host=target.host,
            port=target.port,
            source=source,
            packet_id=packet_id,
            action=action,
            status=status,
            used_fallback=used_fallback,
            payload_digest=stable_digest(payload, length=12),
            summary=summary,
            details=details,
        )

    def _dispatch(self, target: RelayPlaneConfig, payload: str) -> str:
        if not self.dispatch_enabled:
            return "dry_run"
        protocol = target.protocol.lower()
        encoded = payload.encode("utf-8")
        try:
            if protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(encoded, (target.host, target.port))
                return "sent"
            if protocol == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    sock.connect((target.host, target.port))
                    sock.sendall(encoded)
                return "sent"
        except OSError as exc:
            return f"dispatch_error:{exc.__class__.__name__}"
        return "unsupported_protocol"
