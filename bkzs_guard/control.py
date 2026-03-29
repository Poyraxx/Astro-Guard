from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import mean
from typing import Any, Iterable

from bkzs_guard.adapters import DemoAdapter, PeerFeedAdapter, UdpTcpAdapter
from bkzs_guard.attack_lab import AttackLab
from bkzs_guard.config import AppConfig, load_app_config
from bkzs_guard.decision_feed import DecisionFeedEvent, DecisionFeedPublisher
from bkzs_guard.deception import DigitalTwinRouter, ShadowTwinSession, ThreatIntelEvent
from bkzs_guard.models import DecisionRecord
from bkzs_guard.policy import ForensicCase, TrustBulletin, load_trust_bulletin, sample_trust_bulletin
from bkzs_guard.pipeline import MicroLayerEngine
from bkzs_guard.lab_transport import resolve_lab_transport
from bkzs_guard.relay import PlaneRelayEvent, SplitPlaneRelay
from bkzs_guard.satellites import get_satellite_profile
from bkzs_guard.utils import utc_now


@dataclass(slots=True)
class DashboardSnapshot:
    records: list[DecisionRecord] = field(default_factory=list)
    quarantined: list[DecisionRecord] = field(default_factory=list)
    accepted_records: list[DecisionRecord] = field(default_factory=list)
    normal_records: list[DecisionRecord] = field(default_factory=list)
    trap_records: list[DecisionRecord] = field(default_factory=list)
    twin_records: list[DecisionRecord] = field(default_factory=list)
    holdover_records: list[DecisionRecord] = field(default_factory=list)
    credential_leak_records: list[DecisionRecord] = field(default_factory=list)
    mission_breach_records: list[DecisionRecord] = field(default_factory=list)
    total_packets: int = 0
    accepted_count: int = 0
    blocked_count: int = 0
    avg_latency: float = 0.0
    trust_pulse: int = 0
    passports: list[dict[str, Any]] = field(default_factory=list)
    locked_sources: dict[str, float] = field(default_factory=dict)
    active_bulletin: TrustBulletin | None = None
    forensic_cases: list[ForensicCase] = field(default_factory=list)
    shadow_twin_sessions: list[ShadowTwinSession] = field(default_factory=list)
    threat_intel_events: list[ThreatIntelEvent] = field(default_factory=list)
    real_plane_events: list[PlaneRelayEvent] = field(default_factory=list)
    shadow_plane_events: list[PlaneRelayEvent] = field(default_factory=list)
    decision_feed_events: list[DecisionFeedEvent] = field(default_factory=list)
    response_modes: dict[str, int] = field(default_factory=dict)
    remote_threat_contacts: list[dict[str, Any]] = field(default_factory=list)
    remote_blocked_sources: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class NetworkListenerStatus:
    active: bool = False
    protocol: str = "udp"
    host: str = "0.0.0.0"
    port: int = 9000
    started_at: datetime | None = None
    received_packets: int = 0
    last_packet_at: datetime | None = None
    last_error: str | None = None


@dataclass(slots=True)
class RemoteThreatContact:
    remote_ip: str
    protocol: str
    first_seen: datetime
    last_seen: datetime
    packets_seen: int = 0
    accepted_count: int = 0
    blocked_count: int = 0
    twin_count: int = 0
    credential_leak_count: int = 0
    mission_breach_count: int = 0
    holdover_count: int = 0
    network_drop_count: int = 0
    last_remote_port: int | None = None
    recent_ports: list[int] = field(default_factory=list)
    blocked_until: datetime | None = None
    last_source: str = "-"
    last_packet_id: str = "-"
    last_classification: str = "-"
    last_failed_layer: int | None = None
    last_service_mode: str = "normal"
    last_threat_family: str = "-"
    last_anomaly_signature: str = "-"
    last_forensic_case_id: str | None = None
    last_evidence: list[str] = field(default_factory=list)


class BKZSControlCenter:
    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or load_app_config()
        self.authenticated = False
        self.flash_notice: dict[str, str] | None = None
        self.active_bulletin: TrustBulletin | None = None
        self._lock = threading.RLock()
        self._listener_thread: threading.Thread | None = None
        self._listener_stop_event: threading.Event | None = None
        self._listener_status = NetworkListenerStatus()
        self._reset_runtime_state()

    def _reset_runtime_state(self) -> None:
        self.engine = MicroLayerEngine(self.config)
        self.engine.set_trust_bulletin(self.active_bulletin)
        self.attack_lab = AttackLab(self.config)
        self.demo_adapter = DemoAdapter(self.attack_lab)
        self.peer_adapter = PeerFeedAdapter()
        self.digital_twin_router = DigitalTwinRouter()
        self.split_plane_relay = SplitPlaneRelay(
            secure_plane=self.config.relay.secure_plane,
            shadow_plane=self.config.relay.shadow_plane,
            dispatch_enabled=self.config.relay.dispatch_enabled,
        )
        self.decision_feed = DecisionFeedPublisher(self.config.decision_feed)
        self.decisions: list[DecisionRecord] = []
        self.quarantine: list[DecisionRecord] = []
        self.last_run_results: list[DecisionRecord] = []
        self.last_run_truth: list[dict[str, Any]] = []
        self.last_run_meta: dict[str, Any] = {}
        self.forensic_cases: list[ForensicCase] = []
        self.shadow_twin_sessions: list[ShadowTwinSession] = []
        self.threat_intel_events: list[ThreatIntelEvent] = []
        self.real_plane_events: list[PlaneRelayEvent] = []
        self.shadow_plane_events: list[PlaneRelayEvent] = []
        self.decision_feed_events: list[DecisionFeedEvent] = []
        self.last_clean_payload_by_source: dict[str, str] = {}
        self.total_packets = 0
        self.total_accepted = 0
        self.total_blocked = 0
        self.remote_threat_contacts: dict[str, RemoteThreatContact] = {}
        self.remote_ip_strikes: dict[str, int] = {}
        self.blocked_remote_ips_until: dict[str, datetime] = {}

    def authenticate(self, password: str) -> bool:
        self.authenticated = password == self.config.security.ui_password
        return self.authenticated

    def reset_runtime(self, config: AppConfig | None = None, preserve_auth: bool = True) -> None:
        self.stop_network_listener()
        if config is not None:
            self.config = config
        current_auth = self.authenticated if preserve_auth else False
        self._reset_runtime_state()
        self.authenticated = current_auth

    def apply_signal_secret(self, new_secret: str) -> None:
        cleaned = new_secret.strip()
        if not cleaned:
            raise ValueError("Sinyal sifresi bos birakilamaz.")
        self.config.security.signal_secret = cleaned
        self.reset_runtime(preserve_auth=True)

    def apply_session_nonce(self, new_nonce: str) -> None:
        cleaned = new_nonce.strip()
        if not cleaned:
            raise ValueError("Oturum muhru bos birakilamaz.")
        self.config.security.session_nonce = cleaned
        self.reset_runtime(preserve_auth=True)

    def apply_satellite_profile(self, profile_id: str) -> None:
        profile = get_satellite_profile(profile_id)
        self.config.mission.satellite_profile_id = profile.profile_id
        self.config.mission.allowed_channel = profile.primary_channel
        self.config.mission.mission_phase = "relay" if profile.mission_domain == "communications" else "imaging"
        self.reset_runtime(preserve_auth=True)

    def apply_trust_bulletin(self, raw_bulletin: str | dict[str, Any]) -> TrustBulletin:
        bulletin = load_trust_bulletin(raw_bulletin, self.config.bulletin.signing_key)
        self.active_bulletin = bulletin
        self.engine.set_trust_bulletin(bulletin)
        return bulletin

    def clear_trust_bulletin(self) -> None:
        self.active_bulletin = None
        self.engine.set_trust_bulletin(None)

    def sample_bulletin_payload(self) -> dict[str, Any]:
        return sample_trust_bulletin(self.config.bulletin.signing_key)

    def ingest_packets(
        self,
        raw_packets: Iterable[str | dict[str, Any]],
        run_truth: list[dict[str, Any]] | None = None,
        run_meta: dict[str, Any] | None = None,
    ) -> list[DecisionRecord]:
        with self._lock:
            packets = list(raw_packets)
            if not packets:
                return []
            if run_meta and "trust_bulletin" in run_meta:
                self.apply_trust_bulletin(run_meta["trust_bulletin"])

            results = self.engine.process_batch(packets)
            self.decisions.extend(results)
            self.decisions = self.decisions[-400:]

            accepted = [item for item in results if item.decision == "accepted"]
            blocked = [item for item in results if item.quarantined]
            self.total_packets += len(results)
            self.total_accepted += len(accepted)
            self.total_blocked += len(blocked)
            self.quarantine.extend(blocked)
            self.quarantine = self.quarantine[-200:]

            self.last_run_results = results
            self.last_run_truth = list(run_truth or [])
            self.last_run_meta = dict(run_meta or {})
            self._register_forensics(results)
            self._route_shadow_twin(results)
            self._relay_results(results)
            self._publish_decisions(results)
            return results

    def load_normal_run(self, count: int = 5) -> list[DecisionRecord]:
        self.demo_adapter.load_normal(count)
        return self.ingest_packets(self.demo_adapter.drain())

    def load_stage_run(self, stage: int, count: int = 6) -> list[DecisionRecord]:
        self.demo_adapter.load_stage(stage, count)
        return self.ingest_packets(self.demo_adapter.drain())

    def load_chain_run(self) -> list[DecisionRecord]:
        self.demo_adapter.load_chain()
        return self.ingest_packets(self.demo_adapter.drain())

    def load_real_scenario_run(self, base_count: int = 6) -> tuple[list[DecisionRecord], dict[str, Any]]:
        metadata = self.demo_adapter.load_real_scenario(base_count=base_count)
        results = self.ingest_packets(
            self.demo_adapter.drain(),
            run_truth=self.demo_adapter.consume_last_truth(),
            run_meta=self.demo_adapter.consume_last_metadata(),
        )
        return results, metadata

    def load_counter_intel_tour(self, base_count: int = 4) -> tuple[list[DecisionRecord], dict[str, Any]]:
        metadata = self.demo_adapter.load_counter_intel_tour(base_count=base_count)
        results = self.ingest_packets(
            self.demo_adapter.drain(),
            run_truth=self.demo_adapter.consume_last_truth(),
            run_meta=self.demo_adapter.consume_last_metadata(),
        )
        return results, metadata

    def listen_network(
        self,
        protocol: str,
        host: str,
        port: int,
        timeout_seconds: float,
        max_packets: int,
    ) -> list[DecisionRecord]:
        adapter = UdpTcpAdapter(
            protocol=protocol,
            host=host,
            port=port,
            timeout_seconds=timeout_seconds,
        )
        try:
            adapter.connect()
            packets = adapter.listen_batch_with_meta(max_packets=max_packets)
        finally:
            adapter.close()
        all_results: list[DecisionRecord] = []
        for packet, remote_meta in packets:
            if remote_meta is None:
                continue
            packet, remote_meta = resolve_lab_transport(
                packet,
                remote_meta,
                lab_transport_enabled=self.config.lab.transport_simulation_enabled,
            )
            if self._is_remote_ip_blocked(remote_meta):
                self._register_remote_drop(remote_meta)
                continue
            results = self.ingest_packets([packet])
            self._register_remote_contact(remote_meta, results)
            all_results.extend(results)
        return all_results

    def start_network_listener(
        self,
        protocol: str,
        host: str,
        port: int,
        poll_timeout_seconds: float = 0.5,
    ) -> NetworkListenerStatus:
        self.stop_network_listener()
        stop_event = threading.Event()
        status = NetworkListenerStatus(
            active=True,
            protocol=protocol,
            host=host,
            port=port,
            started_at=utc_now(),
            received_packets=0,
            last_packet_at=None,
            last_error=None,
        )
        self._listener_stop_event = stop_event
        self._listener_status = status
        self._listener_thread = threading.Thread(
            target=self._network_listener_worker,
            args=(protocol, host, port, poll_timeout_seconds, stop_event),
            daemon=True,
        )
        self._listener_thread.start()
        return self.network_listener_snapshot()

    def stop_network_listener(self) -> None:
        stop_event = self._listener_stop_event
        thread = self._listener_thread
        if stop_event is not None:
            stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.2)
        with self._lock:
            self._listener_thread = None
            self._listener_stop_event = None
            self._listener_status.active = False

    def network_listener_snapshot(self) -> NetworkListenerStatus:
        with self._lock:
            return NetworkListenerStatus(
                active=self._listener_status.active,
                protocol=self._listener_status.protocol,
                host=self._listener_status.host,
                port=self._listener_status.port,
                started_at=self._listener_status.started_at,
                received_packets=self._listener_status.received_packets,
                last_packet_at=self._listener_status.last_packet_at,
                last_error=self._listener_status.last_error,
            )

    def is_network_listener_active(self) -> bool:
        with self._lock:
            return self._listener_status.active

    def process_manual_text(self, raw_payload: str) -> list[DecisionRecord]:
        lines = [line.strip() for line in raw_payload.splitlines() if line.strip()]
        return self.ingest_packets(lines)

    def process_peer_text(self, raw_payload: str) -> list[DecisionRecord]:
        lines = [line.strip() for line in raw_payload.splitlines() if line.strip()]
        self.peer_adapter.load_packets(lines)
        return self.ingest_packets(self.peer_adapter.drain())

    def push_notice(self, level: str, message: str) -> None:
        self.flash_notice = {"level": level, "message": message}

    def consume_notice(self) -> dict[str, str] | None:
        notice = self.flash_notice
        self.flash_notice = None
        return notice

    def dashboard_snapshot(self) -> DashboardSnapshot:
        with self._lock:
            records = list(self.decisions)
            quarantined = list(self.quarantine)
            accepted_records = [item for item in records if item.decision == "accepted"]
            normal_records = [item for item in accepted_records if item.service_mode == "normal"]
            trap_records = [
                item
                for item in records
                if item.deception_triggered
                or item.twin_engaged
                or item.classification in {"leak_trap_triggered", "shadow_contact_suspect"}
            ]
            twin_records = [item for item in records if item.twin_engaged]
            holdover_records = [item for item in records if item.service_mode == "holdover"]
            credential_leak_records = [item for item in records if item.credential_leak_suspect]
            mission_breach_records = [item for item in records if item.mission_breach]
            avg_latency = round(sum(item.latency_ms for item in records) / len(records), 2) if records else 0.0
            trust_pulse = round(mean(item.trust_score for item in normal_records[-20:])) if normal_records else 0
            response_modes: dict[str, int] = {}
            for item in records:
                response_modes[item.service_mode] = response_modes.get(item.service_mode, 0) + 1
            return DashboardSnapshot(
                records=records,
                quarantined=quarantined,
                accepted_records=accepted_records,
                normal_records=normal_records,
                trap_records=trap_records,
                twin_records=twin_records,
                holdover_records=holdover_records,
                credential_leak_records=credential_leak_records,
                mission_breach_records=mission_breach_records,
                total_packets=self.total_packets,
                accepted_count=self.total_accepted,
                blocked_count=self.total_blocked,
                avg_latency=avg_latency,
                trust_pulse=trust_pulse,
                passports=self.build_source_passports(records),
                locked_sources=self.engine.state.active_locked_sources(),
                active_bulletin=self.active_bulletin,
                forensic_cases=list(self.forensic_cases[-6:]),
                shadow_twin_sessions=list(self.shadow_twin_sessions[-6:]),
                threat_intel_events=list(self.threat_intel_events[-6:]),
                real_plane_events=list(self.real_plane_events[-6:]),
                shadow_plane_events=list(self.shadow_plane_events[-6:]),
                decision_feed_events=list(self.decision_feed_events[-12:]),
                response_modes=response_modes,
                remote_threat_contacts=self.build_remote_threat_contacts(),
                remote_blocked_sources=self.active_remote_ip_blocks(),
            )

    def _register_forensics(self, results: list[DecisionRecord]) -> None:
        for record in results:
            if record.decision == "accepted" and record.service_mode == "normal":
                continue
            if record.packet_id is None or record.source is None:
                continue
            case = ForensicCase(
                case_id=f"case-{len(self.forensic_cases) + 1:04d}",
                created_at=utc_now(),
                packet_id=record.packet_id,
                source=record.source,
                classification=record.classification,
                failed_layer=record.failed_layer,
                defense_mechanism=record.defense_mechanism,
                service_mode=record.service_mode,
                mission_breach=record.mission_breach,
                trust_bulletin_id=record.trust_bulletin_id,
                quorum_result=record.quorum_result,
                evidence_vector=list(record.evidence_vector),
                attacker_profile=dict(record.attacker_profile),
                summary=self._build_case_summary(record),
            )
            record.forensic_case_id = case.case_id
            self.forensic_cases.append(case)
        self.forensic_cases = self.forensic_cases[-120:]

    def _route_shadow_twin(self, results: list[DecisionRecord]) -> None:
        for record in results:
            twin_session, intel_event = self.digital_twin_router.route_record(record)
            if twin_session is None or intel_event is None:
                continue
            self.shadow_twin_sessions.append(twin_session)
            self.threat_intel_events.append(intel_event)
        self.shadow_twin_sessions = self.shadow_twin_sessions[-120:]
        self.threat_intel_events = self.threat_intel_events[-120:]

    def _relay_results(self, results: list[DecisionRecord]) -> None:
        for record in results:
            source = record.source or "-"
            trusted_payload = self.last_clean_payload_by_source.get(source)
            relay_events = self.split_plane_relay.route_record(record, trusted_payload=trusted_payload)
            for event in relay_events:
                if event.plane == "real":
                    self.real_plane_events.append(event)
                else:
                    self.shadow_plane_events.append(event)
            if record.decision == "accepted" and record.payload_view and record.source:
                self.last_clean_payload_by_source[record.source] = record.payload_view
        self.real_plane_events = self.real_plane_events[-160:]
        self.shadow_plane_events = self.shadow_plane_events[-160:]

    def _build_case_summary(self, record: DecisionRecord) -> str:
        parts = [
            f"Durum {record.classification}",
            f"Savunma {record.defense_mechanism}",
            f"Mod {record.service_mode}",
        ]
        if record.credential_leak_suspect:
            parts.append("credential-valid breach")
        if record.mission_breach:
            parts.append("mission breach")
        if record.trust_bulletin_id:
            parts.append(f"bulletin {record.trust_bulletin_id}")
        return " | ".join(parts)

    def _publish_decisions(self, results: list[DecisionRecord]) -> None:
        for record in results:
            event = self.decision_feed.publish_record(record)
            self.decision_feed_events.append(event)
        self.decision_feed_events = self.decision_feed_events[-160:]

    def _register_remote_contact(self, remote_meta: dict[str, Any] | None, results: list[DecisionRecord]) -> None:
        if not remote_meta or not results:
            return
        remote_ip = str(remote_meta.get("remote_ip", "")).strip()
        protocol = str(remote_meta.get("protocol", "udp")).lower()
        if not remote_ip:
            return

        key = f"{protocol}:{remote_ip}"
        now = utc_now()
        with self._lock:
            contact = self.remote_threat_contacts.get(key)
            if contact is None:
                contact = RemoteThreatContact(
                    remote_ip=remote_ip,
                    protocol=protocol,
                    first_seen=now,
                    last_seen=now,
                )
                self.remote_threat_contacts[key] = contact
            contact.last_seen = now

            remote_port = remote_meta.get("remote_port")
            if isinstance(remote_port, int):
                contact.last_remote_port = remote_port
                if remote_port not in contact.recent_ports:
                    contact.recent_ports.append(remote_port)
                    contact.recent_ports = contact.recent_ports[-8:]

            severe_hit = False
            for record in results:
                contact.packets_seen += 1
                if record.decision == "accepted":
                    contact.accepted_count += 1
                    self.remote_ip_strikes[remote_ip] = max(0, int(self.remote_ip_strikes.get(remote_ip, 0)) - 1)
                else:
                    contact.blocked_count += 1
                    strike_weight = 1
                    if record.twin_engaged or record.deception_triggered or record.credential_leak_suspect or record.mission_breach:
                        strike_weight = 3
                        severe_hit = True
                    elif record.classification in {
                        "spoof_suspect",
                        "mesh_divergence_suspect",
                        "credential_compromise_suspect",
                        "leak_trap_triggered",
                    }:
                        strike_weight = 2
                    self.remote_ip_strikes[remote_ip] = int(self.remote_ip_strikes.get(remote_ip, 0)) + strike_weight
                if record.twin_engaged:
                    contact.twin_count += 1
                if record.credential_leak_suspect:
                    contact.credential_leak_count += 1
                if record.mission_breach:
                    contact.mission_breach_count += 1
                if record.service_mode == "holdover":
                    contact.holdover_count += 1
                contact.last_source = record.source or contact.last_source
                contact.last_packet_id = record.packet_id or contact.last_packet_id
                contact.last_classification = record.classification or contact.last_classification
                contact.last_failed_layer = record.failed_layer
                contact.last_service_mode = record.service_mode or contact.last_service_mode
                contact.last_threat_family = str(record.attacker_profile.get("attack_family") or record.classification)
                contact.last_anomaly_signature = record.anomaly_signature or contact.last_anomaly_signature
                contact.last_forensic_case_id = record.forensic_case_id
                contact.last_evidence = list(record.evidence_vector[:5])

            current_strikes = int(self.remote_ip_strikes.get(remote_ip, 0))
            if severe_hit or current_strikes >= 3:
                blocked_until = now + timedelta(seconds=180)
                self.blocked_remote_ips_until[remote_ip] = blocked_until
                contact.blocked_until = blocked_until
            else:
                contact.blocked_until = self.blocked_remote_ips_until.get(remote_ip)

    def _register_remote_drop(self, remote_meta: dict[str, Any] | None) -> None:
        if not remote_meta:
            return
        remote_ip = str(remote_meta.get("remote_ip", "")).strip()
        protocol = str(remote_meta.get("protocol", "udp")).lower()
        if not remote_ip:
            return
        key = f"{protocol}:{remote_ip}"
        now = utc_now()
        with self._lock:
            contact = self.remote_threat_contacts.get(key)
            if contact is None:
                contact = RemoteThreatContact(
                    remote_ip=remote_ip,
                    protocol=protocol,
                    first_seen=now,
                    last_seen=now,
                )
                self.remote_threat_contacts[key] = contact
            contact.last_seen = now
            contact.network_drop_count += 1
            remote_port = remote_meta.get("remote_port")
            if isinstance(remote_port, int):
                contact.last_remote_port = remote_port
                if remote_port not in contact.recent_ports:
                    contact.recent_ports.append(remote_port)
                    contact.recent_ports = contact.recent_ports[-8:]
            contact.blocked_until = self.blocked_remote_ips_until.get(remote_ip)

    def _is_remote_ip_blocked(self, remote_meta: dict[str, Any] | None) -> bool:
        if not remote_meta:
            return False
        remote_ip = str(remote_meta.get("remote_ip", "")).strip()
        if not remote_ip:
            return False
        now = utc_now()
        with self._lock:
            blocked_until = self.blocked_remote_ips_until.get(remote_ip)
            if blocked_until is not None and blocked_until <= now:
                self.blocked_remote_ips_until.pop(remote_ip, None)
                blocked_until = None
                for contact in self.remote_threat_contacts.values():
                    if contact.remote_ip == remote_ip:
                        contact.blocked_until = None
            return blocked_until is not None

    def active_remote_ip_blocks(self) -> dict[str, float]:
        now = utc_now()
        active: dict[str, float] = {}
        with self._lock:
            for remote_ip in list(self.blocked_remote_ips_until):
                blocked_until = self.blocked_remote_ips_until.get(remote_ip)
                if blocked_until is None:
                    continue
                if blocked_until <= now:
                    self.blocked_remote_ips_until.pop(remote_ip, None)
                    continue
                active[remote_ip] = round((blocked_until - now).total_seconds(), 1)
        return active

    def _network_listener_worker(
        self,
        protocol: str,
        host: str,
        port: int,
        poll_timeout_seconds: float,
        stop_event: threading.Event,
    ) -> None:
        adapter = UdpTcpAdapter(
            protocol=protocol,
            host=host,
            port=port,
            timeout_seconds=poll_timeout_seconds,
        )
        try:
            adapter.connect()
            while not stop_event.is_set():
                try:
                    packet, remote_meta = adapter.read_packet_with_meta()
                except OSError as exc:
                    with self._lock:
                        self._listener_status.last_error = str(exc)
                    break
                if packet is None or remote_meta is None:
                    continue
                packet, remote_meta = resolve_lab_transport(
                    packet,
                    remote_meta,
                    lab_transport_enabled=self.config.lab.transport_simulation_enabled,
                )
                batch: list[tuple[str, dict[str, Any] | None]] = [(packet, remote_meta)]
                try:
                    drained = adapter.drain_ready_packets_with_meta(max_packets=63)
                except OSError as exc:
                    drained = []
                    with self._lock:
                        self._listener_status.last_error = str(exc)
                for drained_packet, drained_meta in drained:
                    if drained_packet is None or drained_meta is None:
                        continue
                    normalized_packet, normalized_meta = resolve_lab_transport(
                        drained_packet,
                        drained_meta,
                        lab_transport_enabled=self.config.lab.transport_simulation_enabled,
                    )
                    batch.append((normalized_packet, normalized_meta))

                allowed_packets: list[str] = []
                allowed_meta: list[dict[str, Any] | None] = []
                for raw_packet, meta in batch:
                    if self._is_remote_ip_blocked(meta):
                        self._register_remote_drop(meta)
                        continue
                    allowed_packets.append(raw_packet)
                    allowed_meta.append(meta)

                results: list[DecisionRecord] = []
                if allowed_packets:
                    results = self.ingest_packets(allowed_packets)
                    for meta, record in zip(allowed_meta, results):
                        self._register_remote_contact(meta, [record])
                with self._lock:
                    self._listener_status.received_packets += len(batch)
                    self._listener_status.last_packet_at = utc_now()
        except OSError as exc:
            with self._lock:
                self._listener_status.last_error = str(exc)
        finally:
            adapter.close()
            with self._lock:
                self._listener_status.active = False

    @staticmethod
    def build_source_passports(records: list[DecisionRecord]) -> list[dict[str, Any]]:
        buckets: dict[str, list[DecisionRecord]] = {}
        for record in records:
            if not record.source:
                continue
            buckets.setdefault(record.source, []).append(record)

        rows: list[dict[str, Any]] = []
        for source, items in buckets.items():
            trust = round(mean(item.trust_score for item in items))
            latest = items[-1]
            rows.append(
                {
                    "source": source,
                    "trust": trust,
                    "accepted": sum(1 for item in items if item.decision == "accepted"),
                    "rejected": sum(1 for item in items if item.decision == "blocked"),
                    "signature": latest.anomaly_signature,
                    "latency_ms": round(mean(item.latency_ms for item in items), 2),
                }
            )
        rows.sort(key=lambda item: (-int(item["trust"]), str(item["source"])))
        return rows

    def build_remote_threat_contacts(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for contact in self.remote_threat_contacts.values():
            rows.append(
                {
                    "ip": contact.remote_ip,
                    "protocol": contact.protocol.upper(),
                    "last_port": contact.last_remote_port or "-",
                    "ports_seen": ", ".join(str(port) for port in contact.recent_ports) or "-",
                    "first_seen": contact.first_seen,
                    "last_seen": contact.last_seen,
                    "packets": contact.packets_seen,
                    "accepted": contact.accepted_count,
                    "blocked": contact.blocked_count,
                    "twin": contact.twin_count,
                    "credential_leak": contact.credential_leak_count,
                    "mission_breach": contact.mission_breach_count,
                    "holdover": contact.holdover_count,
                    "network_drop": contact.network_drop_count,
                    "blocked_until": contact.blocked_until,
                    "packet_source": contact.last_source,
                    "packet_id": contact.last_packet_id,
                    "classification": contact.last_classification,
                    "failed_layer": contact.last_failed_layer or "-",
                    "service_mode": contact.last_service_mode,
                    "threat_family": contact.last_threat_family,
                    "signature": contact.last_anomaly_signature,
                    "forensic_case": contact.last_forensic_case_id or "-",
                    "evidence": " | ".join(contact.last_evidence) if contact.last_evidence else "-",
                }
            )
        rows.sort(
            key=lambda item: (
                -int(item["blocked"]),
                -int(item["packets"]),
                str(item["ip"]),
            )
        )
        return rows
