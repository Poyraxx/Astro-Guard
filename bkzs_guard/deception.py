from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bkzs_guard.models import DecisionRecord
from bkzs_guard.utils import stable_digest, utc_now


@dataclass(slots=True)
class ShadowTwinSession:
    session_id: str
    created_at: datetime
    source: str
    packet_id: str
    classification: str
    attack_family: str
    attack_vector: str
    primary_indicator: str
    trigger_label: str
    synthetic_status: str
    summary: str
    threat_intel_score: int
    operator_recommendation: str
    forensic_case_id: str | None = None
    evidence_vector: list[str] = field(default_factory=list)
    attacker_profile: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ThreatIntelEvent:
    event_id: str
    created_at: datetime
    source: str
    packet_id: str
    classification: str
    attack_family: str
    attack_vector: str
    primary_indicator: str
    failed_layer: int | None
    confidence: str
    intel_summary: str
    threat_intel_score: int
    operator_recommendation: str
    twin_session_id: str | None = None
    evidence_vector: list[str] = field(default_factory=list)
    attacker_profile: dict[str, Any] = field(default_factory=dict)


class DigitalTwinRouter:
    def __init__(self) -> None:
        self._sequence = 0

    def route_record(self, record: DecisionRecord) -> tuple[ShadowTwinSession | None, ThreatIntelEvent | None]:
        if not self.should_route(record):
            return None, None

        self._sequence += 1
        created_at = record.processed_at or utc_now()
        source = record.source or "unknown-source"
        packet_id = record.packet_id or f"shadow-packet-{self._sequence:04d}"
        trigger_label = self._trigger_label(record)
        threat_intel_score = self._score_record(record)
        confidence = self._confidence(threat_intel_score)
        analysis = self._analyze_record(record, trigger_label, confidence)
        session_id = f"shadow-{stable_digest({'seq': self._sequence, 'source': source, 'packet_id': packet_id}, length=10)}"
        synthetic_response = (
            f"BKZS Shadow Twin ACK | session={session_id} | source={source} | status=mirrored_accept"
        )

        attacker_profile = dict(record.attacker_profile)
        attacker_profile.update(
            {
                "trigger_label": trigger_label,
                "shadow_session_id": session_id,
                "confidence": confidence,
                "attack_family": analysis["attack_family"],
                "attack_vector": analysis["attack_vector"],
                "primary_indicator": analysis["primary_indicator"],
                "operator_recommendation": analysis["operator_recommendation"],
                "analysis_summary": analysis["analysis_summary"],
            }
        )

        twin_session = ShadowTwinSession(
            session_id=session_id,
            created_at=created_at,
            source=source,
            packet_id=packet_id,
            classification=record.classification,
            attack_family=analysis["attack_family"],
            attack_vector=analysis["attack_vector"],
            primary_indicator=analysis["primary_indicator"],
            trigger_label=trigger_label,
            synthetic_status="mirrored_accept",
            summary=self._session_summary(record, analysis),
            threat_intel_score=threat_intel_score,
            operator_recommendation=analysis["operator_recommendation"],
            forensic_case_id=record.forensic_case_id,
            evidence_vector=list(record.evidence_vector),
            attacker_profile=attacker_profile,
        )
        intel_event = ThreatIntelEvent(
            event_id=f"intel-{stable_digest({'session_id': session_id, 'layer': record.failed_layer}, length=10)}",
            created_at=created_at,
            source=source,
            packet_id=packet_id,
            classification=record.classification,
            attack_family=analysis["attack_family"],
            attack_vector=analysis["attack_vector"],
            primary_indicator=analysis["primary_indicator"],
            failed_layer=record.failed_layer,
            confidence=confidence,
            intel_summary=self._intel_summary(record, analysis, threat_intel_score),
            threat_intel_score=threat_intel_score,
            operator_recommendation=analysis["operator_recommendation"],
            twin_session_id=session_id,
            evidence_vector=list(record.evidence_vector),
            attacker_profile=attacker_profile,
        )

        record.twin_engaged = True
        record.shadow_session_id = session_id
        record.synthetic_response = synthetic_response
        record.threat_intel_score = threat_intel_score
        record.attacker_profile = attacker_profile
        return twin_session, intel_event

    @staticmethod
    def should_route(record: DecisionRecord) -> bool:
        if record.decision != "blocked":
            return False
        if record.twin_engaged:
            return False
        deep_layer = (record.failed_layer or 0) >= 8
        twin_classifications = {
            "credential_compromise_suspect",
            "credential_leak_suspect",
            "leak_trap_triggered",
            "shadow_contact_suspect",
            "mesh_divergence_suspect",
            "spoof_suspect",
        }
        return bool(
            record.deception_triggered
            or record.credential_leak_suspect
            or record.mission_breach
            or record.quorum_result == "disagreement"
            or (deep_layer and record.classification in twin_classifications)
        )

    @staticmethod
    def _trigger_label(record: DecisionRecord) -> str:
        if record.deception_triggered:
            return "shadow_lane_touch"
        if record.credential_leak_suspect:
            return "credential_valid_breach"
        if record.mission_breach:
            return "mission_envelope_breach"
        if record.quorum_result == "disagreement":
            return "mesh_divergence"
        return "deep_spoof_contact"

    @staticmethod
    def _score_record(record: DecisionRecord) -> int:
        score = 55
        if record.credential_leak_suspect:
            score += 18
        if record.deception_triggered:
            score += 22
        if record.mission_breach:
            score += 12
        if record.quorum_result == "disagreement":
            score += 10
        if (record.failed_layer or 0) >= 12:
            score += 6
        score += min(len(record.evidence_vector) * 2, 10)
        return min(score, 99)

    @staticmethod
    def _confidence(score: int) -> str:
        if score >= 85:
            return "high"
        if score >= 70:
            return "elevated"
        return "medium"

    @staticmethod
    def _session_summary(record: DecisionRecord, analysis: dict[str, str]) -> str:
        layer_text = f"layer {record.failed_layer}" if record.failed_layer else "accepted-route"
        return (
            f"Tur {analysis['attack_family']} | Vektor {analysis['attack_vector']} | "
            f"Gosterge {analysis['primary_indicator']} | Ayrim {layer_text}."
        )

    @staticmethod
    def _intel_summary(record: DecisionRecord, analysis: dict[str, str], threat_intel_score: int) -> str:
        source = record.source or "-"
        layer_text = f"katman {record.failed_layer}" if record.failed_layer else "kabul sonrasi"
        return (
            f"{source} kaynagi icin {analysis['attack_family']} saldiri izi cikti. "
            f"Vektor {analysis['attack_vector']} | Kanit {analysis['primary_indicator']} | "
            f"Ayrim {layer_text} | Intel skor {threat_intel_score}."
        )

    @staticmethod
    def _analyze_record(record: DecisionRecord, trigger_label: str, confidence: str) -> dict[str, str]:
        family = "deep_anomaly_probe"
        vector = "layered_consistency_probe"
        indicator = record.anomaly_signature or record.classification
        recommendation = "Kaynak izole kalsin, yeni telemetry ayni profil ile gelirse kilit suresini uzat."

        replay_indicators = {"duplicate_packet_id", "sequence_regression", "non_monotonic_timestamp"}
        rf_indicators = {"satellite_lock_loss", "cn0_floor_breach", "rf_power_jump", "cn0_jump", "doppler_jump"}
        mesh_indicators = {
            "mesh_time_divergence",
            "mesh_baseline_divergence",
            "peer_position_mismatch",
            "peer_clock_bias_mismatch",
            "peer_clock_drift_mismatch",
        }
        mission_indicators = {
            "mission_channel_mismatch",
            "mission_time_window_breach",
            "mission_speed_breach",
            "mission_zone_breach",
            "mission_route_drift",
            "forbidden_zone_breach",
        }
        spoof_indicators = {
            "position_jump",
            "impossible_speed",
            "cumulative_position_drift",
            "clock_bias_step",
            "clock_drift_step",
            "clock_bias_span",
        }

        reason = record.anomaly_signature
        evidence = set(record.evidence_vector)

        if record.deception_triggered or reason in {"shadow_lane_contact", "shadow_lane_packet_seen"}:
            family = "credentialed_shadow_probe"
            vector = "shadow_lane_mimicry"
            indicator = "shadow lane token temasi"
            recommendation = "Oturum muhru ve sinyal sifresi dondurulsun, ayni kaynagin onceki twin oturumlari birlestirilsin."
        elif record.mission_breach or reason in mission_indicators:
            family = "mission_envelope_evasion"
            vector = "route-speed-phase drift"
            indicator = humanize_reason(reason, fallback="mission envelope disi davranis")
            recommendation = "Mission policy sIkilastir, ilgili source icin guarded modda kal ve rota/faz uyumunu izle."
        elif record.credential_leak_suspect:
            family = "credential_reuse_spoof"
            vector = "post-auth deep spoof"
            indicator = humanize_reason(reason, fallback="credential gate gecti ama derin savunma bozgunu")
            recommendation = "Credential rotasyonu yap, ayni source icin challenge proof zincirini yeniden baslat."
        elif record.quorum_result == "disagreement" or reason in mesh_indicators:
            family = "mesh_split_spoof"
            vector = "peer desync"
            indicator = humanize_reason(reason, fallback="peer ve primary uyusmazligi")
            recommendation = "Peer quorum zorunlu kalsin, tek receiver kararlarini kabul etme."
        elif record.classification == "replay_suspect" or reason in replay_indicators:
            family = "replay_injection"
            vector = "freshness abuse"
            indicator = humanize_reason(reason, fallback="timestamp ve sequence bozgunu")
            recommendation = "Replay penceresini koru, ayni packet_id ve epoch izini kara listeye al."
        elif record.classification == "jam_suspect" or reason in rf_indicators:
            family = "rf_disruption"
            vector = "power-cn0 doppler anomaly"
            indicator = humanize_reason(reason, fallback="rf health bozulmasi")
            recommendation = "Holdover veya alternatif referansla gorevi surdur, RF kaynagini saha tarafinda incele."
        elif record.classification in {"spoof_suspect", "credential_compromise_suspect"} or reason in spoof_indicators:
            family = "navigation_spoof"
            vector = "position-clock manipulation"
            indicator = humanize_reason(reason, fallback="konum veya saat manipulasyonu")
            recommendation = "Konum ve saat kararini holdover/peer ile cift dogrula, kaynak karantinada kalsin."
        elif "credential_leak_suspect" in evidence:
            family = "credential_reuse_spoof"
            vector = "credential-valid anomaly"
            indicator = "credential gate passed"
            recommendation = "Oturum ve proof zinciri yenilensin."

        analysis_summary = (
            f"Tur {family} | Vektor {vector} | Ana kanit {indicator} | Guven {confidence}"
        )
        return {
            "attack_family": family,
            "attack_vector": vector,
            "primary_indicator": indicator,
            "operator_recommendation": recommendation,
            "analysis_summary": analysis_summary,
            "trigger_label": trigger_label,
        }


def humanize_reason(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    return value.replace("_", " ")
