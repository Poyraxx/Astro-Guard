from __future__ import annotations

from datetime import UTC, datetime
import json

from bkzs_guard.config import AppConfig, load_app_config
from bkzs_guard.models import DecisionRecord
from bkzs_guard.policy import TrustBulletin
from bkzs_guard.pipeline.layers import (
    build_feature_snapshot,
    layer_adaptive_lockdown,
    layer_authorization_and_integrity,
    layer_clock_consistency,
    layer_consensus,
    layer_deception_lane,
    layer_freshness,
    layer_mission_envelope,
    layer_packet_syntax,
    layer_rf_health,
    layer_schema_gate,
    layer_signal_envelope,
    layer_source_identity,
    layer_spatial_consistency,
)
from bkzs_guard.pipeline.state import PipelineState


class MicroLayerEngine:
    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or load_app_config()
        self.state = PipelineState(
            max_history_packets=self.config.thresholds.max_history_packets,
            max_packet_id_cache=self.config.thresholds.max_packet_id_cache,
        )
        self.active_bulletin: TrustBulletin | None = None

    def set_trust_bulletin(self, bulletin: TrustBulletin | None) -> None:
        self.active_bulletin = bulletin

    def process_raw(self, raw_input: str | dict) -> DecisionRecord:
        snapshot = build_feature_snapshot(raw_input, self.config, self.state, bulletin=self.active_bulletin)
        trace = [layer_signal_envelope(snapshot)]
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_packet_syntax(snapshot))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_schema_gate(snapshot))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_source_identity(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_adaptive_lockdown(snapshot))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_deception_lane(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_authorization_and_integrity(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=False)

        trace.append(layer_freshness(snapshot))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=True)

        trace.append(layer_rf_health(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=True)

        trace.append(layer_spatial_consistency(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=True)

        trace.append(layer_clock_consistency(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=True)

        trace.append(layer_consensus(snapshot, self.config))
        if not trace[-1].passed:
            return self._finalize(snapshot, trace, observe=True)

        trace.append(layer_mission_envelope(snapshot, self.config))
        return self._finalize(snapshot, trace, observe=True)

    def process_batch(self, raw_packets: list[str | dict]) -> list[DecisionRecord]:
        return [self.process_raw(item) for item in raw_packets]

    def _observe_if_available(self, snapshot) -> None:
        if snapshot.packet is not None:
            self.state.observe(snapshot.packet)

    def _finalize(self, snapshot, trace, observe: bool) -> DecisionRecord:
        if observe:
            self._observe_if_available(snapshot)
        decision = self._build_decision(snapshot, trace)
        self.state.register_verdict(snapshot.packet, decision, self.config)
        return decision

    def _build_decision(self, snapshot, trace) -> DecisionRecord:
        failed = next((item for item in trace if not item.passed), None)
        classification = failed.classification if failed else "normal"
        credential_gate_passed = self._credential_gate_passed(trace)
        credential_leak_suspect = bool(
            failed is not None
            and failed.layer_id is not None
            and failed.layer_id > 7
            and credential_gate_passed
        )
        return DecisionRecord(
            decision="accepted" if failed is None else "blocked",
            failed_layer=None if failed is None else failed.layer_id,
            classification=classification,
            attack_stage=snapshot.attack_stage,
            quarantined=failed is not None,
            trace=trace,
            packet_id=snapshot.packet.packet_id if snapshot.packet else None,
            source=snapshot.packet.source if snapshot.packet else None,
            processed_at=datetime.now(UTC),
            payload_view=self._payload_view(snapshot),
            trust_score=self._trust_score(snapshot, failed),
            anomaly_signature="clean_flow" if failed is None else failed.reason_code,
            defense_mechanism=self._defense_mechanism(failed),
            deception_triggered=bool(snapshot.shadow_contact_detected or (failed and failed.classification == "leak_trap_triggered")),
            credential_gate_passed=credential_gate_passed,
            credential_leak_suspect=credential_leak_suspect,
            service_mode=self._service_mode(snapshot, failed),
            response_transition=self._response_transition(failed, snapshot),
            trust_bulletin_id=snapshot.trust_bulletin_id,
            quorum_result=snapshot.quorum_result,
            mission_breach=snapshot.mission_breach_detected,
            mission_phase=snapshot.mission_phase,
            evidence_vector=self._evidence_vector(snapshot, failed, credential_gate_passed, credential_leak_suspect),
            attacker_profile=self._attacker_profile(snapshot, failed, credential_gate_passed, credential_leak_suspect),
        )

    def _credential_gate_passed(self, trace) -> bool:
        auth_layer = next((item for item in trace if item.layer_id == 7), None)
        return auth_layer is not None and auth_layer.passed

    def _payload_view(self, snapshot) -> str:
        if snapshot.packet is not None:
            return json.dumps(snapshot.packet.raw, ensure_ascii=True)
        if snapshot.stripped_payload:
            return snapshot.stripped_payload
        if isinstance(snapshot.raw_input, str):
            return snapshot.raw_input
        return json.dumps(snapshot.raw_input, ensure_ascii=True)

    def _trust_score(self, snapshot, failed) -> int:
        if failed is not None:
            severity_penalties = {
                "unauthorized": 45,
                "malformed": 35,
                "replay_suspect": 42,
                "jam_suspect": 48,
                "signal_tamper": 52,
                "spoof_suspect": 58,
                "credential_compromise_suspect": 68,
                "leak_trap_triggered": 78,
                "shadow_contact_suspect": 70,
                "mesh_divergence_suspect": 62,
            }
            reason_penalty = {
                "source_quarantined": 22,
                "session_nonce_mismatch": 24,
                "flow_tag_invalid": 28,
                "shadow_lane_contact": 30,
                "epoch_chain_broken": 24,
                "mesh_time_divergence": 18,
                "mesh_baseline_divergence": 18,
            }
            base = 100 - (failed.layer_id * 5) - severity_penalties.get(failed.classification, 40)
            base -= reason_penalty.get(failed.reason_code, 0)
            return max(0, min(100, base))

        score = 100
        thresholds = self.config.thresholds
        if snapshot.cn0_delta is not None:
            score -= min(8, int(abs(snapshot.cn0_delta) / max(thresholds.max_cn0_delta, 1) * 8))
        if snapshot.power_delta is not None:
            score -= min(7, int(abs(snapshot.power_delta) / max(thresholds.max_power_delta, 1) * 7))
        if snapshot.doppler_delta is not None:
            score -= min(6, int(abs(snapshot.doppler_delta) / max(thresholds.max_doppler_delta, 1) * 6))
        if snapshot.peer_position_delta_m is not None:
            score -= min(8, int(snapshot.peer_position_delta_m / max(thresholds.max_peer_position_delta_m, 1) * 8))
        if snapshot.peer_clock_bias_delta is not None:
            score -= min(6, int(snapshot.peer_clock_bias_delta / max(thresholds.max_peer_clock_bias_delta, 1) * 6))
        if snapshot.source_strike_count:
            score -= min(8, snapshot.source_strike_count * 2)
        if snapshot.source_risk_level:
            score -= min(8, snapshot.source_risk_level * 3)
        if snapshot.mission_breach_detected:
            score -= 10
        if snapshot.holdover_alignment_valid:
            score += 2
        return max(52, min(99, score))

    def _defense_mechanism(self, failed) -> str:
        if failed is None:
            return "Primary Lane"
        if failed.layer_id == 5:
            return "Adaptive Lockdown"
        if failed.layer_id == 6:
            return "Shadow Lane + Epoch Bait Chain"
        if failed.layer_id == 8:
            return "Replay Gate"
        if failed.layer_id == 9:
            return "RF Shield"
        if failed.layer_id == 12:
            return "Trust Mesh"
        if failed.layer_id == 13:
            return "Mission Envelope"
        if failed.layer_id in {10, 11}:
            return "Spoof Consistency Guard"
        return "Signal Firewall"

    def _service_mode(self, snapshot, failed) -> str:
        if failed is None:
            return "normal"
        if failed.classification in {"leak_trap_triggered", "shadow_contact_suspect", "mesh_divergence_suspect"}:
            return "holdover" if snapshot.holdover_alignment_valid or snapshot.peer_reference_count > 0 else "guarded"
        if failed.classification in {"spoof_suspect", "credential_compromise_suspect"}:
            return "holdover" if snapshot.holdover_alignment_valid else "guarded"
        if failed.classification in {"jam_suspect", "signal_tamper"}:
            return "guarded"
        return "quarantine"

    def _response_transition(self, failed, snapshot) -> str:
        if failed is None:
            return "stable"
        if snapshot.mission_breach_detected:
            return f"normal->{self._service_mode(snapshot, failed)}"
        if failed.classification in {"spoof_suspect", "credential_compromise_suspect", "mesh_divergence_suspect"}:
            return f"normal->{self._service_mode(snapshot, failed)}"
        return "normal->quarantine"

    def _evidence_vector(self, snapshot, failed, credential_gate_passed: bool, credential_leak_suspect: bool) -> list[str]:
        evidence = list(snapshot.evidence_vector)
        if failed is not None and failed.reason_code not in evidence:
            evidence.append(failed.reason_code)
        if credential_gate_passed and "credential_gate_passed" not in evidence:
            evidence.append("credential_gate_passed")
        if credential_leak_suspect and "credential_leak_suspect" not in evidence:
            evidence.append("credential_leak_suspect")
        if snapshot.bulletin_policy_applied and snapshot.trust_bulletin_id:
            evidence.append(f"bulletin:{snapshot.trust_bulletin_id}")
        if snapshot.holdover_alignment_valid and "holdover_ready" not in evidence:
            evidence.append("holdover_ready")
        return evidence[:8]

    def _attacker_profile(self, snapshot, failed, credential_gate_passed: bool, credential_leak_suspect: bool) -> dict:
        packet = snapshot.packet
        if packet is None:
            return {}
        profile = {
            "claimed_source": packet.source,
            "epoch_id": packet.epoch_id,
            "lane_seen": packet.trust_lane,
            "reveal_score": snapshot.attacker_reveal_score,
            "credential_gate_passed": credential_gate_passed,
            "quorum_result": snapshot.quorum_result,
        }
        if credential_leak_suspect:
            profile["credential_leak_suspect"] = True
        if snapshot.trust_bulletin_id:
            profile["trust_bulletin_id"] = snapshot.trust_bulletin_id
        if snapshot.source_risk_level:
            profile["source_risk_level"] = snapshot.source_risk_level
        if snapshot.active_risk_zone:
            profile["active_risk_zone"] = snapshot.active_risk_zone
        if snapshot.mission_breach_detected:
            profile["mission_breach_reason"] = snapshot.mission_breach_reason
        if snapshot.shadow_contact_detected:
            profile["trap_contact"] = "shadow_lane"
        if snapshot.peer_position_delta_m is not None:
            profile["mesh_position_delta_m"] = round(snapshot.peer_position_delta_m, 2)
        if snapshot.peer_clock_bias_delta is not None:
            profile["mesh_clock_bias_delta"] = round(snapshot.peer_clock_bias_delta, 2)
        if snapshot.receiver_baseline_delta_m is not None:
            profile["receiver_baseline_delta_m"] = round(snapshot.receiver_baseline_delta_m, 2)
        if snapshot.holdover_alignment_valid:
            profile["holdover_ready"] = True
        if failed is not None:
            profile["decision_reason"] = failed.reason_code
        return profile
