from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class SignalMetrics:
    cn0: float
    power: float
    doppler: float
    sat_count: int
    clock_bias: float
    clock_drift: float
    latitude: float | None = None
    longitude: float | None = None
    altitude: float | None = None
    speed: float | None = None


@dataclass(slots=True)
class SignalPacket:
    packet_id: str
    source: str
    ts: datetime
    seq: int
    epoch_id: str
    challenge_proof: str
    session_nonce: str
    flow_tag: str
    trust_lane: str
    peer_observations: dict[str, Any]
    holdover_state: dict[str, Any]
    op_code: str
    checksum: str
    payload: dict[str, Any]
    metrics: SignalMetrics
    raw: dict[str, Any]


@dataclass(slots=True)
class FeatureSnapshot:
    raw_input: str | dict[str, Any]
    packet_size_bytes: int
    signal_envelope_valid: bool = False
    signal_envelope_error: str | None = None
    stripped_payload: str | None = None
    parsed_ok: bool = False
    schema_valid: bool = False
    required_fields_present: bool = False
    packet: SignalPacket | None = None
    validation_errors: list[str] = field(default_factory=list)
    source_trusted: bool = False
    source_locked: bool = False
    source_strike_count: int = 0
    lock_remaining_seconds: float | None = None
    session_nonce_valid: bool = False
    flow_tag_valid: bool = False
    checksum_valid: bool = False
    attack_stage: int | None = None
    secret_compromised: bool = False
    duplicate_packet_id: bool = False
    duplicate_sequence: bool = False
    stale_timestamp: bool = False
    future_timestamp: bool = False
    ts_age_seconds: float | None = None
    seq_delta: int | None = None
    ts_delta_seconds: float | None = None
    cn0_delta: float | None = None
    power_delta: float | None = None
    doppler_delta: float | None = None
    clock_bias_delta: float | None = None
    clock_drift_delta: float | None = None
    position_jump_m: float | None = None
    derived_speed_mps: float | None = None
    cumulative_position_drift_m: float | None = None
    cumulative_clock_bias_span: float | None = None
    peer_reference_count: int = 0
    peer_position_delta_m: float | None = None
    peer_clock_bias_delta: float | None = None
    peer_clock_drift_delta: float | None = None
    history_count: int = 0
    expected_primary_proof: str | None = None
    expected_shadow_proof: str | None = None
    expected_genesis_proof: str | None = None
    epoch_chain_valid: bool = False
    genesis_proof_valid: bool = False
    epoch_resync_candidate: bool = False
    shadow_contact_detected: bool = False
    mesh_consensus_valid: bool = True
    holdover_alignment_valid: bool = False
    attacker_reveal_score: int = 0
    trust_lane_seen: str = "primary"
    peer_time_delta_seconds: float | None = None
    receiver_baseline_delta_m: float | None = None
    holdover_position_delta_m: float | None = None
    holdover_clock_bias_delta: float | None = None
    mission_envelope_valid: bool = True
    mission_breach_detected: bool = False
    mission_breach_reason: str | None = None
    mission_phase: str | None = None
    trust_bulletin_id: str | None = None
    bulletin_policy_applied: bool = False
    source_risk_level: int = 0
    threshold_overrides: dict[str, float] = field(default_factory=dict)
    active_risk_zone: str | None = None
    primary_vote_valid: bool = True
    peer_vote_valid: bool | None = None
    holdover_vote_valid: bool | None = None
    quorum_votes: dict[str, bool] = field(default_factory=dict)
    quorum_result: str = "not_evaluated"
    evidence_vector: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LayerDecision:
    layer_id: int
    passed: bool
    reason_code: str
    latency_ms: float
    classification: str
    details: str = ""


@dataclass(slots=True)
class DecisionRecord:
    decision: str
    failed_layer: int | None
    classification: str
    attack_stage: int | None
    quarantined: bool
    trace: list[LayerDecision]
    packet_id: str | None = None
    source: str | None = None
    processed_at: datetime | None = None
    payload_view: str | None = None
    trust_score: int = 0
    anomaly_signature: str = ""
    defense_mechanism: str = ""
    deception_triggered: bool = False
    credential_gate_passed: bool = False
    credential_leak_suspect: bool = False
    service_mode: str = "normal"
    response_transition: str = "stable"
    trust_bulletin_id: str | None = None
    forensic_case_id: str | None = None
    twin_engaged: bool = False
    shadow_session_id: str | None = None
    synthetic_response: str | None = None
    threat_intel_score: int = 0
    quorum_result: str = "not_evaluated"
    mission_breach: bool = False
    mission_phase: str | None = None
    evidence_vector: list[str] = field(default_factory=list)
    attacker_profile: dict[str, Any] = field(default_factory=dict)

    @property
    def latency_ms(self) -> float:
        return round(sum(item.latency_ms for item in self.trace), 3)


@dataclass(slots=True)
class AttackScenario:
    stage: int
    profile: str
    packet_rate: float
    spoof_ratio: float
    secret_compromised: bool
    replay_ratio: float
    deception_ratio: float = 0.0
    mesh_desync_ratio: float = 0.0
    holdover_pressure: float = 0.0
    mission_breach_ratio: float = 0.0
    bulletin_conflict_ratio: float = 0.0
