from __future__ import annotations

import json
from statistics import median
from time import perf_counter
from typing import Any, Callable

from bkzs_guard.config import AppConfig
from bkzs_guard.policy import TrustBulletin
from bkzs_guard.models import FeatureSnapshot, LayerDecision, SignalMetrics, SignalPacket
from bkzs_guard.pipeline.state import PipelineState
from bkzs_guard.satellites import SatelliteProfile, get_satellite_profile
from bkzs_guard.utils import (
    build_challenge_proof,
    build_flow_tag,
    epoch_id_from_timestamp,
    haversine_meters,
    initial_clean_hash,
    packet_checksum_view,
    packet_flow_tag_view,
    parse_timestamp,
    stable_checksum,
    unwrap_signal_payload,
    utc_now,
)


REQUIRED_ROOT_FIELDS = (
    "packet_id",
    "source",
    "ts",
    "seq",
    "epoch_id",
    "challenge_proof",
    "session_nonce",
    "flow_tag",
    "trust_lane",
    "peer_observations",
    "op_code",
    "checksum",
    "payload",
    "metrics",
)
REQUIRED_METRIC_FIELDS = ("cn0", "power", "doppler", "sat_count", "clock_bias", "clock_drift")


def build_feature_snapshot(
    raw_input: str | dict[str, Any],
    config: AppConfig,
    state: PipelineState,
    bulletin: TrustBulletin | None = None,
) -> FeatureSnapshot:
    if isinstance(raw_input, str):
        packet_size = len(raw_input.encode("utf-8"))
    else:
        packet_size = len(json.dumps(raw_input, default=str).encode("utf-8"))

    snapshot = FeatureSnapshot(raw_input=raw_input, packet_size_bytes=packet_size)
    thresholds = config.thresholds

    if packet_size > thresholds.max_packet_size_bytes:
        snapshot.validation_errors.append("packet_too_large")
        return snapshot

    raw_payload: str | dict[str, Any]
    if isinstance(raw_input, str):
        stripped_payload, envelope_error = unwrap_signal_payload(raw_input, config.security.signal_secret)
        if envelope_error:
            snapshot.signal_envelope_error = envelope_error
            snapshot.validation_errors.append(envelope_error)
            return snapshot
        snapshot.signal_envelope_valid = True
        snapshot.stripped_payload = stripped_payload
        raw_payload = stripped_payload
    else:
        snapshot.signal_envelope_valid = True
        raw_payload = dict(raw_input)

    try:
        raw_packet = json.loads(raw_payload) if isinstance(raw_payload, str) else dict(raw_payload)
    except (TypeError, json.JSONDecodeError):
        snapshot.validation_errors.append("json_parse_failed")
        return snapshot

    snapshot.parsed_ok = True
    missing_fields = [field for field in REQUIRED_ROOT_FIELDS if field not in raw_packet]
    if missing_fields:
        snapshot.validation_errors.append(f"missing_fields:{','.join(missing_fields)}")
        return snapshot
    snapshot.required_fields_present = True

    metrics_raw = raw_packet.get("metrics", {})
    if not isinstance(metrics_raw, dict):
        snapshot.validation_errors.append("metrics_not_object")
        return snapshot

    missing_metric_fields = [field for field in REQUIRED_METRIC_FIELDS if field not in metrics_raw]
    if missing_metric_fields:
        snapshot.validation_errors.append(f"missing_metrics:{','.join(missing_metric_fields)}")
        return snapshot

    try:
        metrics = SignalMetrics(
            cn0=float(metrics_raw["cn0"]),
            power=float(metrics_raw["power"]),
            doppler=float(metrics_raw["doppler"]),
            sat_count=int(metrics_raw["sat_count"]),
            clock_bias=float(metrics_raw["clock_bias"]),
            clock_drift=float(metrics_raw["clock_drift"]),
            latitude=_optional_float(metrics_raw.get("latitude")),
            longitude=_optional_float(metrics_raw.get("longitude")),
            altitude=_optional_float(metrics_raw.get("altitude")),
            speed=_optional_float(metrics_raw.get("speed")),
        )
        packet = SignalPacket(
            packet_id=str(raw_packet["packet_id"]),
            source=str(raw_packet["source"]),
            ts=parse_timestamp(str(raw_packet["ts"])),
            seq=int(raw_packet["seq"]),
            epoch_id=str(raw_packet["epoch_id"]),
            challenge_proof=str(raw_packet["challenge_proof"]),
            session_nonce=str(raw_packet["session_nonce"]),
            flow_tag=str(raw_packet["flow_tag"]),
            trust_lane=str(raw_packet["trust_lane"]),
            peer_observations=dict(raw_packet.get("peer_observations", {})),
            holdover_state=dict(raw_packet.get("holdover_state", {})),
            op_code=str(raw_packet["op_code"]),
            checksum=str(raw_packet["checksum"]),
            payload=dict(raw_packet.get("payload", {})),
            metrics=metrics,
            raw=raw_packet,
        )
    except (TypeError, ValueError, KeyError):
        snapshot.validation_errors.append("schema_type_error")
        return snapshot

    snapshot.schema_valid = True
    snapshot.packet = packet
    snapshot.trust_lane_seen = packet.trust_lane
    snapshot.mission_phase = str(packet.payload.get("mission_phase", config.mission.mission_phase))
    attack_meta = packet.payload.get("attack_meta", {}) if isinstance(packet.payload, dict) else {}
    if isinstance(attack_meta, dict):
        stage_hint = attack_meta.get("stage_hint")
        snapshot.attack_stage = int(stage_hint) if stage_hint is not None else None
        snapshot.secret_compromised = bool(attack_meta.get("secret_compromised", False))

    if bulletin is not None and bulletin.is_active(packet.ts):
        snapshot.trust_bulletin_id = bulletin.bulletin_id
        snapshot.bulletin_policy_applied = True
        snapshot.source_risk_level = int(bulletin.source_risk.get(packet.source, 0))
        snapshot.threshold_overrides = dict(bulletin.threshold_overrides)
        if _has_coordinates(packet.metrics):
            for risk_zone in bulletin.risk_zones:
                zone_distance = haversine_meters(
                    packet.metrics.latitude,
                    packet.metrics.longitude,
                    risk_zone.center_latitude,
                    risk_zone.center_longitude,
                )
                if zone_distance <= risk_zone.radius_m:
                    snapshot.active_risk_zone = risk_zone.name
                    break

    snapshot.session_nonce_valid = packet.session_nonce == config.security.session_nonce
    snapshot.source_trusted = packet.source in config.security.trusted_sources
    snapshot.checksum_valid = packet.checksum == stable_checksum(packet_checksum_view(packet.raw))
    snapshot.flow_tag_valid = packet.flow_tag == build_flow_tag(
        packet_flow_tag_view(packet.raw),
        config.security.signal_secret,
        packet.session_nonce,
    )
    snapshot.duplicate_packet_id = state.has_packet_id(packet.packet_id)

    locked, strike_count, remaining = state.get_source_status(packet.source)
    snapshot.source_locked = locked
    snapshot.source_strike_count = strike_count
    snapshot.lock_remaining_seconds = remaining

    previous_clean_hash = state.get_previous_clean_hash(packet.source, config)
    snapshot.expected_primary_proof = build_challenge_proof(
        config.security.signal_secret,
        config.security.session_nonce,
        config.security.shadow_lane_salt,
        packet.source,
        packet.epoch_id,
        previous_clean_hash,
        lane="primary",
    )
    snapshot.expected_shadow_proof = build_challenge_proof(
        config.security.signal_secret,
        config.security.session_nonce,
        config.security.shadow_lane_salt,
        packet.source,
        packet.epoch_id,
        previous_clean_hash,
        lane="shadow",
    )
    snapshot.expected_genesis_proof = build_challenge_proof(
        config.security.signal_secret,
        config.security.session_nonce,
        config.security.shadow_lane_salt,
        packet.source,
        packet.epoch_id,
        initial_clean_hash(packet.source, config.security.session_nonce),
        lane="primary",
    )
    accepted_proof = state.get_accepted_proof(packet.packet_id)
    snapshot.epoch_chain_valid = packet.challenge_proof == snapshot.expected_primary_proof or (
        snapshot.duplicate_packet_id and accepted_proof == packet.challenge_proof
    )
    snapshot.genesis_proof_valid = packet.challenge_proof == snapshot.expected_genesis_proof
    snapshot.shadow_contact_detected = packet.challenge_proof == snapshot.expected_shadow_proof or packet.trust_lane == "shadow"
    snapshot.epoch_resync_candidate = bool(
        snapshot.genesis_proof_valid
        and snapshot.source_trusted
        and snapshot.session_nonce_valid
        and snapshot.flow_tag_valid
        and packet.trust_lane == "primary"
        and not snapshot.source_locked
        and not snapshot.duplicate_packet_id
        and not snapshot.secret_compromised
        and state.get_epoch_chain_failures(packet.source) >= 1
    )

    now = utc_now()
    age_seconds = (now - packet.ts).total_seconds()
    snapshot.ts_age_seconds = age_seconds
    snapshot.stale_timestamp = age_seconds > thresholds.freshness_window_seconds
    snapshot.future_timestamp = age_seconds < -thresholds.max_future_skew_seconds

    history = state.get_history(packet.source)
    snapshot.history_count = len(history)
    if history:
        previous = history[-1]
        snapshot.seq_delta = packet.seq - previous.seq
        snapshot.duplicate_sequence = packet.seq <= previous.seq
        snapshot.ts_delta_seconds = (packet.ts - previous.ts).total_seconds()
        snapshot.cn0_delta = packet.metrics.cn0 - previous.metrics.cn0
        snapshot.power_delta = packet.metrics.power - previous.metrics.power
        snapshot.doppler_delta = packet.metrics.doppler - previous.metrics.doppler
        snapshot.clock_bias_delta = packet.metrics.clock_bias - previous.metrics.clock_bias
        snapshot.clock_drift_delta = packet.metrics.clock_drift - previous.metrics.clock_drift

        if _has_coordinates(packet.metrics) and _has_coordinates(previous.metrics):
            jump = haversine_meters(
                previous.metrics.latitude,
                previous.metrics.longitude,
                packet.metrics.latitude,
                packet.metrics.longitude,
            )
            snapshot.position_jump_m = jump
            if snapshot.ts_delta_seconds and snapshot.ts_delta_seconds > 0:
                snapshot.derived_speed_mps = jump / snapshot.ts_delta_seconds

        if len(history) >= 3 and _has_coordinates(packet.metrics):
            anchor = history[0]
            if _has_coordinates(anchor.metrics):
                snapshot.cumulative_position_drift_m = haversine_meters(
                    anchor.metrics.latitude,
                    anchor.metrics.longitude,
                    packet.metrics.latitude,
                    packet.metrics.longitude,
                )
            bias_values = [sample.metrics.clock_bias for sample in history] + [packet.metrics.clock_bias]
            snapshot.cumulative_clock_bias_span = max(bias_values) - min(bias_values)

    _populate_explicit_peer_observations(snapshot)
    _populate_peer_consensus(snapshot, state, config)
    _populate_holdover_alignment(snapshot, config)
    _inflate_evidence(snapshot)
    return snapshot


def layer_signal_envelope(snapshot: FeatureSnapshot) -> LayerDecision:
    return _time_layer(1, lambda: _signal_envelope_result(snapshot))


def layer_packet_syntax(snapshot: FeatureSnapshot) -> LayerDecision:
    return _time_layer(2, lambda: _packet_syntax_result(snapshot))


def layer_schema_gate(snapshot: FeatureSnapshot) -> LayerDecision:
    return _time_layer(3, lambda: _schema_gate_result(snapshot))


def layer_source_identity(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(4, lambda: _source_identity_result(snapshot, config))


def layer_adaptive_lockdown(snapshot: FeatureSnapshot) -> LayerDecision:
    return _time_layer(5, lambda: _adaptive_lockdown_result(snapshot))


def layer_deception_lane(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(6, lambda: _deception_lane_result(snapshot, config))


def layer_authorization_and_integrity(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(7, lambda: _authorization_result(snapshot, config))


def layer_freshness(snapshot: FeatureSnapshot) -> LayerDecision:
    return _time_layer(8, lambda: _freshness_result(snapshot))


def layer_rf_health(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(9, lambda: _rf_health_result(snapshot, config))


def layer_spatial_consistency(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(10, lambda: _spatial_consistency_result(snapshot, config))


def layer_clock_consistency(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(11, lambda: _clock_consistency_result(snapshot, config))


def layer_consensus(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(12, lambda: _consensus_result(snapshot, config))


def layer_mission_envelope(snapshot: FeatureSnapshot, config: AppConfig) -> LayerDecision:
    return _time_layer(13, lambda: _mission_envelope_result(snapshot, config))


def _signal_envelope_result(snapshot: FeatureSnapshot) -> tuple[bool, str, str, str]:
    if "packet_too_large" in snapshot.validation_errors:
        return False, "packet_too_large", "malformed", "Packet size exceeded the gate limit."
    if "signal_prefix_missing" in snapshot.validation_errors:
        return False, "signal_prefix_missing", "unauthorized", "Signal envelope prefix is missing or incorrect."
    if "signal_suffix_missing" in snapshot.validation_errors:
        return False, "signal_suffix_missing", "unauthorized", "Signal envelope suffix is missing or incorrect."
    if "signal_envelope_empty" in snapshot.validation_errors:
        return False, "signal_envelope_empty", "malformed", "Signal envelope did not contain an inner payload."
    if not snapshot.signal_envelope_valid:
        return False, "signal_envelope_invalid", "unauthorized", "Signal envelope validation failed."
    return True, "signal_envelope_pass", "normal", "Signal envelope was accepted."


def _packet_syntax_result(snapshot: FeatureSnapshot) -> tuple[bool, str, str, str]:
    if "json_parse_failed" in snapshot.validation_errors:
        return False, "json_parse_failed", "malformed", "Packet could not be parsed as JSON."
    if not snapshot.parsed_ok:
        return False, "packet_not_parsed", "malformed", "Packet parsing did not complete."
    return True, "syntax_pass", "normal", "Packet syntax is valid JSON."


def _schema_gate_result(snapshot: FeatureSnapshot) -> tuple[bool, str, str, str]:
    if snapshot.validation_errors:
        return False, snapshot.validation_errors[0], "malformed", "Packet fields or metric schema are invalid."
    if not snapshot.required_fields_present:
        return False, "required_fields_missing", "malformed", "Packet is missing required root fields."
    if not snapshot.schema_valid or snapshot.packet is None:
        return False, "schema_invalid", "malformed", "Packet types did not match the expected schema."
    if not snapshot.packet.op_code:
        return False, "missing_op_code", "malformed", "Packet op_code is missing."
    return True, "schema_pass", "normal", "Packet schema passed."


def _source_identity_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for source identity checks."
    if not snapshot.source_trusted:
        return False, "unknown_source", "unauthorized", "Packet source is not in the trusted registry."
    return True, "source_pass", "normal", "Packet source is trusted."


def _adaptive_lockdown_result(snapshot: FeatureSnapshot) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for adaptive shield checks."
    classification = "credential_compromise_suspect" if snapshot.secret_compromised else "unauthorized"
    if snapshot.source_locked:
        seconds = round(snapshot.lock_remaining_seconds or 0.0, 1)
        return False, "source_quarantined", classification, f"Adaptive shield locked source traffic for another {seconds} seconds."
    return True, "adaptive_lock_pass", "normal", "Adaptive shield left the source open."


def _deception_lane_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for deception lane checks."
    classification = "credential_compromise_suspect" if snapshot.secret_compromised else "unauthorized"
    if not snapshot.session_nonce_valid:
        return False, "session_nonce_mismatch", classification, "Packet did not carry the active session challenge."
    if not snapshot.flow_tag_valid:
        return False, "flow_tag_invalid", classification, "Packet seal did not match the rotating session material."
    if snapshot.trust_lane_seen != "primary":
        return False, "shadow_lane_packet_seen", "shadow_contact_suspect", "A non-primary lane packet reached the primary ingress."
    if snapshot.shadow_contact_detected:
        return False, "shadow_lane_contact", "leak_trap_triggered", "Packet matched the hidden shadow lane bait."
    if not snapshot.epoch_chain_valid and not snapshot.epoch_resync_candidate:
        return False, "epoch_chain_broken", classification, "Packet could not satisfy the epoch bait chain."
    if snapshot.epoch_resync_candidate:
        return True, "epoch_chain_resynced", "normal", "Trusted source re-established the epoch bait chain with a controlled genesis proof."
    return True, "deception_lane_pass", "normal", "Primary lane proof matched the active epoch chain."


def _authorization_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for integrity checks."
    if packet.op_code != config.security.expected_op_code:
        return False, "invalid_op_code", "unauthorized", "Shared operation code verification failed."
    if not snapshot.checksum_valid:
        return False, "checksum_mismatch", "signal_tamper", "Packet checksum does not match the normalized body."
    return True, "auth_pass", "normal", "Authorization and integrity checks passed."


def _freshness_result(snapshot: FeatureSnapshot) -> tuple[bool, str, str, str]:
    if snapshot.packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for freshness checks."
    if snapshot.future_timestamp:
        return False, "future_timestamp", "replay_suspect", "Packet timestamp is too far in the future."
    if snapshot.stale_timestamp:
        return False, "stale_timestamp", "replay_suspect", "Packet timestamp fell outside the freshness window."
    if snapshot.duplicate_packet_id:
        return False, "duplicate_packet_id", "replay_suspect", "Packet identifier has already been observed."
    if snapshot.duplicate_sequence:
        return False, "sequence_regression", "replay_suspect", "Packet sequence did not increase."
    if snapshot.ts_delta_seconds is not None and snapshot.ts_delta_seconds <= 0:
        return False, "non_monotonic_timestamp", "replay_suspect", "Packet timestamp regressed relative to prior traffic."
    return True, "freshness_pass", "normal", "Packet passed freshness and replay checks."


def _rf_health_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for RF checks."
    metrics = packet.metrics
    min_sat_count = int(_threshold_value(snapshot, config, "min_sat_count"))
    min_cn0 = _threshold_value(snapshot, config, "min_cn0")
    max_power_dbm = _threshold_value(snapshot, config, "max_power_dbm")
    max_power_delta = _threshold_value(snapshot, config, "max_power_delta")
    max_cn0_delta = _threshold_value(snapshot, config, "max_cn0_delta")
    max_doppler_delta = _threshold_value(snapshot, config, "max_doppler_delta")
    if metrics.sat_count < min_sat_count:
        return False, "satellite_lock_loss", "jam_suspect", "Visible satellite count dropped below the safe floor."
    if metrics.cn0 < min_cn0:
        return False, "cn0_floor_breach", "jam_suspect", "Carrier-to-noise ratio fell below the operational floor."
    if metrics.power > max_power_dbm and metrics.cn0 < (min_cn0 + 5):
        return False, "power_spike_with_cn0_drop", "jam_suspect", "Received power rose while signal quality collapsed."
    if snapshot.power_delta is not None and abs(snapshot.power_delta) > max_power_delta:
        return False, "rf_power_jump", "jam_suspect", "RF power changed too sharply relative to recent history."
    if snapshot.cn0_delta is not None and abs(snapshot.cn0_delta) > max_cn0_delta:
        return False, "cn0_jump", "jam_suspect", "Signal quality changed too sharply relative to recent history."
    if snapshot.doppler_delta is not None and abs(snapshot.doppler_delta) > max_doppler_delta:
        return False, "doppler_jump", "signal_tamper", "Doppler profile shifted beyond the expected operating band."
    return True, "rf_pass", "normal", "Packet passed RF health checks."


def _spatial_consistency_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    classification = "credential_compromise_suspect" if snapshot.secret_compromised else "spoof_suspect"
    max_position_jump_m = _threshold_value(snapshot, config, "max_position_jump_m")
    max_speed_mps = _threshold_value(snapshot, config, "max_speed_mps")
    max_cumulative_position_drift_m = _threshold_value(snapshot, config, "max_cumulative_position_drift_m")
    if snapshot.position_jump_m is not None and snapshot.position_jump_m > max_position_jump_m:
        return False, "position_jump", classification, "Position jump exceeded the single-hop motion budget."
    if snapshot.derived_speed_mps is not None and snapshot.derived_speed_mps > max_speed_mps:
        return False, "impossible_speed", classification, "Derived motion speed exceeded the platform envelope."
    if snapshot.cumulative_position_drift_m is not None and snapshot.cumulative_position_drift_m > max_cumulative_position_drift_m:
        return False, "cumulative_position_drift", classification, "Short-window position drift exceeded the safe span."
    return True, "spatial_pass", "normal", "Packet passed spatial consistency checks."


def _clock_consistency_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    classification = "credential_compromise_suspect" if snapshot.secret_compromised else "spoof_suspect"
    max_clock_bias_step = _threshold_value(snapshot, config, "max_clock_bias_step")
    max_clock_drift_step = _threshold_value(snapshot, config, "max_clock_drift_step")
    max_cumulative_clock_bias_span = _threshold_value(snapshot, config, "max_cumulative_clock_bias_span")
    if snapshot.clock_bias_delta is not None and abs(snapshot.clock_bias_delta) > max_clock_bias_step:
        return False, "clock_bias_step", classification, "Clock bias changed too sharply relative to prior traffic."
    if snapshot.clock_drift_delta is not None and abs(snapshot.clock_drift_delta) > max_clock_drift_step:
        return False, "clock_drift_step", classification, "Clock drift changed too sharply relative to prior traffic."
    if snapshot.cumulative_clock_bias_span is not None and snapshot.cumulative_clock_bias_span > max_cumulative_clock_bias_span:
        return False, "clock_bias_span", classification, "Short-window clock bias span exceeded the holdover envelope."
    return True, "clock_holdover_pass", "normal", "Packet passed clock and holdover readiness checks."


def _consensus_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    max_mesh_time_delta_seconds = _threshold_value(snapshot, config, "max_mesh_time_delta_seconds")
    max_receiver_baseline_delta_m = _threshold_value(snapshot, config, "max_receiver_baseline_delta_m")
    max_peer_position_delta_m = _threshold_value(snapshot, config, "max_peer_position_delta_m")
    max_peer_clock_bias_delta = _threshold_value(snapshot, config, "max_peer_clock_bias_delta")
    max_peer_clock_drift_delta = _threshold_value(snapshot, config, "max_peer_clock_drift_delta")
    peer_vote_valid = True
    if snapshot.peer_reference_count == 0 and not snapshot.packet.peer_observations:
        snapshot.mesh_consensus_valid = True
        snapshot.quorum_votes = {"primary": True}
        if snapshot.holdover_alignment_valid:
            snapshot.quorum_votes["holdover"] = True
        snapshot.quorum_result = "single_source" if len(snapshot.quorum_votes) == 1 else "partial_consensus"
        return True, "mesh_not_available", "normal", "No peer observations were available for trust mesh checks."
    if snapshot.peer_time_delta_seconds is not None and snapshot.peer_time_delta_seconds > max_mesh_time_delta_seconds:
        snapshot.mesh_consensus_valid = False
        peer_vote_valid = False
        snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
        snapshot.quorum_result = "disagreement"
        return False, "mesh_time_divergence", "mesh_divergence_suspect", "Peer timing diverged beyond the mesh budget."
    if snapshot.receiver_baseline_delta_m is not None and snapshot.receiver_baseline_delta_m > max_receiver_baseline_delta_m:
        snapshot.mesh_consensus_valid = False
        peer_vote_valid = False
        snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
        snapshot.quorum_result = "disagreement"
        return False, "mesh_baseline_divergence", "mesh_divergence_suspect", "Receiver baseline agreement collapsed."
    if snapshot.peer_position_delta_m is not None and snapshot.peer_position_delta_m > max_peer_position_delta_m:
        snapshot.mesh_consensus_valid = False
        peer_vote_valid = False
        snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
        snapshot.quorum_result = "disagreement"
        return False, "peer_position_mismatch", "mesh_divergence_suspect", "Peer references disagree with the reported position."
    if snapshot.peer_clock_bias_delta is not None and snapshot.peer_clock_bias_delta > max_peer_clock_bias_delta:
        snapshot.mesh_consensus_valid = False
        peer_vote_valid = False
        snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
        snapshot.quorum_result = "disagreement"
        return False, "peer_clock_bias_mismatch", "mesh_divergence_suspect", "Peer references disagree with the reported clock bias."
    if snapshot.peer_clock_drift_delta is not None and snapshot.peer_clock_drift_delta > max_peer_clock_drift_delta:
        snapshot.mesh_consensus_valid = False
        peer_vote_valid = False
        snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
        snapshot.quorum_result = "disagreement"
        return False, "peer_clock_drift_mismatch", "mesh_divergence_suspect", "Peer references disagree with the reported clock drift."
    snapshot.quorum_votes = _build_quorum_votes(snapshot, peer_vote_valid)
    positive_votes = sum(1 for value in snapshot.quorum_votes.values() if value)
    total_votes = len(snapshot.quorum_votes)
    snapshot.quorum_result = "consensus" if positive_votes >= min(2, total_votes) else "partial_consensus"
    snapshot.mesh_consensus_valid = True
    return True, "mesh_pass", "normal", "Trust mesh checks passed."


def _mission_envelope_result(snapshot: FeatureSnapshot, config: AppConfig) -> tuple[bool, str, str, str]:
    packet = snapshot.packet
    if packet is None:
        return False, "packet_missing", "malformed", "Packet was not available for mission envelope checks."
    classification = "credential_compromise_suspect" if snapshot.secret_compromised else "spoof_suspect"
    satellite_result = _satellite_profile_result(snapshot, config, classification)
    if satellite_result is not None:
        return satellite_result
    allowed_channel = str(packet.payload.get("channel", config.mission.allowed_channel)) if isinstance(packet.payload, dict) else config.mission.allowed_channel
    if allowed_channel != config.mission.allowed_channel:
        snapshot.mission_envelope_valid = False
        snapshot.mission_breach_detected = True
        snapshot.mission_breach_reason = "mission_channel_mismatch"
        return False, "mission_channel_mismatch", classification, "Packet channel did not match the active mission channel."
    if not _within_mission_hours(packet.ts, config):
        snapshot.mission_envelope_valid = False
        snapshot.mission_breach_detected = True
        snapshot.mission_breach_reason = "mission_time_window_breach"
        return False, "mission_time_window_breach", classification, "Packet arrived outside the authorized mission time window."
    speed_limit = _mission_value(snapshot, config, "max_speed_mps")
    if packet.metrics.speed is not None and packet.metrics.speed > speed_limit:
        snapshot.mission_envelope_valid = False
        snapshot.mission_breach_detected = True
        snapshot.mission_breach_reason = "mission_speed_breach"
        return False, "mission_speed_breach", classification, "Packet speed exceeded the mission envelope."
    if _has_coordinates(packet.metrics):
        primary_distance = haversine_meters(
            packet.metrics.latitude,
            packet.metrics.longitude,
            config.mission.primary_zone.center_latitude,
            config.mission.primary_zone.center_longitude,
        )
        if primary_distance > _mission_value(snapshot, config, "primary_zone_radius_m"):
            snapshot.mission_envelope_valid = False
            snapshot.mission_breach_detected = True
            snapshot.mission_breach_reason = "mission_zone_breach"
            return False, "mission_zone_breach", classification, "Packet drifted outside the mission corridor."
        max_route_drift_m = _mission_value(snapshot, config, "max_route_drift_m")
        if snapshot.cumulative_position_drift_m is not None and snapshot.cumulative_position_drift_m > max_route_drift_m:
            snapshot.mission_envelope_valid = False
            snapshot.mission_breach_detected = True
            snapshot.mission_breach_reason = "mission_route_drift"
            return False, "mission_route_drift", classification, "Packet drift exceeded the mission route envelope."
        for zone in config.mission.forbidden_zones:
            forbidden_distance = haversine_meters(
                packet.metrics.latitude,
                packet.metrics.longitude,
                zone.center_latitude,
                zone.center_longitude,
            )
            if forbidden_distance <= zone.radius_m:
                snapshot.mission_envelope_valid = False
                snapshot.mission_breach_detected = True
                snapshot.mission_breach_reason = "forbidden_zone_breach"
                return False, "forbidden_zone_breach", classification, "Packet entered a forbidden mission zone."
    snapshot.mission_envelope_valid = True
    return True, "mission_envelope_pass", "normal", "Packet satisfied the mission envelope."


def _satellite_profile_result(
    snapshot: FeatureSnapshot,
    config: AppConfig,
    classification: str,
) -> tuple[bool, str, str, str] | None:
    profile = get_satellite_profile(config.mission.satellite_profile_id)
    if profile.profile_id == "generic-bkzs":
        return None
    packet = snapshot.packet
    if packet is None or not isinstance(packet.payload, dict):
        return False, "satellite_profile_missing", classification, "Satellite profile is active but packet payload is missing satellite metadata."

    payload = packet.payload
    payload_profile_id = str(payload.get("satellite_profile_id", ""))
    if payload_profile_id != profile.profile_id:
        return _satellite_breach(snapshot, "satellite_profile_mismatch", classification, "Packet did not match the active satellite profile.")

    satellite_class = str(payload.get("satellite_class", ""))
    if satellite_class != profile.mission_domain:
        return _satellite_breach(snapshot, "satellite_domain_mismatch", classification, "Packet mission domain did not match the active satellite family.")

    orbit_type = str(payload.get("orbit_type", ""))
    if orbit_type != profile.orbit_type:
        return _satellite_breach(snapshot, "satellite_orbit_mismatch", classification, "Packet orbit type did not match the public satellite profile.")

    if profile.orbital_slot_deg_e is not None:
        orbital_slot = _optional_float(payload.get("orbital_slot_deg_e"))
        if orbital_slot is None or abs(orbital_slot - profile.orbital_slot_deg_e) > 0.35:
            return _satellite_breach(snapshot, "satellite_orbital_slot_mismatch", classification, "Packet orbital slot did not match the public GEO profile.")

    if profile.allowed_uplink_bands:
        uplink_band = str(payload.get("uplink_band", ""))
        if uplink_band and uplink_band not in profile.allowed_uplink_bands:
            return _satellite_breach(snapshot, "satellite_band_mismatch", classification, "Packet uplink band is outside the public satellite profile.")

    if profile.allowed_downlink_bands:
        downlink_band = str(payload.get("downlink_band", ""))
        if downlink_band and downlink_band not in profile.allowed_downlink_bands:
            return _satellite_breach(snapshot, "satellite_band_mismatch", classification, "Packet downlink band is outside the public satellite profile.")

    if profile.allowed_tmtc_bands:
        tmtc_band = str(payload.get("tmtc_band", ""))
        if tmtc_band and tmtc_band not in profile.allowed_tmtc_bands:
            return _satellite_breach(snapshot, "satellite_tmtc_band_mismatch", classification, "Packet TM/TC band is outside the public satellite profile.")

    if profile.allowed_transponder_bandwidths_mhz:
        transponder_bw = _optional_float(payload.get("transponder_bandwidth_mhz"))
        if transponder_bw is not None and int(round(transponder_bw)) not in profile.allowed_transponder_bandwidths_mhz:
            return _satellite_breach(snapshot, "satellite_transponder_mismatch", classification, "Packet transponder bandwidth did not match the public satellite profile.")

    if profile.allowed_protocols:
        protocol_family = str(payload.get("protocol_family", ""))
        if protocol_family and protocol_family not in profile.allowed_protocols:
            return _satellite_breach(snapshot, "satellite_protocol_mismatch", classification, "Packet protocol family did not match the public satellite profile.")

    if profile.sensor_type:
        sensor_type = str(payload.get("sensor_type", ""))
        if sensor_type and sensor_type != profile.sensor_type:
            return _satellite_breach(snapshot, "satellite_sensor_mismatch", classification, "Packet sensor type did not match the public satellite profile.")

    return None


def _satellite_breach(
    snapshot: FeatureSnapshot,
    reason_code: str,
    classification: str,
    details: str,
) -> tuple[bool, str, str, str]:
    snapshot.mission_envelope_valid = False
    snapshot.mission_breach_detected = True
    snapshot.mission_breach_reason = reason_code
    return False, reason_code, classification, details


def _populate_explicit_peer_observations(snapshot: FeatureSnapshot) -> None:
    packet = snapshot.packet
    if packet is None:
        return
    observations = packet.peer_observations
    if not observations:
        return
    snapshot.peer_reference_count = max(snapshot.peer_reference_count, int(observations.get("peer_count", 1)))
    snapshot.peer_position_delta_m = _optional_float(observations.get("position_delta_m")) or snapshot.peer_position_delta_m
    snapshot.peer_clock_bias_delta = _optional_float(observations.get("clock_bias_delta")) or snapshot.peer_clock_bias_delta
    snapshot.peer_clock_drift_delta = _optional_float(observations.get("clock_drift_delta")) or snapshot.peer_clock_drift_delta
    snapshot.peer_time_delta_seconds = _optional_float(observations.get("time_delta_seconds"))
    snapshot.receiver_baseline_delta_m = _optional_float(observations.get("receiver_baseline_delta_m"))


def _populate_holdover_alignment(snapshot: FeatureSnapshot, config: AppConfig) -> None:
    packet = snapshot.packet
    if packet is None or not packet.holdover_state:
        return
    holdover = packet.holdover_state
    confidence = _optional_float(holdover.get("confidence")) or 0.0
    if confidence < _threshold_value(snapshot, config, "holdover_confidence_floor"):
        return

    if _has_coordinates(packet.metrics):
        predicted_lat = _optional_float(holdover.get("predicted_latitude"))
        predicted_lon = _optional_float(holdover.get("predicted_longitude"))
        if predicted_lat is not None and predicted_lon is not None:
            snapshot.holdover_position_delta_m = haversine_meters(
                packet.metrics.latitude,
                packet.metrics.longitude,
                predicted_lat,
                predicted_lon,
            )

    predicted_bias = _optional_float(holdover.get("predicted_clock_bias"))
    if predicted_bias is not None:
        snapshot.holdover_clock_bias_delta = abs(packet.metrics.clock_bias - predicted_bias)

    position_ok = snapshot.holdover_position_delta_m is None or snapshot.holdover_position_delta_m <= _threshold_value(snapshot, config, "max_holdover_position_delta_m")
    bias_ok = snapshot.holdover_clock_bias_delta is None or snapshot.holdover_clock_bias_delta <= _threshold_value(snapshot, config, "max_holdover_clock_bias_delta")
    snapshot.holdover_alignment_valid = position_ok and bias_ok


def _populate_peer_consensus(snapshot: FeatureSnapshot, state: PipelineState, config: AppConfig) -> None:
    packet = snapshot.packet
    if packet is None:
        return
    peers = []
    for peer in state.get_peer_packets(packet.source):
        age_gap = abs((packet.ts - peer.ts).total_seconds())
        if age_gap <= config.thresholds.peer_freshness_window_seconds:
            peers.append(peer)
    snapshot.peer_reference_count = max(snapshot.peer_reference_count, len(peers))
    if not peers:
        return

    if _has_coordinates(packet.metrics):
        deltas = []
        for peer in peers:
            if _has_coordinates(peer.metrics):
                deltas.append(
                    haversine_meters(
                        packet.metrics.latitude,
                        packet.metrics.longitude,
                        peer.metrics.latitude,
                        peer.metrics.longitude,
                    )
                )
        if deltas and snapshot.peer_position_delta_m is None:
            snapshot.peer_position_delta_m = float(median(deltas))

    bias_deltas = [abs(packet.metrics.clock_bias - peer.metrics.clock_bias) for peer in peers]
    drift_deltas = [abs(packet.metrics.clock_drift - peer.metrics.clock_drift) for peer in peers]
    time_deltas = [abs((packet.ts - peer.ts).total_seconds()) for peer in peers]
    if bias_deltas and snapshot.peer_clock_bias_delta is None:
        snapshot.peer_clock_bias_delta = float(median(bias_deltas))
    if drift_deltas and snapshot.peer_clock_drift_delta is None:
        snapshot.peer_clock_drift_delta = float(median(drift_deltas))
    if time_deltas and snapshot.peer_time_delta_seconds is None:
        snapshot.peer_time_delta_seconds = float(median(time_deltas))


def _inflate_evidence(snapshot: FeatureSnapshot) -> None:
    if snapshot.shadow_contact_detected:
        snapshot.evidence_vector.append("shadow_contact")
        snapshot.attacker_reveal_score += 55
    if snapshot.secret_compromised:
        snapshot.evidence_vector.append("secret_compromise_hint")
        snapshot.attacker_reveal_score += 15
    if snapshot.source_locked:
        snapshot.evidence_vector.append("adaptive_lock")
        snapshot.attacker_reveal_score += 10
    if snapshot.peer_position_delta_m is not None:
        snapshot.evidence_vector.append("mesh_position")
        snapshot.attacker_reveal_score += 10
    if snapshot.peer_clock_bias_delta is not None:
        snapshot.evidence_vector.append("mesh_clock")
        snapshot.attacker_reveal_score += 5
    if snapshot.holdover_alignment_valid:
        snapshot.evidence_vector.append("holdover_ready")
        snapshot.attacker_reveal_score += 5
    if snapshot.bulletin_policy_applied and "trust_bulletin_active" not in snapshot.evidence_vector:
        snapshot.evidence_vector.append("trust_bulletin_active")
        snapshot.attacker_reveal_score += 4
    if snapshot.active_risk_zone and "risk_zone_overlap" not in snapshot.evidence_vector:
        snapshot.evidence_vector.append("risk_zone_overlap")
        snapshot.attacker_reveal_score += 6
    if snapshot.mission_breach_detected and snapshot.mission_breach_reason and snapshot.mission_breach_reason not in snapshot.evidence_vector:
        snapshot.evidence_vector.append(snapshot.mission_breach_reason)
        snapshot.attacker_reveal_score += 10
    snapshot.attacker_reveal_score = min(99, snapshot.attacker_reveal_score)


def _threshold_value(snapshot: FeatureSnapshot, config: AppConfig, attr: str) -> float:
    if attr in snapshot.threshold_overrides:
        return float(snapshot.threshold_overrides[attr])
    return float(getattr(config.thresholds, attr))


def _mission_value(snapshot: FeatureSnapshot, config: AppConfig, attr: str) -> float:
    override_key = f"mission_{attr}"
    if override_key in snapshot.threshold_overrides:
        return float(snapshot.threshold_overrides[override_key])
    if attr == "primary_zone_radius_m":
        return float(config.mission.primary_zone.radius_m)
    return float(getattr(config.mission, attr))


def _build_quorum_votes(snapshot: FeatureSnapshot, peer_vote_valid: bool | None) -> dict[str, bool]:
    votes: dict[str, bool] = {"primary": True}
    if peer_vote_valid is not None and (snapshot.peer_reference_count > 0 or snapshot.packet.peer_observations):
        votes["peer"] = peer_vote_valid
    if snapshot.holdover_alignment_valid or snapshot.packet.holdover_state:
        votes["holdover"] = snapshot.holdover_alignment_valid
    snapshot.primary_vote_valid = votes["primary"]
    snapshot.peer_vote_valid = votes.get("peer")
    snapshot.holdover_vote_valid = votes.get("holdover")
    return votes


def _within_mission_hours(timestamp, config: AppConfig) -> bool:
    hour = timestamp.hour
    start = int(config.mission.allowed_start_hour)
    end = int(config.mission.allowed_end_hour)
    if start <= end:
        return start <= hour <= end
    return hour >= start or hour <= end


def _time_layer(layer_id: int, evaluate: Callable[[], tuple[bool, str, str, str]]) -> LayerDecision:
    started = perf_counter()
    passed, reason_code, classification, details = evaluate()
    latency_ms = (perf_counter() - started) * 1000
    return LayerDecision(
        layer_id=layer_id,
        passed=passed,
        reason_code=reason_code,
        latency_ms=round(latency_ms, 3),
        classification=classification,
        details=details,
    )


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return float(value)


def _has_coordinates(metrics: SignalMetrics) -> bool:
    return metrics.latitude is not None and metrics.longitude is not None
