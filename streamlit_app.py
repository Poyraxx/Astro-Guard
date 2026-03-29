from __future__ import annotations

import html
import json
import socket
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import pandas as pd
import streamlit as st
import streamlit.runtime as streamlit_runtime

from bkzs_guard.adapters import (
    ensure_esp32_wifi_header,
    ensure_esp8266_wifi_header,
    write_esp32_profile_header,
    write_esp8266_profile_header,
)
from bkzs_guard.control import BKZSControlCenter
from bkzs_guard.config import AppConfig, load_app_config
from bkzs_guard.models import DecisionRecord
from bkzs_guard.satellites import get_satellite_profile, satellite_profile_options
from bkzs_guard.utils import generate_session_nonce


REMOTE_ATTACK_PROFILE_PATH = Path(__file__).resolve().parent / "remote_attack_node" / "attack_target_profile.json"
DEFAULT_ATTACK_SOURCE = "bkzs-edge-1"


LAYER_LABELS = {
    0: "Katman 0 / UI Erisim",
    1: "Katman 1 / Sinyal Zarfi",
    2: "Katman 2 / JSON Parse",
    3: "Katman 3 / Sema Kapisi",
    4: "Katman 4 / Kaynak Kimligi",
    5: "Katman 5 / Adaptif Kilit",
    6: "Katman 6 / Deception Lane",
    7: "Katman 7 / Yetki ve Butunluk",
    8: "Katman 8 / Tazelik ve Replay",
    9: "Katman 9 / RF Sagligi",
    10: "Katman 10 / Mekansal Tutarlilik",
    11: "Katman 11 / Saat ve Holdover",
    12: "Katman 12 / Trust Mesh",
    13: "Katman 13 / Mission Envelope",
}

GROUPS = {
    "Giris ve Veri Zarfi": (1, 2, 3),
    "Kimlik ve Muhur": (4, 5, 6, 7),
    "Tazelik ve RF": (8, 9),
    "Tutarlilik ve Konsensus": (10, 11, 12, 13),
}

CLASSIFICATION_LABELS = {
    "normal": "Temiz akis",
    "unauthorized": "Yetkisiz trafik",
    "malformed": "Bozuk paket",
    "replay_suspect": "Replay supheli",
    "jam_suspect": "Karistirma supheli",
    "signal_tamper": "Veri oynanmis",
    "spoof_suspect": "Taklit supheli",
    "credential_compromise_suspect": "Kimlik sizintisi supheli",
    "credential_leak_suspect": "Credential sizintisi supheli",
    "leak_trap_triggered": "Tuzak tetiklendi",
    "shadow_contact_suspect": "Shadow lane temasi",
    "mesh_divergence_suspect": "Mesh uyusmazligi",
}

SIGNATURE_LABELS = {
    "clean_flow": "Temiz akis",
    "source_quarantined": "Kaynak karantinada",
    "session_nonce_mismatch": "Oturum muhru uyusmuyor",
    "flow_tag_invalid": "Akis muhru gecersiz",
    "invalid_op_code": "Yetki kodu hatali",
    "duplicate_packet_id": "Paket tekrari",
    "sequence_regression": "Sira gerilemesi",
    "non_monotonic_timestamp": "Zaman gerilemesi",
    "satellite_lock_loss": "Uydu kilidi kaybi",
    "cn0_floor_breach": "Sinyal kalitesi cok dusuk",
    "rf_power_jump": "Guc sicrasi",
    "cn0_jump": "C/N0 sicrasi",
    "doppler_jump": "Doppler sicrasi",
    "position_jump": "Konum sicrasi",
    "impossible_speed": "Hiz uyumsuz",
    "cumulative_position_drift": "Kumulatif konum kaymasi",
    "clock_bias_step": "Saat ofset sicrasi",
    "clock_drift_step": "Saat suruklenmesi sicrasi",
    "clock_bias_span": "Saat araligi uyumsuz",
    "shadow_lane_contact": "Tuzak tokeni goruldu",
    "shadow_lane_packet_seen": "Shadow lane paketi yakalandi",
    "epoch_chain_broken": "Epoch zinciri kirildi",
    "mesh_time_divergence": "Mesh zaman uyusmazligi",
    "mesh_baseline_divergence": "Receiver mesh uyusmazligi",
    "peer_position_mismatch": "Kaynaklar arasi konum uyusmazligi",
    "peer_clock_bias_mismatch": "Kaynaklar arasi saat ofset uyusmazligi",
    "peer_clock_drift_mismatch": "Kaynaklar arasi saat drift uyusmazligi",
    "mission_channel_mismatch": "Gorev kanali uyusmazligi",
    "mission_time_window_breach": "Gorev zaman penceresi disi",
    "mission_speed_breach": "Gorev hiz zarfi asildi",
    "mission_zone_breach": "Gorev koridoru disi",
    "mission_route_drift": "Gorev rotasi kaydi",
    "forbidden_zone_breach": "Yasak bolge ihlali",
    "shadow_lane_touch": "Shadow lane temasi",
    "credential_valid_breach": "Credential dogrulandi ama derin savunma bozuldu",
    "mission_envelope_breach": "Mission envelope tetigi",
    "mesh_divergence": "Trust mesh uyusmazligi",
    "deep_spoof_contact": "Derin spoof temasi",
    "satellite_profile_mismatch": "Uydu profili uyusmazligi",
    "satellite_domain_mismatch": "Uydu gorev sinifi uyusmazligi",
    "satellite_orbit_mismatch": "Yorunge tipi uyusmazligi",
    "satellite_orbital_slot_mismatch": "Orbital slot uyusmazligi",
    "satellite_band_mismatch": "Uydu bant plani uyusmazligi",
    "satellite_tmtc_band_mismatch": "TMTC bandi uyusmazligi",
    "satellite_transponder_mismatch": "Transponder genisligi uyusmazligi",
    "satellite_protocol_mismatch": "Uydu protokol ailesi uyusmazligi",
    "satellite_sensor_mismatch": "Uydu sensor tipi uyusmazligi",
    "credentialed_shadow_probe": "Credentialli shadow probe",
    "credential_reuse_spoof": "Credential tekrar kullanimli spoof",
    "mission_envelope_evasion": "Mission envelope kacis denemesi",
    "mesh_split_spoof": "Mesh ayirma saldirisi",
    "replay_injection": "Replay enjeksiyonu",
    "rf_disruption": "RF bozucu saldiri",
    "navigation_spoof": "Navigasyon spoof saldirisi",
    "deep_anomaly_probe": "Derin anomali sondasi",
    "shadow_lane_mimicry": "Shadow lane taklidi",
    "post-auth deep spoof": "Yetki sonrasi derin spoof",
    "route-speed-phase drift": "Rota hiz faz kaymasi",
    "peer desync": "Peer desync",
    "freshness abuse": "Tazelik kotuye kullanimi",
    "power-cn0 doppler anomaly": "Guc C/N0 Doppler anomali izi",
    "position-clock manipulation": "Konum saat manipulasyonu",
    "layered_consistency_probe": "Katmanli tutarlilik sondasi",
}


def bootstrap(config: AppConfig) -> None:
    if "app" not in st.session_state:
        st.session_state.app = BKZSControlCenter(config)


def detect_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"


def normal_lab_fixed_ip_for_source(source: str) -> str:
    mapping = {
        "bkzs-edge-1": "10.10.10.10",
        "bkzs-edge-2": "10.250.10.12",
        "bkzs-core": "10.250.10.13",
    }
    return mapping.get(source, "10.250.10.20")


def sync_remote_attack_profile(config: AppConfig, *, adapter_port: int = 9000, protocol: str = "udp") -> None:
    REMOTE_ATTACK_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    target_host = detect_local_ip()
    payload = {
        "target_host": target_host,
        "target_port": adapter_port,
        "protocol": protocol,
        "source": DEFAULT_ATTACK_SOURCE,
        "signal_secret": config.security.signal_secret,
        "session_nonce": config.security.session_nonce,
        "shadow_salt": config.security.shadow_lane_salt,
        "op_code": config.security.expected_op_code,
        "satellite_profile": config.mission.satellite_profile_id,
        "decision_feed_protocol": config.decision_feed.protocol,
        "decision_feed_port": config.decision_feed.port,
        "relay_protocol": config.relay.secure_plane.protocol,
        "secure_port": config.relay.secure_plane.port,
        "shadow_port": config.relay.shadow_plane.port,
        "lab_transport": "1",
        "lab_random_ip": "1",
        "normal_lab_transport": "1",
        "normal_lab_fixed_ip": normal_lab_fixed_ip_for_source(DEFAULT_ATTACK_SOURCE),
    }
    REMOTE_ATTACK_PROFILE_PATH.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2),
        encoding="utf-8",
    )
    write_esp32_profile_header(
        config,
        target_host=target_host,
        target_port=adapter_port,
        protocol=protocol,
    )
    ensure_esp32_wifi_header()
    write_esp8266_profile_header(
        config,
        target_host=target_host,
        target_port=adapter_port,
        protocol=protocol,
    )
    ensure_esp8266_wifi_header()


def get_control_center() -> BKZSControlCenter:
    return st.session_state.app


def inject_css() -> None:
    st.markdown(
        """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

:root {
  --bg-0: #07131b;
  --bg-1: #0b1c26;
  --bg-2: #102938;
  --ink-0: #eff6fb;
  --ink-1: #b5c5d0;
  --ink-2: #71879a;
  --line: rgba(255,255,255,0.09);
  --good: #3dd598;
  --good-soft: rgba(61,213,152,0.12);
  --bad: #ff6b6b;
  --bad-soft: rgba(255,107,107,0.12);
  --warn: #ffd166;
  --info: #73c2fb;
  --panel: rgba(10, 21, 31, 0.82);
}

.stApp {
  background:
    radial-gradient(circle at top left, rgba(61,213,152,0.14), transparent 28%),
    radial-gradient(circle at top right, rgba(255,107,107,0.12), transparent 24%),
    radial-gradient(circle at 50% 0%, rgba(115,194,251,0.12), transparent 22%),
    linear-gradient(180deg, var(--bg-0) 0%, #08111a 100%);
  color: var(--ink-0);
}

.block-container {
  padding-top: 1.25rem;
  padding-bottom: 3rem;
  max-width: 1440px;
}

h1, h2, h3, h4, .stMarkdown, .stCaption, label {
  font-family: "Space Grotesk", "Aptos", sans-serif !important;
}

code, pre {
  font-family: "IBM Plex Mono", "Consolas", monospace !important;
}

[data-testid="stSidebar"] {
  background: rgba(8,16,24,0.92);
  border-left: 1px solid var(--line);
}

MainMenu,
footer {
  visibility: hidden;
  height: 0;
}

header[data-testid="stHeader"] {
  background: transparent;
}

[data-testid="stToolbar"] {
  visibility: visible !important;
  height: auto !important;
  background: transparent !important;
  right: auto !important;
  left: 0.75rem !important;
  top: 0.75rem !important;
}

[data-testid="collapsedControl"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="stSidebarCollapseButton"] {
  display: flex !important;
  visibility: visible !important;
  opacity: 1 !important;
  z-index: 1000 !important;
}

[data-testid="collapsedControl"] button,
[data-testid="stSidebarCollapsedControl"] button,
[data-testid="stSidebarCollapseButton"] button {
  background: rgba(8,16,24,0.92) !important;
  color: var(--ink-0) !important;
  border: 1px solid var(--line) !important;
  border-radius: 999px !important;
  box-shadow: 0 12px 24px rgba(0,0,0,0.24);
}

.hero-shell {
  border: 1px solid var(--line);
  background:
    linear-gradient(135deg, rgba(18,36,49,0.94), rgba(8,16,24,0.98)),
    radial-gradient(circle at right top, rgba(61,213,152,0.18), transparent 24%);
  border-radius: 26px;
  padding: 28px 30px;
  box-shadow: 0 28px 72px rgba(0,0,0,0.34);
  margin-bottom: 20px;
}

.hero-kicker {
  color: #8df3bf;
  letter-spacing: 0.16em;
  font-size: 0.72rem;
  text-transform: uppercase;
  margin-bottom: 10px;
}

.hero-title {
  font-size: 2.65rem;
  line-height: 0.98;
  font-weight: 700;
  margin: 0 0 14px 0;
}

.hero-sub {
  color: var(--ink-1);
  max-width: 820px;
  margin: 0;
  font-size: 1.02rem;
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 18px 0 20px 0;
}

.stat-tile {
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 18px;
  background: rgba(255,255,255,0.035);
}

.stat-label {
  color: var(--ink-2);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.stat-value {
  color: var(--ink-0);
  font-size: 1.95rem;
  font-weight: 700;
  margin-top: 6px;
}

.feature-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.feature-tile {
  border: 1px solid var(--line);
  border-radius: 20px;
  background: rgba(255,255,255,0.035);
  padding: 18px;
}

.feature-title {
  color: var(--ink-0);
  font-weight: 700;
  margin-bottom: 6px;
}

.feature-body {
  color: var(--ink-1);
  font-size: 0.92rem;
  line-height: 1.45;
}

.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
}

.panel-title {
  font-size: 1.28rem;
  font-weight: 700;
  color: var(--ink-0);
}

.panel-badge {
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.panel-badge.good {
  background: var(--good-soft);
  color: #94f5c1;
}

.panel-badge.bad {
  background: var(--bad-soft);
  color: #ff9d9d;
}

.panel-badge.warn {
  background: rgba(255, 209, 102, 0.14);
  color: #ffe29a;
}

.panel-badge.info {
  background: rgba(115,194,251,0.12);
  color: #9fd8ff;
}

.flow-card {
  border: 1px solid var(--line);
  border-radius: 22px;
  padding: 18px;
  margin-bottom: 14px;
  background: var(--panel);
  box-shadow: 0 16px 40px rgba(0,0,0,0.20);
}

.flow-card.good {
  box-shadow: inset 0 0 0 1px rgba(61,213,152,0.26), 0 16px 40px rgba(0,0,0,0.18);
  background: linear-gradient(180deg, rgba(13,33,28,0.92), rgba(11,21,27,0.96));
}

.flow-card.bad {
  box-shadow: inset 0 0 0 1px rgba(255,107,107,0.24), 0 16px 40px rgba(0,0,0,0.18);
  background: linear-gradient(180deg, rgba(37,20,24,0.94), rgba(12,21,29,0.98));
}

.flow-card.warn {
  box-shadow: inset 0 0 0 1px rgba(255,209,102,0.24), 0 16px 40px rgba(0,0,0,0.18);
  background: linear-gradient(180deg, rgba(39,30,17,0.94), rgba(12,21,29,0.98));
}

.flow-top {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: start;
}

.flow-title {
  font-size: 1rem;
  font-weight: 700;
  margin: 0 0 6px 0;
}

.flow-title.good {
  color: #9cf2c5;
}

.flow-title.bad {
  color: #ffb0b0;
}

.flow-title.warn {
  color: #ffe29a;
}

.flow-meta {
  color: var(--ink-1);
  font-size: 0.86rem;
}

.flow-chip {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 6px 10px;
  background: rgba(255,255,255,0.06);
  color: var(--ink-0);
  font-size: 0.76rem;
  margin-left: 6px;
  margin-bottom: 6px;
}

.flow-summary {
  color: var(--ink-1);
  font-size: 0.92rem;
  line-height: 1.5;
  margin-top: 12px;
}

.flow-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 14px;
}

.flow-kv {
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 11px 12px;
  background: rgba(255,255,255,0.03);
}

.flow-k {
  color: var(--ink-2);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 5px;
}

.flow-v {
  color: var(--ink-0);
  font-size: 0.93rem;
  word-break: break-word;
}

.rail-shell {
  border: 1px solid var(--line);
  border-radius: 24px;
  background: rgba(8,18,26,0.74);
  padding: 18px;
  min-height: 100%;
}

.defense-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 0 0 16px 0;
}

.defense-card {
  border: 1px solid var(--line);
  border-radius: 18px;
  background: rgba(255,255,255,0.03);
  padding: 16px;
}

.defense-kicker {
  color: var(--ink-2);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.73rem;
  margin-bottom: 6px;
}

.defense-title {
  color: var(--ink-0);
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 6px;
}

.defense-body {
  color: var(--ink-1);
  font-size: 0.9rem;
  line-height: 1.45;
}

.passport-card {
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 18px;
  background: rgba(255,255,255,0.03);
  margin-bottom: 14px;
}

.passport-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.passport-title {
  font-weight: 700;
  color: var(--ink-0);
}

.trust-pill {
  border-radius: 999px;
  padding: 6px 10px;
  font-size: 0.78rem;
  font-weight: 700;
}

.trust-high {
  background: var(--good-soft);
  color: #90f2bf;
}

.trust-mid {
  background: rgba(242,185,75,0.12);
  color: #ffd27f;
}

.trust-low {
  background: var(--bad-soft);
  color: #ffb0b0;
}

.passport-body {
  color: var(--ink-1);
  font-size: 0.9rem;
  line-height: 1.45;
}

.section-shell {
  border: 1px solid var(--line);
  border-radius: 24px;
  background: rgba(7, 14, 21, 0.78);
  padding: 18px 18px 10px 18px;
  margin-bottom: 16px;
}

@media (max-width: 900px) {
  .stat-grid, .feature-row, .flow-grid, .defense-grid {
    grid-template-columns: 1fr;
  }
}
</style>
        """,
        unsafe_allow_html=True,
    )


def reset_session(config: AppConfig) -> None:
    get_control_center().reset_runtime(config=config, preserve_auth=True)


def apply_signal_secret(new_secret: str) -> None:
    get_control_center().apply_signal_secret(new_secret)


def apply_session_nonce(new_nonce: str) -> None:
    get_control_center().apply_session_nonce(new_nonce)


def apply_satellite_profile(profile_id: str) -> None:
    get_control_center().apply_satellite_profile(profile_id)


def ingest_packets(
    raw_packets: Iterable[str | dict],
    run_truth: list[dict] | None = None,
    run_meta: dict | None = None,
) -> list[DecisionRecord]:
    return get_control_center().ingest_packets(raw_packets, run_truth=run_truth, run_meta=run_meta)


def push_notice(level: str, message: str) -> None:
    get_control_center().push_notice(level, message)


def consume_notice() -> dict | None:
    return get_control_center().consume_notice()


def decision_rows(records: list[DecisionRecord]) -> list[dict]:
    return [
        {
            "packet_id": record.packet_id or "parse-failed",
            "source": record.source or "-",
            "decision": record.decision,
            "classification": human_label(record.classification),
            "failed_layer": record.failed_layer or 0,
            "failed_layer_label": LAYER_LABELS.get(record.failed_layer or 0, "Accepted"),
            "attack_stage": record.attack_stage or 0,
            "defense_mechanism": record.defense_mechanism,
            "service_mode": record.service_mode,
            "deception_triggered": record.deception_triggered,
            "credential_leak_suspect": record.credential_leak_suspect,
            "mission_breach": record.mission_breach,
            "trust_bulletin_id": record.trust_bulletin_id or "-",
            "quorum_result": record.quorum_result,
            "forensic_case_id": record.forensic_case_id or "-",
            "twin_engaged": record.twin_engaged,
            "shadow_session_id": record.shadow_session_id or "-",
            "threat_intel_score": record.threat_intel_score,
            "trust_score": record.trust_score,
            "latency_ms": record.latency_ms,
            "signature": human_label(record.anomaly_signature),
        }
        for record in records
    ]


def trace_rows(record: DecisionRecord) -> list[dict]:
    return [
        {
            "layer_id": item.layer_id,
            "layer": LAYER_LABELS[item.layer_id],
            "passed": item.passed,
            "reason_code": item.reason_code,
            "classification": item.classification,
            "latency_ms": item.latency_ms,
            "details": item.details,
        }
        for item in record.trace
    ]


def summarize_groups(records: list[DecisionRecord]) -> list[dict]:
    rows = []
    for group_name, layer_ids in GROUPS.items():
        failures = [item for item in records if item.failed_layer in layer_ids]
        rows.append(
            {
                "group": group_name,
                "blocked_packets": len(failures),
                "dominant_reason": Counter(item.classification for item in failures).most_common(1)[0][0]
                if failures
                else "normal",
            }
        )
    return rows


def summarize_run_quality(results: list[DecisionRecord], truth: list[dict]) -> dict[str, float | int]:
    paired = list(zip(results, truth))
    if not paired:
        return {}

    true_attacks = sum(1 for _, item in paired if item.get("label") == "attack")
    true_normals = sum(1 for _, item in paired if item.get("label") == "normal")
    true_positive = sum(
        1 for result, item in paired if item.get("label") == "attack" and result.decision == "blocked"
    )
    false_negative = sum(
        1 for result, item in paired if item.get("label") == "attack" and result.decision == "accepted"
    )
    false_positive = sum(
        1 for result, item in paired if item.get("label") == "normal" and result.decision == "blocked"
    )
    true_negative = sum(
        1 for result, item in paired if item.get("label") == "normal" and result.decision == "accepted"
    )
    total = len(paired)
    accuracy = round(((true_positive + true_negative) / total) * 100, 1)
    recall = round((true_positive / true_attacks) * 100, 1) if true_attacks else 0.0
    precision = round((true_positive / (true_positive + false_positive)) * 100, 1) if (true_positive + false_positive) else 0.0
    deception_hits = sum(1 for result, item in paired if item.get("label") == "attack" and result.deception_triggered)
    twin_engagements = sum(1 for result, item in paired if item.get("label") == "attack" and result.twin_engaged)
    holdover_activations = sum(1 for result, _ in paired if result.service_mode == "holdover")
    quorum_disagreements = sum(1 for result, _ in paired if result.quorum_result == "disagreement")
    return {
        "total": total,
        "true_attacks": true_attacks,
        "true_normals": true_normals,
        "true_positive": true_positive,
        "false_negative": false_negative,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "accuracy": accuracy,
        "recall": recall,
        "precision": precision,
        "deception_hits": deception_hits,
        "twin_engagements": twin_engagements,
        "holdover_activations": holdover_activations,
        "quorum_disagreements": quorum_disagreements,
    }


def stage_detection_rows(results: list[DecisionRecord], truth: list[dict]) -> list[dict]:
    paired = list(zip(results, truth))
    stage_buckets: dict[int, list[tuple[DecisionRecord, dict]]] = defaultdict(list)
    for result, item in paired:
        stage_buckets[int(item.get("stage", 0))].append((result, item))

    rows = []
    for stage in sorted(stage_buckets):
        items = stage_buckets[stage]
        blocked = sum(1 for result, _ in items if result.decision == "blocked")
        rows.append(
            {
                "stage": stage,
                "profile": items[0][1].get("profile", "-"),
                "total_packets": len(items),
                "blocked": blocked,
                "accepted": len(items) - blocked,
                "catch_rate": round((blocked / len(items)) * 100, 1) if items else 0.0,
            }
        )
    return rows


def family_detection_rows(results: list[DecisionRecord], truth: list[dict]) -> list[dict]:
    paired = list(zip(results, truth))
    buckets: dict[str, list[tuple[DecisionRecord, dict]]] = defaultdict(list)
    for result, item in paired:
        buckets[str(item.get("family", "unknown"))].append((result, item))

    rows = []
    for family in sorted(buckets):
        items = buckets[family]
        blocked = sum(1 for result, _ in items if result.decision == "blocked")
        trap_hits = sum(1 for result, _ in items if result.deception_triggered)
        holdover = sum(1 for result, _ in items if result.service_mode == "holdover")
        rows.append(
            {
                "family": family,
                "profile": items[0][1].get("profile", "-"),
                "total_packets": len(items),
                "blocked": blocked,
                "accepted": len(items) - blocked,
                "deception_hits": trap_hits,
                "holdover": holdover,
                "catch_rate": round((blocked / len(items)) * 100, 1) if items else 0.0,
            }
        )
    return rows


def micro_layer_rows(records: list[DecisionRecord], authenticated: bool) -> list[dict]:
    fail_counts = Counter(item.failed_layer for item in records if item.failed_layer is not None)
    rows = [
        {
            "layer_id": 0,
            "layer": LAYER_LABELS[0],
            "blocked_packets": 0 if authenticated else 1,
            "status": "authenticated" if authenticated else "locked",
        }
    ]
    for layer_id in range(1, 14):
        rows.append(
            {
                "layer_id": layer_id,
                "layer": LAYER_LABELS[layer_id],
                "blocked_packets": fail_counts.get(layer_id, 0),
                "status": "active",
            }
        )
    return rows


def parse_payload(payload_view: str | None) -> dict | None:
    if not payload_view:
        return None


def bulletin_payload_view(active_bulletin) -> dict:
    if active_bulletin is None:
        return {}
    return {
        "bulletin_id": active_bulletin.bulletin_id,
        "valid_from": active_bulletin.valid_from.isoformat(),
        "valid_to": active_bulletin.valid_to.isoformat(),
        "risk_zones": [
            {
                "name": zone.name,
                "center_latitude": zone.center_latitude,
                "center_longitude": zone.center_longitude,
                "radius_m": zone.radius_m,
                "severity": zone.severity,
            }
            for zone in active_bulletin.risk_zones
        ],
        "source_risk": dict(active_bulletin.source_risk),
        "threshold_overrides": dict(active_bulletin.threshold_overrides),
        "signature": active_bulletin.signature,
    }
    try:
        return json.loads(payload_view)
    except json.JSONDecodeError:
        return None


def format_short_time(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return value[11:19] if "T" in value else value[:8]
    except Exception:
        return value


def format_location(metrics: dict) -> str:
    latitude = metrics.get("latitude")
    longitude = metrics.get("longitude")
    if latitude is None or longitude is None:
        return "-"
    try:
        return f"{float(latitude):.4f}, {float(longitude):.4f}"
    except (TypeError, ValueError):
        return "-"


def human_label(value: str | None) -> str:
    if not value:
        return "-"
    return CLASSIFICATION_LABELS.get(value, SIGNATURE_LABELS.get(value, value.replace("_", " ")))


def compact_payload(record: DecisionRecord) -> dict[str, str]:
    payload = parse_payload(record.payload_view)
    if not payload:
        return {
            "Kaynak": record.source or "-",
            "Durum": human_label(record.classification),
            "Savunma": record.defense_mechanism or "-",
            "Mod": record.service_mode,
            "Icerik": (record.payload_view or "-")[:120],
        }

    signal_payload = payload.get("payload", {})
    metrics = payload.get("metrics", {})
    return {
        "Zaman": format_short_time(str(payload.get("ts", "-"))),
        "Kaynak": str(payload.get("source", record.source or "-")),
        "Platform": str(signal_payload.get("satellite_id", signal_payload.get("satellite_profile_id", "-"))),
        "Kanal": str(signal_payload.get("channel", "-")),
        "Band": str(signal_payload.get("downlink_band", signal_payload.get("uplink_band", "-"))),
        "Protokol": str(signal_payload.get("protocol_family", "-")),
        "Seq": str(payload.get("seq", "-")),
        "Epoch": str(payload.get("epoch_id", "-")),
        "C/N0": str(metrics.get("cn0", "-")),
        "Doppler": str(metrics.get("doppler", "-")),
        "Uydu": str(metrics.get("sat_count", "-")),
        "Hiz": str(metrics.get("speed", "-")),
        "Konum": format_location(metrics),
    }


def render_signal_card(record: DecisionRecord, tone: str) -> str:
    is_accepted = record.decision == "accepted"
    title = (
        "Guvenli devam modu"
        if record.service_mode == "holdover"
        else "Normal kalan trafik"
        if tone == "good"
        else "Golge ikize yonlendirilen trafik"
        if record.twin_engaged
        else "Mission breach trafik"
        if record.mission_breach
        else "Sifre sizintisi supheli trafik"
        if record.credential_leak_suspect
        else "Tuzaga basan trafik"
        if record.deception_triggered
        else "Reddedilen trafik"
    )
    layer_text = "Tum katmanlardan gecti" if record.decision == "accepted" else LAYER_LABELS.get(record.failed_layer or 0, "Bilinmiyor")
    data = compact_payload(record)
    grid_html = "".join(
        (
            f'<div class="flow-kv">'
            f'<div class="flow-k">{html.escape(key)}</div>'
            f'<div class="flow-v">{html.escape(value)}</div>'
            f"</div>"
        )
        for key, value in data.items()
    )
    decision_text = human_label(record.classification)
    reason_text = human_label(record.anomaly_signature)
    service_mode = record.service_mode.replace("_", " ")
    leak_warning = (
        " | Kritik: operasyonel dogrulama gecti, sifre sizintisi supheli"
        if record.credential_leak_suspect
        else ""
    )
    mission_warning = " | Mission envelope ihlali" if record.mission_breach else ""
    twin_warning = " | Dijital ikiz devrede" if record.twin_engaged else ""
    summary = (
        f"Durum: {html.escape(decision_text)} | Mod: {html.escape(service_mode)}{html.escape(leak_warning)}{html.escape(mission_warning)}{html.escape(twin_warning)}"
        if is_accepted
        else f"Durum: {html.escape(decision_text)} | Savunma: {html.escape(record.defense_mechanism)} | Mod: {html.escape(service_mode)}{html.escape(leak_warning)}{html.escape(mission_warning)}{html.escape(twin_warning)} | Neden: {html.escape(reason_text)}"
    )
    return (
        f'<div class="flow-card {tone}">'
        f'<div class="flow-top">'
        f'<div><div class="flow-title {tone}">{title}</div>'
        f'<div class="flow-meta">{html.escape(record.processed_at.strftime("%H:%M:%S") if record.processed_at else "-")}</div></div>'
        f'<div><span class="flow-chip">Guven {record.trust_score}</span><span class="flow-chip">{html.escape(service_mode)}</span>'
        f'{"<span class=\"flow-chip\">Sizinti alarmi</span>" if record.credential_leak_suspect else ""}'
        f'{"<span class=\"flow-chip\">Mission breach</span>" if record.mission_breach else ""}'
        f'{"<span class=\"flow-chip\">Golge ikiz</span>" if record.twin_engaged else ""}'
        f'{"<span class=\"flow-chip\">Intel " + str(record.threat_intel_score) + "</span>" if record.twin_engaged else ""}</div>'
        f"</div>"
        f'<div class="flow-summary">{summary}</div>'
        f'<div class="flow-grid">{grid_html}</div>'
        f"</div>"
    )


def render_credential_leak_alert(records: list[DecisionRecord]) -> None:
    flagged = [item for item in records if item.credential_leak_suspect]
    if not flagged:
        return
    latest = flagged[-1]
    layer_text = LAYER_LABELS.get(latest.failed_layer or 0, "Bilinmiyor")
    st.error(
        "Kritik Uyari: Operasyonel dogrulamayi gecen trafik daha sonra derin savunma katmaninda reddedildi. "
        f"Son olay kaynak `{latest.source or '-'}` icin `{layer_text}` noktasinda yakalandi. "
        "Sistem bunu olasi sifre sizintisi olarak isaretledi."
    )


def render_mission_breach_alert(records: list[DecisionRecord]) -> None:
    flagged = [item for item in records if item.mission_breach]
    if not flagged:
        return
    latest = flagged[-1]
    st.warning(
        "Mission Uyarisi: Paket operasyonel mission envelope disina cikti. "
        f"Son olay kaynak `{latest.source or '-'}` icin `{human_label(latest.anomaly_signature)}` seklinde isaretlendi."
    )


def render_shadow_twin_alert(records: list[DecisionRecord]) -> None:
    flagged = [item for item in records if item.twin_engaged]
    if not flagged:
        return
    latest = flagged[-1]
    twin_id = latest.shadow_session_id or "-"
    family = human_label(str(latest.attacker_profile.get("attack_family")))
    vector = human_label(str(latest.attacker_profile.get("attack_vector")))
    indicator = human_label(str(latest.attacker_profile.get("primary_indicator")))
    recommendation = str(latest.attacker_profile.get("operator_recommendation", "Kaynak izleniyor."))
    st.info(
        "Dijital Ikiz Devrede: Derin anomali gercek veri duzleminden ayrildi ve kontrollu golge ortama yonlendirildi. "
        f"Son twin oturumu `{twin_id}` kaynak `{latest.source or '-'}` icin acildi. "
        f"Tur `{family}` | Vektor `{vector}` | Kanit `{indicator}` | Aksiyon `{recommendation}`"
    )


def format_listener_timestamp(value) -> str:
    if value is None:
        return "-"
    try:
        return value.strftime("%H:%M:%S")
    except Exception:
        return str(value)


def show_record_stream(records: list[DecisionRecord], accepted: bool, limit: int = 6) -> None:
    if not records:
        message = "Henuz kabul edilen veri yok." if accepted else "Henuz red edilen veri yok."
        st.info(message)
        return
    for record in records[-limit:][::-1]:
        st.markdown(render_signal_card(record, tone="good" if accepted else "bad"), unsafe_allow_html=True)


def render_stream_panel(
    records: list[DecisionRecord],
    title: str,
    accepted: bool | None = None,
    tone: str | None = None,
    limit: int = 6,
    badge_count: int | None = None,
) -> str:
    if tone is None:
        tone = "good" if accepted is not False else "bad"
    count_value = len(records) if badge_count is None else badge_count
    if not records:
        if accepted is True:
            empty = "Henuz kabul edilen veri yok."
        elif accepted is False:
            empty = "Henuz red edilen veri yok."
        else:
            empty = "Henuz veri yok."
        content = f'<div class="passport-body">{html.escape(empty)}</div>'
    else:
        content = "".join(render_signal_card(record, tone=tone) for record in records[-limit:][::-1])
    return (
        '<div class="rail-shell">'
        '<div class="panel-head">'
        f'<div class="panel-title">{html.escape(title)}</div>'
        f'<div class="panel-badge {tone}">{count_value}</div>'
        "</div>"
        f"{content}"
        "</div>"
    )


def build_source_passports(records: list[DecisionRecord]) -> list[dict]:
    return BKZSControlCenter.build_source_passports(records)


def render_passport_card(passport: dict) -> str:
    trust = passport["trust"]
    tone = "trust-high" if trust >= 85 else "trust-mid" if trust >= 60 else "trust-low"
    body = (
        f"Kabul {passport['accepted']} | Red {passport['rejected']} | "
        f"Imza {passport['signature']} | Ortalama gecikme {passport['latency_ms']} ms"
    )
    return (
        '<div class="passport-card">'
        '<div class="passport-head">'
        f'<div class="passport-title">{html.escape(passport["source"])}</div>'
        f'<div class="trust-pill {tone}">Trust {passport["trust"]}</div>'
        "</div>"
        f'<div class="passport-body">{html.escape(body)}</div>'
        "</div>"
    )


def render_passport_panel(passports: list[dict]) -> str:
    if not passports:
        body = '<div class="passport-body">Pasaport olusmasi icin veri akisi gerekli.</div>'
    else:
        body = "".join(render_passport_card(passport) for passport in passports[:4])
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Kaynak Pasaportu</div>'
        '<div class="panel-badge info">Kaynak Guveni</div>'
        "</div>"
        f"{body}"
        "</div>"
    )


def render_operations_panel(active_bulletin, response_modes: dict[str, int], mission_breach_records: list[DecisionRecord]) -> str:
    bulletin_body = (
        f"Aktif bulletin `{active_bulletin.bulletin_id}` | Risk bolgesi {active_bulletin.risk_zone_count} | "
        f"Kaynak riski {len(active_bulletin.source_risk)} | Override {len(active_bulletin.threshold_overrides)}"
        if active_bulletin is not None
        else "Aktif trust bulletin yok."
    )
    response_body = " | ".join(f"{mode}: {count}" for mode, count in sorted(response_modes.items())) if response_modes else "Henuz response mode yok."
    mission_body = (
        f"Mission breach sayisi {len(mission_breach_records)} | Son kayit {mission_breach_records[-1].source or '-'}"
        if mission_breach_records
        else "Mission envelope ihlali gorulmedi."
    )
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Operasyon Ozeti</div>'
        '<div class="panel-badge warn">Live Policy</div>'
        "</div>"
        f'<div class="passport-card"><div class="passport-title">Aktif Bulletin</div><div class="passport-body">{html.escape(bulletin_body)}</div></div>'
        f'<div class="passport-card"><div class="passport-title">Response Mode</div><div class="passport-body">{html.escape(response_body)}</div></div>'
        f'<div class="passport-card"><div class="passport-title">Mission Breach</div><div class="passport-body">{html.escape(mission_body)}</div></div>'
        "</div>"
    )


def render_satellite_profile_panel(profile) -> str:
    details = [
        f"Profil {profile.display_name}",
        f"Alan {profile.mission_domain}",
        f"Yorunge {profile.orbit_type}",
    ]
    if profile.orbital_slot_deg_e is not None:
        details.append(f"Slot {profile.orbital_slot_deg_e}E")
    if profile.altitude_km is not None:
        details.append(f"Irtifa {profile.altitude_km} km")
    if profile.allowed_downlink_bands:
        details.append(f"Downlink {', '.join(profile.allowed_downlink_bands)}")
    if profile.allowed_protocols:
        details.append(f"Protokol {', '.join(profile.allowed_protocols)}")
    body = " | ".join(details)
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Uydu Profili</div>'
        '<div class="panel-badge info">Active Profile</div>'
        "</div>"
        f'<div class="passport-card"><div class="passport-title">{html.escape(profile.display_name)}</div><div class="passport-body">{html.escape(body)}<br>{html.escape(profile.public_note)}</div></div>'
        "</div>"
    )


def render_forensic_panel(forensic_cases) -> str:
    if not forensic_cases:
        body = '<div class="passport-body">Henuz forensic case uretilmedi.</div>'
    else:
        latest_cases = "".join(
            (
                '<div class="passport-card">'
                f'<div class="passport-head"><div class="passport-title">{html.escape(case.case_id)}</div>'
                f'<div class="trust-pill trust-mid">{html.escape(case.service_mode)}</div></div>'
                f'<div class="passport-body">{html.escape(case.summary)}</div>'
                "</div>"
            )
            for case in forensic_cases[-3:][::-1]
        )
        body = latest_cases
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Forensic Black Box</div>'
        '<div class="panel-badge info">Case Feed</div>'
        "</div>"
        f"{body}"
        "</div>"
    )


def render_relay_panel(real_plane_events, shadow_plane_events) -> str:
    def render_event(event, badge: str) -> str:
        fallback_text = "fallback temiz veri" if event.used_fallback else "canli temiz veri"
        return (
            '<div class="passport-card">'
            f'<div class="passport-head"><div class="passport-title">{html.escape(event.channel_name)}</div>'
            f'<div class="trust-pill trust-mid">{html.escape(event.status)}</div></div>'
            f'<div class="passport-body">{html.escape(event.summary)}<br>'
            f'Port {event.port} | {event.protocol.upper()} | {fallback_text} | Paket {event.packet_id}</div>'
            "</div>"
        )

    if not real_plane_events and not shadow_plane_events:
        body = '<div class="passport-body">Henuz split-plane relay olayi yok.</div>'
    else:
        body = ""
        if real_plane_events:
            body += "".join(render_event(event, "real") for event in real_plane_events[-2:][::-1])
        if shadow_plane_events:
            body += "".join(render_event(event, "shadow") for event in shadow_plane_events[-2:][::-1])
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Split-Plane Relay</div>'
        '<div class="panel-badge good">Continuity</div>'
        "</div>"
        f"{body}"
        "</div>"
    )


def render_shadow_twin_panel(shadow_sessions) -> str:
    if not shadow_sessions:
        body = '<div class="passport-body">Henuz golge ikiz yonlendirmesi yok.</div>'
    else:
        body = "".join(
            (
                '<div class="passport-card">'
                f'<div class="passport-head"><div class="passport-title">{html.escape(session.session_id)}</div>'
                f'<div class="trust-pill trust-high">Intel {session.threat_intel_score}</div></div>'
                f'<div class="passport-body">Tur {html.escape(human_label(session.attack_family))} | '
                f'Vektor {html.escape(human_label(session.attack_vector))} | '
                f'Gosterge {html.escape(human_label(session.primary_indicator))}<br>'
                f'{html.escape(session.summary)}<br>'
                f'Aksiyon: {html.escape(session.operator_recommendation)}</div>'
                "</div>"
            )
            for session in shadow_sessions[-3:][::-1]
        )
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Digital Twin Router</div>'
        '<div class="panel-badge warn">Shadow Plane</div>'
        "</div>"
        f"{body}"
        "</div>"
    )


def render_threat_intel_panel(threat_intel_events) -> str:
    if not threat_intel_events:
        body = '<div class="passport-body">Henuz tehdit istihbarati olayi yok.</div>'
    else:
        body = "".join(
            (
                '<div class="passport-card">'
                f'<div class="passport-head"><div class="passport-title">{html.escape(event.source)}</div>'
                f'<div class="trust-pill trust-mid">{html.escape(event.confidence)}</div></div>'
                f'<div class="passport-body">Tur {html.escape(human_label(event.attack_family))} | '
                f'Vektor {html.escape(human_label(event.attack_vector))} | '
                f'Kanit {html.escape(human_label(event.primary_indicator))}<br>'
                f'{html.escape(event.intel_summary)}<br>'
                f'Oneri: {html.escape(event.operator_recommendation)}</div>'
                "</div>"
            )
            for event in threat_intel_events[-3:][::-1]
        )
    return (
        '<div class="section-shell">'
        '<div class="panel-head">'
        '<div class="panel-title">Threat Intel Feed</div>'
        '<div class="panel-badge info">Observatory</div>'
        "</div>"
        f"{body}"
        "</div>"
    )


def render_defense_strip(session_nonce: str, locked_sources: dict[str, float]) -> None:
    locked_body = "Aktif kaynak kilidi yok." if not locked_sources else ", ".join(
        f"{source} ({seconds}s)" for source, seconds in locked_sources.items()
    )
    st.markdown(
        (
            '<div class="defense-grid">'
            '<div class="defense-card">'
            '<div class="defense-kicker">Innovation</div>'
            '<div class="defense-title">Shadow Lane</div>'
            '<div class="defense-body">Gorunmeyen sahte referans akisi canary token uretir. Bu lane biliniyorsa saldirgan kendini ele verir.</div>'
            "</div>"
            '<div class="defense-card">'
            '<div class="defense-kicker">Innovation</div>'
            '<div class="defense-title">Epoch Bait Chain</div>'
            '<div class="defense-body">Her temiz epoch sonraki challenge proof icin yeni zincir uretir. Secret sizsa bile shadow token olmadan zincir devam etmez.</div>'
              "</div>"
              '<div class="defense-card">'
              '<div class="defense-kicker">Innovation</div>'
              '<div class="defense-title">Adaptive Lockdown</div>'
              f'<div class="defense-body">{html.escape(locked_body)}</div>'
              "</div>"
              '<div class="defense-card">'
              '<div class="defense-kicker">Innovation</div>'
              '<div class="defense-title">Digital Twin Router</div>'
              '<div class="defense-body">Derin anomaliler gercek veri duzleminden ayrilir. Saldirgan icin sentetik kabul akisi acilirken sistem tehdit istihbarati toplar.</div>'
              "</div>"
              "</div>"
          ),
          unsafe_allow_html=True,
      )


def render_hero(
    total_packets: int,
    accepted_count: int,
    blocked_count: int,
    avg_latency: float,
    trust_pulse: int,
    active_passports: int,
    defended_layers: int,
) -> None:
    st.markdown(
        (
            '<div class="hero-shell">'
            '<div class="hero-kicker">BKZS Signal Defense Matrix</div>'
            '<div class="hero-title">Canli Operasyon ve Sinyal Savunma Durumu</div>'
            '<p class="hero-sub">Arayuz sade ve net. Cekirdekte ise zarf, oturum muhru, adaptif kilit, RF, zaman, mekan ve konsensus katmanlari erken durdurma mantigi ile calisiyor.</p>'
            '<div class="stat-grid">'
            f'<div class="stat-tile"><div class="stat-label">Toplam Paket</div><div class="stat-value">{total_packets}</div></div>'
            f'<div class="stat-tile"><div class="stat-label">Kabul</div><div class="stat-value">{accepted_count}</div></div>'
            f'<div class="stat-tile"><div class="stat-label">Red</div><div class="stat-value">{blocked_count}</div></div>'
            f'<div class="stat-tile"><div class="stat-label">Ort. Gecikme</div><div class="stat-value">{avg_latency} ms</div></div>'
            "</div>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def show_login(config: AppConfig) -> None:
    inject_css()
    st.markdown(
        """
<div class="hero-shell">
  <div class="hero-kicker">BKZS Guard Access</div>
  <div class="hero-title">Operasyonel Giris</div>
  <p class="hero-sub">Kontrol paneli yalnizca yetkili operatorler icindir. Giris sonrasi sinyal sifresi panelden degistirilebilir.</p>
</div>
        """,
        unsafe_allow_html=True,
    )
    password = st.text_input("Operasyonel sifre", type="password")
    if st.button("Panele Gir", width="stretch"):
        if get_control_center().authenticate(password):
            st.rerun()
        st.error("Sifre gecersiz.")
    st.stop()


def main() -> None:
    config = load_app_config()
    st.set_page_config(page_title="BKZS Guard", layout="wide")
    bootstrap(config)
    inject_css()

    app = get_control_center()
    if not app.authenticated:
        show_login(app.config)

    config = app.config
    sync_remote_attack_profile(config)
    active_satellite_profile = get_satellite_profile(config.mission.satellite_profile_id)
    dashboard = app.dashboard_snapshot()
    records = dashboard.records
    quarantined = dashboard.quarantined
    accepted_records = dashboard.accepted_records
    normal_records = dashboard.normal_records
    trap_records = dashboard.trap_records
    holdover_records = dashboard.holdover_records
    credential_leak_records = dashboard.credential_leak_records
    mission_breach_records = dashboard.mission_breach_records
    twin_records = dashboard.twin_records
    passports = dashboard.passports
    locked_sources = dashboard.locked_sources
    active_bulletin = dashboard.active_bulletin
    forensic_cases = dashboard.forensic_cases
    shadow_twin_sessions = dashboard.shadow_twin_sessions
    threat_intel_events = dashboard.threat_intel_events
    real_plane_events = dashboard.real_plane_events
    shadow_plane_events = dashboard.shadow_plane_events
    response_modes = dashboard.response_modes

    notice = consume_notice()
    if notice:
        level = notice.get("level", "info")
        message = str(notice.get("message", ""))
        if level == "success":
            st.success(message)
        elif level == "warning":
            st.warning(message)
        elif level == "error":
            st.error(message)
        else:
            st.info(message)
    with st.sidebar:
        st.subheader("Canli Guvenlik Ayari")
        st.caption("Sinyal sifresi ve oturum muhru panelden degisir; yeni deger aninda savunma zincirine yansir.")
        satellite_options = satellite_profile_options()
        satellite_labels = {profile_id: label for profile_id, label in satellite_options}
        satellite_ids = list(satellite_labels)
        selected_satellite_profile = st.selectbox(
            "Uydu Profili",
            options=satellite_ids,
            index=satellite_ids.index(active_satellite_profile.profile_id) if active_satellite_profile.profile_id in satellite_ids else 0,
            format_func=lambda profile_id: satellite_labels[profile_id],
            key="satellite_profile_input",
        )
        if st.button("Uydu Profilini Uygula", width="stretch"):
            apply_satellite_profile(selected_satellite_profile)
            st.success("Uydu profili uygulandi ve runtime yeniden yuklendi.")
            st.rerun()
        new_signal_secret = st.text_input(
            "Sinyal sifresi",
            value=config.security.signal_secret,
            type="password",
            key="signal_secret_input",
        )
        if st.button("Sinyal Sifresini Uygula", width="stretch"):
            try:
                apply_signal_secret(new_signal_secret)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("Yeni sinyal sifresi uygulandi. Oturum verisi sifirlandi.")
                st.rerun()

        new_session_nonce = st.text_input(
            "Oturum muhru",
            value=config.security.session_nonce,
            type="password",
            key="session_nonce_input",
        )
        nonce_apply_col, nonce_rotate_col = st.columns(2)
        if nonce_apply_col.button("Muhru Uygula", width="stretch"):
            try:
                apply_session_nonce(new_session_nonce)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("Yeni oturum muhru uygulandi. Hazir saldiri akislarinin etiketi bozuldu.")
                st.rerun()
        if nonce_rotate_col.button("Muhru Dondur", width="stretch"):
            fresh_nonce = generate_session_nonce()
            apply_session_nonce(fresh_nonce)
            st.success("Yeni oturum muhru uretildi ve uygulandi.")
            st.rerun()

        st.subheader("Aktif Beklentiler")
        st.write(f"Beklenen op_code: `{config.security.expected_op_code}`")
        st.caption(
            f"Gorev kanali: `{config.mission.allowed_channel}` | Gorev fazi: `{config.mission.mission_phase}` | "
            f"Aktif platform: `{active_satellite_profile.display_name}`"
        )
        if locked_sources:
            st.caption("Adaptif kilit altindaki kaynaklar")
            st.json(locked_sources)
        st.subheader("Trust Bulletin")
        bulletin_text = st.text_area(
            "Imzali bulletin JSON",
            height=180,
            value=json.dumps(bulletin_payload_view(active_bulletin), ensure_ascii=True, indent=2) if active_bulletin else json.dumps(app.sample_bulletin_payload(), ensure_ascii=True, indent=2),
            key="trust_bulletin_text",
        )
        bulletin_col1, bulletin_col2, bulletin_col3 = st.columns(3)
        if bulletin_col1.button("Bulletin Uygula", width="stretch"):
            try:
                app.apply_trust_bulletin(bulletin_text)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("Trust bulletin uygulandi.")
                st.rerun()
        if bulletin_col2.button("Ornek Bulletin", width="stretch"):
            st.session_state.trust_bulletin_text = json.dumps(app.sample_bulletin_payload(), ensure_ascii=True, indent=2)
            st.rerun()
        if bulletin_col3.button("Bulletin Temizle", width="stretch"):
            app.clear_trust_bulletin()
            st.success("Trust bulletin temizlendi.")
            st.rerun()
        if st.button("Oturumu Sifirla", width="stretch"):
            reset_session(config)
            st.rerun()

    jury_tab, remote_tab, threat_tab, report_tab, adapter_tab, debug_tab = st.tabs(
        ["Canli Operasyon", "Uzak Saldiri Dugumu", "Tehdit Kaynaklari", "Karantina Raporu", "Gercek Adaptor", "Debug"]
    )

    fast_refresh = 0.25 if app.is_network_listener_active() else None
    slow_refresh = 0.9 if app.is_network_listener_active() else None

    @st.fragment(run_every=fast_refresh)
    def render_operation_fragment() -> None:
        live_dashboard = app.dashboard_snapshot()
        live_active_satellite_profile = get_satellite_profile(app.config.mission.satellite_profile_id)
        live_records = live_dashboard.records
        live_quarantined = live_dashboard.quarantined
        live_accepted_records = live_dashboard.accepted_records
        live_passports = live_dashboard.passports
        live_active_bulletin = live_dashboard.active_bulletin
        live_forensic_cases = live_dashboard.forensic_cases
        live_shadow_twin_sessions = live_dashboard.shadow_twin_sessions
        live_threat_intel_events = live_dashboard.threat_intel_events
        live_real_plane_events = live_dashboard.real_plane_events
        live_shadow_plane_events = live_dashboard.shadow_plane_events
        live_response_modes = live_dashboard.response_modes
        live_credential_leak_records = live_dashboard.credential_leak_records
        live_mission_breach_records = live_dashboard.mission_breach_records
        live_twin_records = live_dashboard.twin_records

        render_hero(
            total_packets=live_dashboard.total_packets,
            accepted_count=live_dashboard.accepted_count,
            blocked_count=live_dashboard.blocked_count,
            avg_latency=live_dashboard.avg_latency,
            trust_pulse=live_dashboard.trust_pulse,
            active_passports=len(live_passports),
            defended_layers=13,
        )
        render_credential_leak_alert(app.last_run_results or live_credential_leak_records[-3:])
        render_mission_breach_alert(app.last_run_results or live_mission_breach_records[-3:])
        render_shadow_twin_alert(app.last_run_results or live_twin_records[-3:])

        left_col, right_col = st.columns((1.5, 1))
        with left_col:
            accepted_col, blocked_col = st.columns(2)
            with accepted_col:
                st.markdown(
                    render_stream_panel(
                        live_accepted_records,
                        accepted=True,
                        title="Kabul Edilenler",
                        badge_count=live_dashboard.accepted_count,
                    ),
                    unsafe_allow_html=True,
                )
            with blocked_col:
                st.markdown(
                    render_stream_panel(
                        live_quarantined,
                        accepted=False,
                        title="Red Edilenler",
                        badge_count=live_dashboard.blocked_count,
                    ),
                    unsafe_allow_html=True,
                )

        with right_col:
            st.markdown(render_satellite_profile_panel(live_active_satellite_profile), unsafe_allow_html=True)
            st.markdown(render_passport_panel(live_passports), unsafe_allow_html=True)
            st.markdown(render_operations_panel(live_active_bulletin, live_response_modes, live_mission_breach_records), unsafe_allow_html=True)
            st.markdown(render_relay_panel(live_real_plane_events, live_shadow_plane_events), unsafe_allow_html=True)
            st.markdown(render_forensic_panel(live_forensic_cases), unsafe_allow_html=True)
            st.markdown(render_shadow_twin_panel(live_shadow_twin_sessions), unsafe_allow_html=True)
            st.markdown(render_threat_intel_panel(live_threat_intel_events), unsafe_allow_html=True)

            if live_accepted_records:
                st.markdown(
                    '<div class="panel-head" style="margin-top:18px;"><div class="panel-title">Son Temiz Akis</div><div class="panel-badge good">Guven Nabzi</div></div>',
                    unsafe_allow_html=True,
                )
                latest_clean = live_accepted_records[-1]
                st.metric("Temiz Sinyal Guveni", f"{latest_clean.trust_score}/100")
                st.caption(f"Imza: {latest_clean.anomaly_signature}")

    @st.fragment(run_every=fast_refresh)
    def render_remote_fragment() -> None:
        live_dashboard = app.dashboard_snapshot()
        live_accepted_records = live_dashboard.accepted_records
        live_quarantined = live_dashboard.quarantined
        st.markdown(
            '<div class="panel-head"><div class="panel-title">Live Ekran</div><div class="panel-badge info">Canli Akis</div></div>',
            unsafe_allow_html=True,
        )
        live_accepted_col, live_blocked_col = st.columns(2, gap="large")
        with live_accepted_col:
            st.markdown(
                render_stream_panel(
                    live_accepted_records,
                    accepted=True,
                    title="Kabul Edilenler",
                    limit=12,
                    badge_count=live_dashboard.accepted_count,
                ),
                unsafe_allow_html=True,
            )
        with live_blocked_col:
            st.markdown(
                render_stream_panel(
                    live_quarantined,
                    accepted=False,
                    title="Red Edilenler",
                    limit=12,
                    badge_count=live_dashboard.blocked_count,
                ),
                unsafe_allow_html=True,
            )

    @st.fragment(run_every=fast_refresh)
    def render_listener_status_fragment() -> None:
        status = app.network_listener_snapshot()
        if status.active:
            st.success(
                f"Dinleme aktif: {status.protocol.upper()} {status.host}:{status.port} | "
                f"Alinan paket: {status.received_packets} | Son paket: {format_listener_timestamp(status.last_packet_at)}"
            )
        else:
            st.info("Dinleme pasif.")
        if status.last_error:
            st.error(f"Son adaptor hatasi: {status.last_error}")

    @st.fragment(run_every=slow_refresh)
    def render_threat_sources_fragment() -> None:
        live_dashboard = app.dashboard_snapshot()
        contacts = live_dashboard.remote_threat_contacts
        remote_blocks = live_dashboard.remote_blocked_sources
        st.markdown(
            '<div class="panel-head"><div class="panel-title">Ag Kaynak Istihbarati</div><div class="panel-badge bad">Canli Izleme</div></div>',
            unsafe_allow_html=True,
        )
        st.caption(
            "Bu ekranda sadece gercekten gozlenebilen bilgiler vardir: IP, port, protokol ve paketlerden cikan kaynak/saldiri izleri."
        )
        if not contacts:
            st.info("Henuz uzaktan gelen trafik yok.")
            return

        total_remote_packets = sum(int(item["packets"]) for item in contacts)
        suspicious_ips = sum(1 for item in contacts if int(item["blocked"]) > 0)
        latest_contact = max(contacts, key=lambda item: item["last_seen"])
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        metric_col1.metric("IP Sayisi", len(contacts))
        metric_col2.metric("Supheli IP", suspicious_ips)
        metric_col3.metric("Uzak Paket", total_remote_packets)
        metric_col4.metric("Aktif Blok", len(remote_blocks))
        st.caption(f"Son gorulen kaynak: {latest_contact['ip']}")

        table_rows: list[dict[str, object]] = []
        for item in contacts:
            failed_layer = item["failed_layer"]
            layer_label = LAYER_LABELS.get(failed_layer, "Ag seviyesi drop") if isinstance(failed_layer, int) else "Ag seviyesi drop"
            table_rows.append(
                {
                    "IP": item["ip"],
                    "Protokol": str(item["protocol"]),
                    "Son Port": str(item["last_port"]),
                    "Gorulen Portlar": str(item["ports_seen"]),
                    "Ilk Gorulum": format_listener_timestamp(item["first_seen"]),
                    "Son Gorulum": format_listener_timestamp(item["last_seen"]),
                    "Paket": item["packets"],
                    "Kabul": item["accepted"],
                    "Red": item["blocked"],
                    "Twin": item["twin"],
                    "Sizinti": item["credential_leak"],
                    "Mission": item["mission_breach"],
                    "Holdover": item["holdover"],
                    "Ag Drop": item["network_drop"],
                    "Blok Bitis": format_listener_timestamp(item["blocked_until"]),
                    "Paket Kaynagi": str(item["packet_source"]),
                    "Sinif": human_label(str(item["classification"])),
                    "Katman": layer_label,
                    "Mod": str(item["service_mode"]),
                    "Aile": human_label(str(item["threat_family"])),
                    "Imza": human_label(str(item["signature"])),
                    "Forensic": str(item["forensic_case"]),
                    "Kanit": str(item["evidence"]),
                }
            )
        st.dataframe(pd.DataFrame(table_rows), width="stretch", hide_index=True)
        if remote_blocks:
            st.subheader("Aktif Uzak IP Karantinalari")
            block_rows = [
                {"IP": remote_ip, "Kalan Saniye": remaining}
                for remote_ip, remaining in remote_blocks.items()
            ]
            st.dataframe(pd.DataFrame(block_rows), width="stretch", hide_index=True)

    @st.fragment(run_every=slow_refresh)
    def render_quarantine_report_fragment() -> None:
        live_dashboard = app.dashboard_snapshot()
        quarantined = live_dashboard.quarantined
        threat_events = live_dashboard.threat_intel_events
        remote_blocks = live_dashboard.remote_blocked_sources

        st.markdown(
            '<div class="panel-head"><div class="panel-title">Karantina Analiz Raporu</div><div class="panel-badge bad">Rapor</div></div>',
            unsafe_allow_html=True,
        )
        st.caption("Karantinaya dusen kayitlar burada saldiri yontemi, aile ve etki izleriyle ozetlenir.")
        if not quarantined:
            st.info("Henuz karantinaya dusen kayit yok.")
            return

        classification_counts = Counter(record.classification for record in quarantined)
        family_counts = Counter(
            str(event.attack_family)
            for event in threat_events
        )
        metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
        metric_col1.metric("Karantina Kaydi", len(quarantined))
        metric_col2.metric("Tespit Yontemi", len(classification_counts))
        metric_col3.metric("Saldiri Ailesi", len(family_counts))
        metric_col4.metric("IP Karantina", len(remote_blocks))

        method_rows = []
        for classification, count in classification_counts.most_common():
            sample = next((record for record in reversed(quarantined) if record.classification == classification), None)
            method_rows.append(
                {
                    "Yontem": human_label(classification),
                    "Adet": count,
                    "Son Katman": LAYER_LABELS.get(sample.failed_layer or 0, "-") if sample else "-",
                    "Son Mod": sample.service_mode if sample else "-",
                    "Twin": "Evet" if sample and sample.twin_engaged else "Hayir",
                }
            )
        family_rows = []
        for family, count in family_counts.most_common():
            sample = next((event for event in reversed(threat_events) if event.attack_family == family), None)
            family_rows.append(
                {
                    "Aile": human_label(family),
                    "Adet": count,
                    "Vektor": human_label(sample.attack_vector) if sample else "-",
                    "Kanit": human_label(sample.primary_indicator) if sample else "-",
                    "Guven": sample.confidence if sample else "-",
                }
            )

        method_col, family_col = st.columns(2, gap="large")
        with method_col:
            st.subheader("Saldiri Yontemleri")
            st.dataframe(pd.DataFrame(method_rows), width="stretch", hide_index=True)
        with family_col:
            st.subheader("Saldiri Aileleri")
            if family_rows:
                st.dataframe(pd.DataFrame(family_rows), width="stretch", hide_index=True)
            else:
                st.info("HenÃ¼z threat intel ailesi olusmadi.")

        recent_rows = []
        for record in quarantined[-20:][::-1]:
            recent_rows.append(
                {
                    "Saat": format_listener_timestamp(record.processed_at),
                    "Kaynak": record.source or "-",
                    "Yontem": human_label(record.classification),
                    "Katman": LAYER_LABELS.get(record.failed_layer or 0, "-"),
                    "Mod": record.service_mode,
                    "Sizinti": "Evet" if record.credential_leak_suspect else "Hayir",
                    "Twin": "Evet" if record.twin_engaged else "Hayir",
                    "Mission": "Evet" if record.mission_breach else "Hayir",
                    "Aile": human_label(str(record.attacker_profile.get("attack_family"))) if record.attacker_profile else "-",
                    "Kanit": " | ".join(record.evidence_vector[:3]) if record.evidence_vector else "-",
                }
            )
        st.subheader("Son Karantina Olaylari")
        st.dataframe(pd.DataFrame(recent_rows), width="stretch", hide_index=True)

    with jury_tab:
        render_operation_fragment()

    with remote_tab:
        render_remote_fragment()

    with threat_tab:
        render_threat_sources_fragment()

    with report_tab:
        render_quarantine_report_fragment()

        if False and app.last_run_results:
            st.subheader("Son Deneme Dagilimi")
            st.dataframe(pd.DataFrame(decision_rows(app.last_run_results)), width="stretch", hide_index=True)
            current_run_truth = app.last_run_truth
            current_run_meta = app.last_run_meta
            if current_run_meta.get("mode") == "real_scenario" and current_run_truth:
                quality = summarize_run_quality(app.last_run_results, current_run_truth)
                st.subheader("Gercek Senaryo Ayirim Ozeti")
                metric_col1, metric_col2, metric_col3 = st.columns(3)
                metric_col1.metric("Attack Recall", f"{quality.get('recall', 0.0)}%")
                metric_col2.metric("Precision", f"{quality.get('precision', 0.0)}%")
                metric_col3.metric("Genel Isabet", f"{quality.get('accuracy', 0.0)}%")
                st.caption(
                    f"Gercek attack: {quality.get('true_attacks', 0)} | "
                    f"Yakalanan: {quality.get('true_positive', 0)} | "
                    f"Kacan: {quality.get('false_negative', 0)} | "
                    f"Yanlis alarm: {quality.get('false_positive', 0)}"
                )
                st.dataframe(
                    pd.DataFrame(stage_detection_rows(app.last_run_results, current_run_truth)),
                    width="stretch",
                    hide_index=True,
                )
                segment_order = current_run_meta.get("segment_order", [])
                if segment_order:
                    st.caption("Bu turdaki rastgele akisin sirasi")
                    st.dataframe(pd.DataFrame(segment_order), width="stretch", hide_index=True)
            elif current_run_meta.get("mode") == "counter_intel_tour" and current_run_truth:
                quality = summarize_run_quality(app.last_run_results, current_run_truth)
                st.subheader("Counter-Intel Tur Ozeti")
                metric_col1, metric_col2, metric_col3, metric_col4, metric_col5, metric_col6 = st.columns(6)
                metric_col1.metric("Attack Recall", f"{quality.get('recall', 0.0)}%")
                metric_col2.metric("Precision", f"{quality.get('precision', 0.0)}%")
                metric_col3.metric("Genel Isabet", f"{quality.get('accuracy', 0.0)}%")
                metric_col4.metric("Tuzak Temasi", quality.get("deception_hits", 0))
                metric_col5.metric("Quorum UyuÅŸmazligi", quality.get("quorum_disagreements", 0))
                st.dataframe(
                    pd.DataFrame(family_detection_rows(app.last_run_results, current_run_truth)),
                    width="stretch",
                    hide_index=True,
                )
                metric_col6.metric("Twin Oturumu", quality.get("twin_engagements", 0))
                segment_order = current_run_meta.get("segment_order", [])
                if segment_order:
                    st.caption("Bu turdaki aile sirasi")
                    st.dataframe(pd.DataFrame(segment_order), width="stretch", hide_index=True)

    with adapter_tab:
        st.markdown('<div class="panel-head"><div class="panel-title">UDP / TCP Adaptor</div><div class="panel-badge good">Live Feed</div></div>', unsafe_allow_html=True)
        st.caption("Gelen ham veri gizli zarf + JSON + gizli zarf yapisinda olmali. Gercek zarf bilgisi arayuzde gosterilmez.")
        protocol = st.selectbox("Protokol", ["udp", "tcp"], index=0)
        host = st.text_input("Host", value="0.0.0.0")
        port = st.number_input("Port", min_value=1, max_value=65535, value=9000, step=1)
        sync_remote_attack_profile(config, adapter_port=int(port), protocol=protocol)
        start_col, stop_col = st.columns(2)
        if start_col.button("Dinlemeyi Baslat", width="stretch"):
            try:
                app.start_network_listener(
                    protocol=protocol,
                    host=host,
                    port=int(port),
                    poll_timeout_seconds=0.5,
                )
            except OSError as exc:
                st.error(f"Adaptor acilamadi: {exc}")
            else:
                push_notice("success", "Adaptor dinlemesi baslatildi. Durdurulana kadar aktif kalacak.")
                st.rerun()
        if stop_col.button("Dinlemeyi Durdur", width="stretch"):
            app.stop_network_listener()
            push_notice("warning", "Adaptor dinlemesi durduruldu.")
            st.rerun()

        render_listener_status_fragment()

        st.subheader("Elle Paket Girdisi")
        raw_payload = st.text_area(
            "Cerceveli ham paketler (her satira bir veri)",
            height=180,
            placeholder='[gizli-zarf]{"packet_id":"demo-1", ...}[gizli-zarf]',
        )
        if st.button("Metni Islet", width="stretch"):
            results = app.process_manual_text(raw_payload)
            if not results:
                st.warning("Islenecek satir bulunamadi.")
            else:
                push_notice("success", f"Metin alanindan {len(results)} paket islendi. Canli ekrana yansitildi.")
                st.rerun()

        st.subheader("Peer Feed Girdisi")
        peer_payload = st.text_area(
            "Peer feed cerceveli paketler",
            height=150,
            placeholder='[gizli-zarf]{"packet_id":"peer-1", ... "peer_observations": {...}}[gizli-zarf]',
        )
        if st.button("Peer Feed Islet", width="stretch"):
            results = app.process_peer_text(peer_payload)
            if not results:
                st.warning("Peer feed icin islenecek satir bulunamadi.")
            else:
                push_notice("success", f"Peer feed uzerinden {len(results)} paket islendi. Canli ekrana yansitildi.")
                st.rerun()

    with debug_tab:
        st.markdown('<div class="panel-head"><div class="panel-title">Teknik Gorunum</div><div class="panel-badge bad">Debug</div></div>', unsafe_allow_html=True)
        group_df = pd.DataFrame(summarize_groups(records))
        layer_df = pd.DataFrame(micro_layer_rows(records, authenticated=app.authenticated))
        group_col, layer_col = st.columns((1, 1))
        with group_col:
            st.dataframe(group_df, width="stretch", hide_index=True)
        with layer_col:
            st.dataframe(layer_df, width="stretch", hide_index=True)

        if records:
            st.subheader("Tum Kararlar")
            st.dataframe(pd.DataFrame(decision_rows(records[-80:])), width="stretch", hide_index=True)
            if forensic_cases:
                st.subheader("Forensic Cases")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "case_id": case.case_id,
                                "source": case.source,
                                "classification": human_label(case.classification),
                                "service_mode": case.service_mode,
                                "mission_breach": case.mission_breach,
                                "bulletin": case.trust_bulletin_id or "-",
                                "quorum_result": case.quorum_result,
                                "summary": case.summary,
                            }
                            for case in forensic_cases[-20:]
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )
            if shadow_twin_sessions:
                st.subheader("Digital Twin Sessions")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "session_id": session.session_id,
                                "source": session.source,
                                "classification": human_label(session.classification),
                                "attack_family": human_label(session.attack_family),
                                "attack_vector": human_label(session.attack_vector),
                                "primary_indicator": human_label(session.primary_indicator),
                                "trigger": human_label(session.trigger_label),
                                "intel_score": session.threat_intel_score,
                                "case_id": session.forensic_case_id or "-",
                                "recommendation": session.operator_recommendation,
                                "summary": session.summary,
                            }
                            for session in shadow_twin_sessions[-20:]
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )
            if threat_intel_events:
                st.subheader("Threat Intel Events")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "event_id": event.event_id,
                                "source": event.source,
                                "classification": human_label(event.classification),
                                "attack_family": human_label(event.attack_family),
                                "attack_vector": human_label(event.attack_vector),
                                "primary_indicator": human_label(event.primary_indicator),
                                "layer": event.failed_layer or 0,
                                "confidence": event.confidence,
                                "intel_score": event.threat_intel_score,
                                "twin_session_id": event.twin_session_id or "-",
                                "recommendation": event.operator_recommendation,
                                "summary": event.intel_summary,
                            }
                            for event in threat_intel_events[-20:]
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )
            if real_plane_events or shadow_plane_events:
                st.subheader("Split-Plane Relay Events")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "relay_id": event.relay_id,
                                "plane": event.plane,
                                "channel": event.channel_name,
                                "protocol": event.protocol,
                                "host": event.host,
                                "port": event.port,
                                "source": event.source,
                                "packet_id": event.packet_id,
                                "action": event.action,
                                "status": event.status,
                                "used_fallback": event.used_fallback,
                                "summary": event.summary,
                            }
                            for event in (real_plane_events + shadow_plane_events)[-24:]
                        ]
                    ),
                    width="stretch",
                    hide_index=True,
                )
            st.subheader("Son Karar Izi")
            latest = records[-1]
            st.dataframe(pd.DataFrame(trace_rows(latest)), width="stretch", hide_index=True)
            with st.expander("Son Kaydin Ham Icerigi"):
                st.code(latest.payload_view or "-", language="json")
        else:
            st.info("Henuz islenmis veri yok.")


if __name__ == "__main__":
    if not streamlit_runtime.exists():
        print("Bu uygulamayi tarayicida acmak icin su komutu kullanin:")
        print("python -m streamlit run streamlit_app.py")
        sys.exit(0)
    main()
