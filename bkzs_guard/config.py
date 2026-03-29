from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(slots=True)
class SecurityConfig:
    ui_password: str = "astro-guard"
    signal_secret: str = "bkzs-signal-guard"
    session_nonce: str = "bkzs-session-seal"
    shadow_lane_salt: str = "bkzs-shadow-lane"
    expected_op_code: str = "BKZS-OPS-2026"
    trusted_sources: tuple[str, ...] = ("bkzs-core", "bkzs-edge-1", "bkzs-edge-2", "bkzs-esp32-1", "bkzs-esp8266-1")


@dataclass(slots=True)
class ThresholdConfig:
    max_packet_size_bytes: int = 4096
    challenge_epoch_seconds: int = 1
    freshness_window_seconds: float = 15.0
    max_future_skew_seconds: float = 2.0
    peer_freshness_window_seconds: float = 5.0
    adaptive_lock_threshold: int = 3
    adaptive_lock_seconds: float = 35.0
    min_cn0: float = 28.0
    min_sat_count: int = 4
    max_power_dbm: float = -85.0
    max_power_delta: float = 14.0
    max_cn0_delta: float = 10.0
    max_doppler_delta: float = 850.0
    max_clock_bias_step: float = 120.0
    max_clock_drift_step: float = 6.0
    max_speed_mps: float = 95.0
    max_position_jump_m: float = 120.0
    max_cumulative_position_drift_m: float = 120.0
    max_cumulative_clock_bias_span: float = 250.0
    max_peer_position_delta_m: float = 180.0
    max_peer_clock_bias_delta: float = 150.0
    max_peer_clock_drift_delta: float = 5.0
    max_mesh_time_delta_seconds: float = 1.5
    max_receiver_baseline_delta_m: float = 120.0
    max_holdover_position_delta_m: float = 75.0
    max_holdover_clock_bias_delta: float = 100.0
    holdover_confidence_floor: float = 0.55
    max_history_packets: int = 12
    max_packet_id_cache: int = 2048


@dataclass(slots=True)
class MissionZoneConfig:
    name: str
    center_latitude: float
    center_longitude: float
    radius_m: float


@dataclass(slots=True)
class MissionConfig:
    mission_id: str = "bkzs-operasyon"
    satellite_profile_id: str = "generic-bkzs"
    allowed_channel: str = "bkzs-nav"
    mission_phase: str = "operational"
    allowed_start_hour: int = 0
    allowed_end_hour: int = 23
    max_speed_mps: float = 65.0
    max_route_drift_m: float = 220.0
    primary_zone: MissionZoneConfig = field(
        default_factory=lambda: MissionZoneConfig(
            name="istanbul-core",
            center_latitude=41.0082,
            center_longitude=28.9784,
            radius_m=900.0,
        )
    )
    forbidden_zones: tuple[MissionZoneConfig, ...] = field(
        default_factory=lambda: (
            MissionZoneConfig(
                name="forbidden-hub",
                center_latitude=41.0205,
                center_longitude=29.0465,
                radius_m=140.0,
            ),
        )
    )
    source_roles: dict[str, str] = field(
        default_factory=lambda: {
            "bkzs-core": "command",
            "bkzs-edge-1": "edge",
            "bkzs-edge-2": "edge",
            "bkzs-esp32-1": "edge",
            "bkzs-esp8266-1": "edge",
        }
    )


@dataclass(slots=True)
class BulletinConfig:
    enabled: bool = True
    signing_key: str = "bkzs-bulletin-key"


@dataclass(slots=True)
class RelayPlaneConfig:
    protocol: str = "udp"
    host: str = "127.0.0.1"
    port: int = 9101
    channel_name: str = "real-plane"


@dataclass(slots=True)
class RelayConfig:
    dispatch_enabled: bool = False
    secure_plane: RelayPlaneConfig = field(
        default_factory=lambda: RelayPlaneConfig(
            protocol="udp",
            host="127.0.0.1",
            port=9101,
            channel_name="secure-plane",
        )
    )
    shadow_plane: RelayPlaneConfig = field(
        default_factory=lambda: RelayPlaneConfig(
            protocol="udp",
            host="127.0.0.1",
            port=9102,
            channel_name="shadow-plane",
        )
    )


@dataclass(slots=True)
class DecisionFeedConfig:
    enabled: bool = False
    protocol: str = "udp"
    host: str = "127.0.0.1"
    port: int = 9200
    channel_name: str = "decision-feed"


@dataclass(slots=True)
class LabConfig:
    """Demo-only: accept JSON envelopes that remap remote_ip for strike/block logic."""

    transport_simulation_enabled: bool = False


@dataclass(slots=True)
class AppConfig:
    security: SecurityConfig = field(default_factory=SecurityConfig)
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    mission: MissionConfig = field(default_factory=MissionConfig)
    bulletin: BulletinConfig = field(default_factory=BulletinConfig)
    relay: RelayConfig = field(default_factory=RelayConfig)
    decision_feed: DecisionFeedConfig = field(default_factory=DecisionFeedConfig)
    lab: LabConfig = field(default_factory=LabConfig)


def load_app_config() -> AppConfig:
    security = SecurityConfig(
        ui_password=os.getenv("BKZS_UI_PASSWORD", "astro-guard"),
        signal_secret=os.getenv("BKZS_SIGNAL_SECRET", "bkzs-signal-guard"),
        session_nonce=os.getenv("BKZS_SESSION_NONCE", "bkzs-session-seal"),
        shadow_lane_salt=os.getenv("BKZS_SHADOW_SALT", "bkzs-shadow-lane"),
        expected_op_code=os.getenv("BKZS_OP_CODE", "BKZS-OPS-2026"),
    )
    bulletin = BulletinConfig(
        enabled=os.getenv("BKZS_BULLETIN_ENABLED", "1") != "0",
        signing_key=os.getenv("BKZS_BULLETIN_SIGNING_KEY", "bkzs-bulletin-key"),
    )
    relay = RelayConfig(
        dispatch_enabled=os.getenv("BKZS_RELAY_ENABLED", "0") == "1",
        secure_plane=RelayPlaneConfig(
            protocol=os.getenv("BKZS_SECURE_RELAY_PROTOCOL", "udp"),
            host=os.getenv("BKZS_SECURE_RELAY_HOST", "127.0.0.1"),
            port=int(os.getenv("BKZS_SECURE_RELAY_PORT", "9101")),
            channel_name=os.getenv("BKZS_SECURE_RELAY_CHANNEL", "secure-plane"),
        ),
        shadow_plane=RelayPlaneConfig(
            protocol=os.getenv("BKZS_SHADOW_RELAY_PROTOCOL", "udp"),
            host=os.getenv("BKZS_SHADOW_RELAY_HOST", "127.0.0.1"),
            port=int(os.getenv("BKZS_SHADOW_RELAY_PORT", "9102")),
            channel_name=os.getenv("BKZS_SHADOW_RELAY_CHANNEL", "shadow-plane"),
        ),
    )
    decision_feed = DecisionFeedConfig(
        enabled=os.getenv("BKZS_DECISION_FEED_ENABLED", "0") == "1",
        protocol=os.getenv("BKZS_DECISION_FEED_PROTOCOL", "udp"),
        host=os.getenv("BKZS_DECISION_FEED_HOST", "127.0.0.1"),
        port=int(os.getenv("BKZS_DECISION_FEED_PORT", "9200")),
        channel_name=os.getenv("BKZS_DECISION_FEED_CHANNEL", "decision-feed"),
    )
    mission = MissionConfig(
        satellite_profile_id=os.getenv("BKZS_SATELLITE_PROFILE", "generic-bkzs"),
    )
    lab = LabConfig(
        transport_simulation_enabled=os.getenv("BKZS_LAB_TRANSPORT_SIMULATION", "1") != "0",
    )
    return AppConfig(
        security=security,
        bulletin=bulletin,
        relay=relay,
        mission=mission,
        decision_feed=decision_feed,
        lab=lab,
    )
