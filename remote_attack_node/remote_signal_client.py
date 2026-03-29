from __future__ import annotations

import argparse
import hashlib
from argparse import BooleanOptionalAction
import json
import random
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable
from uuid import uuid4

from profile_loader import load_target_profile


SATELLITE_PROFILES: dict[str, dict[str, object]] = {
    "generic-bkzs": {
        "channel": "bkzs-nav",
        "mission_phase": "operational",
    },
    "turksat-6a": {
        "channel": "satcom-relay",
        "mission_phase": "relay",
        "satellite_profile_id": "turksat-6a",
        "satellite_id": "Turksat 6A",
        "satellite_class": "communications",
        "orbit_type": "GEO",
        "orbital_slot_deg_e": 42.0,
        "uplink_band": "Ku-Band",
        "downlink_band": "Ku-Band",
        "protocol_family": "transponder-metadata",
    },
    "imece": {
        "channel": "eo-downlink",
        "mission_phase": "imaging",
        "satellite_profile_id": "imece",
        "satellite_id": "IMECE",
        "satellite_class": "earth_observation",
        "orbit_type": "LEO_SSO",
        "altitude_km": 680.0,
        "tmtc_band": "S-Band",
        "downlink_band": "X-Band",
        "protocol_family": "ccsds-tm",
        "sensor_type": "electro_optical",
    },
    "gokturk-2": {
        "channel": "eo-downlink",
        "mission_phase": "imaging",
        "satellite_profile_id": "gokturk-2",
        "satellite_id": "Gokturk-2",
        "satellite_class": "earth_observation",
        "orbit_type": "LEO",
        "tmtc_band": "S-Band",
        "downlink_band": "X-Band",
        "protocol_family": "ccsds-tm",
        "sensor_type": "optical",
    },
}


@dataclass(slots=True)
class ClientConfig:
    host: str
    port: int
    protocol: str = "udp"
    mode: str = "normal"
    count: int = 3
    interval_ms: int = 150
    source: str = "bkzs-edge-1"
    signal_secret: str = "bkzs-demo-signal"
    session_nonce: str = "bkzs-demo-session"
    shadow_salt: str = "bkzs-demo-shadow"
    op_code: str = "BKZS-DEMO-2026"
    satellite_profile: str = "generic-bkzs"
    seq_start: int = 100
    previous_clean_hash_override: str = ""
    lab_transport: bool = False
    lab_random_ip_per_packet: bool = True
    lab_fixed_ip: str = ""


def default_client_config() -> ClientConfig:
    profile = load_target_profile()
    return ClientConfig(
        host=str(profile.get("target_host", "127.0.0.1")),
        port=int(profile.get("target_port", 9000)),
        protocol=str(profile.get("protocol", "udp")),
        mode="normal",
        count=3,
        interval_ms=150,
        source=str(profile.get("source", "bkzs-edge-1")),
        signal_secret=str(profile.get("signal_secret", "bkzs-demo-signal")),
        session_nonce=str(profile.get("session_nonce", "bkzs-demo-session")),
        shadow_salt=str(profile.get("shadow_salt", "bkzs-demo-shadow")),
        op_code=str(profile.get("op_code", "BKZS-DEMO-2026")),
        satellite_profile=str(profile.get("satellite_profile", "generic-bkzs")),
        seq_start=int(profile.get("seq_start", 100)),
        previous_clean_hash_override=str(profile.get("previous_clean_hash_override", "")),
        lab_transport=str(profile.get("lab_transport", "1")) != "0",
        lab_random_ip_per_packet=str(profile.get("lab_random_ip", "1")) != "0",
        lab_fixed_ip=str(profile.get("lab_fixed_ip", "")),
    )


def utc_now() -> datetime:
    return datetime.now(UTC)


def stable_digest(payload: object, length: int = 24) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:length]


def build_flow_tag(payload: dict[str, object], signal_secret: str, session_nonce: str) -> str:
    return stable_digest({"signal_secret": signal_secret, "session_nonce": session_nonce, "payload": payload}, length=24)


def stable_checksum(payload: dict[str, object]) -> str:
    return stable_digest(payload, length=16)


def packet_flow_tag_view(raw_packet: dict[str, object]) -> dict[str, object]:
    clone = dict(raw_packet)
    clone.pop("checksum", None)
    clone.pop("flow_tag", None)
    return clone


def packet_chain_view(raw_packet: dict[str, object]) -> dict[str, object]:
    clone = dict(raw_packet)
    clone.pop("checksum", None)
    clone.pop("flow_tag", None)
    return clone


def build_packet_chain_hash(raw_packet: dict[str, object]) -> str:
    return stable_digest(packet_chain_view(raw_packet), length=24)


def initial_clean_hash(source: str, session_nonce: str) -> str:
    return stable_digest({"source": source, "session_nonce": session_nonce, "lane": "genesis"}, length=24)


def epoch_id_from_timestamp(value: datetime, epoch_seconds: int = 1) -> str:
    return str(int(value.timestamp()) // max(epoch_seconds, 1))


def build_challenge_proof(
    signal_secret: str,
    session_nonce: str,
    shadow_lane_salt: str,
    source: str,
    epoch_id: str,
    previous_clean_hash: str,
    lane: str = "primary",
) -> str:
    material = {
        "lane": lane,
        "seed": shadow_lane_salt if lane == "shadow" else signal_secret,
        "session_nonce": session_nonce,
        "source": source,
        "epoch_id": epoch_id,
        "previous_clean_hash": previous_clean_hash,
    }
    return stable_digest(material, length=24)


def split_signal_secret(signal_secret: str) -> tuple[str, str]:
    midpoint = len(signal_secret) // 2
    if midpoint == 0:
        return signal_secret, ""
    return signal_secret[:midpoint], signal_secret[midpoint:]


def frame_signal_payload(payload: str, signal_secret: str) -> str:
    prefix, suffix = split_signal_secret(signal_secret)
    return f"{prefix}{payload}{suffix}"


def random_lab_ipv4() -> str:
    r = random.Random()
    zone = r.randint(0, 2)
    if zone == 0:
        return f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    if zone == 1:
        return f"172.{r.randint(16, 31)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    return f"192.168.{r.randint(0, 255)}.{r.randint(1, 254)}"


def wrap_lab_transport_payload(signal_payload: str, simulated_remote_ip: str) -> str:
    return json.dumps(
        {
            "bkzs_lab_transport": {"simulated_remote_ip": simulated_remote_ip.strip(), "v": 1},
            "signal_payload": signal_payload,
        },
        ensure_ascii=True,
    )


def apply_lab_transport_wrap(config: ClientConfig, framed_payload: str) -> str:
    if not config.lab_transport:
        return framed_payload
    fixed = (config.lab_fixed_ip or "").strip()
    if not config.lab_random_ip_per_packet and fixed:
        ip = fixed
    else:
        ip = random_lab_ipv4()
    return wrap_lab_transport_payload(framed_payload, ip)


def parse_args() -> argparse.Namespace:
    defaults = default_client_config()
    parser = argparse.ArgumentParser(description="Standalone remote client for BKZS Guard.")
    parser.add_argument("--host", default=defaults.host)
    parser.add_argument("--port", default=defaults.port, type=int)
    parser.add_argument("--protocol", choices=("udp", "tcp"), default=defaults.protocol)
    parser.add_argument(
        "--mode",
        choices=("normal", "unauthorized", "jam", "replay", "shadow-contact", "mission-breach", "mesh-divergence"),
        default=defaults.mode,
    )
    parser.add_argument("--count", type=int, default=defaults.count)
    parser.add_argument("--interval-ms", type=int, default=defaults.interval_ms)
    parser.add_argument("--source", default=defaults.source)
    parser.add_argument("--signal-secret", default=defaults.signal_secret)
    parser.add_argument("--session-nonce", default=defaults.session_nonce)
    parser.add_argument("--shadow-salt", default=defaults.shadow_salt)
    parser.add_argument("--op-code", default=defaults.op_code)
    parser.add_argument("--satellite-profile", default=defaults.satellite_profile, choices=tuple(SATELLITE_PROFILES))
    parser.add_argument("--seq-start", type=int, default=defaults.seq_start)
    parser.add_argument("--previous-clean-hash", dest="previous_clean_hash_override", default=defaults.previous_clean_hash_override)
    parser.add_argument(
        "--lab-transport",
        default=defaults.lab_transport,
        action=BooleanOptionalAction,
        help="JSON laboratuvar zarfÄ± ile paket basÄ±na sanal IPv4 (varsayÄ±lan: profildeki lab_transport; kapat: --no-lab-transport).",
    )
    parser.add_argument(
        "--lab-random-ip",
        dest="lab_random_ip_per_packet",
        action="store_true",
        default=True,
        help="Her paket iÃ§in rastgele Ã¶zel IPv4 (varsayÄ±lan: aÃ§Ä±k).",
    )
    parser.add_argument(
        "--no-lab-random-ip",
        dest="lab_random_ip_per_packet",
        action="store_false",
        help="Sabit IP kullan (--lab-fixed-ip ile).",
    )
    parser.add_argument("--lab-fixed-ip", default="", help="lab_random kapalÄ±yken kullanÄ±lacak IPv4.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = ClientConfig(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        mode=args.mode,
        count=args.count,
        interval_ms=args.interval_ms,
        source=args.source,
        signal_secret=args.signal_secret,
        session_nonce=args.session_nonce,
        shadow_salt=args.shadow_salt,
        op_code=args.op_code,
        satellite_profile=args.satellite_profile,
        seq_start=args.seq_start,
        lab_transport=args.lab_transport,
        lab_random_ip_per_packet=args.lab_random_ip_per_packet,
        lab_fixed_ip=args.lab_fixed_ip,
    )
    send_batch(
        config,
        on_result=lambda index, total, payload, success, error: print(
            f"[{index}/{total}] {'sent' if success else 'failed'} {config.mode} packet "
            f"to {config.host}:{config.port} via {config.protocol.upper()}"
            + (f" | {error}" if error else "")
        ),
    )


def build_packets(args: ClientConfig | argparse.Namespace) -> list[str]:
    packets: list[str] = []
    override_hash = str(getattr(args, "previous_clean_hash_override", "") or "").strip()
    previous_clean_hash = override_hash or initial_clean_hash(args.source, args.session_nonce)
    replay_packet: str | None = None

    for offset in range(args.count):
        timestamp = utc_now() + timedelta(milliseconds=max(args.interval_ms, 1) * offset)
        packet = build_packet(args, seq=args.seq_start + offset, timestamp=timestamp, previous_clean_hash=previous_clean_hash)
        attack_meta = packet.get("payload", {}).get("attack_meta", {})
        if isinstance(attack_meta, dict):
            attack_meta["simulation_mode"] = args.mode
            attack_meta["simulation_role"] = "normal" if args.mode == "normal" else "attack"
        if args.mode == "unauthorized":
            packet["op_code"] = "BKZS-LEAKED"
        elif args.mode == "jam":
            packet["metrics"]["cn0"] = 18.0
            packet["metrics"]["sat_count"] = 3
            packet["metrics"]["power"] = -74.0
        elif args.mode == "shadow-contact":
            packet["payload"]["attack_meta"]["secret_compromised"] = True
            packet["challenge_proof"] = build_challenge_proof(
                args.signal_secret,
                args.session_nonce,
                args.shadow_salt,
                args.source,
                packet["epoch_id"],
                previous_clean_hash,
                lane="shadow",
            )
        elif args.mode == "mission-breach":
            apply_mission_breach(packet, args.satellite_profile)
        elif args.mode == "mesh-divergence":
            packet["peer_observations"] = {
                "peer_count": 2,
                "position_delta_m": 280.0,
                "clock_bias_delta": 170.0,
                "clock_drift_delta": 6.2,
                "time_delta_seconds": 2.1,
                "receiver_baseline_delta_m": 160.0,
            }

        finalize_packet(packet, args.signal_secret, args.session_nonce)
        framed = frame_signal_payload(json.dumps(packet, ensure_ascii=True), args.signal_secret)

        if args.mode == "replay":
            if replay_packet is None:
                replay_packet = framed
            packets.append(replay_packet)
        else:
            packets.append(framed)

        if args.mode in {"normal", "jam", "mesh-divergence"}:
            previous_clean_hash = build_packet_chain_hash(packet)

    if hasattr(args, "previous_clean_hash_override"):
        setattr(args, "previous_clean_hash_override", previous_clean_hash)

    return packets


def build_packet(args: ClientConfig | argparse.Namespace, seq: int, timestamp: datetime, previous_clean_hash: str) -> dict[str, object]:
    profile = dict(SATELLITE_PROFILES[args.satellite_profile])
    channel = str(profile.pop("channel", "bkzs-nav"))
    mission_phase = str(profile.pop("mission_phase", "operational"))
    epoch_id = epoch_id_from_timestamp(timestamp, 1)
    return {
        "packet_id": uuid4().hex[:12],
        "source": args.source,
        "ts": timestamp.isoformat(),
        "seq": seq,
        "epoch_id": epoch_id,
        "challenge_proof": build_challenge_proof(
            args.signal_secret,
            args.session_nonce,
            args.shadow_salt,
            args.source,
            epoch_id,
            previous_clean_hash,
            lane="primary",
        ),
        "session_nonce": args.session_nonce,
        "flow_tag": "",
        "trust_lane": "primary",
        "peer_observations": {},
        "holdover_state": {},
        "op_code": args.op_code,
        "checksum": "",
        "payload": {
            "channel": channel,
            "mission_phase": mission_phase,
            "confidence": 0.995,
            **profile,
            "attack_meta": {"stage_hint": None, "secret_compromised": False},
        },
        "metrics": {
            "cn0": 43.2,
            "power": -109.6,
            "doppler": 1210.4,
            "sat_count": 9,
            "clock_bias": 12.5,
            "clock_drift": 0.8,
            "latitude": 41.0082,
            "longitude": 28.9784,
            "altitude": 19.2,
            "speed": 12.8,
        },
    }


def apply_mission_breach(packet: dict[str, object], satellite_profile_id: str) -> None:
    payload = packet["payload"]
    if not isinstance(payload, dict):
        return
    if satellite_profile_id == "turksat-6a":
        payload["downlink_band"] = "X-Band"
        payload["orbital_slot_deg_e"] = 49.0
    elif satellite_profile_id in {"imece", "gokturk-2"}:
        payload["downlink_band"] = "Ka-Band"
        payload["protocol_family"] = "unknown-protocol"
    else:
        payload["channel"] = "unexpected-channel"


def finalize_packet(packet: dict[str, object], signal_secret: str, session_nonce: str) -> None:
    packet["flow_tag"] = build_flow_tag(packet_flow_tag_view(packet), signal_secret, session_nonce)
    packet["checksum"] = stable_checksum({k: v for k, v in packet.items() if k not in {"checksum", "flow_tag"}})


def send_payload(protocol: str, host: str, port: int, payload: str) -> None:
    encoded = payload.encode("utf-8")
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(encoded, (host, port))
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        sock.connect((host, port))
        sock.sendall(encoded)


def send_batch(
    config: ClientConfig,
    on_sent: Callable[[int, int, str], None] | None = None,
    on_result: Callable[[int, int, str, bool, str | None], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[str]:
    packets = build_packets(config)
    total = len(packets)
    for index, packet in enumerate(packets, start=1):
        if should_stop is not None and should_stop():
            break
        success = False
        error_message: str | None = None
        try:
            to_send = apply_lab_transport_wrap(config, packet)
            send_payload(config.protocol, config.host, config.port, to_send)
            success = True
            if on_sent is not None:
                on_sent(index, total, packet)
        except (OSError, TimeoutError) as exc:
            error_message = str(exc)
        if on_result is not None:
            on_result(index, total, packet, success, error_message)
        remaining_sleep = max(config.interval_ms, 0) / 1000
        while remaining_sleep > 0:
            if should_stop is not None and should_stop():
                break
            slice_sleep = min(0.05, remaining_sleep)
            time.sleep(slice_sleep)
            remaining_sleep -= slice_sleep
    return packets


if __name__ == "__main__":
    main()
