from __future__ import annotations

import ipaddress
import json
from typing import Any


def is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except (ValueError, AttributeError):
        return False


def wrap_lab_transport(signal_payload: str, simulated_remote_ip: str) -> str:
    return json.dumps(
        {
            "bkzs_lab_transport": {"simulated_remote_ip": simulated_remote_ip.strip(), "v": 1},
            "signal_payload": signal_payload,
        },
        ensure_ascii=True,
    )


def try_unwrap_lab_transport(raw: str) -> tuple[str, str | None]:
    stripped = raw.strip()
    if not stripped.startswith("{"):
        return raw, None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return raw, None
    if not isinstance(obj, dict):
        return raw, None
    lab = obj.get("bkzs_lab_transport")
    inner = obj.get("signal_payload")
    if not isinstance(lab, dict) or not isinstance(inner, str):
        return raw, None
    ip = lab.get("simulated_remote_ip")
    if not isinstance(ip, str):
        return raw, None
    ip = ip.strip()
    if not ip or not is_valid_ipv4(ip):
        return raw, None
    return inner, ip


def resolve_lab_transport(
    raw: str,
    remote_meta: dict[str, Any],
    *,
    lab_transport_enabled: bool,
) -> tuple[str, dict[str, Any]]:
    inner, simulated = try_unwrap_lab_transport(raw)
    if simulated is None:
        return raw, remote_meta
    meta = dict(remote_meta)
    socket_ip = meta.get("remote_ip")
    if lab_transport_enabled:
        meta["remote_ip"] = simulated
        meta["lab_transport"] = True
        if socket_ip is not None:
            meta["socket_remote_ip"] = socket_ip
    else:
        meta["lab_transport_simulation_ignored"] = True
    return inner, meta
