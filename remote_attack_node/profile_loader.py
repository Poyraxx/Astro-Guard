from __future__ import annotations

import json
from pathlib import Path


PROFILE_PATH = Path(__file__).resolve().parent / "attack_target_profile.json"


def load_target_profile() -> dict[str, object]:
    if not PROFILE_PATH.exists():
        return {}
    try:
        payload = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
