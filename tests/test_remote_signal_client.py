from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

REMOTE_ATTACK_NODE = Path(__file__).resolve().parents[1] / "remote_attack_node"
if str(REMOTE_ATTACK_NODE) not in sys.path:
    sys.path.insert(0, str(REMOTE_ATTACK_NODE))

from remote_signal_client import ClientConfig, build_packets, split_signal_secret


def _unwrap(payload: str, secret: str) -> dict:
    prefix, suffix = split_signal_secret(secret)
    body = payload[len(prefix):]
    if suffix:
        body = body[: -len(suffix)]
    return json.loads(body)


class RemoteSignalClientTests(unittest.TestCase):
    def test_build_packets_respects_seq_start_and_monotonic_timestamps(self) -> None:
        config = ClientConfig(
            host="127.0.0.1",
            port=9000,
            mode="normal",
            count=3,
            interval_ms=200,
            seq_start=500,
        )

        packets = build_packets(config)
        decoded = [_unwrap(packet, config.signal_secret) for packet in packets]

        self.assertEqual([item["seq"] for item in decoded], [500, 501, 502])
        timestamps = [datetime.fromisoformat(item["ts"]) for item in decoded]
        self.assertLess(timestamps[0], timestamps[1])
        self.assertLess(timestamps[1], timestamps[2])

    def test_build_packets_updates_previous_clean_hash_override_for_next_batch(self) -> None:
        config = ClientConfig(
            host="127.0.0.1",
            port=9000,
            mode="normal",
            count=2,
            interval_ms=150,
            seq_start=700,
        )

        first_batch = build_packets(config)
        first_override = config.previous_clean_hash_override
        second_batch = build_packets(config)
        second_override = config.previous_clean_hash_override

        self.assertTrue(first_override)
        self.assertTrue(second_override)
        self.assertNotEqual(first_override, "")
        self.assertNotEqual(second_override, "")
        self.assertNotEqual(first_override, second_override)
        first_packet_second_batch = _unwrap(second_batch[0], config.signal_secret)
        self.assertEqual(first_packet_second_batch["seq"], 700)


if __name__ == "__main__":
    unittest.main()
