from __future__ import annotations

import json
import socket
import unittest

from bkzs_guard.config import AppConfig, DecisionFeedConfig
from bkzs_guard.control import BKZSControlCenter


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class DecisionFeedTests(unittest.TestCase):
    def test_decision_feed_emits_accept_record(self) -> None:
        port = _free_port()
        config = AppConfig()
        config.decision_feed = DecisionFeedConfig(enabled=True, protocol="udp", host="127.0.0.1", port=port)
        app = BKZSControlCenter(config)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", port))
            sock.settimeout(1.0)
            app.load_normal_run(count=1)
            payload, _ = sock.recvfrom(8192)

        message = json.loads(payload.decode("utf-8"))
        self.assertEqual(message["decision"], "accepted")
        self.assertEqual(message["classification"], "normal")
        self.assertIn("packet_id", message)

    def test_decision_feed_emits_blocked_twin_record(self) -> None:
        port = _free_port()
        config = AppConfig()
        config.decision_feed = DecisionFeedConfig(enabled=True, protocol="udp", host="127.0.0.1", port=port)
        app = BKZSControlCenter(config)
        app.last_clean_payload_by_source["bkzs-edge-1"] = '{"packet_id":"trusted-baseline"}'

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", port))
            sock.settimeout(1.0)
            app.ingest_packets(app.attack_lab._mission_envelope_break(1))
            payload, _ = sock.recvfrom(8192)

        message = json.loads(payload.decode("utf-8"))
        self.assertEqual(message["decision"], "blocked")
        self.assertTrue(message["twin_engaged"])
        self.assertTrue(message["mission_breach"])


if __name__ == "__main__":
    unittest.main()
