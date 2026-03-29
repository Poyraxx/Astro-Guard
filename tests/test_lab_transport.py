from __future__ import annotations

import json
import os
import unittest

from bkzs_guard.config import load_app_config
from bkzs_guard.lab_transport import (
    resolve_lab_transport,
    try_unwrap_lab_transport,
    wrap_lab_transport,
)


class LabTransportTests(unittest.TestCase):
    def test_wrap_unwrap_roundtrip(self) -> None:
        inner = '{"hello":"world"}'
        wrapped = wrap_lab_transport(inner, "10.20.30.40")
        out, ip = try_unwrap_lab_transport(wrapped)
        self.assertEqual(ip, "10.20.30.40")
        self.assertEqual(out, inner)

    def test_plain_payload_not_unwrapped(self) -> None:
        raw = "not-json"
        out, ip = try_unwrap_lab_transport(raw)
        self.assertIsNone(ip)
        self.assertEqual(out, raw)

    def test_resolve_when_lab_enabled_remaps_ip(self) -> None:
        inner = '{"x":1}'
        wrapped = wrap_lab_transport(inner, "192.168.99.1")
        payload, meta = resolve_lab_transport(
            wrapped,
            {"remote_ip": "127.0.0.1", "remote_port": 5555, "protocol": "udp"},
            lab_transport_enabled=True,
        )
        self.assertEqual(payload, inner)
        self.assertEqual(meta["remote_ip"], "192.168.99.1")
        self.assertEqual(meta["socket_remote_ip"], "127.0.0.1")
        self.assertTrue(meta["lab_transport"])

    def test_resolve_when_lab_disabled_keeps_socket_ip(self) -> None:
        inner = '{"x":1}'
        wrapped = wrap_lab_transport(inner, "192.168.99.1")
        payload, meta = resolve_lab_transport(
            wrapped,
            {"remote_ip": "127.0.0.1", "remote_port": 5555, "protocol": "udp"},
            lab_transport_enabled=False,
        )
        self.assertEqual(payload, inner)
        self.assertEqual(meta["remote_ip"], "127.0.0.1")

    def test_load_app_config_lab_transport_disabled_via_env(self) -> None:
        os.environ["BKZS_LAB_TRANSPORT_SIMULATION"] = "0"
        try:
            cfg = load_app_config()
            self.assertFalse(cfg.lab.transport_simulation_enabled)
        finally:
            os.environ.pop("BKZS_LAB_TRANSPORT_SIMULATION", None)

    def test_load_app_config_lab_transport_default_enabled(self) -> None:
        os.environ.pop("BKZS_LAB_TRANSPORT_SIMULATION", None)
        cfg = load_app_config()
        self.assertTrue(cfg.lab.transport_simulation_enabled)


if __name__ == "__main__":
    unittest.main()
