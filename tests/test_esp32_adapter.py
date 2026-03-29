from __future__ import annotations

import unittest

from bkzs_guard.adapters.esp32 import build_esp32_profile_header
from bkzs_guard.config import load_app_config


class Esp32AdapterTests(unittest.TestCase):
    def test_build_esp32_profile_header_contains_runtime_values(self) -> None:
        config = load_app_config()
        header = build_esp32_profile_header(
            config,
            target_host="192.168.1.77",
            target_port=9010,
            protocol="udp",
        )
        self.assertIn('#define BKZS_TARGET_HOST "192.168.1.77"', header)
        self.assertIn("#define BKZS_TARGET_PORT 9010", header)
        self.assertIn("#define BKZS_USE_UDP 1", header)
        self.assertIn('#define BKZS_SOURCE "bkzs-esp32-1"', header)
        self.assertIn(f'#define BKZS_SIGNAL_SECRET "{config.security.signal_secret}"', header)


if __name__ == "__main__":
    unittest.main()
