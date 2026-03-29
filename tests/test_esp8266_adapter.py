from __future__ import annotations

import unittest

from bkzs_guard.adapters.esp8266 import build_esp8266_profile_header
from bkzs_guard.config import load_app_config


class Esp8266AdapterTests(unittest.TestCase):
    def test_build_esp8266_profile_header_contains_runtime_values(self) -> None:
        config = load_app_config()
        header = build_esp8266_profile_header(
            config,
            target_host="192.168.1.88",
            target_port=9020,
            protocol="udp",
        )
        self.assertIn('#define BKZS_TARGET_HOST "192.168.1.88"', header)
        self.assertIn("#define BKZS_TARGET_PORT 9020", header)
        self.assertIn("#define BKZS_USE_UDP 1", header)
        self.assertIn('#define BKZS_SOURCE "bkzs-esp8266-1"', header)
        self.assertIn(f'#define BKZS_SIGNAL_SECRET "{config.security.signal_secret}"', header)


if __name__ == "__main__":
    unittest.main()
