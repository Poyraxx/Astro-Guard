from __future__ import annotations

from pathlib import Path

from bkzs_guard.config import AppConfig


ESP32_DEFAULT_SOURCE = "bkzs-esp32-1"
ESP32_ROOT = Path(__file__).resolve().parents[2] / "esp32_node" / "BKZS_ESP32_Sender"
ESP32_PROFILE_HEADER_PATH = ESP32_ROOT / "bkzs_esp32_profile.h"
ESP32_WIFI_HEADER_PATH = ESP32_ROOT / "bkzs_wifi_secrets.h"


def _cpp_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_esp32_profile_header(
    config: AppConfig,
    *,
    target_host: str,
    target_port: int,
    protocol: str = "udp",
    source: str = ESP32_DEFAULT_SOURCE,
) -> str:
    use_udp = 1 if protocol.lower() == "udp" else 0
    zone = config.mission.primary_zone
    return "\n".join(
        [
            "#pragma once",
            "// Bu dosya BKZS Guard tarafindan otomatik uretilir.",
            "// Wi-Fi bilgilerini bkzs_wifi_secrets.h icinde guncelle.",
            "",
            f'#define BKZS_TARGET_HOST "{_cpp_escape(target_host)}"',
            f"#define BKZS_TARGET_PORT {int(target_port)}",
            f"#define BKZS_USE_UDP {use_udp}",
            f'#define BKZS_SOURCE "{_cpp_escape(source)}"',
            f'#define BKZS_SIGNAL_SECRET "{_cpp_escape(config.security.signal_secret)}"',
            f'#define BKZS_SESSION_NONCE "{_cpp_escape(config.security.session_nonce)}"',
            f'#define BKZS_SHADOW_SALT "{_cpp_escape(config.security.shadow_lane_salt)}"',
            f'#define BKZS_OP_CODE "{_cpp_escape(config.security.expected_op_code)}"',
            f'#define BKZS_SATELLITE_PROFILE "{_cpp_escape(config.mission.satellite_profile_id)}"',
            f'#define BKZS_CHANNEL "{_cpp_escape(config.mission.allowed_channel)}"',
            f'#define BKZS_MISSION_PHASE "{_cpp_escape(config.mission.mission_phase)}"',
            f"#define BKZS_BASE_LATITUDE {zone.center_latitude:.6f}f",
            f"#define BKZS_BASE_LONGITUDE {zone.center_longitude:.6f}f",
            "#define BKZS_BASE_ALTITUDE 19.2f",
            "#define BKZS_BASE_SPEED_MPS 12.8f",
            "#define BKZS_SEND_INTERVAL_MS 1000",
            "#define BKZS_SEQ_START 100",
            "#define BKZS_NTP_SERVER \"pool.ntp.org\"",
            "#define BKZS_FORCE_GENESIS_ON_BOOT 0",
            "",
        ]
    )


def write_esp32_profile_header(
    config: AppConfig,
    *,
    target_host: str,
    target_port: int,
    protocol: str = "udp",
    source: str = ESP32_DEFAULT_SOURCE,
    path: Path = ESP32_PROFILE_HEADER_PATH,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_esp32_profile_header(
            config,
            target_host=target_host,
            target_port=target_port,
            protocol=protocol,
            source=source,
        ),
        encoding="utf-8",
    )
    return path


def ensure_esp32_wifi_header(path: Path = ESP32_WIFI_HEADER_PATH) -> Path:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                [
                    "#pragma once",
                    "// Bu dosyayi kendi Wi-Fi agina gore duzenle.",
                    '#define BKZS_WIFI_SSID "WiFi_Adi"',
                    '#define BKZS_WIFI_PASSWORD "WiFi_Sifresi"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
    return path
