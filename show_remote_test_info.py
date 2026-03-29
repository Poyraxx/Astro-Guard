from __future__ import annotations

import argparse
import socket
from textwrap import dedent

from bkzs_guard.config import load_app_config


def detect_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BKZS Guard uzak saldiri testi bilgi ciktisi")
    parser.add_argument("--adapter-port", type=int, default=9000, help="Gercek adaptor dinleme portu")
    parser.add_argument("--streamlit-port", type=int, default=8501, help="Streamlit portu")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Env'den gelen sinyal secret / session nonce / op_code bilgilerini de yazdir",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_app_config()
    ip_address = detect_local_ip()

    header = dedent(
        f"""
        BKZS Guard Uzak Test Bilgileri
        ==============================
        Ana bilgisayar IP      : {ip_address}
        Streamlit URL          : http://{ip_address}:{args.streamlit_port}
        Saldiri hedef host     : {ip_address}
        Saldiri hedef port     : {args.adapter_port}
        Adaptor bind host      : 0.0.0.0
        Karar feed             : {config.decision_feed.protocol.upper()} {config.decision_feed.host}:{config.decision_feed.port}
        Secure relay           : {config.relay.secure_plane.protocol.upper()} {config.relay.secure_plane.host}:{config.relay.secure_plane.port}
        Shadow relay           : {config.relay.shadow_plane.protocol.upper()} {config.relay.shadow_plane.host}:{config.relay.shadow_plane.port}
        Uydu profili (env)     : {config.mission.satellite_profile_id}
        """
    ).strip()

    print(header)
    print()
    print("Ana bilgisayarda adaptor icin:")
    print(f"  Host = 0.0.0.0")
    print(f"  Port = {args.adapter_port}")
    print()
    print("Ikinci bilgisayarda saldiri konsolu:")
    print("  cd remote_attack_node")
    print("  python attack_console.py")
    print()
    print("Ikinci bilgisayarda ornek terminal komutlari:")
    print(
        f"  python remote_signal_client.py --host {ip_address} --port {args.adapter_port} --protocol udp --mode normal --count 3 --satellite-profile {config.mission.satellite_profile_id}"
    )
    print(
        f"  python remote_signal_client.py --host {ip_address} --port {args.adapter_port} --protocol udp --mode mission-breach --count 2 --satellite-profile {config.mission.satellite_profile_id}"
    )
    print(
        f"  python remote_signal_client.py --host {ip_address} --port {args.adapter_port} --protocol udp --mode shadow-contact --count 2 --satellite-profile {config.mission.satellite_profile_id}"
    )
    print()
    print("Ana bilgisayarda acilabilecek ortam degiskenleri:")
    print("  set BKZS_RELAY_ENABLED=1")
    print(f"  set BKZS_SECURE_RELAY_HOST={ip_address}")
    print(f"  set BKZS_SECURE_RELAY_PORT={config.relay.secure_plane.port}")
    print(f"  set BKZS_SHADOW_RELAY_HOST={ip_address}")
    print(f"  set BKZS_SHADOW_RELAY_PORT={config.relay.shadow_plane.port}")
    print("  set BKZS_DECISION_FEED_ENABLED=1")
    print(f"  set BKZS_DECISION_FEED_HOST={ip_address}")
    print(f"  set BKZS_DECISION_FEED_PORT={config.decision_feed.port}")
    print()

    if args.include_sensitive:
        print("Dikkat: bu alanlar hassastir.")
        print(f"  signal_secret  = {config.security.signal_secret}")
        print(f"  session_nonce  = {config.security.session_nonce}")
        print(f"  op_code        = {config.security.expected_op_code}")
        print()
    else:
        print("Not:")
        print("  UI uzerinden sinyal sifresi, oturum muhru veya op_code degisti ise")
        print("  bunlari ayri paylasman gerekir. Bu script varsayilan/env degerlerini baz alir.")


if __name__ == "__main__":
    main()
