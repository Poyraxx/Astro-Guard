from __future__ import annotations

import argparse
import socket


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Standalone relay sink for secure-plane or shadow-plane traffic.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--protocol", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--label", default="relay-sink")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.protocol == "udp":
        run_udp(args.host, args.port, args.label)
    else:
        run_tcp(args.host, args.port, args.label)


def run_udp(host: str, port: int, label: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"[{label}] listening on UDP {host}:{port}")
        while True:
            payload, addr = sock.recvfrom(8192)
            print(f"[{label}] {addr[0]}:{addr[1]} -> {payload.decode('utf-8', errors='replace')}")


def run_tcp(host: str, port: int, label: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[{label}] listening on TCP {host}:{port}")
        while True:
            conn, addr = sock.accept()
            with conn:
                chunks: list[bytes] = []
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                payload = b"".join(chunks).decode("utf-8", errors="replace")
                print(f"[{label}] {addr[0]}:{addr[1]} -> {payload}")


if __name__ == "__main__":
    main()
