from __future__ import annotations

import argparse
import json
import queue
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from profile_loader import load_target_profile
from remote_signal_client import (
    ClientConfig,
    build_packet_chain_hash,
    initial_clean_hash,
    send_batch,
    split_signal_secret,
)


SUCCESS_LOG_DIR = Path(__file__).resolve().parent / "success_logs"
STATE_PATH = Path(__file__).resolve().parent / "normal_sender_state.json"
TRUSTED_NORMAL_SOURCES = ("bkzs-edge-1", "bkzs-edge-2", "bkzs-core")
INSTANCE_GUARD_PORT = 43119


def parse_args() -> argparse.Namespace:
    profile = load_target_profile()
    parser = argparse.ArgumentParser(description="BKZS temiz normal trafik gonderici")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--interval-ms", type=int, default=180)
    parser.add_argument("--wait-seconds", type=float, default=0.35)
    parser.add_argument("--host", default=str(profile.get("target_host", "127.0.0.1")))
    parser.add_argument("--port", type=int, default=int(profile.get("target_port", 9000)))
    parser.add_argument("--protocol", choices=("udp", "tcp"), default=str(profile.get("protocol", "udp")))
    parser.add_argument("--source", default=str(profile.get("source", "bkzs-edge-1")))
    parser.add_argument("--satellite-profile", default=str(profile.get("satellite_profile", "generic-bkzs")))
    parser.add_argument("--signal-secret", default=str(profile.get("signal_secret", "bkzs-demo-signal")))
    parser.add_argument("--session-nonce", default=str(profile.get("session_nonce", "bkzs-demo-session")))
    parser.add_argument("--shadow-salt", default=str(profile.get("shadow_salt", "bkzs-demo-shadow")))
    parser.add_argument("--op-code", default=str(profile.get("op_code", "BKZS-DEMO-2026")))
    parser.add_argument("--decision-protocol", choices=("udp", "tcp"), default=str(profile.get("decision_feed_protocol", "udp")))
    parser.add_argument("--decision-port", type=int, default=int(profile.get("decision_feed_port", 9200)))
    parser.add_argument("--lab-transport", action="store_true", default=str(profile.get("normal_lab_transport", profile.get("lab_transport", "1"))) != "0")
    parser.add_argument("--lab-fixed-ip", default=str(profile.get("normal_lab_fixed_ip", "10.10.10.10")))
    return parser.parse_args()


def unwrap_framed_payload(payload: str, signal_secret: str) -> dict[str, Any] | None:
    prefix, suffix = split_signal_secret(signal_secret)
    if not payload.startswith(prefix):
        return None
    body = payload[len(prefix):]
    if suffix and body.endswith(suffix):
        body = body[: -len(suffix)]
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


class DecisionListener(threading.Thread):
    def __init__(
        self,
        *,
        protocol: str,
        port: int,
        event_queue: queue.Queue[dict[str, Any]],
        stop_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True)
        self.protocol = protocol.lower()
        self.port = port
        self.fallback_port = port + 1
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.bind_error: str | None = None
        self.bound_port: int | None = None

    def run(self) -> None:
        try:
            if self.protocol == "tcp":
                self._run_tcp()
            else:
                self._run_udp()
        except OSError as exc:
            self.bind_error = str(exc)
            print(f"Karar dinleyicisi baslatilamadi: {exc}. Gonderim izleme olmadan devam edilecek. Attack console aciksa kapat veya farkli decision port kullan.")

    def _bind_udp_socket(self) -> socket.socket:
        primary_error: OSError | None = None
        for candidate in (self.port, self.fallback_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("0.0.0.0", candidate))
                self.bound_port = candidate
                if candidate != self.port:
                    print(f"Karar dinleyicisi ana portta dolu; yedek port {candidate} dinleniyor.")
                return sock
            except OSError as exc:
                sock.close()
                if candidate == self.port:
                    primary_error = exc
                    continue
                raise primary_error or exc
        raise primary_error or OSError("Karar dinleyicisi baglanamadi.")

    def _forward_payload(self, payload: bytes) -> None:
        if self.bound_port != self.port:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fanout:
                fanout.sendto(payload, ("127.0.0.1", self.fallback_port))
        except OSError:
            return

    def _run_udp(self) -> None:
        with self._bind_udp_socket() as sock:
            sock.settimeout(0.4)
            while not self.stop_event.is_set():
                try:
                    payload, _ = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                self._forward_payload(payload)
                self._push(payload.decode("utf-8", errors="replace"))

    def _run_tcp(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen()
            server.settimeout(0.4)
            while not self.stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with conn:
                    chunks: list[bytes] = []
                    while True:
                        try:
                            chunk = conn.recv(4096)
                        except TimeoutError:
                            break
                        if not chunk:
                            break
                        chunks.append(chunk)
                    if chunks:
                        self._push(b"".join(chunks).decode("utf-8", errors="replace"))

    def _push(self, payload: str) -> None:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return
        if isinstance(parsed, dict):
            self.event_queue.put(parsed)


def load_sender_state(source: str) -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    source_state = payload.get(source, {})
    return source_state if isinstance(source_state, dict) else {}


def save_sender_state(source: str, next_seq_start: int, previous_clean_hash: str) -> None:
    payload: dict[str, Any] = {}
    if STATE_PATH.exists():
        try:
            loaded = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except (OSError, json.JSONDecodeError):
            payload = {}
    payload[source] = {
        "next_seq_start": next_seq_start,
        "previous_clean_hash": previous_clean_hash,
        "updated_at": datetime.now().isoformat(),
    }
    STATE_PATH.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")


def build_source_rotation(primary_source: str) -> list[str]:
    ordered = [primary_source, *TRUSTED_NORMAL_SOURCES]
    unique: list[str] = []
    for item in ordered:
        if item not in unique:
            unique.append(item)
    return unique


def hydrate_source_runtime(source: str, session_nonce: str) -> tuple[int, str, str]:
    saved_state = load_sender_state(source)
    persisted_seq_start = int(saved_state.get("next_seq_start", 100))
    initial_hash = initial_clean_hash(source, session_nonce)
    current_clean_hash = initial_hash
    next_seq_start = max(persisted_seq_start, 100)
    return next_seq_start, current_clean_hash, initial_hash


def acquire_instance_guard() -> socket.socket | None:
    guard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        guard.bind(("127.0.0.1", INSTANCE_GUARD_PORT))
    except OSError:
        guard.close()
        return None
    guard.listen(1)
    return guard


def main() -> None:
    args = parse_args()
    SUCCESS_LOG_DIR.mkdir(parents=True, exist_ok=True)
    instance_guard = acquire_instance_guard()
    if instance_guard is None:
        print("normal_sender zaten calisiyor. Once eski normal_sender surecini kapat, sonra tekrar dene.")
        return

    source_pool = build_source_rotation(args.source)
    source_index = 0
    active_source = source_pool[source_index]
    next_seq_start, current_clean_hash, initial_hash = hydrate_source_runtime(active_source, args.session_nonce)

    config = ClientConfig(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        mode="normal",
        count=1,
        interval_ms=args.interval_ms,
        source=active_source,
        signal_secret=args.signal_secret,
        session_nonce=args.session_nonce,
        shadow_salt=args.shadow_salt,
        op_code=args.op_code,
        satellite_profile=args.satellite_profile,
        seq_start=next_seq_start,
        previous_clean_hash_override=current_clean_hash,
        lab_transport=args.lab_transport,
        lab_random_ip_per_packet=False,
        lab_fixed_ip=args.lab_fixed_ip,
    )

    decision_queue: queue.Queue[dict[str, Any]] = queue.Queue()
    decision_cache: dict[str, dict[str, Any]] = {}
    stop_event = threading.Event()
    listener = DecisionListener(
        protocol=args.decision_protocol,
        port=args.decision_port,
        event_queue=decision_queue,
        stop_event=stop_event,
    )
    listener.start()
    time.sleep(0.1)
    decision_listener_available = listener.bind_error is None
    if not decision_listener_available:
        current_clean_hash = initial_hash
        config.previous_clean_hash_override = current_clean_hash

    sent_packet_ids: set[str] = set()
    sent_ok = 0
    sent_fail = 0
    send_attempts = 0
    accepted_rows: list[dict[str, Any]] = []
    seen_packet_ids: set[str] = set()
    stop_requested = False
    consecutive_decision_timeouts = 0
    source_failures: dict[str, int] = {item: 0 for item in source_pool}
    def on_result(index: int, total: int, payload: str, success: bool, error: str | None) -> None:
        nonlocal sent_ok, sent_fail, send_attempts
        send_attempts += 1
        packet = unwrap_framed_payload(payload, config.signal_secret) or {}
        packet_id = str(packet.get("packet_id", f"packet-{index}"))
        seq = packet.get("seq", "-")
        if success:
            sent_ok += 1
            sent_packet_ids.add(packet_id)
            print(f"[Toplam {send_attempts}] normal paket gonderildi: {packet_id} | seq {seq}")
        else:
            sent_fail += 1
            print(f"[Toplam {send_attempts}] gonderim hatasi: {packet_id} | seq {seq} | {error or 'bilinmeyen hata'}")

    def drain_decisions(wait_seconds: float = 0.0) -> None:
        deadline = time.time() + max(wait_seconds, 0.0)
        while True:
            timeout = 0.0
            if wait_seconds > 0:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                timeout = min(0.4, max(remaining, 0.05))
            try:
                decision = decision_queue.get(timeout=timeout) if timeout > 0 else decision_queue.get_nowait()
            except queue.Empty:
                if wait_seconds > 0:
                    continue
                break
            packet_id = str(decision.get("packet_id", ""))
            if packet_id not in sent_packet_ids:
                if packet_id:
                    decision_cache[packet_id] = decision
                continue
            if packet_id in seen_packet_ids:
                continue
            if str(decision.get("decision", "")).lower() != "accepted":
                if packet_id:
                    decision_cache[packet_id] = decision
                continue
            seen_packet_ids.add(packet_id)
            accepted_rows.append(decision)

    def wait_for_packet_decision(packet_id: str, wait_seconds: float) -> dict[str, Any] | None:
        cached = decision_cache.pop(packet_id, None)
        if cached is not None:
            return cached
        deadline = time.time() + max(wait_seconds, 0.0)
        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                decision = decision_queue.get(timeout=min(0.4, max(remaining, 0.05)))
            except queue.Empty:
                continue
            current_packet_id = str(decision.get("packet_id", ""))
            if current_packet_id == packet_id:
                return decision
            if current_packet_id:
                decision_cache[current_packet_id] = decision
        return None

    try:
        print("Temiz normal trafik basladi. Durdurmak icin Ctrl+C kullan.")
        if config.lab_transport:
            print(f"Temiz trafik laboratuvar IPv4 ile etiketlenecek: {config.lab_fixed_ip}")
        while True:
            attempted_hashes: set[str] = set()
            while True:
                config.source = active_source
                config.seq_start = next_seq_start
                config.previous_clean_hash_override = current_clean_hash
                last_payload: str | None = None

                def capture_result(index: int, total: int, payload: str, success: bool, error: str | None) -> None:
                    nonlocal last_payload
                    last_payload = payload
                    on_result(index, total, payload, success, error)

                send_batch(config, on_result=capture_result)
                if not last_payload:
                    time.sleep(max(config.interval_ms, 1) / 1000)
                    break

                packet = unwrap_framed_payload(last_payload, config.signal_secret) or {}
                packet_id = str(packet.get("packet_id", ""))
                candidate_next_hash = str(config.previous_clean_hash_override or "").strip()

                if not decision_listener_available:
                    current_clean_hash = candidate_next_hash or current_clean_hash
                    next_seq_start += 1
                    save_sender_state(active_source, next_seq_start, current_clean_hash)
                    break

                decision = wait_for_packet_decision(packet_id, args.wait_seconds)
                if decision is None:
                    consecutive_decision_timeouts += 1
                    if consecutive_decision_timeouts >= 2:
                        decision_listener_available = False
                        current_clean_hash = candidate_next_hash or current_clean_hash or initial_hash
                        print("Karar feed gec cevap veriyor. Hizli akis moduna gecildi; zincir yerel olarak ilerletilecek.")
                    current_clean_hash = candidate_next_hash or current_clean_hash
                    next_seq_start += 1
                    save_sender_state(active_source, next_seq_start, current_clean_hash)
                    break
                consecutive_decision_timeouts = 0

                if str(decision.get("decision", "")).lower() == "accepted":
                    source_failures[active_source] = 0
                    seen_packet_ids.add(packet_id)
                    if packet_id not in sent_packet_ids:
                        sent_packet_ids.add(packet_id)
                    if packet_id not in {str(item.get("packet_id", "")) for item in accepted_rows}:
                        accepted_rows.append(decision)
                    current_clean_hash = candidate_next_hash or build_packet_chain_hash(packet)
                    next_seq_start += 1
                    save_sender_state(active_source, next_seq_start, current_clean_hash)
                    break

                failed_layer = int(decision.get("failed_layer") or 0)
                classification = str(decision.get("classification", "")).lower()

                if failed_layer == 6:
                    attempted_hashes.add(current_clean_hash)
                    fallback_hash = initial_hash if current_clean_hash != initial_hash else ""
                    if fallback_hash and fallback_hash not in attempted_hashes:
                        current_clean_hash = fallback_hash
                        print(f"Epoch zinciri {active_source} icin senkronize ediliyor, paket yeniden denenecek...")
                        continue
                    source_failures[active_source] += 1
                    if source_failures[active_source] >= 2 and len(source_pool) > 1:
                        source_index = (source_index + 1) % len(source_pool)
                        active_source = source_pool[source_index]
                        next_seq_start, current_clean_hash, initial_hash = hydrate_source_runtime(active_source, args.session_nonce)
                        config.source = active_source
                        config.seq_start = next_seq_start
                        config.previous_clean_hash_override = current_clean_hash
                        print(f"Epoch zinciri toparlanamadi. Yedek kaynaga geciliyor: {active_source}")
                        attempted_hashes.clear()
                        continue

                if failed_layer == 8 or classification == "replay_suspect":
                    next_seq_start += 1000
                    print("Replay/regression algilandi, sira numarasi ileri alinip akisa devam ediliyor...")
                else:
                    next_seq_start += 1
                save_sender_state(active_source, next_seq_start, current_clean_hash)
                break
    except KeyboardInterrupt:
        stop_requested = True
        print()
        print("Durdurma sinyali alindi. Son kararlar toplanip log yaziliyor...")
    finally:
        stop_event.set()
        listener.join(timeout=1.0)
        drain_decisions(wait_seconds=1.0)
        instance_guard.close()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = SUCCESS_LOG_DIR / f"accepted_normal_{timestamp}.jsonl"
    summary_path = SUCCESS_LOG_DIR / f"summary_{timestamp}.json"

    with log_path.open("w", encoding="utf-8") as handle:
        for row in accepted_rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")

    summary = {
        "target": f"{config.protocol.upper()} {config.host}:{config.port}",
        "source": config.source,
        "satellite_profile": config.satellite_profile,
        "batch_packet_count": config.count,
        "stop_requested": stop_requested,
        "sent_success": sent_ok,
        "sent_failed": sent_fail,
        "accepted_logged": len(accepted_rows),
        "decision_port": args.decision_port,
        "accepted_log": str(log_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")

    print()
    print("Temiz trafik gonderimi tamamlandi.")
    print(f"Basarili gonderim : {sent_ok}")
    print(f"Basarisiz gonderim: {sent_fail}")
    print(f"Kabul logu        : {log_path}")
    print(f"Ozet dosyasi      : {summary_path}")


if __name__ == "__main__":
    main()
