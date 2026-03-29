from __future__ import annotations

import json
import queue
import random
import socket
import threading
import time
from tkinter import BOTH, LEFT, BooleanVar, Button, Checkbutton, Frame, Label, StringVar, Tk

from profile_loader import load_target_profile
from remote_signal_client import ClientConfig, send_batch


class SocketListener(threading.Thread):
    def __init__(
        self,
        *,
        kind: str,
        protocol: str,
        bind_host: str,
        port: int,
        event_queue: queue.Queue[tuple[str, object]],
        stop_event: threading.Event,
        fallback_port: int | None = None,
        forward_port: int | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.kind = kind
        self.protocol = protocol.lower()
        self.bind_host = bind_host
        self.port = port
        self.fallback_port = fallback_port
        self.forward_port = forward_port
        self.event_queue = event_queue
        self.stop_event = stop_event
        self.bound_port: int | None = None

    def run(self) -> None:
        try:
            if self.protocol == "tcp":
                self._run_tcp()
            else:
                self._run_udp()
        except OSError as exc:
            self.event_queue.put(("monitor-error", f"{self.kind} dinleyicisi acilamadi: {exc}"))

    def _bind_udp_socket(self) -> socket.socket:
        candidates = [self.port]
        if self.fallback_port is not None:
            candidates.append(self.fallback_port)
        primary_error: OSError | None = None
        for candidate in candidates:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self.bind_host, candidate))
                self.bound_port = candidate
                if candidate != self.port:
                    self.event_queue.put(("monitor-error", f"{self.kind} yedek port {candidate} uzerinden dinleniyor"))
                return sock
            except OSError as exc:
                sock.close()
                if candidate == self.port:
                    primary_error = exc
                    continue
                raise primary_error or exc
        raise primary_error or OSError(f"{self.kind} dinleyicisi baglanamadi")

    def _forward_payload(self, payload: bytes) -> None:
        if self.forward_port is None or self.bound_port != self.port:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fanout:
                fanout.sendto(payload, ("127.0.0.1", self.forward_port))
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
                self.event_queue.put((self.kind, payload.decode("utf-8", errors="replace")))

    def _run_tcp(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_host, self.port))
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
                    conn.settimeout(0.4)
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
                        self.event_queue.put((self.kind, b"".join(chunks).decode("utf-8", errors="replace")))


class AttackConsole:
    BG = "#050505"
    PANEL = "#101010"
    PANEL_ALT = "#16090B"
    BORDER = "#4B0E14"
    RED = "#C1121F"
    RED_SOFT = "#FF6B75"
    RED_DARK = "#7A1D25"
    TEXT = "#F6F1F1"
    MUTED = "#B89FA2"
    GREEN = "#45D483"
    AMBER = "#F5A524"

    def __init__(self) -> None:
        profile = load_target_profile()
        self.root = Tk()
        self.root.title("BKZS Remote Attack Console")
        self.root.geometry("1080x700")
        self.root.minsize(920, 620)
        self.root.configure(bg=self.BG)
        self.random = random.Random()

        self.profile = profile
        self.target_host = str(profile.get("target_host", "127.0.0.1"))
        self.target_port = int(profile.get("target_port", 9000))
        self.target_protocol = str(profile.get("protocol", "udp")).lower()
        self.source = str(profile.get("source", "bkzs-edge-1"))
        self.signal_secret = str(profile.get("signal_secret", "bkzs-demo-signal"))
        self.session_nonce = str(profile.get("session_nonce", "bkzs-demo-session"))
        self.shadow_salt = str(profile.get("shadow_salt", "bkzs-demo-shadow"))
        self.op_code = str(profile.get("op_code", "BKZS-DEMO-2026"))
        self.satellite_profile = str(profile.get("satellite_profile", "generic-bkzs"))
        self.decision_protocol = str(profile.get("decision_feed_protocol", "udp")).lower()
        self.decision_port = int(profile.get("decision_feed_port", 9200))
        self.relay_protocol = str(profile.get("relay_protocol", "udp")).lower()
        self.secure_port = int(profile.get("secure_port", 9101))
        self.shadow_port = int(profile.get("shadow_port", 9102))

        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.monitor_stop_event = threading.Event()
        self.listeners: list[SocketListener] = []
        self.scenario_stop_event = threading.Event()
        self.scenario_thread: threading.Thread | None = None

        self.action_text = StringVar(value="Saldiriyi Baslat")
        self.monitor_status = StringVar(value="Karar dinleyicisi baglaniyor...")
        self.scenario_status = StringVar(value="Senaryo hazir")
        self.last_send_status = StringVar(value="Son gonderim: Beklemede")
        self.sent_total = StringVar(value="0")
        self.send_success = StringVar(value="0")
        self.send_failed = StringVar(value="0")
        self.accepted_total = StringVar(value="0")
        self.blocked_total = StringVar(value="0")
        self.lab_transport_var = BooleanVar(value=True)

        self._build_ui()
        self._start_monitor()
        self.root.after(150, self._pump_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        outer = Frame(self.root, bg=self.BG, padx=20, pady=20)
        outer.pack(fill=BOTH, expand=True)

        hero = Frame(outer, bg=self.PANEL_ALT, highlightbackground=self.RED, highlightthickness=1, padx=22, pady=20)
        hero.pack(fill="x", pady=(0, 16))
        Label(
            hero,
            text="BKZS Uzak Saldiri Konsolu",
            bg=self.PANEL_ALT,
            fg=self.TEXT,
            font=("Segoe UI", 24, "bold"),
            anchor="w",
        ).pack(fill="x")
        Label(
            hero,
            text="Hedef IP, port ve kimlik bilgileri ana istasyondan otomatik aliniyor. Burada sadece saldiri akisini baslatip sonucu izliyorsun.",
            bg=self.PANEL_ALT,
            fg=self.MUTED,
            font=("Segoe UI", 11),
            anchor="w",
            justify=LEFT,
            wraplength=900,
        ).pack(fill="x", pady=(6, 0))

        action_shell = Frame(outer, bg=self.BG)
        action_shell.pack(fill="x", pady=(0, 16))
        lab_row = Frame(action_shell, bg=self.BG)
        lab_row.pack(fill="x", pady=(0, 12))
        Checkbutton(
            lab_row,
            text="Laboratuvar IP simulasyonu (paket basina rastgele sanal IPv4; ana istasyonda BKZS_LAB_TRANSPORT_SIMULATION=1 gerekir)",
            variable=self.lab_transport_var,
            bg=self.BG,
            fg=self.TEXT,
            selectcolor=self.PANEL,
            activebackground=self.BG,
            activeforeground=self.TEXT,
            font=("Segoe UI", 10),
            anchor="w",
        ).pack(anchor="w")
        self.action_button = Button(
            action_shell,
            textvariable=self.action_text,
            command=self._toggle_attack,
            bg=self.RED,
            fg=self.TEXT,
            activebackground=self.RED_SOFT,
            activeforeground=self.TEXT,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI", 18, "bold"),
            padx=24,
            pady=16,
        )
        self.action_button.pack(fill="x")

        status_row = Frame(outer, bg=self.BG)
        status_row.pack(fill="x", pady=(0, 16))
        self._status_card(status_row, "Dinleyici", self.monitor_status, self.GREEN).pack(side=LEFT, fill="both", expand=True, padx=(0, 8))
        self._status_card(status_row, "Senaryo", self.scenario_status, self.RED_SOFT).pack(side=LEFT, fill="both", expand=True, padx=8)
        self._status_card(status_row, "Son Gonderim", self.last_send_status, self.AMBER).pack(side=LEFT, fill="both", expand=True, padx=(8, 0))

        summary = Frame(outer, bg=self.BG)
        summary.pack(fill="x", pady=(0, 8))
        self._metric(summary, "Gonderilen Paket", self.sent_total).pack(side=LEFT, fill="both", expand=True, padx=(0, 8))
        self._metric(summary, "Basarili Gonderim", self.send_success).pack(side=LEFT, fill="both", expand=True, padx=8)
        self._metric(summary, "Basarisiz Gonderim", self.send_failed).pack(side=LEFT, fill="both", expand=True, padx=8)
        self._metric(summary, "Gecen", self.accepted_total).pack(side=LEFT, fill="both", expand=True, padx=8)
        self._metric(summary, "Engellenen", self.blocked_total).pack(side=LEFT, fill="both", expand=True, padx=(8, 0))

        footer = Frame(outer, bg=self.BG)
        footer.pack(fill="x", pady=(12, 0))
        Label(
            footer,
            text="Arac otomatik olarak karar feed ve secure/shadow relay portlarini dinler. Bu konsol yalnizca saldiri paketleri gonderir; temiz normal akis icin normal_sender kullanilir.",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 10),
            wraplength=960,
            justify=LEFT,
            anchor="w",
        ).pack(fill="x")

    def _metric(self, parent: Frame, title: str, variable: StringVar) -> Frame:
        card = Frame(parent, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1, padx=12, pady=14)
        Label(
            card,
            text=title.upper(),
            bg=self.PANEL,
            fg=self.RED_SOFT,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        Label(
            card,
            textvariable=variable,
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 28, "bold"),
            pady=8,
        ).pack(anchor="w")
        return card

    def _status_card(self, parent: Frame, title: str, variable: StringVar, accent: str) -> Frame:
        card = Frame(parent, bg=self.PANEL, highlightbackground=self.BORDER, highlightthickness=1, padx=14, pady=14)
        Label(
            card,
            text=title.upper(),
            bg=self.PANEL,
            fg=accent,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        Label(
            card,
            textvariable=variable,
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 12, "bold"),
            wraplength=280,
            justify=LEFT,
            anchor="w",
            pady=6,
        ).pack(anchor="w")
        return card

    def _build_client_config(
        self,
        *,
        mode: str,
        source: str,
        count: int,
        interval_ms: int,
    ) -> ClientConfig:
        return ClientConfig(
            host=self.target_host,
            port=self.target_port,
            protocol=self.target_protocol,
            mode=mode,
            count=count,
            interval_ms=interval_ms,
            source=source,
            signal_secret=self.signal_secret,
            session_nonce=self.session_nonce,
            shadow_salt=self.shadow_salt,
            op_code=self.op_code,
            satellite_profile=self.satellite_profile,
            lab_transport=self.lab_transport_var.get(),
            lab_random_ip_per_packet=True,
            lab_fixed_ip="",
        )

    def _start_monitor(self) -> None:
        self._stop_monitor()
        self.monitor_stop_event = threading.Event()
        self.listeners = [
            SocketListener(
                kind="decision",
                protocol=self.decision_protocol,
                bind_host="0.0.0.0",
                port=self.decision_port,
                fallback_port=self.decision_port + 1,
                forward_port=self.decision_port + 1,
                event_queue=self.event_queue,
                stop_event=self.monitor_stop_event,
            ),
            SocketListener(
                kind="secure",
                protocol=self.relay_protocol,
                bind_host="0.0.0.0",
                port=self.secure_port,
                event_queue=self.event_queue,
                stop_event=self.monitor_stop_event,
            ),
            SocketListener(
                kind="shadow",
                protocol=self.relay_protocol,
                bind_host="0.0.0.0",
                port=self.shadow_port,
                event_queue=self.event_queue,
                stop_event=self.monitor_stop_event,
            ),
        ]
        for listener in self.listeners:
            listener.start()
        self.monitor_status.set("Karar ve relay dinleme aktif")

    def _stop_monitor(self) -> None:
        if self.listeners:
            self.monitor_stop_event.set()
            self.listeners = []
        self.monitor_status.set("Dinleme kapali")

    def _toggle_attack(self) -> None:
        if self.scenario_thread is not None and self.scenario_thread.is_alive():
            self._stop_attack()
            return
        self._start_attack()

    def _start_attack(self) -> None:
        self.scenario_stop_event = threading.Event()
        self.scenario_thread = threading.Thread(target=self._scenario_worker, daemon=True)
        self.scenario_thread.start()
        self.action_text.set("Saldiriyi Durdur")
        self.scenario_status.set("Surekli saldiri akisi aktif")

    def _stop_attack(self) -> None:
        self.scenario_stop_event.set()
        self.action_text.set("Saldiriyi Baslat")
        self.scenario_status.set("Senaryo durduruluyor")

    def _scenario_worker(self) -> None:
        source_pools = {
            "spoof": ["bkzs-core", "bkzs-core-clone", "relay-ghost", "turksat-6a-shadow"],
            "rogue": ["spoofed-edge", "unknown-relay", "ghost-uplink", "mirror-node"],
        }
        profiles = [
            {"mode": "jam", "weight": 2, "count": (1, 3), "interval": (70, 130), "pool": "spoof", "method": "rf bozma"},
            {"mode": "unauthorized", "weight": 1, "count": (1, 2), "interval": (80, 150), "pool": "rogue", "method": "kaynak spoof"},
            {"mode": "replay", "weight": 2, "count": (2, 4), "interval": (60, 120), "pool": "spoof", "method": "replay + port hopping"},
            {"mode": "mission-breach", "weight": 3, "count": (2, 4), "interval": (60, 120), "pool": "spoof", "method": "kimlik dondurme + mission drift"},
            {"mode": "mesh-divergence", "weight": 2, "count": (2, 4), "interval": (60, 110), "pool": "spoof", "method": "peer ayirma denemesi"},
            {"mode": "shadow-contact", "weight": 2, "count": (1, 3), "interval": (60, 100), "pool": "rogue", "method": "credential taklidi"},
        ]
        weights = [item["weight"] for item in profiles]
        while not self.scenario_stop_event.is_set():
            selected = self.random.choices(profiles, weights=weights, k=1)[0]
            source_pool = source_pools[str(selected["pool"])]
            config = self._build_client_config(
                mode=str(selected["mode"]),
                source=self.random.choice(source_pool),
                count=self.random.randint(*selected["count"]),
                interval_ms=self.random.randint(*selected["interval"]),
            )
            self.event_queue.put(("scenario-status", f"Aktif yontem: {selected['method']}"))
            send_batch(
                config,
                on_result=self._on_send_result,
                should_stop=self.scenario_stop_event.is_set,
            )
            remaining = self.random.uniform(0.2, 0.9)
            while remaining > 0 and not self.scenario_stop_event.is_set():
                step = min(0.05, remaining)
                time.sleep(step)
                remaining -= step
        self.event_queue.put(("scenario-stopped", None))

    def _on_send_result(self, index: int, total: int, payload: str, success: bool, error: str | None) -> None:
        self.event_queue.put(
            (
                "send-result",
                {
                    "index": index,
                    "total": total,
                    "success": success,
                    "error": error or "",
                },
            )
        )

    def _pump_events(self) -> None:
        while True:
            try:
                kind, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_event(kind, payload)
        self.root.after(150, self._pump_events)

    def _handle_event(self, kind: str, payload: object) -> None:
        if kind == "send-result":
            item = payload if isinstance(payload, dict) else {}
            self.sent_total.set(str(int(self.sent_total.get()) + 1))
            if bool(item.get("success")):
                self.send_success.set(str(int(self.send_success.get()) + 1))
                self.last_send_status.set("Son gonderim: Basarili")
            else:
                self.send_failed.set(str(int(self.send_failed.get()) + 1))
                error = str(item.get("error", "")).strip()
                detail = f"Son gonderim: Basarisiz{f' | {error}' if error else ''}"
                self.last_send_status.set(detail)
            return
        if kind == "decision":
            self._handle_decision_payload(str(payload))
            return
        if kind == "monitor-error":
            self.monitor_status.set(str(payload))
            return
        if kind == "scenario-stopped":
            self.action_text.set("Saldiriyi Baslat")
            self.scenario_status.set("Senaryo durdu")
            return
        if kind == "scenario-status":
            self.scenario_status.set(str(payload))
            return
        if kind in {"secure", "shadow"}:
            return

    def _handle_decision_payload(self, payload: str) -> None:
        try:
            decision = json.loads(payload)
        except json.JSONDecodeError:
            return
        decision_value = str(decision.get("decision", "")).lower()
        if decision_value == "accepted":
            self.accepted_total.set(str(int(self.accepted_total.get()) + 1))
        else:
            self.blocked_total.set(str(int(self.blocked_total.get()) + 1))

    def _on_close(self) -> None:
        self._stop_attack()
        self._stop_monitor()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    AttackConsole().run()


if __name__ == "__main__":
    main()
