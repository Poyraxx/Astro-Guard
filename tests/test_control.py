from __future__ import annotations

import os
import socket
import time
import unittest

from bkzs_guard.config import load_app_config
from bkzs_guard.control import BKZSControlCenter
from bkzs_guard.lab_transport import wrap_lab_transport


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ControlCenterTests(unittest.TestCase):
    def test_dashboard_snapshot_tracks_demo_results(self) -> None:
        app = BKZSControlCenter()
        self.assertTrue(app.authenticate("astro-guard"))

        results = app.load_normal_run(count=3)
        snapshot = app.dashboard_snapshot()

        self.assertEqual(len(results), 3)
        self.assertEqual(len(snapshot.records), 3)
        self.assertEqual(snapshot.accepted_count, 3),
        self.assertEqual(snapshot.blocked_count, 0)
        self.assertFalse(snapshot.quarantined)
        self.assertTrue(snapshot.passports)
        self.assertTrue(app.real_plane_events)
        self.assertFalse(app.shadow_plane_events)

    def test_counter_intel_tour_updates_run_metadata(self) -> None:
        app = BKZSControlCenter()

        results, metadata = app.load_counter_intel_tour(base_count=4)

        self.assertEqual(metadata["mode"], "counter_intel_tour")
        self.assertEqual(app.last_run_meta["mode"], "counter_intel_tour")
        self.assertEqual(len(results), len(app.last_run_results))
        self.assertEqual(len(results), len(app.last_run_truth))
        self.assertTrue(any(item["label"] == "attack" for item in app.last_run_truth))

    def test_forensic_cases_are_created_for_blocked_results(self) -> None:
        app = BKZSControlCenter()
        app.load_stage_run(stage=5, count=3)

        self.assertTrue(app.forensic_cases)
        self.assertTrue(any(case.case_id.startswith("case-") for case in app.forensic_cases))

    def test_deep_breach_is_routed_to_shadow_twin(self) -> None:
        app = BKZSControlCenter()
        app.last_clean_payload_by_source["bkzs-edge-1"] = '{"packet_id":"trusted-baseline"}'

        results = app.ingest_packets(app.attack_lab._mission_envelope_break(1))
        snapshot = app.dashboard_snapshot()

        self.assertTrue(any(record.twin_engaged for record in results))
        self.assertTrue(any((record.shadow_session_id or "").startswith("shadow-") for record in results))
        self.assertTrue(app.shadow_twin_sessions)
        self.assertTrue(app.threat_intel_events)
        self.assertTrue(snapshot.twin_records)
        self.assertTrue(snapshot.shadow_twin_sessions)
        self.assertTrue(snapshot.threat_intel_events)
        self.assertEqual(app.shadow_twin_sessions[-1].attack_family, "mission_envelope_evasion")
        self.assertIn("Mission", app.shadow_twin_sessions[-1].operator_recommendation)
        self.assertEqual(app.threat_intel_events[-1].attack_vector, "route-speed-phase drift")
        self.assertTrue(app.shadow_plane_events)
        self.assertTrue(any(event.action == "continuity_forward" and event.used_fallback for event in app.real_plane_events))
        self.assertTrue(snapshot.real_plane_events)
        self.assertTrue(snapshot.shadow_plane_events)

    def test_clean_run_does_not_create_shadow_twin_session(self) -> None:
        app = BKZSControlCenter()
        app.load_normal_run(count=2)

        self.assertFalse(app.shadow_twin_sessions)
        self.assertFalse(app.threat_intel_events)

    def test_applying_trust_bulletin_updates_dashboard_snapshot(self) -> None:
        app = BKZSControlCenter()
        bulletin_payload = app.sample_bulletin_payload()
        bulletin = app.apply_trust_bulletin(bulletin_payload)
        snapshot = app.dashboard_snapshot()

        self.assertEqual(snapshot.active_bulletin.bulletin_id, bulletin.bulletin_id)

    def test_applying_satellite_profile_updates_runtime_config(self) -> None:
        app = BKZSControlCenter()
        app.apply_satellite_profile("imece")

        self.assertEqual(app.config.mission.satellite_profile_id, "imece")
        self.assertEqual(app.config.mission.allowed_channel, "eo-downlink")
        self.assertEqual(app.config.mission.mission_phase, "imaging")

    def test_network_listener_runs_until_stopped(self) -> None:
        app = BKZSControlCenter()
        port = _free_port()
        app.start_network_listener(protocol="udp", host="127.0.0.1", port=port, poll_timeout_seconds=0.1)
        try:
            time.sleep(0.15)
            packet = app.attack_lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=55)[0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(packet.encode("utf-8"), ("127.0.0.1", port))

            deadline = time.time() + 2.0
            while time.time() < deadline:
                status = app.network_listener_snapshot()
                if status.received_packets >= 1:
                    break
                time.sleep(0.05)

            status = app.network_listener_snapshot()
            self.assertGreaterEqual(status.received_packets, 1)
            self.assertIsNotNone(status.last_packet_at)
            snapshot = app.dashboard_snapshot()
            self.assertTrue(snapshot.records)
            self.assertTrue(snapshot.remote_threat_contacts)
            self.assertEqual(snapshot.remote_threat_contacts[0]["ip"], "127.0.0.1")
            self.assertGreaterEqual(snapshot.remote_threat_contacts[0]["packets"], 1)
        finally:
            app.stop_network_listener()

        self.assertFalse(app.network_listener_snapshot().active)

    def test_network_listener_handles_udp_burst(self) -> None:
        app = BKZSControlCenter()
        port = _free_port()
        app.start_network_listener(protocol="udp", host="127.0.0.1", port=port, poll_timeout_seconds=0.05)
        try:
            packets = app.attack_lab.generate_normal_batch(count=16, source="bkzs-edge-1", start_seq=800)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for packet in packets:
                    sock.sendto(packet.encode("utf-8"), ("127.0.0.1", port))

            deadline = time.time() + 2.0
            while time.time() < deadline:
                status = app.network_listener_snapshot()
                if status.received_packets >= len(packets):
                    break
                time.sleep(0.05)

            status = app.network_listener_snapshot()
            snapshot = app.dashboard_snapshot()

            self.assertGreaterEqual(status.received_packets, len(packets) - 2)
            self.assertTrue(snapshot.remote_threat_contacts)
            observed_total = snapshot.remote_threat_contacts[0]["packets"] + snapshot.remote_threat_contacts[0]["network_drop"]
            self.assertGreaterEqual(observed_total, len(packets) - 2)
        finally:
            app.stop_network_listener()

    def test_lab_transport_remapped_contact_ip(self) -> None:
        os.environ["BKZS_LAB_TRANSPORT_SIMULATION"] = "1"
        try:
            cfg = load_app_config()
            self.assertTrue(cfg.lab.transport_simulation_enabled)
            app = BKZSControlCenter(cfg)
            port = _free_port()
            app.start_network_listener(protocol="udp", host="127.0.0.1", port=port, poll_timeout_seconds=0.1)
            try:
                packet = app.attack_lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=55)[0]
                wrapped = wrap_lab_transport(packet, "10.12.13.14")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(wrapped.encode("utf-8"), ("127.0.0.1", port))
                deadline = time.time() + 3.0
                while time.time() < deadline:
                    status = app.network_listener_snapshot()
                    snapshot = app.dashboard_snapshot()
                    if status.received_packets >= 1 and snapshot.remote_threat_contacts:
                        break
                    time.sleep(0.05)
                snapshot = app.dashboard_snapshot()
                self.assertTrue(snapshot.remote_threat_contacts)
                self.assertEqual(snapshot.remote_threat_contacts[0]["ip"], "10.12.13.14")
            finally:
                app.stop_network_listener()
        finally:
            os.environ.pop("BKZS_LAB_TRANSPORT_SIMULATION", None)

    def test_remote_ip_is_blocked_after_repeated_failures(self) -> None:
        app = BKZSControlCenter()
        port = _free_port()
        app.start_network_listener(protocol="udp", host="127.0.0.1", port=port, poll_timeout_seconds=0.1)
        try:
            bad_packets = app.attack_lab.generate_stage_batch(stage=5, count=6)[:6]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for packet in bad_packets:
                    sock.sendto(packet.encode("utf-8"), ("127.0.0.1", port))
                    time.sleep(0.05)

            deadline = time.time() + 2.0
            while time.time() < deadline:
                snapshot = app.dashboard_snapshot()
                if snapshot.remote_blocked_sources:
                    break
                time.sleep(0.05)

            before_records = len(app.dashboard_snapshot().records)
            clean_packet = app.attack_lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=501)[0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(clean_packet.encode("utf-8"), ("127.0.0.1", port))
            time.sleep(0.3)

            snapshot = app.dashboard_snapshot()
            self.assertTrue(snapshot.remote_blocked_sources)
            self.assertEqual(len(snapshot.records), before_records)
            self.assertGreaterEqual(snapshot.remote_threat_contacts[0]["network_drop"], 1)
        finally:
            app.stop_network_listener()

    def test_dashboard_totals_continue_after_record_windows_rotate(self) -> None:
        app = BKZSControlCenter()
        accepted_samples = app.load_normal_run(count=3)
        blocked_samples = app.load_stage_run(stage=1, count=3)
        app.decisions = (accepted_samples + blocked_samples) * 67
        app.decisions = app.decisions[:400]
        app.quarantine = (blocked_samples * 67)[:200]
        app.total_packets = 610
        app.total_accepted = 405
        app.total_blocked = 205
        snapshot = app.dashboard_snapshot()

        self.assertEqual(snapshot.total_packets, 610)
        self.assertEqual(snapshot.accepted_count, 405)
        self.assertEqual(snapshot.blocked_count, 205)
        self.assertEqual(len(snapshot.records), 400)
        self.assertEqual(len(snapshot.quarantined), 200)


if __name__ == "__main__":
    unittest.main()
