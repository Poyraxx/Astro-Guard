from __future__ import annotations

import json
import unittest

from bkzs_guard.attack_lab import AttackLab
from bkzs_guard.policy import sample_trust_bulletin, load_trust_bulletin
from bkzs_guard.pipeline import MicroLayerEngine
from bkzs_guard.satellites import get_satellite_profile
from bkzs_guard.utils import (
    build_challenge_proof,
    build_flow_tag,
    frame_signal_payload,
    initial_clean_hash,
    packet_flow_tag_view,
    stable_checksum,
)


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = MicroLayerEngine()
        self.lab = AttackLab()

    def _frame_packet(self, packet: dict) -> str:
        packet["flow_tag"] = build_flow_tag(
            packet_flow_tag_view(packet),
            self.engine.config.security.signal_secret,
            packet["session_nonce"],
        )
        packet["checksum"] = stable_checksum({k: v for k, v in packet.items() if k not in {"checksum", "flow_tag"}})
        return frame_signal_payload(json.dumps(packet), self.engine.config.security.signal_secret)

    def test_normal_traffic_passes_all_layers(self) -> None:
        packet = self.lab.generate_normal_batch(count=1)[0]
        decision = self.engine.process_raw(packet)
        self.assertEqual(decision.decision, "accepted")
        self.assertIsNone(decision.failed_layer)
        self.assertEqual(decision.classification, "normal")
        self.assertEqual(decision.service_mode, "normal")

    def test_malformed_packet_stops_at_layer_two(self) -> None:
        framed_broken = frame_signal_payload('{"packet_id":"broken"', self.engine.config.security.signal_secret)
        decision = self.engine.process_raw(framed_broken)
        self.assertEqual(decision.failed_layer, 2)
        self.assertEqual(decision.classification, "malformed")

    def test_signal_envelope_missing_stops_at_layer_one(self) -> None:
        packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1)[0]))
        raw_json = json.dumps(packet)
        decision = self.engine.process_raw(raw_json)
        self.assertEqual(decision.failed_layer, 1)
        self.assertEqual(decision.classification, "unauthorized")

    def test_epoch_chain_break_after_secret_leak_stops_at_layer_six(self) -> None:
        packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-core", start_seq=20)[0]))
        self.engine.process_raw(self._frame_packet(packet))
        packet["seq"] += 1
        packet["epoch_id"] = str(int(packet["epoch_id"]) + 1)
        packet["payload"]["attack_meta"]["secret_compromised"] = True
        packet["challenge_proof"] = "broken-epoch-chain"
        decision = self.engine.process_raw(self._frame_packet(packet))
        self.assertEqual(decision.failed_layer, 6)
        self.assertEqual(decision.classification, "credential_compromise_suspect")

    def test_shadow_lane_contact_triggers_leak_trap(self) -> None:
        packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-core", start_seq=40)[0]))
        self.engine.process_raw(self._frame_packet(packet))
        packet["seq"] += 1
        packet["epoch_id"] = str(int(packet["epoch_id"]) + 1)
        previous_clean_hash = self.engine.state.get_previous_clean_hash("bkzs-core", self.engine.config)
        packet["payload"]["attack_meta"]["secret_compromised"] = True
        packet["challenge_proof"] = build_challenge_proof(
            self.engine.config.security.signal_secret,
            self.engine.config.security.session_nonce,
            self.engine.config.security.shadow_lane_salt,
            "bkzs-core",
            packet["epoch_id"],
            previous_clean_hash,
            lane="shadow",
        )
        decision = self.engine.process_raw(self._frame_packet(packet))
        self.assertEqual(decision.failed_layer, 6)
        self.assertEqual(decision.classification, "leak_trap_triggered")
        self.assertTrue(decision.deception_triggered)

    def test_trusted_source_can_resync_epoch_chain_with_genesis_proof(self) -> None:
        baseline = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=60)[0]))
        accepted = self.engine.process_raw(self._frame_packet(baseline))
        self.assertEqual(accepted.decision, "accepted")

        broken = dict(baseline)
        broken["packet_id"] = "broken-epoch-001"
        broken["seq"] = int(baseline["seq"]) + 1
        broken["epoch_id"] = str(int(baseline["epoch_id"]) + 1)
        broken["ts"] = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=61)[0]))["ts"]
        broken["challenge_proof"] = "broken-epoch-chain"
        first_fail = self.engine.process_raw(self._frame_packet(broken))
        self.assertEqual(first_fail.failed_layer, 6)

        resynced = dict(broken)
        resynced["packet_id"] = "resync-epoch-001"
        resynced["seq"] = broken["seq"] + 1
        resynced["epoch_id"] = str(int(broken["epoch_id"]) + 1)
        resynced["ts"] = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=62)[0]))["ts"]
        resynced["challenge_proof"] = build_challenge_proof(
            self.engine.config.security.signal_secret,
            self.engine.config.security.session_nonce,
            self.engine.config.security.shadow_lane_salt,
            "bkzs-edge-1",
            resynced["epoch_id"],
            initial_clean_hash("bkzs-edge-1", self.engine.config.security.session_nonce),
            lane="primary",
        )
        decision = self.engine.process_raw(self._frame_packet(resynced))
        self.assertEqual(decision.decision, "accepted")
        self.assertTrue(any(item.reason_code == "epoch_chain_resynced" for item in decision.trace))

    def test_attack_sim_acceptance_does_not_poison_mesh_peer_history(self) -> None:
        attack_like_peer = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-core", start_seq=80)[0]))
        attack_like_peer["packet_id"] = "attack-sim-peer-001"
        attack_like_peer["metrics"]["latitude"] = 41.0105
        attack_like_peer["metrics"]["longitude"] = 28.9805
        attack_like_peer["payload"]["attack_meta"]["simulation_role"] = "attack"
        attack_like_peer["payload"]["attack_meta"]["simulation_mode"] = "replay"
        self.assertEqual(self.engine.process_raw(self._frame_packet(attack_like_peer)).decision, "accepted")

        edge_packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=70)[0]))
        next_edge_packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=71)[0]))
        self.assertEqual(self.engine.process_raw(self._frame_packet(edge_packet)).decision, "accepted")
        decision = self.engine.process_raw(self._frame_packet(next_edge_packet))
        self.assertEqual(decision.decision, "accepted")

    def test_replay_packet_stops_at_layer_eight(self) -> None:
        packet = self.lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=101)[0]
        first = self.engine.process_raw(packet)
        replay = self.engine.process_raw(packet)
        self.assertEqual(first.decision, "accepted")
        self.assertEqual(replay.failed_layer, 8)
        self.assertEqual(replay.classification, "replay_suspect")
        self.assertTrue(replay.credential_gate_passed)
        self.assertTrue(replay.credential_leak_suspect)

    def test_mesh_divergence_stops_at_layer_twelve(self) -> None:
        warmup = self.lab.generate_normal_batch(count=2, source="bkzs-edge-1", start_seq=201)
        for packet in warmup:
            self.engine.process_raw(packet)
        decisions = self.engine.process_batch(self.lab._mesh_divergence(3))
        self.assertTrue(any(item.failed_layer == 12 for item in decisions))
        self.assertTrue(any(item.classification == "mesh_divergence_suspect" for item in decisions))
        self.assertTrue(any(item.quorum_result == "disagreement" for item in decisions))

    def test_holdover_mode_activates_on_deep_spoof(self) -> None:
        warmup = self.lab.generate_normal_batch(count=2, source="bkzs-edge-2", start_seq=301)
        for packet in warmup:
            self.engine.process_raw(packet)
        decisions = self.engine.process_batch(self.lab._holdover_break_attempt(3))
        self.assertTrue(any(item.service_mode == "holdover" for item in decisions))

    def test_adaptive_lockdown_blocks_repeated_malicious_source(self) -> None:
        warmup = self.lab.generate_normal_batch(count=4, source="bkzs-edge-2", start_seq=401)
        for packet in warmup:
            self.engine.process_raw(packet)
        decisions = self.engine.process_batch(self.lab.generate_stage_batch(stage=5, count=8))
        self.assertTrue(any(item.failed_layer == 5 for item in decisions))
        self.assertTrue(any(item.anomaly_signature == "source_quarantined" for item in decisions))

    def test_mission_envelope_breach_stops_at_layer_thirteen(self) -> None:
        packet = self.lab._mission_envelope_break(1)[0]
        decision = self.engine.process_raw(packet)
        self.assertEqual(decision.failed_layer, 13)
        self.assertTrue(decision.mission_breach)
        self.assertEqual(decision.defense_mechanism, "Mission Envelope")

    def test_trust_bulletin_override_can_turn_clean_packet_into_mission_breach(self) -> None:
        packet = json.loads(self.lab.unwrap_packet_text(self.lab.generate_normal_batch(count=1, source="bkzs-edge-2", start_seq=901)[0]))
        packet["metrics"]["speed"] = 52.0
        framed_packet = self._frame_packet(packet)

        clean_engine = MicroLayerEngine()
        clean_decision = clean_engine.process_raw(framed_packet)
        self.assertEqual(clean_decision.decision, "accepted")

        strict_engine = MicroLayerEngine()
        strict_engine.set_trust_bulletin(
            load_trust_bulletin(
                sample_trust_bulletin(strict_engine.config.bulletin.signing_key),
                strict_engine.config.bulletin.signing_key,
            )
        )
        strict_decision = strict_engine.process_raw(framed_packet)
        self.assertEqual(strict_decision.failed_layer, 13)
        self.assertEqual(strict_decision.trust_bulletin_id is not None, True)

    def test_selected_satellite_profile_accepts_matching_public_metadata(self) -> None:
        engine = MicroLayerEngine()
        profile = get_satellite_profile("turksat-6a")
        engine.config.mission.satellite_profile_id = profile.profile_id
        engine.config.mission.allowed_channel = profile.primary_channel
        engine.config.mission.mission_phase = "relay"
        lab = AttackLab(config=engine.config)

        decision = engine.process_raw(lab.generate_normal_batch(count=1, source="bkzs-edge-1", start_seq=990)[0])

        self.assertEqual(decision.decision, "accepted")
        self.assertIn("Turksat 6A", decision.payload_view or "")

    def test_selected_satellite_profile_blocks_public_band_slot_mismatch(self) -> None:
        engine = MicroLayerEngine()
        profile = get_satellite_profile("turksat-6a")
        engine.config.mission.satellite_profile_id = profile.profile_id
        engine.config.mission.allowed_channel = profile.primary_channel
        engine.config.mission.mission_phase = "relay"
        lab = AttackLab(config=engine.config)

        decision = engine.process_raw(lab._mission_envelope_break(1)[0])

        self.assertEqual(decision.failed_layer, 13)
        self.assertTrue(
            decision.anomaly_signature in {"satellite_orbital_slot_mismatch", "satellite_band_mismatch"}
        )


if __name__ == "__main__":
    unittest.main()
