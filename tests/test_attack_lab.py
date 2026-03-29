from __future__ import annotations

import json
import unittest

from bkzs_guard.attack_lab import AttackLab


class AttackLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = AttackLab(seed=7)

    def test_stage_profiles_cover_all_six_levels(self) -> None:
        profiles = [self.lab.default_scenario(stage) for stage in range(1, 7)]
        self.assertEqual([item.stage for item in profiles], [1, 2, 3, 4, 5, 6])

    def test_stage_two_packets_are_structurally_valid_json(self) -> None:
        packets = self.lab.generate_stage_batch(stage=2, count=2)
        parsed = [json.loads(self.lab.unwrap_packet_text(item)) for item in packets]
        self.assertEqual(len(parsed), 2)
        self.assertTrue(all("checksum" in item for item in parsed))
        self.assertTrue(all("epoch_id" in item for item in parsed))

    def test_chain_batch_contains_baseline_and_attacks(self) -> None:
        chain = self.lab.generate_chain_batch()
        self.assertGreater(len(chain), 20)

    def test_real_scenario_batch_contains_truth_and_metadata(self) -> None:
        packets, truth, metadata = self.lab.generate_real_scenario_batch(base_count=4)
        self.assertEqual(len(packets), len(truth))
        self.assertEqual(metadata["mode"], "real_scenario")
        self.assertTrue(metadata["selected_stages"])
        self.assertTrue(any(item["label"] == "attack" for item in truth))
        self.assertTrue(any(item["label"] == "normal" for item in truth))

    def test_counter_intel_tour_contains_all_attack_families(self) -> None:
        packets, truth, metadata = self.lab.generate_counter_intel_tour(base_count=4)
        families = {item["family"] for item in truth if item["label"] == "attack"}
        self.assertEqual(len(packets), len(truth))
        self.assertEqual(metadata["mode"], "counter_intel_tour")
        self.assertEqual(
            families,
            {
                "bulletin_conflict",
                "classic_replay",
                "mission_envelope_break",
                "secret_leak_after_spoof",
                "shadow_lane_contact",
                "mesh_divergence",
                "holdover_break_attempt",
            },
        )
        self.assertIn("trust_bulletin", metadata)


if __name__ == "__main__":
    unittest.main()
