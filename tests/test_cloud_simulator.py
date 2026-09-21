"""
tests/test_cloud_simulator.py

Unit tests for simulator/cloud/cloud_simulator.py.

Run with:
    python -m tests.test_cloud_simulator
"""

import ipaddress
import time
import unittest

from shared.schemas.event_schema import CommonEvent
from simulator.cloud.cloud_simulator import CloudSimulator


NORMAL_EVENT_TYPES = {
    "cloud_storage_access",
    "vm_session",
    "cloud_api_call",
    "security_config_review",
    "storage_config_review",
    "iam_policy_check",
    "role_update",
}

# Attack event.type values -- note several intentionally REUSE a
# normal type (role_update, cloud_storage_access, cloud_api_call) and
# are only distinguishable by status/source/pattern, not by name.
ATTACK_EVENT_TYPES = {
    "role_update",              # iam_privilege_escalation AND mfa_disablement (both reused)
    "storage_config_review",    # public_bucket_exposure (reused type)
    "security_config_review",   # security_group_misconfiguration (reused type)
    "cloud_storage_access",     # mass_data_exfiltration (reused type)
    "cloud_api_call",           # api_key_abuse (reused type)
}

INTERNAL_NET = ipaddress.ip_network("10.10.1.0/24")


class TestCloudSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = CloudSimulator("CLOUD-01")

    # ------------------------------------------------------------
    # Structural correctness
    # ------------------------------------------------------------

    def test_normal_event_is_common_event(self):
        event = self.sim.generate_normal_event()
        self.assertIsInstance(event, CommonEvent)

    def test_attack_event_is_common_event(self):
        event = self.sim.generate_attack_event()
        self.assertIsInstance(event, CommonEvent)

    def test_event_id_prefix(self):
        event = self.sim.generate_normal_event()
        self.assertTrue(event.event_id.startswith("EVT-CLOUD-"))

    def test_source_matches_cloud_01(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.source.asset_id, "CLOUD-01")
        self.assertEqual(event.source.asset_type, "cloud_environment")
        self.assertEqual(event.source.hostname, "cloud-01")

    def test_target_asset_is_cloud_01(self):
        event = self.sim.generate_attack_event()
        self.assertEqual(event.target.asset_id, "CLOUD-01")

    def test_context_marks_simulation(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.context.environment, "simulated_enterprise")
        self.assertTrue(event.context.simulation)

    def test_network_destination_fields_are_null(self):
        # Matches the project's own CLOUD-01 sample event: only
        # source_ip (the calling client) is populated.
        event = self.sim.generate_normal_event()
        self.assertIsNone(event.network.destination_ip)
        self.assertIsNone(event.network.destination_port)
        self.assertIsNone(event.network.protocol)

    def test_data_includes_call_source(self):
        event = self.sim.generate_normal_event()
        self.assertIn("call_source", event.data)

    # ------------------------------------------------------------
    # Source IP discipline: normal = real employee workstation IP,
    # attack = anomalous external IP
    # ------------------------------------------------------------

    def test_normal_source_ip_is_internal(self):
        for _ in range(50):
            event = self.sim.generate_normal_event()
            self.assertIn(
                ipaddress.ip_address(str(event.network.source_ip)), INTERNAL_NET
            )

    def test_attack_source_ip_is_external(self):
        for _ in range(50):
            event = self.sim.generate_attack_event()
            self.assertNotIn(
                ipaddress.ip_address(str(event.network.source_ip)), INTERNAL_NET
            )

    # ------------------------------------------------------------
    # Reachability
    # ------------------------------------------------------------

    def test_all_normal_types_reachable(self):
        seen = set()
        for _ in range(400):
            seen.add(self.sim.generate_normal_event().event.type)
        self.assertEqual(seen, NORMAL_EVENT_TYPES)

    def test_all_attack_types_reachable(self):
        seen = set()
        for _ in range(400):
            seen.add(self.sim.generate_attack_event().event.type)
        self.assertEqual(seen, ATTACK_EVENT_TYPES)

    # ------------------------------------------------------------
    # Reused-type discipline: normal vs. attack differ by
    # status/source/pattern, NOT by a giveaway label
    # ------------------------------------------------------------

    def test_role_update_reused_but_differs_by_privilege_jump(self):
        normal = self.sim._normal_role_update()
        attack = self.sim._attack_iam_privilege_escalation()
        self.assertEqual(normal.event.type, "role_update")
        self.assertEqual(attack.event.type, "role_update")
        self.assertEqual(normal.event.status, "success")
        self.assertEqual(attack.event.status, "blocked")
        self.assertIn(
            ipaddress.ip_address(str(normal.network.source_ip)), INTERNAL_NET
        )
        self.assertNotIn(
            ipaddress.ip_address(str(attack.network.source_ip)), INTERNAL_NET
        )

    def test_only_it_admin_performs_normal_role_update(self):
        for _ in range(20):
            event = self.sim._normal_role_update()
            self.assertEqual(event.actor.user_id, "EMP-003")

    def test_data_exfiltration_reuses_storage_access_type(self):
        normal = self.sim._normal_cloud_storage_access()
        attack = self.sim._attack_mass_data_exfiltration()
        self.assertEqual(normal.event.type, "cloud_storage_access")
        self.assertEqual(attack.event.type, "cloud_storage_access")
        self.assertEqual(attack.event.status, "blocked")

    def test_api_key_abuse_reuses_api_call_type(self):
        normal = self.sim._normal_cloud_api_call()
        attack = self.sim._attack_api_key_abuse()
        self.assertEqual(normal.event.type, "cloud_api_call")
        self.assertEqual(attack.event.type, "cloud_api_call")
        self.assertEqual(attack.event.status, "blocked")

    # ------------------------------------------------------------
    # Domain-specific correctness
    # ------------------------------------------------------------

    def test_iam_privilege_escalation_shows_large_jump(self):
        event = self.sim._attack_iam_privilege_escalation()
        self.assertIn(
            (event.data["config_before"], event.data["config_after"]),
            CloudSimulator.ROLE_LEVELS_ESCALATION,
        )

    def test_mfa_disablement_targets_iam(self):
        event = self.sim._attack_mfa_disablement()
        self.assertEqual(event.target.resource, "IAM-01")
        self.assertEqual(event.data["config_after"], "mfa_disabled")

    def test_public_bucket_exposure_targets_storage(self):
        event = self.sim._attack_public_bucket_exposure()
        self.assertEqual(event.target.resource, "STORAGE-01")
        self.assertEqual(event.data["config_after"], "public-read")

    def test_security_group_misconfiguration_opens_to_internet(self):
        event = self.sim._attack_security_group_misconfiguration()
        self.assertEqual(event.target.resource, "SEC-01")
        self.assertIn("0.0.0.0/0", event.data["config_after"])

    # ------------------------------------------------------------
    # Burst attacks
    # ------------------------------------------------------------

    def test_mass_data_exfiltration_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("mass_data_exfiltration", on_event=received.append, burst_size=6)
        self.assertEqual(len(received), 6)
        for event in received:
            self.assertEqual(event.event.type, "cloud_storage_access")

    def test_mass_data_exfiltration_burst_shares_session_and_source(self):
        received = []
        self.sim.trigger_attack("mass_data_exfiltration", on_event=received.append, burst_size=5)
        sessions = {e.actor.session_id for e in received}
        sources = {str(e.network.source_ip) for e in received}
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(sources), 1)

    def test_api_key_abuse_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("api_key_abuse", on_event=received.append, burst_size=5)
        self.assertEqual(len(received), 5)

    def test_api_key_abuse_burst_shares_same_key(self):
        received = []
        self.sim.trigger_attack("api_key_abuse", on_event=received.append, burst_size=6)
        keys = {e.data["api_key_id"] for e in received}
        self.assertEqual(len(keys), 1)

    def test_burst_returns_last_event(self):
        received = []
        last = self.sim.trigger_attack("mass_data_exfiltration", on_event=received.append, burst_size=4)
        self.assertEqual(last.event_id, received[-1].event_id)

    def test_non_burst_attack_fires_exactly_one_event(self):
        for attack_type in (
            "iam_privilege_escalation",
            "mfa_disablement",
            "public_bucket_exposure",
            "security_group_misconfiguration",
        ):
            received = []
            self.sim.trigger_attack(attack_type, on_event=received.append)
            self.assertEqual(len(received), 1, f"{attack_type} should fire exactly one event")

    def test_burst_size_override_respected(self):
        received = []
        self.sim.trigger_attack("api_key_abuse", on_event=received.append, burst_size=3)
        self.assertEqual(len(received), 3)

    def test_generate_attack_event_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            self.sim.generate_attack_event(attack_type="not_a_real_attack")

    # ------------------------------------------------------------
    # Continuous background normal-activity stream
    # ------------------------------------------------------------

    def test_start_and_stop_normal_stream(self):
        received = []
        self.sim.start_normal_stream(
            on_event=received.append, interval_seconds=0.1, jitter_seconds=0.02
        )
        self.assertTrue(self.sim.is_streaming())
        time.sleep(0.55)
        self.sim.stop_normal_stream()

        self.assertFalse(self.sim.is_streaming())
        self.assertGreaterEqual(len(received), 2)
        for event in received:
            self.assertIn(event.event.type, NORMAL_EVENT_TYPES)

    def test_cannot_start_stream_twice(self):
        self.sim.start_normal_stream(on_event=lambda e: None, interval_seconds=0.5)
        try:
            with self.assertRaises(RuntimeError):
                self.sim.start_normal_stream(on_event=lambda e: None, interval_seconds=0.5)
        finally:
            self.sim.stop_normal_stream()

    def test_stream_normal_events_generator(self):
        gen = self.sim.stream_normal_events(interval_seconds=0.05)
        first_two = [next(gen) for _ in range(2)]
        for event in first_two:
            self.assertIn(event.event.type, NORMAL_EVENT_TYPES)

    def test_event_ids_are_unique(self):
        events = self.sim.generate_events(mode="mixed", count=100)
        ids = [e.event_id for e in events]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()