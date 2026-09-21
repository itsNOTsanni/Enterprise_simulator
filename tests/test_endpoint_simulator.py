"""
tests/test_endpoint_simulator.py

Unit tests for simulator/endpoints/endpoint_simulator.py.

Run with:
    python -m tests.test_endpoint_simulator
"""

import unittest

from shared.schemas.event_schema import CommonEvent
from simulator.endpoints.endpoint_simulator import EndpointSimulator


NORMAL_EVENT_TYPES = {
    "process_started",
    "file_accessed",
    "user_logon",
    "user_logoff",
    "network_connection",
    "usb_file_transfer",
    "software_installed",
}

# Attack event.type values -- note several intentionally REUSE a
# normal type (network_connection, usb_file_transfer, software_installed)
# and are only distinguishable by status/pattern, not by name.
ATTACK_EVENT_TYPES = {
    "file_accessed",       # ransomware (reused type)
    "process_started",     # credential_dumping (reused type)
    "user_logon",          # privilege_escalation (reused type)
    "network_connection",  # lateral_movement (reused type)
    "usb_file_transfer",   # usb_data_exfiltration (reused type)
    "software_installed",  # unauthorized_software_install (reused type)
}


class TestEndpointSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = EndpointSimulator("END-01")

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
        self.assertTrue(event.event_id.startswith("EVT-END-"))

    def test_source_matches_endpoint(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.source.asset_id, "END-01")
        self.assertEqual(event.source.asset_type, "employee_workstation")
        self.assertEqual(event.source.hostname, "employee-01")

    def test_context_marks_simulation(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.context.environment, "simulated_enterprise")
        self.assertTrue(event.context.simulation)

    def test_actor_defaults_to_machine_owner(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.actor.user_id, "EMP-001")

    # ------------------------------------------------------------
    # MAC address enrichment
    # ------------------------------------------------------------

    def test_mac_address_present_on_normal_events(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.data["source_mac_address"], "02:1A:2B:3C:4D:01")

    def test_mac_address_present_on_attack_events(self):
        event = self.sim.generate_attack_event()
        self.assertEqual(event.data["source_mac_address"], "02:1A:2B:3C:4D:01")

    def test_lateral_movement_carries_destination_mac(self):
        event = self.sim._attack_lateral_movement(target_id="END-02")
        self.assertEqual(event.data["destination_mac_address"], "02:1A:2B:3C:4D:02")

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
    # status/pattern, NOT by a giveaway label
    # ------------------------------------------------------------

    def test_usb_exfiltration_reuses_normal_type_but_differs_by_status(self):
        normal = self.sim._normal_usb_file_transfer()
        attack = self.sim._attack_usb_data_exfiltration()
        self.assertEqual(normal.event.type, attack.event.type)
        self.assertEqual(normal.event.status, "success")
        self.assertEqual(attack.event.status, "blocked")

    def test_unauthorized_install_reuses_normal_type_but_differs_by_status(self):
        normal = self.sim._normal_software_installed()
        attack = self.sim._attack_unauthorized_software_install()
        self.assertEqual(normal.event.type, attack.event.type)
        self.assertFalse(attack.data["publisher_verified"])
        self.assertTrue(normal.data["publisher_verified"])

    def test_lateral_movement_reuses_network_connection_type(self):
        normal = self.sim._normal_network_connection()
        attack = self.sim._attack_lateral_movement()
        self.assertEqual(normal.event.type, "network_connection")
        self.assertEqual(attack.event.type, "network_connection")
        self.assertEqual(normal.event.status, "success")
        self.assertEqual(attack.event.status, "failure")

    # ------------------------------------------------------------
    # Domain-specific correctness
    # ------------------------------------------------------------

    def test_normal_network_connection_targets_allowed_asset(self):
        allowed = set(self.sim.asset.get("communicates_with", []))
        for _ in range(30):
            event = self.sim._normal_network_connection()
            self.assertIn(event.target.asset_id, allowed)

    def test_lateral_movement_never_targets_self(self):
        for _ in range(30):
            event = self.sim._attack_lateral_movement()
            self.assertNotEqual(event.target.asset_id, "END-01")

    def test_credential_dumping_targets_lsass(self):
        event = self.sim._attack_credential_dumping()
        self.assertEqual(event.data["target_process"], "lsass.exe")
        self.assertEqual(event.event.status, "blocked")

    def test_privilege_escalation_shows_privilege_jump(self):
        event = self.sim._attack_privilege_escalation()
        self.assertEqual(event.data["from_privilege"], "user")
        self.assertEqual(event.data["to_privilege"], "SYSTEM")

    def test_ransomware_uses_known_extension(self):
        event = self.sim._attack_ransomware()
        self.assertIn(event.data["new_extension"], EndpointSimulator.RANSOMWARE_EXTENSIONS)
        self.assertEqual(event.event.status, "blocked")

    # ------------------------------------------------------------
    # Burst attacks
    # ------------------------------------------------------------

    def test_ransomware_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("ransomware", on_event=received.append, burst_size=8)
        self.assertEqual(len(received), 8)
        for event in received:
            self.assertEqual(event.event.type, "file_accessed")
            self.assertIn("new_extension", event.data)

    def test_ransomware_burst_shares_session_and_process(self):
        received = []
        self.sim.trigger_attack("ransomware", on_event=received.append, burst_size=6)
        sessions = {e.actor.session_id for e in received}
        processes = {e.data["encrypting_process"] for e in received}
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(processes), 1)

    def test_lateral_movement_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("lateral_movement", on_event=received.append, burst_size=3)
        self.assertEqual(len(received), 3)
        for event in received:
            self.assertNotEqual(event.target.asset_id, "END-01")

    def test_lateral_movement_burst_returns_last_event(self):
        received = []
        last = self.sim.trigger_attack("lateral_movement", on_event=received.append, burst_size=4)
        self.assertEqual(last.event_id, received[-1].event_id)

    def test_usb_exfiltration_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("usb_data_exfiltration", on_event=received.append, burst_size=7)
        self.assertEqual(len(received), 7)
        for event in received:
            self.assertEqual(event.data["data_classification"], "confidential")

    def test_non_burst_attack_fires_exactly_one_event(self):
        for attack_type in ("credential_dumping", "privilege_escalation", "unauthorized_software_install"):
            received = []
            self.sim.trigger_attack(attack_type, on_event=received.append)
            self.assertEqual(len(received), 1, f"{attack_type} should fire exactly one event")

    def test_burst_size_override_respected(self):
        received = []
        self.sim.trigger_attack("ransomware", on_event=received.append, burst_size=3)
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
        import time
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

    # ------------------------------------------------------------
    # Multi-endpoint independence (4 separate machines)
    # ------------------------------------------------------------

    def test_each_endpoint_has_distinct_identity(self):
        sims = {aid: EndpointSimulator(aid) for aid in EndpointSimulator.ALL_ENDPOINT_IDS}
        macs = {s.mac_address for s in sims.values()}
        ips = {s.ip_address for s in sims.values()}
        owners = {s.owner_employee_id for s in sims.values()}
        self.assertEqual(len(macs), 4)
        self.assertEqual(len(ips), 4)
        self.assertEqual(len(owners), 4)

    def test_event_ids_are_unique(self):
        events = self.sim.generate_events(mode="mixed", count=100)
        ids = [e.event_id for e in events]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()