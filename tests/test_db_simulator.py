"""
tests/test_db_simulator.py

Unit tests for simulator/database/db_simulator.py.

Run with:
    python -m tests.test_db_simulator
"""

import ipaddress
import random
import time
import unittest

from shared.schemas.event_schema import CommonEvent
from simulator.database.db_simulator import DatabaseSimulator


NORMAL_EVENT_TYPES = {
    "query_executed",
    "db_login",
    "db_logout",
    "maintenance_operation",
    "connection_established",
    "backup_created",
    "config_review",
}

# Attack event.type values -- brute_force reuses "db_login",
# mass_data_exfiltration/destructive_query/stored_procedure_abuse/
# anomalous_query_flood all reuse "query_executed",
# privilege_escalation reuses "maintenance_operation", and
# unauthorized_config_change reuses "config_review" -- distinguishable
# only by source/status/pattern/query_type, never by a giveaway type.
ATTACK_EVENT_TYPES = {
    "db_login",               # brute_force (reused type)
    "maintenance_operation",  # privilege_escalation (reused type)
    "config_review",          # unauthorized_config_change (reused type)
    "query_executed",         # mass_data_exfiltration, destructive_query,
                              # stored_procedure_abuse, anomalous_query_flood (all reused)
}

ALLOWED_SOURCES = {"10.10.1.10", "10.10.1.33"}  # WEB-01 and END-03 only, per the registry


class TestDatabaseSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = DatabaseSimulator("DB-01")

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
        self.assertTrue(event.event_id.startswith("EVT-DB-"))

    def test_source_matches_db_01(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.source.asset_id, "DB-01")
        self.assertEqual(event.source.asset_type, "database_server")
        self.assertEqual(event.source.hostname, "db-01")

    def test_destination_is_db_01(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(str(event.network.destination_ip), "10.10.1.20")
        self.assertEqual(event.network.destination_port, 5432)
        self.assertEqual(event.network.protocol, "TCP")

    def test_target_asset_is_db_01(self):
        event = self.sim.generate_attack_event()
        self.assertEqual(event.target.asset_id, "DB-01")

    def test_context_marks_simulation(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.context.environment, "simulated_enterprise")
        self.assertTrue(event.context.simulation)

    # ------------------------------------------------------------
    # Registry-driven source discipline: normal traffic only ever
    # comes from WEB-01 or END-03 (per communicates_with); most
    # attacks come from elsewhere
    # ------------------------------------------------------------

    def test_normal_source_is_always_web01_or_end03(self):
        for _ in range(100):
            event = self.sim.generate_normal_event()
            self.assertIn(str(event.network.source_ip), ALLOWED_SOURCES)

    def test_most_attacks_source_from_unexpected_location(self):
        # privilege_escalation is the deliberate exception (sourced
        # from a normal internal workstation -- the anomaly is the
        # ACTION, not the source), so it's excluded here and checked
        # separately below. Since privilege_escalation now shares its
        # event.type ("maintenance_operation") with normal DB
        # maintenance traffic, we select by ATTACK KEY name via
        # generate_attack_event(attack_type=...) rather than trying to
        # filter generate_attack_event()'s random output by type.
        non_priv_esc_attacks = [
            a for a in self.sim.available_attack_types() if a != "privilege_escalation"
        ]
        for _ in range(100):
            attack_type = random.choice(non_priv_esc_attacks)
            event = self.sim.generate_attack_event(attack_type=attack_type)
            self.assertNotIn(str(event.network.source_ip), ALLOWED_SOURCES)

    def test_privilege_escalation_sourced_from_normal_workstation(self):
        event = self.sim._attack_privilege_escalation()
        # Sourced from SOME real employee workstation (not WEB-01/END-03
        # specifically, but a legitimate internal machine nonetheless)
        internal_net = ipaddress.ip_network("10.10.1.0/24")
        self.assertIn(ipaddress.ip_address(str(event.network.source_ip)), internal_net)
        self.assertIsNotNone(event.actor.user_id)

    def test_admin_only_events_use_end03_and_emp003(self):
        for generator in (
            self.sim._normal_db_login,
            self.sim._normal_db_logout,
            self.sim._normal_maintenance_operation,
            self.sim._normal_backup_created,
        ):
            event = generator()
            self.assertEqual(event.actor.user_id, "EMP-003")
            self.assertEqual(str(event.network.source_ip), "10.10.1.33")

    def test_query_executed_sourced_from_web01(self):
        for _ in range(20):
            event = self.sim._normal_query_executed()
            self.assertEqual(str(event.network.source_ip), "10.10.1.10")
            self.assertIn(event.actor.user_id, DatabaseSimulator.ALL_EMPLOYEE_IDS)

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
    # Reused-type discipline
    # ------------------------------------------------------------

    def test_brute_force_reuses_db_login_type(self):
        normal = self.sim._normal_db_login()
        attack = self.sim._attack_brute_force()
        self.assertEqual(normal.event.type, "db_login")
        self.assertEqual(attack.event.type, "db_login")
        self.assertEqual(normal.event.status, "success")
        self.assertEqual(attack.event.status, "failure")
        self.assertIsNone(attack.actor.user_id)

    def test_mass_exfiltration_reuses_query_executed_type(self):
        normal = self.sim._normal_query_executed()
        attack = self.sim._attack_mass_data_exfiltration()
        self.assertEqual(normal.event.type, "query_executed")
        self.assertEqual(attack.event.type, "query_executed")
        self.assertEqual(attack.event.status, "blocked")
        self.assertGreater(attack.data["rows_returned"], normal.data["rows_returned"])

    # ------------------------------------------------------------
    # Domain-specific correctness
    # ------------------------------------------------------------

    def test_stored_procedure_abuse_uses_copy_to_program(self):
        event = self.sim._attack_stored_procedure_abuse()
        self.assertEqual(event.data["technique"], "COPY ... TO PROGRAM")
        self.assertEqual(event.event.status, "blocked")

    def test_destructive_query_uses_drop_or_truncate(self):
        event = self.sim._attack_destructive_query()
        self.assertIn(event.data["query_type"], ("DROP", "TRUNCATE"))

    def test_privilege_escalation_shows_large_jump(self):
        event = self.sim._attack_privilege_escalation()
        self.assertEqual(event.data["from_role"], "read_only")
        self.assertEqual(event.data["to_role"], "superuser")

    def test_unauthorized_config_change_is_a_known_parameter(self):
        event = self.sim._attack_unauthorized_config_change()
        known_params = {p[0] for p in DatabaseSimulator.CONFIG_PARAMETERS}
        self.assertIn(event.data["config_parameter"], known_params)

    # ------------------------------------------------------------
    # Burst attacks
    # ------------------------------------------------------------

    def test_brute_force_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=6)
        self.assertEqual(len(received), 6)
        for event in received:
            self.assertEqual(event.event.type, "db_login")

    def test_brute_force_burst_increments_attempt_number(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=4)
        self.assertEqual([e.data["attempt_number_in_session"] for e in received], [1, 2, 3, 4])

    def test_mass_data_exfiltration_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("mass_data_exfiltration", on_event=received.append, burst_size=5)
        self.assertEqual(len(received), 5)

    def test_mass_data_exfiltration_burst_shares_session_and_source(self):
        received = []
        self.sim.trigger_attack("mass_data_exfiltration", on_event=received.append, burst_size=5)
        sessions = {e.actor.session_id for e in received}
        sources = {str(e.network.source_ip) for e in received}
        self.assertEqual(len(sessions), 1)
        self.assertEqual(len(sources), 1)

    def test_anomalous_query_flood_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("anomalous_query_flood", on_event=received.append, burst_size=12)
        self.assertEqual(len(received), 12)
        for event in received:
            self.assertEqual(event.event.type, "query_executed")
            self.assertIn("queries_per_second", event.data)

    def test_burst_returns_last_event(self):
        received = []
        last = self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=5)
        self.assertEqual(last.event_id, received[-1].event_id)

    def test_non_burst_attack_fires_exactly_one_event(self):
        for attack_type in (
            "privilege_escalation",
            "unauthorized_config_change",
            "destructive_query",
            "stored_procedure_abuse",
        ):
            received = []
            self.sim.trigger_attack(attack_type, on_event=received.append)
            self.assertEqual(len(received), 1, f"{attack_type} should fire exactly one event")

    def test_burst_size_override_respected(self):
        received = []
        self.sim.trigger_attack("anomalous_query_flood", on_event=received.append, burst_size=7)
        self.assertEqual(len(received), 7)

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