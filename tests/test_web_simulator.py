"""
tests/test_web_simulator.py

Unit tests for simulator/web/web_simulator.py.

Run with:
    python -m tests.test_web_simulator
"""

import ipaddress
import random
import time
import unittest

from shared.schemas.event_schema import CommonEvent
from simulator.web.web_simulator import WebServerSimulator


NORMAL_EVENT_TYPES = {
    "login_attempt",
    "page_view",
    "form_submission",
    "api_call",
    "static_asset_request",
    "logout",
}

# Every attack now REUSES one of the normal types above --
# distinguishable only by status/source/pattern/payload, never by a
# giveaway type name. Not all 6 normal types have an attack reusing
# them (no attack currently mimics static_asset_request or logout),
# so this is the subset actually reachable via attacks.
ATTACK_EVENT_TYPES = {"login_attempt", "page_view", "form_submission", "api_call"}


class TestWebServerSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = WebServerSimulator("WEB-01")

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
        self.assertTrue(event.event_id.startswith("EVT-WEB-"))

    def test_source_matches_web_01(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.source.asset_id, "WEB-01")
        self.assertEqual(event.source.asset_type, "web_server")
        self.assertEqual(event.source.hostname, "web-01")

    def test_destination_is_web_01_ip(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(
            str(event.network.destination_ip),
            "10.10.1.10",
        )
        self.assertEqual(event.network.destination_port, 443)
        self.assertEqual(event.network.protocol, "HTTPS")

    def test_target_asset_is_web_01(self):
        event = self.sim.generate_attack_event()
        self.assertEqual(event.target.asset_id, "WEB-01")

    def test_context_marks_simulation(self):
        event = self.sim.generate_normal_event()
        self.assertEqual(event.context.environment, "simulated_enterprise")
        self.assertTrue(event.context.simulation)

    # ------------------------------------------------------------
    # Domain-specific correctness
    # ------------------------------------------------------------

    def test_normal_source_ip_is_internal(self):
        # Normal traffic should always originate from an internal
        # endpoint (10.10.1.0/24), never an external attacker IP.
        internal_net = ipaddress.ip_network("10.10.1.0/24")
        for _ in range(50):
            event = self.sim.generate_normal_event()
            self.assertIn(
                ipaddress.ip_address(str(event.network.source_ip)),
                internal_net,
            )

    def test_attack_source_ip_is_external(self):
        # Most attacks come from an external attacker IP. CSRF is a
        # deliberate exception: it exploits the VICTIM's own already-
        # authenticated browser, so its source is intentionally
        # internal -- that's correct modeling, not a bug, so it's
        # excluded here and covered separately in
        # test_csrf_sourced_from_internal_victim. Since several attack
        # types now share the same event.type as each other (and as
        # normal traffic), we select by ATTACK KEY name via
        # generate_attack_event(attack_type=...) rather than trying to
        # filter generate_attack_event()'s random output by type.
        internal_net = ipaddress.ip_network("10.10.1.0/24")
        non_csrf_attacks = [a for a in self.sim.available_attack_types() if a != "csrf"]
        for _ in range(50):
            attack_type = random.choice(non_csrf_attacks)
            event = self.sim.generate_attack_event(attack_type=attack_type)
            self.assertNotIn(
                ipaddress.ip_address(str(event.network.source_ip)),
                internal_net,
            )

    def test_normal_login_has_user_id(self):
        # Force enough samples to hit login_attempt at least once
        found = False
        for _ in range(50):
            event = self.sim._normal_login_success()
            self.assertIsNotNone(event.actor.user_id)
            self.assertEqual(event.event.status, "success")
            found = True
        self.assertTrue(found)

    def test_brute_force_has_no_user_id_and_fails(self):
        for _ in range(20):
            event = self.sim._attack_brute_force()
            self.assertIsNone(event.actor.user_id)
            self.assertEqual(event.event.status, "failure")
            self.assertEqual(event.data["http_status"], 401)

    def test_sql_injection_flags_special_characters(self):
        event = self.sim._attack_sql_injection()
        self.assertTrue(event.data["special_characters_present"])
        self.assertEqual(event.event.status, "blocked")

    def test_all_normal_types_reachable(self):
        seen = set()
        for _ in range(300):
            seen.add(self.sim.generate_normal_event().event.type)
        self.assertEqual(seen, NORMAL_EVENT_TYPES)

    def test_all_attack_types_reachable(self):
        seen = set()
        for _ in range(600):
            seen.add(self.sim.generate_attack_event().event.type)
        self.assertEqual(seen, ATTACK_EVENT_TYPES)

    # ------------------------------------------------------------
    # BaseSimulator.generate_events integration
    # ------------------------------------------------------------

    def test_generate_events_normal_mode(self):
        events = self.sim.generate_events(mode="normal", count=10)
        self.assertEqual(len(events), 10)
        for e in events:
            self.assertIn(e.event.type, NORMAL_EVENT_TYPES)

    def test_generate_events_attack_mode(self):
        events = self.sim.generate_events(mode="attack", count=10)
        self.assertEqual(len(events), 10)
        for e in events:
            self.assertIn(e.event.type, ATTACK_EVENT_TYPES)

    def test_generate_events_mixed_mode(self):
        events = self.sim.generate_events(mode="mixed", count=30)
        self.assertEqual(len(events), 30)

    def test_generate_events_rejects_bad_mode(self):
        with self.assertRaises(ValueError):
            self.sim.generate_events(mode="invalid", count=5)

    def test_generate_events_rejects_zero_count(self):
        with self.assertRaises(ValueError):
            self.sim.generate_events(mode="normal", count=0)

    def test_event_ids_are_unique(self):
        events = self.sim.generate_events(mode="mixed", count=100)
        ids = [e.event_id for e in events]
        self.assertEqual(len(ids), len(set(ids)))

    # ------------------------------------------------------------
    # On-demand attack selection
    # ------------------------------------------------------------

    def test_generate_attack_event_with_explicit_type(self):
        for attack_type in self.sim.available_attack_types():
            event = self.sim.generate_attack_event(attack_type=attack_type)
            self.assertIsInstance(event, CommonEvent)

    def test_generate_attack_event_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            self.sim.generate_attack_event(attack_type="not_a_real_attack")

    def test_trigger_attack_returns_requested_type(self):
        event = self.sim.trigger_attack("path_traversal")
        self.assertEqual(event.event.type, "page_view")
        self.assertEqual(event.event.status, "blocked")
        self.assertEqual(event.data["http_status"], 403)

    def test_trigger_attack_invokes_callback(self):
        received = []
        event = self.sim.trigger_attack("xss", on_event=received.append)
        self.assertEqual(len(received), 1)
        self.assertIs(received[0], event)

    # ------------------------------------------------------------
    # Continuous background normal-traffic stream
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
        # ~5 ticks expected at 0.1s interval over 0.55s; allow generous slack
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

    def test_attack_does_not_interrupt_normal_stream(self):
        received = []
        self.sim.start_normal_stream(
            on_event=received.append, interval_seconds=0.1, jitter_seconds=0.02
        )
        time.sleep(0.25)
        attack_event = self.sim.trigger_attack("brute_force")
        time.sleep(0.25)
        self.sim.stop_normal_stream()

        self.assertEqual(attack_event.event.type, "login_attempt")
        self.assertEqual(attack_event.event.status, "failure")
        # stream kept running before and after the on-demand attack
        self.assertGreaterEqual(len(received), 2)

    def test_stream_normal_events_generator(self):
        gen = self.sim.stream_normal_events(interval_seconds=0.05)
        first_two = [next(gen) for _ in range(2)]
        for event in first_two:
            self.assertIn(event.event.type, NORMAL_EVENT_TYPES)

    # ------------------------------------------------------------
    # Burst attacks (brute_force)
    # ------------------------------------------------------------

    def test_brute_force_fires_multiple_events(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=6)
        self.assertEqual(len(received), 6)
        for event in received:
            self.assertEqual(event.event.type, "login_attempt")
            self.assertEqual(event.event.status, "failure")

    def test_brute_force_burst_shares_session_and_source(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=5)
        session_ids = {e.actor.session_id for e in received}
        source_ips = {str(e.network.source_ip) for e in received}
        self.assertEqual(len(session_ids), 1)
        self.assertEqual(len(source_ips), 1)

    def test_brute_force_burst_increments_attempt_number(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=4)
        attempt_numbers = [e.data["attempt_number_in_session"] for e in received]
        self.assertEqual(attempt_numbers, [1, 2, 3, 4])

    def test_brute_force_burst_returns_last_event(self):
        received = []
        last = self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=5)
        self.assertEqual(last.event_id, received[-1].event_id)

    def test_non_burst_attack_fires_exactly_one_event(self):
        for attack_type in (
            "sql_injection",
            "xss",
            "path_traversal",
            "command_injection",
            "csrf",
            "ssrf",
            "insecure_file_upload",
        ):
            received = []
            self.sim.trigger_attack(attack_type, on_event=received.append)
            self.assertEqual(len(received), 1, f"{attack_type} should fire exactly one event")

    def test_burst_size_override_respected(self):
        received = []
        self.sim.trigger_attack("brute_force", on_event=received.append, burst_size=3)
        self.assertEqual(len(received), 3)

    # ------------------------------------------------------------
    # New attack types: CSRF, SSRF, insecure file upload,
    # broken access control (IDOR burst)
    # ------------------------------------------------------------

    def test_csrf_sourced_from_internal_victim(self):
        # CSRF exploits a victim's already-authenticated browser, so
        # the source must be an internal endpoint with a real user_id,
        # not an anonymous external attacker. Reuses "form_submission"
        # -- distinguishable by source/user_id/csrf_token_present, not
        # by type.
        internal_net = ipaddress.ip_network("10.10.1.0/24")
        event = self.sim.generate_attack_event(attack_type="csrf")
        self.assertEqual(event.event.type, "form_submission")
        self.assertIn(ipaddress.ip_address(str(event.network.source_ip)), internal_net)
        self.assertIsNotNone(event.actor.user_id)
        self.assertFalse(event.data["csrf_token_present"])

    def test_ssrf_targets_internal_url(self):
        event = self.sim.generate_attack_event(attack_type="ssrf")
        self.assertEqual(event.event.type, "api_call")
        self.assertIn("requested_target_url", event.data)
        self.assertEqual(event.event.status, "blocked")

    def test_insecure_file_upload_flags_type_mismatch(self):
        event = self.sim.generate_attack_event(attack_type="insecure_file_upload")
        self.assertEqual(event.event.type, "form_submission")
        self.assertNotEqual(
            event.data["declared_content_type"], event.data["actual_content_type"]
        )


if __name__ == "__main__":
    unittest.main()