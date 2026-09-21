"""
tests/test_network_agent.py

Unit tests for agents/network_agent.py.

Run with:
    python -m tests.test_network_agent
"""

import unittest

from agents.network_agent import NetworkAgent


def base_event(**overrides):
    """A minimal, valid-shaped event dict, overridable per test."""
    event = {
        "event_id": "EVT-TEST-00000001",
        "timestamp": "2026-09-13 02:00:00.000000+00:00",
        "source": {"asset_id": "WEB-01", "asset_type": "web_server", "hostname": "web-01"},
        "network": {
            "source_ip": "10.10.1.31",
            "source_port": 50000,
            "destination_ip": "10.10.1.10",
            "destination_port": 443,
            "protocol": "HTTPS",
        },
        "actor": {"user_id": "EMP-001", "session_id": "SESSION-TEST-0001"},
        "event": {"category": "web", "type": "page_view", "action": "view", "status": "success"},
        "target": {"asset_id": "WEB-01", "resource": "/dashboard", "resource_type": "page"},
        "data": {},
        "context": {"environment": "simulated_enterprise", "simulation": True},
    }
    event.update(overrides)
    return event


class TestNetworkAgent(unittest.TestCase):

    def setUp(self):
        self.agent = NetworkAgent()

    # ------------------------------------------------------------
    # No false positives on clean traffic
    # ------------------------------------------------------------

    def test_normal_single_event_raises_nothing(self):
        flags = self.agent.analyze([base_event()])
        self.assertEqual(flags, [])

    def test_normal_web_to_db_traffic_raises_nothing(self):
        # WEB-01 -> DB-01 is an allowed pair per the registry
        event = base_event(
            event_id="EVT-TEST-2",
            network={
                "source_ip": "10.10.1.10", "source_port": 50000,
                "destination_ip": "10.10.1.20", "destination_port": 5432, "protocol": "TCP",
            },
            source={"asset_id": "DB-01", "asset_type": "database_server", "hostname": "db-01"},
            target={"asset_id": "DB-01", "resource": "orders_table", "resource_type": "table"},
        )
        self.assertEqual(self.agent.analyze([event]), [])

    # ------------------------------------------------------------
    # Rule 1: external source
    # ------------------------------------------------------------

    def test_external_source_flagged(self):
        event = base_event(network={
            "source_ip": "203.0.113.15", "source_port": 50000,
            "destination_ip": "10.10.1.10", "destination_port": 443, "protocol": "HTTPS",
        })
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "external_source" for f in flags))

    def test_internal_source_not_flagged_as_external(self):
        event = base_event()  # source_ip 10.10.1.31, internal
        flags = self.agent.analyze([event])
        self.assertFalse(any(f.rule == "external_source" for f in flags))

    # ------------------------------------------------------------
    # Rule 2: topology violation
    # ------------------------------------------------------------

    def test_disallowed_pair_flagged(self):
        # END-01 -> DB-01 is never listed as allowed in the registry
        event = base_event(
            source={"asset_id": "END-01", "asset_type": "employee_workstation", "hostname": "employee-01"},
            network={
                "source_ip": "10.10.1.31", "source_port": 50000,
                "destination_ip": "10.10.1.20", "destination_port": 445, "protocol": "TCP",
            },
            target={"asset_id": "DB-01", "resource": "db-01", "resource_type": "network_connection"},
        )
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "topology_violation" for f in flags))

    def test_allowed_pair_not_flagged(self):
        # END-03 -> DB-01 IS explicitly allowed in the registry
        event = base_event(
            source={"asset_id": "END-03", "asset_type": "employee_workstation", "hostname": "employee-03"},
            network={
                "source_ip": "10.10.1.33", "source_port": 50000,
                "destination_ip": "10.10.1.20", "destination_port": 5432, "protocol": "TCP",
            },
            target={"asset_id": "DB-01", "resource": "db-01", "resource_type": "network_connection"},
        )
        flags = self.agent.analyze([event])
        self.assertFalse(any(f.rule == "topology_violation" for f in flags))

    def test_asymmetric_registry_listing_still_recognized_as_allowed(self):
        # END-04 lists WEB-01 in its communicates_with, even though
        # WEB-01's own list doesn't separately mention END-04 -- the
        # pair must still be treated as allowed either direction.
        event = base_event(
            source={"asset_id": "END-04", "asset_type": "employee_workstation", "hostname": "employee-04"},
            network={
                "source_ip": "10.10.1.34", "source_port": 50000,
                "destination_ip": "10.10.1.10", "destination_port": 443, "protocol": "HTTPS",
            },
            target={"asset_id": "WEB-01", "resource": "web-01", "resource_type": "network_connection"},
        )
        flags = self.agent.analyze([event])
        self.assertFalse(any(f.rule == "topology_violation" for f in flags))

    # ------------------------------------------------------------
    # Rule 3: unusual destination port
    # ------------------------------------------------------------

    def test_unusual_port_flagged(self):
        event = base_event(network={
            "source_ip": "10.10.1.31", "source_port": 50000,
            "destination_ip": "10.10.1.20", "destination_port": 3389, "protocol": "TCP",
        })
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "unusual_destination_port" for f in flags))

    def test_known_ports_not_flagged(self):
        for port in (443, 5432):
            event = base_event(event_id=f"EVT-PORT-{port}", network={
                "source_ip": "10.10.1.31", "source_port": 50000,
                "destination_ip": "10.10.1.20", "destination_port": port, "protocol": "TCP",
            })
            flags = self.agent.analyze([event])
            self.assertFalse(any(f.rule == "unusual_destination_port" for f in flags))

    # ------------------------------------------------------------
    # Rule 4: repeated failures
    # ------------------------------------------------------------

    def test_repeated_failures_flagged_at_threshold(self):
        events = [
            base_event(
                event_id=f"EVT-FAIL-{i}",
                event={"category": "authentication", "type": "login_attempt", "action": "authenticate", "status": "failure"},
                actor={"user_id": None, "session_id": "SESSION-BRUTE-1"},
            )
            for i in range(4)
        ]
        flags = self.agent.analyze(events)
        self.assertTrue(any(f.rule == "repeated_failures" for f in flags))

    def test_few_failures_below_threshold_not_flagged(self):
        events = [
            base_event(
                event_id=f"EVT-FAIL-{i}",
                event={"category": "authentication", "type": "login_attempt", "action": "authenticate", "status": "failure"},
                actor={"user_id": None, "session_id": "SESSION-BRUTE-2"},
            )
            for i in range(2)
        ]
        flags = self.agent.analyze(events)
        self.assertFalse(any(f.rule == "repeated_failures" for f in flags))

    # ------------------------------------------------------------
    # Rule 5: fan-out
    # ------------------------------------------------------------

    def test_fan_out_flagged(self):
        events = [
            base_event(
                event_id=f"EVT-FANOUT-{i}",
                source={"asset_id": "END-02", "asset_type": "employee_workstation", "hostname": "employee-02"},
                actor={"user_id": "EMP-002", "session_id": "SESSION-LATERAL-1"},
                target={"asset_id": target_id, "resource": target_id.lower(), "resource_type": "network_connection"},
            )
            for i, target_id in enumerate(["END-01", "END-03", "DB-01"])
        ]
        flags = self.agent.analyze(events)
        self.assertTrue(any(f.rule == "fan_out" for f in flags))

    def test_single_destination_not_flagged_as_fan_out(self):
        events = [
            base_event(
                event_id="EVT-SINGLE-1",
                actor={"user_id": "EMP-001", "session_id": "SESSION-NORMAL-1"},
            )
        ]
        flags = self.agent.analyze(events)
        self.assertFalse(any(f.rule == "fan_out" for f in flags))

    # ------------------------------------------------------------
    # Rule 6: rate spike
    # ------------------------------------------------------------

    def test_rate_spike_flagged_for_tight_burst(self):
        events = [
            base_event(
                event_id=f"EVT-RATE-{i}",
                timestamp=f"2026-09-13 02:00:00.{i:06d}+00:00",
                actor={"user_id": "EMP-001", "session_id": "SESSION-BURST-1"},
            )
            for i in range(6)
        ]
        flags = self.agent.analyze(events)
        self.assertTrue(any(f.rule == "rate_spike" for f in flags))

    def test_spread_out_events_not_flagged_as_rate_spike(self):
        # Same count, but spread across a much longer time window
        timestamps = [
            "2026-09-13 02:00:00.000000+00:00",
            "2026-09-13 02:05:00.000000+00:00",
            "2026-09-13 02:10:00.000000+00:00",
            "2026-09-13 02:15:00.000000+00:00",
            "2026-09-13 02:20:00.000000+00:00",
            "2026-09-13 02:25:00.000000+00:00",
        ]
        events = [
            base_event(
                event_id=f"EVT-SPREAD-{i}",
                timestamp=ts,
                actor={"user_id": "EMP-001", "session_id": "SESSION-SPREAD-1"},
            )
            for i, ts in enumerate(timestamps)
        ]
        flags = self.agent.analyze(events)
        self.assertFalse(any(f.rule == "rate_spike" for f in flags))

    # ------------------------------------------------------------
    # Rule 7: bulk volume
    # ------------------------------------------------------------

    def test_large_rows_returned_flagged(self):
        event = base_event(data={"rows_returned": 500_000})
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "bulk_volume" for f in flags))

    def test_normal_rows_returned_not_flagged(self):
        event = base_event(data={"rows_returned": 42})
        flags = self.agent.analyze([event])
        self.assertFalse(any(f.rule == "bulk_volume" for f in flags))

    def test_large_bytes_transferred_flagged(self):
        event = base_event(data={"bytes_transferred": 15_000_000})
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "bulk_volume" for f in flags))

    def test_large_file_size_flagged(self):
        event = base_event(data={"file_size_bytes": 9_000_000})
        flags = self.agent.analyze([event])
        self.assertTrue(any(f.rule == "bulk_volume" for f in flags))

    # ------------------------------------------------------------
    # Flag structure
    # ------------------------------------------------------------

    def test_flag_to_dict_has_expected_keys(self):
        event = base_event(network={
            "source_ip": "203.0.113.15", "source_port": 50000,
            "destination_ip": "10.10.1.10", "destination_port": 443, "protocol": "HTTPS",
        })
        flags = self.agent.analyze([event])
        flag_dict = flags[0].to_dict()
        self.assertEqual(
            set(flag_dict.keys()),
            {"agent", "rule", "confidence", "summary", "event_ids", "asset_id"},
        )
        self.assertEqual(flag_dict["agent"], "network")


if __name__ == "__main__":
    unittest.main()