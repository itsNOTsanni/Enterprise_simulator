"""
tests/test_cloud_agent.py

Unit tests for the pattern-based Cloud Agent (agents/cloud_agent.py)
and shared/storage/event_tailer.py.

The agent knows no attack names. These tests check that:
  - normal traffic from the REAL CloudSimulator is never flagged
  - all 6 simulator cloud attacks are flagged
  - attack VARIANTS the agent was never written for are flagged too
    (hand-built events: different API actions, roles, ports, resources)
  - weak signals alone (new action, unfamiliar IP) never raise a flag
  - continuous monitoring, de-duplication and bad input all behave

Run with:
    python -m tests.test_cloud_agent -v
"""

import json
import random
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.cloud_agent import CloudAgent, run
from agents.network_agent import Flag as NetworkFlag
from shared.storage.event_tailer import EventTailer
from simulator.cloud.cloud_simulator import CloudSimulator
from simulator.database.db_simulator import DatabaseSimulator
from simulator.endpoints.endpoint_simulator import EndpointSimulator
from simulator.web.web_simulator import WebServerSimulator

T0 = datetime(2026, 9, 21, 9, 0, 0, tzinfo=timezone.utc)


def as_dict(event):
    """CommonEvent -> the dict shape stored in events.jsonl."""
    return json.loads(json.dumps(event.model_dump(), default=str))


def at(event_dict, seconds):
    """Give an event a deterministic timestamp T0 + seconds."""
    event_dict["timestamp"] = str(T0 + timedelta(seconds=seconds))
    return event_dict


def attack_events(attack_type, **kwargs):
    sim = CloudSimulator()
    out = []
    sim.trigger_attack(attack_type, on_event=lambda e: out.append(as_dict(e)),
                       burst_delay_seconds=0, **kwargs)
    return out


def rules(flags):
    return {f.rule for f in flags}


_counter = iter(range(10**9))

RESOURCE_TYPES = {"IAM-01": "identity_management", "SEC-01": "security_configuration",
                  "STORAGE-01": "object_storage", "API-01": "cloud_api", "CLOUD-VM-01": "virtual_machine"}


def cloud_event(api_action, user_id="EMP-003", source_ip="10.10.1.33", resource="IAM-01",
                action="modify", event_type="cloud_change", **data):
    """A hand-built cloud event in the same shape as CloudSimulator._build_event."""
    return {
        "event_id": f"EVT-CLOUD-T{next(_counter):08d}",
        "timestamp": str(T0),
        "source": {"asset_id": "CLOUD-01", "asset_type": "cloud_environment", "hostname": "cloud-01"},
        "network": {"source_ip": source_ip, "source_port": None, "destination_ip": None,
                    "destination_port": None, "protocol": None},
        "actor": {"user_id": user_id, "session_id": "CLOUD-SESSION-TEST"},
        "event": {"category": "cloud", "type": event_type, "action": action, "status": "success"},
        "target": {"asset_id": "CLOUD-01", "resource": resource, "resource_type": RESOURCE_TYPES[resource]},
        "data": {"api_action": api_action, **data},
        "context": {"environment": "simulated_enterprise", "simulation": True},
    }


def normal_stream(n, interval=2.0, jitter=0.5, start=0.0, seed=1):
    """n real normal cloud events, timed like start_normal_stream (interval +/- jitter)."""
    rng, sim, t, out = random.Random(seed), CloudSimulator(), start, []
    for _ in range(n):
        t += interval + rng.uniform(-jitter, jitter)
        out.append(at(as_dict(sim.generate_normal_event()), t))
    return out, t


def warmed_agent(n=600):
    """An agent that has watched n normal events (as it would in real use)."""
    agent = CloudAgent()
    events, t = normal_stream(n)
    assert agent.analyze(events) == []
    return agent, t


def timed(events, start, step=0.15):
    return [at(e, start + 1 + step * i) for i, e in enumerate(events)]


def patterns(flags):
    return {p for f in flags for p in f.patterns}


# ======================================================================
# Normal behaviour
# ======================================================================

class TestNormalCloudActivity(unittest.TestCase):

    def test_real_normal_traffic_is_never_flagged_at_several_speeds(self):
        for interval in (1.0, 2.0, 3.0):
            agent = CloudAgent()
            events, _ = normal_stream(1500, interval=interval, seed=int(interval * 10))
            self.assertEqual(agent.analyze(events), [], f"false positive at {interval}s cadence")
            self.assertEqual(agent.stats["cloud_events_analyzed"], 1500)

    def test_agent_learns_a_baseline(self):
        agent, _ = warmed_agent()
        self.assertTrue(agent.baseline.warmed_up)
        self.assertIn("s3:GetObject", agent.baseline.actions)
        self.assertAlmostEqual(agent.baseline.median_gap(), 2.0, delta=0.3)

    def test_unfamiliar_location_alone_is_not_a_flag(self):
        agent, t = warmed_agent()
        event = at(as_dict(CloudSimulator()._normal_cloud_storage_access()), t + 1)
        event["network"]["source_ip"] = "203.0.113.50"
        self.assertEqual(agent.process_event(event), [])

    def test_novelty_alone_is_not_a_flag(self):
        # admin, own laptop, brand-new action AND brand-new config value -- but it
        # strengthens security, so nothing suspicious beyond "new"
        agent, t = warmed_agent()
        event = at(cloud_event("iam:EnableMFADevice", config_before="mfa_disabled",
                               config_after="mfa_enabled"), t + 1)
        self.assertEqual(agent.process_event(event), [])

    def test_admin_routine_change_from_own_laptop_not_flagged(self):
        agent, t = warmed_agent()
        event = at(cloud_event("iam:UpdateRole", config_before="employee", config_after="manager"), t + 1)
        self.assertEqual(agent.process_event(event), [])

    def test_blocked_status_alone_is_not_a_flag(self):
        agent, t = warmed_agent()
        event = at(as_dict(CloudSimulator()._normal_vm_session()), t + 1)
        event["event"]["status"] = "blocked"
        self.assertEqual(agent.process_event(event), [])

    def test_no_attack_names_in_output(self):
        agent, t = warmed_agent()
        flags = agent.analyze(timed(attack_events("mfa_disablement"), t))
        self.assertEqual({f.rule for f in flags}, {"suspicious_cloud_activity"})


# ======================================================================
# The 6 simulator attacks
# ======================================================================

class TestSimulatorAttacksDetected(unittest.TestCase):

    def check(self, attack, expected_patterns, **kwargs):
        agent, t = warmed_agent()
        flags = agent.analyze(timed(attack_events(attack, **kwargs), t))
        self.assertTrue(flags, f"{attack} not detected")
        self.assertTrue(expected_patterns & patterns(flags),
                        f"{attack}: expected one of {expected_patterns}, got {patterns(flags)}")
        return flags

    def test_iam_privilege_escalation(self):
        flags = self.check("iam_privilege_escalation", {"security_weakening"})
        self.assertEqual(flags[0].severity, "high")

    def test_mfa_disablement(self):
        self.check("mfa_disablement", {"security_weakening"})

    def test_public_bucket_exposure(self):
        flags = self.check("public_bucket_exposure", {"security_weakening"})
        self.assertEqual(flags[0].severity, "critical")

    def test_security_group_misconfiguration(self):
        flags = self.check("security_group_misconfiguration", {"security_weakening"})
        self.assertEqual(flags[0].severity, "critical")

    def test_mass_data_exfiltration(self):
        events_flags = self.check("mass_data_exfiltration", {"activity_burst", "bulk_data_transfer"}, burst_size=10)
        self.assertEqual(len({f.correlation_key for f in events_flags if f.correlation_key}), 1)

    def test_api_key_abuse(self):
        flags = self.check("api_key_abuse", {"activity_burst"}, burst_size=8)
        self.assertIn("enumeration", patterns(flags))

    def test_detected_even_without_warm_up(self):
        for attack in CloudSimulator().available_attack_types():
            events = attack_events(attack, burst_size=8) if attack in ("mass_data_exfiltration", "api_key_abuse") \
                else attack_events(attack)
            self.assertTrue(CloudAgent().analyze(timed(events, 0)), f"{attack} missed with a cold agent")


# ======================================================================
# Attack VARIANTS the agent was never written for
# ======================================================================

class TestUnseenAttackVariants(unittest.TestCase):
    """None of these API actions, roles, ports or resources appear in the agent's code."""

    def detect(self, events, step=0.15):
        agent, t = warmed_agent()
        flags = agent.analyze(timed(events, t, step))
        self.assertTrue(flags, "variant not detected")
        return flags

    def test_escalation_to_a_different_role_name(self):
        flags = self.detect([cloud_event("iam:UpdateRole", user_id="EMP-002", source_ip="10.10.1.32",
                                         config_before="employee", config_after="superuser")])
        self.assertIn("security_weakening", patterns(flags))

    def test_admin_policy_attached_via_different_api(self):
        self.detect([cloud_event("iam:AttachUserPolicy", user_id="EMP-004", source_ip="203.0.113.9",
                                 config_before="ReadOnly", config_after="AdministratorAccess")])

    def test_audit_logging_stopped(self):
        flags = self.detect([cloud_event("cloudtrail:StopLogging", user_id="EMP-001", source_ip="10.10.1.31",
                                         resource="SEC-01", config_before="logging_enabled",
                                         config_after="logging_disabled")])
        self.assertIn("security_weakening", patterns(flags))

    def test_new_access_key_created_by_non_admin(self):
        flags = self.detect([cloud_event("iam:CreateAccessKey", user_id="EMP-001", source_ip="198.51.100.4",
                                         action="create")])
        self.assertIn("sensitive_change_by_non_admin", patterns(flags))

    def test_other_port_opened_to_internet_even_by_admin(self):
        flags = self.detect([cloud_event("ec2:ModifySecurityGroupRules", resource="SEC-01",
                                         config_before="internal_only", config_after="0.0.0.0/0:3389")])
        self.assertEqual(flags[0].severity, "critical")

    def test_storage_encryption_disabled(self):
        self.detect([cloud_event("s3:PutBucketEncryption", user_id="EMP-002", source_ip="10.10.1.32",
                                 resource="STORAGE-01", config_before="encryption_enabled",
                                 config_after="encryption_disabled")])

    def test_exfiltration_via_different_api(self):
        flags = self.detect([cloud_event("s3:CopyObject", user_id="EMP-004", source_ip="10.10.1.34",
                                         resource="STORAGE-01", action="read", bytes_transferred=8_000_000)
                             for _ in range(8)])
        self.assertIn("activity_burst", patterns(flags))

    def test_mass_deletion(self):
        flags = self.detect([cloud_event("s3:DeleteObject", user_id="EMP-001", source_ip="10.10.1.31",
                                         resource="STORAGE-01", action="delete") for _ in range(10)])
        self.assertIn("activity_burst", patterns(flags))

    def test_reconnaissance_via_other_apis(self):
        actions = ["lambda:ListFunctions", "rds:DescribeDBInstances", "kms:ListKeys",
                   "organizations:ListAccounts", "sts:GetCallerIdentity", "ec2:DescribeVpcs"]
        flags = self.detect([cloud_event(a, user_id="EMP-002", source_ip="203.0.113.77", resource="API-01",
                                         action="request") for a in actions])
        self.assertIn("enumeration", patterns(flags))

    def test_slow_large_download(self):
        flags = self.detect([cloud_event("s3:GetObject", user_id="EMP-002", source_ip="10.10.1.32",
                                         resource="STORAGE-01", action="read", bytes_transferred=20_000_000)
                             for _ in range(3)], step=20)
        self.assertIn("bulk_data_transfer", patterns(flags))


# ======================================================================
# Confidence reflects how many patterns agree
# ======================================================================

class TestScoring(unittest.TestCase):

    def test_more_patterns_means_higher_confidence(self):
        agent, t = warmed_agent()
        admin_own_laptop = at(cloud_event("iam:UpdateRole", config_before="employee", config_after="admin"), t + 1)
        outsider = at(cloud_event("iam:UpdateRole", user_id="EMP-002", source_ip="198.51.100.77",
                                  config_before="employee", config_after="admin"), t + 5)
        low = agent.process_event(admin_own_laptop)[0]
        high = agent.process_event(outsider)[0]
        self.assertLess(low.score, high.score)
        self.assertEqual(high.confidence, "high")
        self.assertIn("sensitive_change_by_non_admin", high.patterns)

    def test_flagged_events_do_not_become_normal(self):
        agent, t = warmed_agent()
        agent.analyze(timed([cloud_event("cloudtrail:StopLogging", user_id="EMP-001", source_ip="10.10.1.31",
                                         resource="SEC-01", config_after="logging_disabled")], t))
        self.assertNotIn("cloudtrail:StopLogging", agent.baseline.actions)

    def test_burst_ends_when_activity_slows(self):
        agent, t = warmed_agent()
        burst = timed(attack_events("mass_data_exfiltration", burst_size=6), t)
        self.assertTrue(agent.analyze(burst))
        user = burst[0]["actor"]["user_id"]
        later = as_dict(CloudSimulator()._normal_cloud_storage_access())
        later["actor"]["user_id"] = user
        later["network"]["source_ip"] = agent.identities[user]["workstation_ip"]
        later["data"]["api_action"] = "s3:GetObject"
        later["data"]["bytes_transferred"] = 1_000_000
        self.assertEqual(agent.process_event(at(later, t + 40)), [])


# ======================================================================
# Scope: other enterprise components
# ======================================================================

class TestNonCloudEventsIgnored(unittest.TestCase):

    def test_other_simulators_normal_and_attack_events_raise_nothing(self):
        agent = CloudAgent()
        events = []
        web, db = WebServerSimulator(), DatabaseSimulator()
        endpoints = [EndpointSimulator(eid) for eid in EndpointSimulator.ALL_ENDPOINT_IDS]
        for sim in [web, db, *endpoints]:
            events += [as_dict(sim.generate_normal_event()) for _ in range(40)]
            for attack in sim.available_attack_types():
                sim.trigger_attack(attack, on_event=lambda e: events.append(as_dict(e)), burst_delay_seconds=0)
        self.assertEqual(agent.analyze(events), [])
        self.assertEqual(agent.stats["cloud_events_analyzed"], 0)
        self.assertEqual(agent.stats["non_cloud_ignored"], len(events))

    def test_endpoint_connection_to_cloud_is_not_a_cloud_event(self):
        sim, agent = EndpointSimulator("END-01"), CloudAgent()
        found = False
        for _ in range(200):
            e = as_dict(sim._normal_network_connection())
            if e["target"]["asset_id"] == "CLOUD-01":
                found = True
                self.assertEqual(agent.process_event(e), [])
        self.assertTrue(found, "expected at least one END-01 -> CLOUD-01 connection")


# ======================================================================
# Robustness and duplicates
# ======================================================================

class TestRobustness(unittest.TestCase):

    def test_same_event_processed_only_once(self):
        agent = CloudAgent()
        event = attack_events("mfa_disablement")[0]
        self.assertEqual(len(agent.process_event(event)), 1)
        self.assertEqual(agent.process_event(event), [])
        self.assertEqual(agent.process_event(dict(event)), [])
        self.assertEqual(agent.stats["duplicates_skipped"], 2)

    def test_malformed_and_unknown_inputs_handled_safely(self):
        agent = CloudAgent()
        good = attack_events("public_bucket_exposure")[0]
        bad_inputs = [
            None, "not an event", 42, [], {},
            {"event_id": "EVT-X"},
            {**good, "event_id": "EVT-Y", "source": "CLOUD-01"},
            {**good, "event_id": "EVT-Z", "data": ["x"]},
        ]
        for bad in bad_inputs:
            self.assertEqual(agent.process_event(bad), [])
        self.assertEqual(agent.stats["malformed"], len(bad_inputs))
        odd = [
            {**good, "event_id": "EVT-1", "timestamp": "yesterday-ish"},
            {**good, "event_id": "EVT-2", "data": {"api_action": "quantum:Teleport"}},
            {**good, "event_id": "EVT-3", "actor": {}, "network": {}},
            {**good, "event_id": "EVT-4", "data": {"api_action": "s3:GetObject", "bytes_transferred": "lots"}},
            {**good, "event_id": "EVT-5", "network": {"source_ip": "not-an-ip"}},
            {**good, "event_id": "EVT-6", "target": {}, "data": {}},
        ]
        for event in odd:
            agent.process_event(event)  # must not raise
        self.assertEqual(agent.stats["errors"], 0)

    def test_flag_dict_contains_network_agent_keys(self):
        network_keys = set(NetworkFlag("r", "low", "s", ["e"], "A").to_dict().keys())
        flag = CloudAgent().analyze(attack_events("mfa_disablement"))[0].to_dict()
        self.assertTrue(network_keys.issubset(flag.keys()))
        self.assertEqual(flag["agent"], "cloud")
        self.assertIn(flag["confidence"], ("low", "medium", "high"))
        for key in ("severity", "score", "patterns", "timestamp", "evidence", "user_id", "source_ip", "resource"):
            self.assertIn(key, flag)
        json.dumps(flag)


# ======================================================================
# Continuous monitoring
# ======================================================================

class TestEventTailer(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "events.jsonl"

    def tearDown(self):
        self.dir.cleanup()

    def append(self, text):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(text)

    def test_missing_file_returns_nothing(self):
        self.assertEqual(EventTailer(self.path).poll(), [])

    def test_only_new_lines_returned(self):
        tailer = EventTailer(self.path)
        self.append('{"event_id": "A"}\n{"event_id": "B"}\n')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["A", "B"])
        self.assertEqual(tailer.poll(), [])
        self.append('{"event_id": "C"}\n')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["C"])

    def test_partial_line_waits_for_completion(self):
        tailer = EventTailer(self.path)
        self.append('{"event_id": "A"}\n{"event_id": ')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["A"])
        self.assertEqual(tailer.poll(), [])
        self.append('"B"}\n')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["B"])

    def test_truncated_file_is_reread_from_start(self):
        tailer = EventTailer(self.path)
        self.append('{"event_id": "A"}\n{"event_id": "B"}\n')
        tailer.poll()
        self.path.write_text('{"event_id": "X"}\n', encoding="utf-8")
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["X"])

    def test_malformed_lines_skipped_and_counted(self):
        tailer = EventTailer(self.path)
        self.append('{"event_id": "A"}\nnot json\n[1,2]\n{"event_id": "B"}\n')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["A", "B"])
        self.assertEqual(tailer.malformed_lines, 2)

    def test_start_at_end_skips_existing(self):
        self.append('{"event_id": "OLD"}\n')
        tailer = EventTailer(self.path, start_at_end=True)
        self.assertEqual(tailer.poll(), [])
        self.append('{"event_id": "NEW"}\n')
        self.assertEqual([r["event_id"] for r in tailer.poll()], ["NEW"])


class TestContinuousAgent(unittest.TestCase):

    def test_agent_keeps_running_and_processes_new_events_once(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "events.jsonl"
            flags_out = Path(d) / "cloud_flags.jsonl"
            log.touch()
            stop = threading.Event()
            agent = CloudAgent()
            thread = threading.Thread(target=run, daemon=True, kwargs=dict(
                path=log, output_path=flags_out, poll_interval=0.05, stop_event=stop, agent=agent))
            thread.start()

            def write(events):
                with open(log, "a", encoding="utf-8") as f:
                    for e in events:
                        f.write(json.dumps(e) + "\n")

            def wait_for(n_lines, timeout=5.0):
                deadline = time.time() + timeout
                while time.time() < deadline:
                    if flags_out.exists() and len(flags_out.read_text().splitlines()) >= n_lines:
                        return
                    time.sleep(0.05)

            normal, t = normal_stream(5)          # spaced like the real stream
            write(normal)
            mfa = [at(e, t + 2) for e in attack_events("mfa_disablement")]
            write(mfa)
            wait_for(1)

            # the agent is still alive after flagging and picks up the next attack
            self.assertTrue(thread.is_alive())
            bucket = [at(e, t + 4) for e in attack_events("public_bucket_exposure")]
            write(bucket)
            write(mfa)  # the same event appended again must not be re-flagged
            wait_for(2)
            time.sleep(0.3)

            stop.set()
            thread.join(timeout=5)

            written = [json.loads(l) for l in flags_out.read_text().splitlines()]
            self.assertEqual(len(written), 2)
            self.assertEqual({f["rule"] for f in written}, {"suspicious_cloud_activity"})
            self.assertEqual(written[0]["event_ids"], [mfa[0]["event_id"]])
            self.assertEqual(written[1]["event_ids"], [bucket[0]["event_id"]])
            self.assertEqual(agent.stats["duplicates_skipped"], 1)
            self.assertEqual(agent.stats["events_seen"], 7)


if __name__ == "__main__":
    unittest.main()
