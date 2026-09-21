"""
tests/test_cloud_agent.py

Unit tests for agents/cloud_agent.py and shared/storage/event_tailer.py.

Attack and normal events come from the REAL CloudSimulator (and the
other real simulators), so the tests break if the agent drifts away
from what the simulators actually produce.

Run with:
    python -m tests.test_cloud_agent -v
"""

import json
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


def cloud_event(api_action, event_type, user_id="EMP-003", source_ip="10.10.1.33", **data):
    """A hand-built cloud event matching CloudSimulator._build_event's shape."""
    return {
        "event_id": f"EVT-CLOUD-{abs(hash((api_action, user_id, source_ip, str(data)))) % 10**8:08d}",
        "timestamp": str(T0),
        "source": {"asset_id": "CLOUD-01", "asset_type": "cloud_environment", "hostname": "cloud-01"},
        "network": {"source_ip": source_ip, "source_port": None, "destination_ip": None,
                    "destination_port": None, "protocol": None},
        "actor": {"user_id": user_id, "session_id": "CLOUD-SESSION-TEST"},
        "event": {"category": "iam", "type": event_type, "action": "modify", "status": "success"},
        "target": {"asset_id": "CLOUD-01", "resource": "IAM-01", "resource_type": "identity_management"},
        "data": {"api_action": api_action, "call_source": "employee03", **data},
        "context": {"environment": "simulated_enterprise", "simulation": True},
    }


# ======================================================================
# Normal behaviour
# ======================================================================

class TestNormalCloudActivity(unittest.TestCase):

    def test_large_batch_of_real_normal_events_raises_nothing(self):
        # 1500 events at the simulator's default 2 s stream cadence (~50 min).
        sim, agent = CloudSimulator(), CloudAgent()
        events = [at(as_dict(sim.generate_normal_event()), 2 * i) for i in range(1500)]
        self.assertEqual(agent.analyze(events), [])
        self.assertEqual(agent.stats["cloud_events_analyzed"], 1500)

    def test_each_normal_generator_individually_raises_nothing(self):
        sim, agent = CloudSimulator(), CloudAgent()
        generators = [
            sim._normal_cloud_storage_access, sim._normal_vm_session, sim._normal_cloud_api_call,
            sim._normal_security_config_review, sim._normal_storage_config_review,
            sim._normal_iam_policy_check, sim._normal_role_update,
        ]
        for i, gen in enumerate(generators * 20):
            flags = agent.process_event(at(as_dict(gen()), 10 * i))
            self.assertEqual(flags, [], f"{gen.__name__} was flagged")

    def test_unfamiliar_location_alone_is_not_a_flag(self):
        # A perfectly ordinary read, but from an external IP: supporting
        # evidence only, never an alert by itself.
        event = at(as_dict(CloudSimulator()._normal_cloud_storage_access()), 0)
        event["network"]["source_ip"] = "203.0.113.50"
        self.assertEqual(CloudAgent().process_event(event), [])

    def test_blocked_status_alone_is_not_a_flag(self):
        event = at(as_dict(CloudSimulator()._normal_vm_session()), 0)
        event["event"]["status"] = "blocked"
        self.assertEqual(CloudAgent().process_event(event), [])


# ======================================================================
# One test per cloud attack
# ======================================================================

class TestCloudAttackDetection(unittest.TestCase):

    def test_iam_privilege_escalation_detected(self):
        flags = CloudAgent().analyze(attack_events("iam_privilege_escalation"))
        self.assertEqual(rules(flags), {"iam_privilege_escalation"})
        flag = flags[0]
        self.assertIn(flag.evidence["config_after"], ("admin", "owner"))
        self.assertEqual(flag.severity, "high")

    def test_escalation_confidence_depends_on_supporting_evidence(self):
        # IT admin promoting someone to admin from their own workstation: a lead, medium.
        legit_looking = cloud_event("iam:UpdateRole", "role_update", config_before="employee", config_after="admin")
        flag = CloudAgent().process_event(legit_looking)[0]
        self.assertEqual(flag.confidence, "medium")
        self.assertEqual(flag.evidence["supporting_signals"], [])

        # Unprivileged HR user, from outside: high.
        suspicious = cloud_event("iam:UpdateRole", "role_update", user_id="EMP-002", source_ip="198.51.100.77",
                                 config_before="employee", config_after="admin")
        flag = CloudAgent().process_event(suspicious)[0]
        self.assertEqual(flag.confidence, "high")
        self.assertIn("caller_not_privileged", flag.evidence["supporting_signals"])
        self.assertIn("caller_location=external", flag.evidence["supporting_signals"])

    def test_role_downgrade_or_unknown_roles_not_flagged(self):
        agent = CloudAgent()
        self.assertEqual(agent.process_event(cloud_event(
            "iam:UpdateRole", "role_update", config_before="admin", config_after="employee")), [])
        self.assertEqual(agent.process_event(cloud_event(
            "iam:UpdateRole", "role_update", config_before="intern", config_after="wizard")), [])

    def test_mfa_disablement_detected(self):
        flags = CloudAgent().analyze(attack_events("mfa_disablement"))
        self.assertEqual(rules(flags), {"mfa_disablement"})
        self.assertEqual(flags[0].confidence, "high")

    def test_public_bucket_exposure_detected(self):
        flags = CloudAgent().analyze(attack_events("public_bucket_exposure"))
        self.assertEqual(rules(flags), {"public_bucket_exposure"})
        self.assertEqual(flags[0].severity, "critical")
        self.assertEqual(flags[0].resource, "STORAGE-01")

    def test_bucket_made_private_not_flagged(self):
        event = cloud_event("s3:PutBucketAcl", "storage_config_review",
                            config_before="public-read", config_after="private")
        self.assertEqual(CloudAgent().process_event(event), [])

    def test_security_group_misconfiguration_detected(self):
        flags = CloudAgent().analyze(attack_events("security_group_misconfiguration"))
        self.assertEqual(rules(flags), {"security_group_misconfiguration"})
        self.assertEqual(flags[0].evidence["exposed_port"], 22)
        self.assertEqual(flags[0].severity, "critical")

    def test_security_group_internal_only_rule_not_flagged(self):
        event = cloud_event("ec2:AuthorizeSecurityGroupIngress", "security_config_review",
                            config_before="none", config_after="10.10.1.0/24:443")
        self.assertEqual(CloudAgent().process_event(event), [])

    def test_mass_data_exfiltration_detected(self):
        events = attack_events("mass_data_exfiltration", burst_size=12)
        flags = CloudAgent().analyze(events)
        self.assertEqual(rules(flags), {"mass_data_exfiltration"})
        # The threshold may be crossed by COUNT (5 reads) or earlier by
        # VOLUME (25 MB -- attack reads are up to 20 MB each). Either way,
        # the first flag covers the window so far, later reads get
        # continuation flags, every event of the burst ends up covered,
        # and all flags share one correlation key.
        self.assertLessEqual(len(flags[0].event_ids), 5)
        covered = {eid for f in flags for eid in f.event_ids}
        self.assertEqual(covered, {e["event_id"] for e in events})
        self.assertEqual(len({f.correlation_key for f in flags}), 1)

    def test_few_normal_reads_or_spread_out_reads_not_exfiltration(self):
        sim, agent = CloudSimulator(), CloudAgent()
        reads = []
        while len(reads) < 5:
            e = as_dict(sim._normal_cloud_storage_access())
            if e["data"]["api_action"] == "s3:GetObject" and e["actor"]["user_id"] == "EMP-001":
                reads.append(e)
        # 5 reads by one user, but one every 2 minutes: normal pace
        self.assertEqual(agent.analyze([at(e, 120 * i) for i, e in enumerate(reads)]), [])

    def test_exfiltration_by_volume_alone(self):
        agent = CloudAgent()
        events = []
        for i in range(3):  # only 3 reads, but 3 x 10 MB = 30 MB in 3 seconds
            e = as_dict(CloudSimulator()._attack_mass_data_exfiltration(employee_id="EMP-004", username="employee04"))
            e["data"]["bytes_transferred"] = 10_000_000
            events.append(at(e, i))
        self.assertEqual(rules(agent.analyze(events)), {"mass_data_exfiltration"})

    def test_normal_read_after_burst_ends_is_not_a_new_exfiltration(self):
        agent = CloudAgent()
        burst = [at(e, i * 0.2) for i, e in enumerate(attack_events("mass_data_exfiltration", burst_size=6))]
        self.assertTrue(agent.analyze(burst))
        user = burst[0]["actor"]["user_id"]
        later = as_dict(CloudSimulator()._normal_cloud_storage_access())
        later["actor"]["user_id"] = user
        later["data"]["api_action"] = "s3:GetObject"
        # 30 s later: burst is over (quiet > 10 s) but still inside the 60 s volume window
        self.assertEqual(agent.process_event(at(later, 30)), [])

    def test_api_key_abuse_detected(self):
        events = attack_events("api_key_abuse", burst_size=8)
        flags = CloudAgent().analyze(events)
        self.assertEqual(rules(flags), {"api_key_abuse"})
        burst_flags = [f for f in flags if f.correlation_key]
        self.assertTrue(burst_flags)
        self.assertEqual(burst_flags[0].confidence, "high")
        self.assertGreaterEqual(len(burst_flags[0].evidence["distinct_actions"]), 3)

    def test_single_recon_call_is_only_a_weak_lead(self):
        event = cloud_event("iam:ListUsers", "cloud_api_call", source_ip="10.10.1.33")
        flags = CloudAgent().process_event(event)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0].confidence, "low")

    def test_normal_api_actions_not_flagged(self):
        agent = CloudAgent()
        for action in ("reports:Generate", "orders:List", "profile:Get"):
            self.assertEqual(agent.process_event(cloud_event(action, "cloud_api_call")), [])


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
            {"event_id": "EVT-X"},                                       # missing blocks
            {**good, "event_id": "EVT-Y", "source": "CLOUD-01"},         # wrong block type
            {**good, "event_id": "EVT-Z", "data": ["x"]},                # data not a dict
        ]
        for bad in bad_inputs:
            self.assertEqual(agent.process_event(bad), [])
        self.assertEqual(agent.stats["malformed"], len(bad_inputs))

        odd = [
            {**good, "event_id": "EVT-1", "timestamp": "yesterday-ish"},  # unparseable time
            {**good, "event_id": "EVT-2", "data": {"api_action": "quantum:Teleport"}},
            {**good, "event_id": "EVT-3", "actor": {}, "network": {}},  # no user, no IP
            {**good, "event_id": "EVT-4", "data": {"api_action": "s3:GetObject", "bytes_transferred": "lots"}},
            {**good, "event_id": "EVT-5", "network": {"source_ip": "not-an-ip"}},
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
        for key in ("severity", "timestamp", "evidence", "user_id", "source_ip", "resource"):
            self.assertIn(key, flag)
        json.dumps(flag)  # must be JSON-serialisable for the flag log


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

            sim = CloudSimulator()
            write([as_dict(sim.generate_normal_event()) for _ in range(5)])
            mfa = attack_events("mfa_disablement")
            write(mfa)
            wait_for(1)

            # the agent is still alive after flagging and picks up the next attack
            self.assertTrue(thread.is_alive())
            bucket = attack_events("public_bucket_exposure")
            write(bucket)
            write(mfa)  # the same event appended again must not be re-flagged
            wait_for(2)
            time.sleep(0.3)

            stop.set()
            thread.join(timeout=5)

            written = [json.loads(l) for l in flags_out.read_text().splitlines()]
            self.assertEqual([f["rule"] for f in written], ["mfa_disablement", "public_bucket_exposure"])
            self.assertEqual(agent.stats["duplicates_skipped"], 1)
            self.assertEqual(agent.stats["events_seen"], 7)


if __name__ == "__main__":
    unittest.main()
