"""
run_attack_scenario.py

Plays out realistic MULTI-STAGE attack scenarios across several assets
at once, in a believable order with real delays between steps --
unlike calling trigger_attack() by hand, which only ever produces one
isolated attack on one asset with no connection to anything else.

This exists to give a future Coordinator Agent something real to
correlate. Each scenario below is deliberately designed so that AT
LEAST 3 of the 4 planned monitoring agents (Log: web+db, Network:
cross-cutting source/destination/port/topology, Cloud, Endpoint) would
each independently flag ONE piece of the story on their own -- the
full picture ("this is one attack, not three") only becomes visible
once those pieces are combined, which is exactly the Coordinator
Agent's future job.

All 4 simulators keep generating their own continuous normal traffic
in the background throughout each scenario, exactly like
run_soc_feed.py, and every event -- scenario steps AND background
normal traffic -- is written to the shared event log via
shared.storage.event_writer. Every scenario step also gets a ground
truth entry, same as run_soc_feed.py's attacks.

Usage:
    python run_attack_scenario.py                    # lists scenarios
    python run_attack_scenario.py ransomware_to_db
    python run_attack_scenario.py credential_to_cloud
    python run_attack_scenario.py insider_threat
"""

import json
import sys
import time

from shared.storage.event_writer import (
    write_event,
    DEFAULT_EVENT_LOG_PATH,
    DEFAULT_GROUND_TRUTH_PATH,
)
from simulator.web.web_simulator import WebServerSimulator
from simulator.endpoints.endpoint_simulator import EndpointSimulator
from simulator.cloud.cloud_simulator import CloudSimulator
from simulator.database.db_simulator import DatabaseSimulator


def _print_event(event, prefix: str = "") -> None:
    dump = event.model_dump() if hasattr(event, "model_dump") else event.dict()
    print(prefix.strip())
    print(json.dumps(dump, indent=2, default=str))
    print("-" * 60)


def build_simulators() -> dict:
    sims = {"WEB-01": WebServerSimulator("WEB-01")}
    for endpoint_id in EndpointSimulator.ALL_ENDPOINT_IDS:
        sims[endpoint_id] = EndpointSimulator(endpoint_id)
    sims["CLOUD-01"] = CloudSimulator("CLOUD-01")
    sims["DB-01"] = DatabaseSimulator("DB-01")
    return sims


def fire_step(
    sims: dict,
    asset_id: str,
    attack_type: str,
    narration: str,
    agent: str,
    delay_before: float = 0.0,
    **kwargs,
) -> None:
    """Run one stage of a scenario: wait, narrate which agent should catch it, fire the attack."""
    if delay_before:
        time.sleep(delay_before)

    print(f"\n>>> [{agent} agent territory] {narration}")

    def handler(event):
        write_event(event, is_attack=True, attack_type=attack_type)
        _print_event(event, prefix="[ATTACK] ")

    sims[asset_id].trigger_attack(attack_type, on_event=handler, **kwargs)


# ----------------------------------------------------------------------
# Scenario definitions
# ----------------------------------------------------------------------

SCENARIOS = {
    "ransomware_to_db": {
        "description": (
            "Ransomware on END-02 pivots into DB-01 and pulls a large amount "
            "of data. Hits: ENDPOINT, NETWORK, LOG agents."
        ),
        "steps": [
            dict(
                asset_id="END-02", attack_type="ransomware", agent="ENDPOINT",
                narration="Stage 1: Ransomware begins encrypting files on END-02.",
                burst_size=12, delay_before=0,
            ),
            dict(
                asset_id="END-02", attack_type="lateral_movement", agent="NETWORK",
                narration=(
                    "Stage 2: The compromised END-02 pivots toward DB-01 -- a "
                    "connection the registry says should never happen."
                ),
                burst_size=3, delay_before=2.0,
            ),
            dict(
                asset_id="DB-01", attack_type="mass_data_exfiltration", agent="LOG",
                narration="Stage 3: An abnormally large data pull hits DB-01.",
                burst_size=8, delay_before=1.5,
            ),
        ],
    },
    "credential_to_cloud": {
        "description": (
            "Brute force on WEB-01 leads to stolen-credential abuse in "
            "CLOUD-01. Hits: LOG, CLOUD, NETWORK agents."
        ),
        "steps": [
            dict(
                asset_id="WEB-01", attack_type="brute_force", agent="LOG",
                narration="Stage 1: Brute-force login attempts against WEB-01.",
                burst_size=10, delay_before=0,
            ),
            dict(
                asset_id="CLOUD-01", attack_type="iam_privilege_escalation", agent="CLOUD",
                narration="Stage 2: Stolen credentials used to self-grant elevated cloud privileges.",
                delay_before=2.5,
            ),
            dict(
                asset_id="CLOUD-01", attack_type="api_key_abuse", agent="NETWORK",
                narration="Stage 3: The abused API key fires unusual calls from an unfamiliar location.",
                burst_size=6, delay_before=1.5,
            ),
        ],
    },
    "insider_threat": {
        "description": (
            "An IT admin's own workstation escalates privilege, exfiltrates "
            "via USB, then a destructive query hits the database from an "
            "unexpected source. Hits: ENDPOINT, NETWORK, LOG agents."
        ),
        "steps": [
            dict(
                asset_id="END-03", attack_type="privilege_escalation", agent="ENDPOINT",
                narration="Stage 1: Privilege escalation attempt on END-03 (the DB admin's own machine).",
                delay_before=0,
            ),
            dict(
                asset_id="END-03", attack_type="usb_data_exfiltration", agent="ENDPOINT",
                narration="Stage 2: Sensitive files are copied to a USB device from END-03.",
                burst_size=6, delay_before=2.0,
            ),
            dict(
                asset_id="DB-01", attack_type="destructive_query", agent="NETWORK + LOG",
                narration=(
                    "Stage 3: A destructive DROP/TRUNCATE query hits DB-01 from a "
                    "source that has no business talking to it (Network angle) "
                    "using a dangerous query type (Log angle) -- one event, two "
                    "independent signals."
                ),
                delay_before=1.5,
            ),
        ],
    },
}


def run_scenario(name: str) -> None:
    scenario = SCENARIOS[name]
    print(f"=== Running scenario: {name} ===")
    print(scenario["description"])
    print()
    print(f"Event log:        {DEFAULT_EVENT_LOG_PATH}")
    print(f"Ground truth log: {DEFAULT_GROUND_TRUTH_PATH}")

    sims = build_simulators()

    def normal_handler(event):
        write_event(event, is_attack=False)

    # All 4 assets keep producing real background traffic throughout,
    # exactly like a real company would, so the scenario's events
    # aren't sitting in an artificially empty log.
    for sim in sims.values():
        sim.start_normal_stream(on_event=normal_handler, interval_seconds=3.0)

    try:
        for step in scenario["steps"]:
            fire_step(sims, **step)
        print("\n=== Scenario complete. ===")
        time.sleep(2)  # let a little normal traffic continue around the scenario
    finally:
        for sim in sims.values():
            sim.stop_normal_stream()
        print("Stopped.")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in SCENARIOS:
        print("Usage: python run_attack_scenario.py <scenario_name>\n")
        print("Available scenarios:")
        for key, s in SCENARIOS.items():
            print(f"  {key}\n      {s['description']}\n")
        sys.exit(0)

    run_scenario(sys.argv[1])



"""ransomware_to_db → ENDPOINT, NETWORK, LOG
Ransomware bursts on END-02 (12 files encrypted)
2-second pause, then END-02 pivots to DB-01 over SMB/RDP/WinRM — a connection your own registry says should never happen
1.5-second pause, then DB-01 gets hit with queries returning 1M+ rows (normal is 1–100)"""

"""credential_to_cloud → LOG, CLOUD, NETWORK
Brute force on WEB-01 (10 failed logins)
Stolen creds used to self-escalate cloud privileges on CLOUD-01
Abused API key fires a burst of unusual calls from an anomalous location"""

"""insider_threat → ENDPOINT, NETWORK, LOG
Privilege escalation on END-03 (the DB admin's own machine — deliberate twist)
USB exfiltration burst from that same machine
A destructive DROP/TRUNCATE hits DB-01 — and this single event trips two signals at once: Network flags the source (never talks to DB-01), g flags the query type (destructive)"""