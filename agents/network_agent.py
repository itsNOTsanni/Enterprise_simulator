import argparse
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import List, Optional

from shared.storage.event_writer import read_events, DEFAULT_EVENT_LOG_PATH
from shared.utils.config_loader import load_registry


# ----------------------------------------------------------------------
# Thresholds -- grounded in the simulators' own real normal/attack
# ranges (checked directly in the source), not guesses.
# ----------------------------------------------------------------------

# Ports used ANYWHERE in this project's normal traffic (WEB-01: 443,
# DB-01: 5432). Anything else showing up as a destination_port is
# unusual by construction -- e.g. lateral_movement's SMB/RDP/WinRM/WMI
# (445/3389/5985/135) never appear in normal traffic.
KNOWN_NORMAL_PORTS = {443, 5432}

# DB rows_returned: normal is 1-100, attack (mass_data_exfiltration) is
# 50,000-2,000,000. This threshold sits comfortably between the two,
# with no overlap.
ROWS_RETURNED_THRESHOLD = 5_000

# Cloud bytes_transferred: normal is 10,000-5,000,000, attack
# (mass_data_exfiltration) is 500,000-20,000,000 -- these RANGES
# OVERLAP (500,000-5,000,000 could be either). A single threshold
# can't cleanly separate them alone, so this rule is deliberately
# lower-confidence than the others and is meant to be combined with
# external_source/topology_violation for a real verdict, not relied on
# by itself.
BYTES_TRANSFERRED_THRESHOLD = 6_000_000

# Endpoint file_size_bytes: normal ranges top out around 5-10MB
# depending on context; this sits above the typical normal ceiling.
FILE_SIZE_THRESHOLD = 8_000_000

FAILURE_BURST_THRESHOLD = 4     # 4+ failures in one session -> flag
FAN_OUT_THRESHOLD = 3           # 3+ distinct assets touched by one session -> flag
RATE_SPIKE_COUNT_THRESHOLD = 5  # 5+ events from one session ...
RATE_SPIKE_WINDOW_SECONDS = 30  # ... within this many seconds -> flag


class Flag:
    """One thing the Network Agent noticed. Not a verdict -- a lead."""

    def __init__(self, rule: str, confidence: str, summary: str, event_ids: List[str], asset_id: Optional[str] = None):
        self.rule = rule
        self.confidence = confidence  # "low" | "medium" | "high"
        self.summary = summary
        self.event_ids = event_ids
        self.asset_id = asset_id

    def to_dict(self) -> dict:
        return {
            "agent": "network",
            "rule": self.rule,
            "confidence": self.confidence,
            "summary": self.summary,
            "event_ids": self.event_ids,
            "asset_id": self.asset_id,
        }

    def __repr__(self) -> str:
        shown = ", ".join(self.event_ids[:3])
        more = f" (+{len(self.event_ids) - 3} more)" if len(self.event_ids) > 3 else ""
        return f"[{self.confidence.upper():6s}] {self.rule}: {self.summary} | events: {shown}{more}"


def _parse_timestamp(ts) -> datetime:
    """Events are stored with timestamps as strings (JSONL has no native datetime type)."""
    if isinstance(ts, datetime):
        return ts
    return datetime.fromisoformat(ts)


class NetworkAgent:
    """
    Analyzes a batch of raw event dicts (as produced by
    shared.storage.event_writer.read_events) purely through the
    network/timing lens, using the real company topology from
    config/asset_registry.yaml.
    """

    def __init__(self):
        registry = load_registry()
        self.internal_net = ip_network(registry["network"]["cidr"])

        self.ip_to_asset = {
            asset["ip_address"]: asset["asset_id"]
            for asset in registry.get("assets", [])
            if "ip_address" in asset
        }

        # An UNDIRECTED allowed-pair set built from communicates_with.
        # The registry isn't always listed symmetrically (e.g. END-04
        # lists WEB-01, but WEB-01 doesn't separately list END-04) --
        # a real network connection is bidirectional regardless of
        # which side's config happened to mention it, so either
        # direction being listed makes the pair allowed.
        self.allowed_pairs = set()
        for asset in registry.get("assets", []):
            for target in asset.get("communicates_with", []):
                self.allowed_pairs.add(frozenset({asset["asset_id"], target}))

    def _asset_for_ip(self, ip_str: Optional[str]) -> Optional[str]:
        return self.ip_to_asset.get(ip_str) if ip_str else None

    def _is_internal(self, ip_str: str) -> bool:
        try:
            return ip_address(ip_str) in self.internal_net
        except ValueError:
            return False

    def _group_by_session(self, events: List[dict]) -> dict:
        groups = defaultdict(list)
        for e in events:
            session_id = e.get("actor", {}).get("session_id")
            if session_id:
                groups[session_id].append(e)
        return groups

    # ------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------

    def analyze(self, events: List[dict]) -> List[Flag]:
        """Run every rule over a list of raw event dicts and return all flags raised."""
        flags: List[Flag] = []
        flags += self._check_external_source(events)
        flags += self._check_topology_violations(events)
        flags += self._check_unusual_ports(events)
        flags += self._check_repeated_failures(events)
        flags += self._check_fan_out(events)
        flags += self._check_rate_spike(events)
        flags += self._check_bulk_volume(events)
        return flags

    # ------------------------------------------------------------
    # Rule 1: external source
    # ------------------------------------------------------------

    def _check_external_source(self, events: List[dict]) -> List[Flag]:
        flags = []
        for e in events:
            source_ip = e.get("network", {}).get("source_ip")
            if source_ip and not self._is_internal(source_ip):
                flags.append(Flag(
                    rule="external_source",
                    confidence="medium",
                    summary=f"{e['source']['asset_id']} activity sourced from external IP {source_ip}",
                    event_ids=[e["event_id"]],
                    asset_id=e["source"]["asset_id"],
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 2: topology violation
    # ------------------------------------------------------------

    def _check_topology_violations(self, events: List[dict]) -> List[Flag]:
        flags = []
        for e in events:
            network = e.get("network", {})
            source_ip, destination_ip = network.get("source_ip"), network.get("destination_ip")
            if not source_ip or not destination_ip:
                continue

            source_asset = self._asset_for_ip(source_ip)
            destination_asset = self._asset_for_ip(destination_ip) or e.get("target", {}).get("asset_id")

            if not source_asset or not destination_asset or source_asset == destination_asset:
                continue

            pair = frozenset({source_asset, destination_asset})
            if pair not in self.allowed_pairs:
                flags.append(Flag(
                    rule="topology_violation",
                    confidence="high",
                    summary=(
                        f"{source_asset} connected to {destination_asset}, a pairing "
                        f"the asset registry never lists as allowed"
                    ),
                    event_ids=[e["event_id"]],
                    asset_id=destination_asset,
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 3: unusual destination port
    # ------------------------------------------------------------

    def _check_unusual_ports(self, events: List[dict]) -> List[Flag]:
        flags = []
        for e in events:
            port = e.get("network", {}).get("destination_port")
            if port is not None and port not in KNOWN_NORMAL_PORTS:
                flags.append(Flag(
                    rule="unusual_destination_port",
                    confidence="medium",
                    summary=f"Connection to port {port}, never used by normal traffic in this environment",
                    event_ids=[e["event_id"]],
                    asset_id=e["source"]["asset_id"],
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 4: repeated failures (brute force pattern)
    # ------------------------------------------------------------

    def _check_repeated_failures(self, events: List[dict]) -> List[Flag]:
        flags = []
        for session_id, group in self._group_by_session(events).items():
            failures = [e for e in group if e.get("event", {}).get("status") == "failure"]
            if len(failures) >= FAILURE_BURST_THRESHOLD:
                flags.append(Flag(
                    rule="repeated_failures",
                    confidence="high",
                    summary=f"{len(failures)} failed attempts in one session ({session_id})",
                    event_ids=[e["event_id"] for e in failures],
                    asset_id=failures[0]["source"]["asset_id"],
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 5: fan-out (lateral movement pattern)
    # ------------------------------------------------------------

    def _check_fan_out(self, events: List[dict]) -> List[Flag]:
        flags = []
        for session_id, group in self._group_by_session(events).items():
            source_assets = {e["source"]["asset_id"] for e in group}
            destinations = {
                e["target"]["asset_id"] for e in group
                if e.get("target", {}).get("asset_id")
            }
            distinct_external_targets = destinations - source_assets
            if len(distinct_external_targets) >= FAN_OUT_THRESHOLD:
                flags.append(Flag(
                    rule="fan_out",
                    confidence="high",
                    summary=(
                        f"One session reached {len(distinct_external_targets)} different "
                        f"assets ({', '.join(sorted(distinct_external_targets))}) -- {session_id}"
                    ),
                    event_ids=[e["event_id"] for e in group],
                    asset_id=group[0]["source"]["asset_id"],
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 6: rate spike
    # ------------------------------------------------------------

    def _check_rate_spike(self, events: List[dict]) -> List[Flag]:
        flags = []
        for session_id, group in self._group_by_session(events).items():
            if len(group) < RATE_SPIKE_COUNT_THRESHOLD:
                continue
            timestamps = sorted(_parse_timestamp(e["timestamp"]) for e in group)
            span_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
            if span_seconds <= RATE_SPIKE_WINDOW_SECONDS:
                flags.append(Flag(
                    rule="rate_spike",
                    confidence="medium",
                    summary=(
                        f"{len(group)} events from one session within "
                        f"{span_seconds:.1f}s ({session_id})"
                    ),
                    event_ids=[e["event_id"] for e in group],
                    asset_id=group[0]["source"]["asset_id"],
                ))
        return flags

    # ------------------------------------------------------------
    # Rule 7: bulk volume
    # ------------------------------------------------------------

    def _check_bulk_volume(self, events: List[dict]) -> List[Flag]:
        flags = []
        for e in events:
            data = e.get("data", {})

            rows = data.get("rows_returned")
            if rows and rows >= ROWS_RETURNED_THRESHOLD:
                flags.append(Flag(
                    rule="bulk_volume",
                    confidence="high",
                    summary=f"Query returned {rows:,} rows -- far above this environment's normal range",
                    event_ids=[e["event_id"]],
                    asset_id=e["source"]["asset_id"],
                ))

            bytes_transferred = data.get("bytes_transferred")
            if bytes_transferred and bytes_transferred >= BYTES_TRANSFERRED_THRESHOLD:
                flags.append(Flag(
                    rule="bulk_volume",
                    confidence="low",  # overlapping normal/attack ranges -- see threshold comment
                    summary=f"Transfer of {bytes_transferred:,} bytes -- above baseline, but this range overlaps normal traffic",
                    event_ids=[e["event_id"]],
                    asset_id=e["source"]["asset_id"],
                ))

            file_size = data.get("file_size_bytes")
            if file_size and file_size >= FILE_SIZE_THRESHOLD:
                flags.append(Flag(
                    rule="bulk_volume",
                    confidence="low",
                    summary=f"File transfer of {file_size:,} bytes -- above this environment's typical ceiling",
                    event_ids=[e["event_id"]],
                    asset_id=e["source"]["asset_id"],
                ))
        return flags


def run(path: Path = DEFAULT_EVENT_LOG_PATH) -> List[Flag]:
    events = list(read_events(path))
    agent = NetworkAgent()
    flags = agent.analyze(events)

    print(f"Network Agent: analyzed {len(events)} events from {path}")
    print(f"Raised {len(flags)} flag(s):\n")

    by_rule = defaultdict(int)
    for flag in flags:
        print(flag)
        by_rule[flag.rule] += 1

    if flags:
        print("\nSummary by rule:")
        for rule, count in sorted(by_rule.items(), key=lambda kv: -kv[1]):
            print(f"  {rule}: {count}")

    return flags


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Network Agent over a saved event log.")
    parser.add_argument(
        "--path", type=Path, default=DEFAULT_EVENT_LOG_PATH,
        help=f"Path to the event log (default: {DEFAULT_EVENT_LOG_PATH})",
    )
    args = parser.parse_args()
    run(args.path)



    """
agents/network_agent.py

Phase C, agent 1 of 4: the NETWORK AGENT.

This agent watches events from ALL FOUR asset simulators at once --
unlike a per-asset agent, it only looks at one dimension of every
event: the `network` block (source_ip, destination_ip,
destination_port, protocol) plus timing/session grouping from `actor`.
Every event, from any of the four simulators, already carries this
information, so this agent needs no new simulator data -- it's a
different LENS on the same events the Log/Cloud/Endpoint agents will
also read.

It reads from the shared event log (storage/events.jsonl) via
shared.storage.event_writer.read_events -- and ONLY that file. It
never reads storage/ground_truth.jsonl; that file exists purely for a
human to grade results afterward, not for any agent to consult.

The agent does not decide "this is an attack." It raises FLAGS: one
rule fired, on which event(s), with a confidence level. Turning flags
into a decision is the future Coordinator Agent's job (Phase D).

Detection rules implemented, each grounded in this project's actual
simulator data (see the threshold comments below for where each
number comes from):

    1. external_source        -- source_ip falls outside the
                                  registry's internal CIDR
    2. topology_violation      -- a source/destination asset pair that
                                  asset_registry.yaml's
                                  communicates_with never lists
    3. unusual_destination_port -- a port never used by any normal
                                  traffic in this project
    4. repeated_failures       -- several status=failure events from
                                  one session (brute force pattern)
    5. fan_out                 -- one session reaching several
                                  different assets (lateral movement)
    6. rate_spike              -- many events from one session
                                  clustered in a short time window
    7. bulk_volume             -- a rows_returned/bytes_transferred/
                                  file_size_bytes value far above this
                                  project's normal baseline

Usage:
    python -m agents.network_agent                       # analyze the full log
    python -m agents.network_agent --path some/other.jsonl
"""