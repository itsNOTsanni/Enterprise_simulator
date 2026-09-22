"""
agents/cloud_agent.py

Monitoring Layer: the CLOUD SECURITY AGENT (pattern-based).

Continuously watches the shared enterprise event log (storage/events.jsonl),
picks out events LOGGED BY the cloud environment (CLOUD-01), and flags
anything SUSPICIOUS -- without knowing the names of any attacks.

Instead of one rule per known attack, every cloud event is checked
against general behavioural PATTERNS that attacks break, whatever they
are called:

  Pattern                     Question asked of every event
  --------------------------  ----------------------------------------------
  security_weakening          Does this change reduce protection? (something
                              becomes public / open to the internet, a
                              protection is disabled or stopped, or someone
                              gains a highly privileged role)
  sensitive_change_*          Is someone changing identity / security /
                              storage configuration who the registry says is
                              not an admin -- or an admin from an unfamiliar
                              place?
  novelty                     Has this action / configuration value / resource
                              ever been seen before (globally, or for this
                              user)? Learned from observed normal traffic.
  activity_burst              Is one identity acting far faster than the whole
                              cloud normally produces events? (+ enumeration
                              when the burst sweeps many different actions)
  bulk_data_transfer          Is one identity moving far more data than the
                              largest normal transfers seen?
  unfamiliar_context          Unfamiliar source IP / identity not in the registry
                              (supporting evidence only)

Each pattern that fires adds to a SUSPICION SCORE. A flag is raised when
the score reaches FLAG_THRESHOLD; the flag lists every pattern that fired
and its evidence. No single weak signal (an unfamiliar IP, a first-time
action) can raise a flag on its own.

LEARNING "NORMAL":
  - The agent builds baselines while watching: which actions/resources
    each user uses, which configuration values occur, how fast the cloud
    event stream normally runs, how large normal transfers are.
  - Only events that were NOT judged suspicious update the baselines, so
    an attacker can't teach the agent that attacks are normal.
  - Novelty is scored only after a warm-up period (WARMUP_CLOUD_EVENTS).
  - With --from-end, the existing log is read silently first to learn
    the baseline, then only new events are reported.

Unchanged from the first version:
  - continuous monitoring (shared.storage.event_tailer), each event
    processed at most once, never crashes on bad input
  - flags keep the Network Agent's six keys (agent, rule, confidence,
    summary, event_ids, asset_id) plus extra fields
  - reads ONLY events.jsonl and the registry; never ground_truth.jsonl;
    never modifies the registry

Usage:
    python -m agents.cloud_agent                  # learn from the log, report as it goes, keep watching
    python -m agents.cloud_agent --from-end       # learn silently from the existing log, report new events only
    python -m agents.cloud_agent --once           # single pass over the log, then exit
"""

import argparse
import logging
import re
import signal
import statistics
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set

from shared.storage.event_tailer import EventTailer
from shared.storage.event_writer import DEFAULT_EVENT_LOG_PATH, STORAGE_DIR, _append_jsonl
from shared.utils.config_loader import load_registry

logger = logging.getLogger("cloud_agent")

DEFAULT_FLAG_LOG_PATH = STORAGE_DIR / "cloud_flags.jsonl"
RULE_NAME = "suspicious_cloud_activity"
CONFIDENCE_LEVELS = ["low", "medium", "high"]  # same scale as the Network Agent


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------
# HEURISTIC weights. Strong behavioural patterns score 3, so one of them
# alone reaches the threshold; weak signals (novelty, context) score 1-2,
# so they only matter in combination.
WEIGHTS = {
    "security_weakening": 3,
    "sensitive_change_by_non_admin": 3,
    "sensitive_change_by_unknown_identity": 3,
    "admin_change_from_unfamiliar_location": 2,
    "never_seen_action": 2,
    "never_seen_config_value": 2,
    "unusual_action_for_user": 1,
    "unusual_resource_for_user": 1,
    "activity_burst": 3,
    "enumeration": 1,
    "bulk_data_transfer": 3,
    "unfamiliar_location": 1,
    "unknown_identity": 2,
}
NOVELTY_CAP = 2          # novelty together counts at most 2 < FLAG_THRESHOLD: "new" alone is never enough
FLAG_THRESHOLD = 3       # score needed to raise a flag
MEDIUM_CONFIDENCE_AT = 5
HIGH_CONFIDENCE_AT = 7


# ----------------------------------------------------------------------
# Learning / behaviour parameters
# ----------------------------------------------------------------------
# Novelty is only scored after this many cloud events have been learned.
# SIMULATOR: the rarest normal action is ~7% of cloud events, so after 100
# events the chance a normal action is still unseen is < 0.1%. Novelty
# can never flag on its own anyway (max 2 < threshold 3 unless combined).
WARMUP_CLOUD_EVENTS = 100

# Burst: BURST_MIN_EVENTS events by one identity within
# BURST_SPAN_FACTOR x the median gap between cloud events.
# SIMULATOR: the normal stream emits one event every interval +/- 0.5 s
# (base_simulator.start_normal_stream), so consecutive normal events are
# at least ~0.75 x the median gap apart and 5 of them span >= ~3 median
# gaps. 5 events inside 1.5 median gaps therefore can't come from normal
# traffic at ANY stream speed. Adapts automatically to the cadence.
BURST_MIN_EVENTS = 5
BURST_SPAN_FACTOR = 1.5
BURST_CONTINUE_FACTOR = 0.5   # burst continues while events arrive < 0.5 x median gap apart
DEFAULT_MEDIAN_GAP_SECONDS = 0.5  # conservative until the real stream speed is learned (a normal
                                  # stream can't put 5 events of one user inside 0.75 s)
MIN_GAPS_FOR_ESTIMATE = 20
ENUMERATION_DISTINCT_ACTIONS = 3  # HEURISTIC

# Bulk transfer: bytes moved by one identity within the window, compared
# with what normal traffic actually moves. The limit is the larger of
#   BULK_FACTOR x the typical-large (95th percentile) normal transfer, and
#   BULK_WINDOW_FACTOR x the 95th percentile normal per-identity 60 s total
# so it adapts to how busy the stream is. Percentiles, not maxima, so one
# unusually large transfer can't quietly raise the bar for the next ones.
# HEURISTIC factors; defaults before learning match the simulator's
# largest normal object (5 MB).
BULK_WINDOW_SECONDS = 60
BULK_FACTOR = 5
DEFAULT_MAX_NORMAL_TRANSFER = 5_000_000
MIN_TRANSFERS_FOR_ESTIMATE = 50
DEFAULT_BULK_LIMIT_BEFORE_LEARNING = 50_000_000  # HEURISTIC: 10 x the largest normal object
BULK_WINDOW_FACTOR = 3
BULK_PERCENTILE = 0.95
VOLUME_LEARNING_CEILING = 0.5   # learn volume only when below half the current limit

MAX_SEEN_EVENT_IDS = 200_000


# ----------------------------------------------------------------------
# Generic security vocabulary (cloud-agnostic, not tied to any attack)
# ----------------------------------------------------------------------
READ_VERB_PREFIXES = ("Get", "List", "Describe", "Head", "Lookup", "Search", "Read", "View", "Check")
MUTATING_EVENT_ACTIONS = {"modify", "create", "delete", "update", "write", "disable", "remove"}
CONTROL_PLANE_RESOURCE_TYPES = {"identity_management", "security_configuration"}
STORAGE_CONFIG_NOUNS = ("Bucket", "Acl", "Policy", "PublicAccess", "Encryption", "Logging", "Versioning", "Lifecycle")

EXPOSURE_MARKERS = ("public", "0.0.0.0/0", "::/0", "allusers", "all_users", "everyone", "anonymous", "internet")
PRIVILEGED_TOKENS = {"admin", "administrator", "owner", "root", "superuser", "su", "fullaccess", "poweruser", "*"}
DISABLED_TOKENS = {"disabled", "disable", "off", "none", "false", "suspended", "stopped", "deleted", "removed", "inactive"}
ENABLED_TOKENS = {"enabled", "enable", "on", "true", "active", "running"}
WEAKENING_VERBS = ("Deactivate", "Disable", "Stop", "Delete", "Remove", "Detach", "Revoke", "Suspend")
PROTECTION_NOUNS = ("mfa", "log", "trail", "audit", "monitor", "alarm", "guard", "encrypt", "backup", "flowlog", "detector")

SENSITIVE_PORTS = {22, 23, 3389, 5432, 3306, 1433, 27017, 6379}


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _parse_timestamp(ts) -> Optional[datetime]:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if not isinstance(ts, str):
        return None
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _percentile(values, q: float) -> float:
    ordered = sorted(values)
    return ordered[min(int(q * len(ordered)), len(ordered) - 1)]


def _tokens(value) -> Set[str]:
    return {t for t in re.split(r"[^a-z0-9*]+", str(value or "").lower()) if t}


def _verb(api_action: str) -> str:
    return api_action.split(":", 1)[-1] if api_action else ""


def _is_mutation(api_action: str, event_action: str) -> bool:
    if event_action in MUTATING_EVENT_ACTIONS:
        return True
    verb = _verb(api_action)
    return bool(verb) and not verb.startswith(READ_VERB_PREFIXES) and verb not in ("StartSession", "Generate")


def _exposed_port(config_after: str) -> Optional[int]:
    tail = config_after.rsplit(":", 1)[-1] if ":" in config_after else ""
    return int(tail) if tail.isdigit() else None


# ----------------------------------------------------------------------
# Flag
# ----------------------------------------------------------------------

class CloudFlag:
    """
    One suspicious finding. Not a verdict -- a lead for the Coordinator.

    to_dict() starts with exactly the Network Agent's Flag keys
    (agent, rule, confidence, summary, event_ids, asset_id); everything
    after that is additional cloud context. `patterns` says WHY it is
    suspicious; there is no attack name.
    """

    def __init__(self, confidence, severity, score, patterns, summary, event_ids, asset_id,
                 timestamp, resource=None, user_id=None, source_ip=None, evidence=None,
                 correlation_key=None):
        self.rule = RULE_NAME
        self.confidence = confidence
        self.severity = severity
        self.score = score
        self.patterns = patterns
        self.summary = summary
        self.event_ids = event_ids
        self.asset_id = asset_id
        self.timestamp = timestamp
        self.detected_at = datetime.now(timezone.utc).isoformat()
        self.resource = resource
        self.user_id = user_id
        self.source_ip = source_ip
        self.evidence = evidence or {}
        self.correlation_key = correlation_key

    def to_dict(self) -> dict:
        return {
            # --- Network Agent-compatible core ---
            "agent": "cloud",
            "rule": self.rule,
            "confidence": self.confidence,
            "summary": self.summary,
            "event_ids": self.event_ids,
            "asset_id": self.asset_id,
            # --- cloud extensions ---
            "severity": self.severity,
            "score": self.score,
            "patterns": self.patterns,
            "timestamp": self.timestamp,
            "detected_at": self.detected_at,
            "resource": self.resource,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "evidence": self.evidence,
            "correlation_key": self.correlation_key,
        }

    def __repr__(self) -> str:
        shown = ", ".join(self.event_ids[:3])
        more = f" (+{len(self.event_ids) - 3} more)" if len(self.event_ids) > 3 else ""
        return (
            f"[{self.confidence.upper():6s}|{self.severity.upper():8s}|score {self.score:>2}] "
            f"{self.summary} | events: {shown}{more}"
        )


# ----------------------------------------------------------------------
# Baseline of normal behaviour (learned while watching)
# ----------------------------------------------------------------------

class _Baseline:
    def __init__(self):
        self.events_learned = 0
        self.actions: Set[str] = set()
        self.config_values: Set[str] = set()
        self.user_actions: Dict[str, Set[str]] = defaultdict(set)
        self.user_resources: Dict[str, Set[str]] = defaultdict(set)
        self.gaps: Deque[float] = deque(maxlen=500)
        self.transfer_sizes: Deque[float] = deque(maxlen=500)
        self.window_totals: Deque[float] = deque(maxlen=500)
        self.last_learned_time: Optional[datetime] = None

    @property
    def warmed_up(self) -> bool:
        return self.events_learned >= WARMUP_CLOUD_EVENTS

    def median_gap(self) -> float:
        if len(self.gaps) < MIN_GAPS_FOR_ESTIMATE:
            return DEFAULT_MEDIAN_GAP_SECONDS
        return max(statistics.median(self.gaps), 0.05)

    def max_normal_transfer(self) -> float:
        # Too few samples -> the largest one seen so far is not representative yet.
        if len(self.transfer_sizes) < MIN_TRANSFERS_FOR_ESTIMATE:
            return DEFAULT_MAX_NORMAL_TRANSFER
        return _percentile(self.transfer_sizes, BULK_PERCENTILE)

    def bulk_limit(self) -> float:
        if len(self.transfer_sizes) < MIN_TRANSFERS_FOR_ESTIMATE:
            return DEFAULT_BULK_LIMIT_BEFORE_LEARNING  # conservative until volume is learned
        limit = BULK_FACTOR * self.max_normal_transfer()
        if len(self.window_totals) >= MIN_TRANSFERS_FOR_ESTIMATE:
            limit = max(limit, BULK_WINDOW_FACTOR * _percentile(self.window_totals, BULK_PERCENTILE))
        return limit

    def learn(self, f: dict) -> None:
        self.events_learned += 1
        if f["api_action"]:
            self.actions.add(f["api_action"])
            self.user_actions[f["identity"]].add(f["api_action"])
        if f["resource"]:
            self.user_resources[f["identity"]].add(f["resource"])
        if f["config_after"]:
            self.config_values.add(f["config_after"].lower())
        # Volume is learned only while it is clearly within normal range, so
        # an attacker ramping up slowly can't drag the baseline up with them.
        if f["bytes"] > 0 and f.get("window_bytes", 0) <= VOLUME_LEARNING_CEILING * self.bulk_limit():
            self.transfer_sizes.append(f["bytes"])
            if f.get("window_bytes"):
                self.window_totals.append(f["window_bytes"])
        if f["when"] is not None:
            if self.last_learned_time is not None:
                gap = (f["when"] - self.last_learned_time).total_seconds()
                if gap > 0:
                    self.gaps.append(gap)
            self.last_learned_time = f["when"]


# ----------------------------------------------------------------------
# Agent
# ----------------------------------------------------------------------

class CloudAgent:
    """
    process_event(event, report=True) -> list of CloudFlag   (streaming entry point)
    analyze(events)                   -> list of CloudFlag   (batch convenience)
    """

    def __init__(self, registry: Optional[dict] = None):
        registry = registry if registry is not None else load_registry()

        self.internal_net = ip_network(registry["network"]["cidr"])
        assets = {a["asset_id"]: a for a in registry.get("assets", [])}
        self.cloud_asset_ids = {aid for aid, a in assets.items() if a.get("asset_type") == "cloud_environment"}
        self.resource_types = {
            r["resource_id"]: r.get("resource_type") for r in registry.get("cloud_resources", []) or []
        }
        profiles = registry.get("access_profiles", {}) or {}
        self.identities: Dict[str, dict] = {}
        for emp in registry.get("employees", []):
            profile = profiles.get(emp.get("access_profile"), {}) or {}
            self.identities[emp["employee_id"]] = {
                "workstation_ip": assets.get(emp.get("workstation_id"), {}).get("ip_address"),
                "privileged": bool(profile.get("privileged", False)),
            }

        self.baseline = _Baseline()
        self._seen_ids: Set[str] = set()
        self._seen_order: Deque[str] = deque()
        self._recent: Dict[str, Deque[dict]] = defaultdict(deque)  # identity -> recent events
        self._burst_active: Dict[str, bool] = {}
        self._burst_key: Dict[str, str] = {}
        self._burst_members: Dict[str, List[dict]] = {}
        self._burst_counter = 0
        self.stats = defaultdict(int)

    # ------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------

    def analyze(self, events: List[dict]) -> List[CloudFlag]:
        flags: List[CloudFlag] = []
        for event in events:
            flags += self.process_event(event)
        return flags

    def process_event(self, event: Any, report: bool = True) -> List[CloudFlag]:
        """
        Analyse ONE event. Never raises, never processes an event twice.
        report=False scores and learns silently (used to bootstrap the
        baseline from an existing log).
        """
        if not self._is_well_formed(event):
            self.stats["malformed"] += 1
            return []
        event_id = event["event_id"]
        if event_id in self._seen_ids:
            self.stats["duplicates_skipped"] += 1
            return []
        self._remember(event_id)
        self.stats["events_seen"] += 1

        if not self._is_cloud_event(event):
            self.stats["non_cloud_ignored"] += 1
            return []
        self.stats["cloud_events_analyzed"] += 1

        try:
            features = self._extract(event)
            signals = self._score(features)
            score = self._total(signals)
            suspicious = score >= FLAG_THRESHOLD or features["in_burst"]
            if not suspicious:
                self.baseline.learn(features)
            if not suspicious or not report:
                return []
            flag = self._make_flag(event, features, signals, score)
        except Exception:  # one odd event must never stop monitoring
            logger.exception("Error analysing event %s; skipping it.", event_id)
            self.stats["errors"] += 1
            return []

        self.stats["flags_raised"] += 1
        return [flag]

    # ------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------

    @staticmethod
    def _is_well_formed(event: Any) -> bool:
        if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
            return False
        for block in ("source", "event"):
            if not isinstance(event.get(block), dict):
                return False
        for block in ("network", "actor", "target", "data"):
            if event.get(block) is not None and not isinstance(event.get(block), dict):
                return False
        return True

    def _remember(self, event_id: str) -> None:
        self._seen_ids.add(event_id)
        self._seen_order.append(event_id)
        if len(self._seen_order) > MAX_SEEN_EVENT_IDS:
            self._seen_ids.discard(self._seen_order.popleft())

    def _is_cloud_event(self, event: dict) -> bool:
        """Logged BY the cloud. Endpoint events connecting TO CLOUD-01 are other agents' concern."""
        source = event["source"]
        return source.get("asset_type") == "cloud_environment" or source.get("asset_id") in self.cloud_asset_ids

    # ------------------------------------------------------------
    # Feature extraction -- only fields every cloud event carries
    # ------------------------------------------------------------

    def _extract(self, event: dict) -> dict:
        data = event.get("data") or {}
        target = event.get("target") or {}
        actor = event.get("actor") or {}
        network = event.get("network") or {}

        user_id = actor.get("user_id")
        source_ip = network.get("source_ip")
        identity_info = self.identities.get(user_id)
        api_key_id = data.get("api_key_id")
        identity = user_id or (f"key:{api_key_id}" if api_key_id else None) or f"ip:{source_ip}"

        location = "unknown"
        if source_ip:
            try:
                internal = ip_address(str(source_ip)) in self.internal_net
            except ValueError:
                internal = False
            if identity_info and str(source_ip) == identity_info["workstation_ip"]:
                location = "registered_workstation"
            else:
                location = "other_internal_host" if internal else "external"

        resource = target.get("resource")
        bytes_moved = data.get("bytes_transferred") or 0
        return {
            "event_id": event["event_id"],
            "identity": identity,
            "user_id": user_id,
            "known_user": identity_info is not None,
            "privileged": bool(identity_info and identity_info["privileged"]),
            "source_ip": str(source_ip) if source_ip else None,
            "location": location,
            "when": _parse_timestamp(event.get("timestamp")),
            "api_action": str(data.get("api_action") or ""),
            "event_action": str(event["event"].get("action") or "").lower(),
            "event_type": event["event"].get("type"),
            "resource": resource,
            "resource_type": target.get("resource_type") or self.resource_types.get(resource),
            "config_before": str(data["config_before"]) if data.get("config_before") is not None else "",
            "config_after": str(data["config_after"]) if data.get("config_after") is not None else "",
            "bytes": bytes_moved if isinstance(bytes_moved, (int, float)) and bytes_moved > 0 else 0,
            "api_key_id": api_key_id,
            "in_burst": False,
        }

    # ------------------------------------------------------------
    # Patterns
    # ------------------------------------------------------------

    def _score(self, f: dict) -> Dict[str, dict]:
        signals: Dict[str, dict] = {}
        signals.update(self._pattern_security_weakening(f))
        signals.update(self._pattern_sensitive_change(f))
        signals.update(self._pattern_novelty(f))
        signals.update(self._pattern_behaviour(f))
        signals.update(self._pattern_context(f))
        return signals

    @staticmethod
    def _total(signals: Dict[str, dict]) -> int:
        novelty = sum(WEIGHTS[n] for n in signals if n in
                      ("never_seen_action", "never_seen_config_value", "unusual_action_for_user", "unusual_resource_for_user"))
        other = sum(WEIGHTS[n] for n in signals if n not in
                    ("never_seen_action", "never_seen_config_value", "unusual_action_for_user", "unusual_resource_for_user"))
        return other + min(novelty, NOVELTY_CAP)

    def _pattern_security_weakening(self, f: dict) -> Dict[str, dict]:
        """A change that leaves the environment LESS protected, whatever API did it."""
        before, after = f["config_before"].lower(), f["config_after"].lower()
        before_t, after_t = _tokens(before), _tokens(after)
        reasons = []

        if after and any(m in after for m in EXPOSURE_MARKERS) and not any(m in before for m in EXPOSURE_MARKERS):
            port = _exposed_port(after)
            reasons.append(f"exposed to the internet/public ({f['config_before']} -> {f['config_after']})"
                           + (f", sensitive port {port}" if port in SENSITIVE_PORTS else ""))
        if (after_t & DISABLED_TOKENS) and not (before_t & DISABLED_TOKENS):
            reasons.append(f"protection disabled ({f['config_before']} -> {f['config_after']})")
        if (after_t & PRIVILEGED_TOKENS) and not (before_t & PRIVILEGED_TOKENS):
            reasons.append(f"privilege gained ({f['config_before'] or '?'} -> {f['config_after']})")

        verb = _verb(f["api_action"])
        action_l = f["api_action"].lower()
        if verb.startswith(WEAKENING_VERBS) and any(n in action_l for n in PROTECTION_NOUNS):
            reasons.append(f"security control turned off via {f['api_action']}")

        if not reasons:
            return {}
        port = _exposed_port(after)
        critical = any("exposed" in r for r in reasons) or port in SENSITIVE_PORTS
        return {"security_weakening": {"reasons": reasons, "critical": critical}}

    def _pattern_sensitive_change(self, f: dict) -> Dict[str, dict]:
        """A mutation of identity / security / storage configuration, judged by who and from where."""
        if not _is_mutation(f["api_action"], f["event_action"]):
            return {}
        control_plane = f["resource_type"] in CONTROL_PLANE_RESOURCE_TYPES or (
            f["resource_type"] == "object_storage" and any(n in _verb(f["api_action"]) for n in STORAGE_CONFIG_NOUNS)
        )
        if not control_plane:
            return {}
        detail = {"api_action": f["api_action"], "resource": f["resource"], "resource_type": f["resource_type"]}
        if not f["known_user"]:
            return {"sensitive_change_by_unknown_identity": detail}
        if not f["privileged"]:
            return {"sensitive_change_by_non_admin": detail}
        if f["location"] != "registered_workstation":
            return {"admin_change_from_unfamiliar_location": {**detail, "location": f["location"]}}
        return {}

    def _pattern_novelty(self, f: dict) -> Dict[str, dict]:
        """Things never observed during normal operation (after warm-up)."""
        b = self.baseline
        if not b.warmed_up:
            return {}
        signals = {}
        action = f["api_action"]
        if action and action not in b.actions:
            signals["never_seen_action"] = {"api_action": action}
        elif action and action not in b.user_actions.get(f["identity"], set()):
            signals["unusual_action_for_user"] = {"api_action": action}
        if f["config_after"] and f["config_after"].lower() not in b.config_values:
            signals["never_seen_config_value"] = {"config_after": f["config_after"]}
        if f["resource"] and f["resource"] not in b.user_resources.get(f["identity"], set()):
            signals["unusual_resource_for_user"] = {"resource": f["resource"]}
        return signals

    def _pattern_behaviour(self, f: dict) -> Dict[str, dict]:
        """Rate and volume per identity, relative to the learned stream speed and transfer sizes."""
        if f["when"] is None:
            return {}
        signals = {}
        key = f["identity"]
        recent = self._recent[key]
        gap = self.baseline.median_gap()

        # an ongoing burst ends once the identity slows back down
        if recent and self._burst_active.get(key):
            if (f["when"] - recent[-1]["when"]).total_seconds() > BURST_CONTINUE_FACTOR * gap:
                self._burst_active[key] = False
                recent.clear()

        recent.append({"when": f["when"], "event_id": f["event_id"], "action": f["api_action"], "bytes": f["bytes"]})
        horizon = f["when"] - timedelta(seconds=max(BULK_WINDOW_SECONDS, BURST_SPAN_FACTOR * gap * 4))
        while recent and recent[0]["when"] < horizon:
            recent.popleft()

        # --- activity burst ---
        last_n = list(recent)[-BURST_MIN_EVENTS:]
        started = False
        if self._burst_active.get(key):
            self._burst_members[key].append(recent[-1])
        elif len(last_n) >= BURST_MIN_EVENTS and \
                (last_n[-1]["when"] - last_n[0]["when"]).total_seconds() <= BURST_SPAN_FACTOR * gap:
            self._burst_active[key] = True
            self._burst_counter += 1
            self._burst_key[key] = f"{key}#burst{self._burst_counter}"
            self._burst_members[key] = list(last_n)
            started = True

        if self._burst_active.get(key):
            f["in_burst"] = True
            members = self._burst_members[key]
            actions = sorted({m["action"] for m in members if m["action"]})
            signals["activity_burst"] = {
                "events_in_burst": len(members),
                "normal_median_gap_seconds": round(gap, 2),
                "burst_started": started,
                # the flag that STARTS a burst covers every event in it so far;
                # later flags cover just their own event
                "burst_event_ids": [m["event_id"] for m in members] if started else [f["event_id"]],
                "correlation_key": self._burst_key[key],
            }
            if len(actions) >= ENUMERATION_DISTINCT_ACTIONS:
                signals["enumeration"] = {"distinct_actions": actions}

        # --- bulk data transfer ---
        cutoff = f["when"] - timedelta(seconds=BULK_WINDOW_SECONDS)
        window_bytes = sum(r["bytes"] for r in recent if r["when"] >= cutoff)
        f["window_bytes"] = window_bytes
        limit = self.baseline.bulk_limit()
        if f["bytes"] > 0 and window_bytes >= limit:
            signals["bulk_data_transfer"] = {
                "bytes_in_window": int(window_bytes),
                "window_seconds": BULK_WINDOW_SECONDS,
                "limit_bytes": int(limit),
            }
            for r in recent:  # reported: don't let these bytes re-trigger on later events
                r["bytes"] = 0
        return signals

    def _pattern_context(self, f: dict) -> Dict[str, dict]:
        """Supporting evidence only (weights too small to flag alone)."""
        if not f["known_user"] and f["user_id"]:
            return {"unknown_identity": {"user_id": f["user_id"]}}
        if f["location"] in ("external", "other_internal_host"):
            return {"unfamiliar_location": {"source_ip": f["source_ip"], "location": f["location"]}}
        return {}

    # ------------------------------------------------------------
    # Flag construction
    # ------------------------------------------------------------

    def _make_flag(self, event: dict, f: dict, signals: Dict[str, dict], score: int) -> CloudFlag:
        if score >= HIGH_CONFIDENCE_AT:
            confidence = "high"
        elif score >= MEDIUM_CONFIDENCE_AT:
            confidence = "medium"
        else:
            confidence = "low"

        weakening = signals.get("security_weakening")
        if weakening and weakening["critical"]:
            severity = "critical"
        elif weakening or "bulk_data_transfer" in signals or any(k.startswith("sensitive_change") for k in signals):
            severity = "high"
        else:
            severity = "medium"

        patterns = sorted(signals, key=lambda n: -WEIGHTS[n])
        burst = signals.get("activity_burst")
        event_ids = burst["burst_event_ids"] if burst else [f["event_id"]]
        who = f["user_id"] or f["identity"]
        headline = []
        if weakening:
            headline.append("; ".join(weakening["reasons"]))
        if burst:
            headline.append(f"burst of {burst['events_in_burst']} events (normal gap ~{burst['normal_median_gap_seconds']}s)")
        if "bulk_data_transfer" in signals:
            headline.append(f"{signals['bulk_data_transfer']['bytes_in_window']:,} bytes moved in {BULK_WINDOW_SECONDS}s")
        others = [p for p in patterns if p not in ("security_weakening", "activity_burst", "bulk_data_transfer")]
        summary = f"{who} via {f['api_action'] or f['event_type']} on {f['resource']}: " + " | ".join(
            headline + ([", ".join(others)] if others else [])
        )

        return CloudFlag(
            confidence=confidence,
            severity=severity,
            score=score,
            patterns=patterns,
            summary=summary,
            event_ids=event_ids,
            asset_id=(event.get("target") or {}).get("asset_id") or event["source"].get("asset_id"),
            timestamp=str(event.get("timestamp")),
            resource=f["resource"],
            user_id=f["user_id"],
            source_ip=f["source_ip"],
            evidence={
                "api_action": f["api_action"],
                "event_type": f["event_type"],
                "config_before": f["config_before"] or None,
                "config_after": f["config_after"] or None,
                "caller_location": f["location"],
                "caller_privileged": f["privileged"],
                "signals": signals,
            },
            correlation_key=burst["correlation_key"] if burst else None,
        )


# ----------------------------------------------------------------------
# Continuous runner
# ----------------------------------------------------------------------

def run(
    path: Path = DEFAULT_EVENT_LOG_PATH,
    output_path: Optional[Path] = DEFAULT_FLAG_LOG_PATH,
    from_end: bool = False,
    once: bool = False,
    poll_interval: float = 1.0,
    stop_event: Optional[threading.Event] = None,
    agent: Optional[CloudAgent] = None,
) -> CloudAgent:
    """Watch the event log, analyse each new event, keep running after flags."""
    agent = agent or CloudAgent()
    tailer = EventTailer(path)

    def handle(record: dict) -> None:
        for flag in agent.process_event(record):
            print(flag, flush=True)
            if output_path is not None:
                _append_jsonl(Path(output_path), flag.to_dict())

    print(f"Cloud Agent (pattern-based): monitoring {path}")
    if from_end:
        learned = 0
        for record in tailer.poll():  # silent pass: learn the baseline from history
            agent.process_event(record, report=False)
            learned += 1
        print(f"Learned baseline from {learned} existing events "
              f"({agent.baseline.events_learned} normal cloud events); reporting new events only.")
    if output_path is not None:
        print(f"Flags are also written to {output_path}")
    if not agent.baseline.warmed_up:
        print(f"Warm-up: novelty checks start after {WARMUP_CLOUD_EVENTS} normal cloud events "
              f"(other patterns are active immediately).")
    print("" if once else "Press Ctrl+C to stop.\n", end="", flush=True)

    try:
        if once:
            for record in tailer.poll():
                handle(record)
        else:
            for record in tailer.follow(poll_interval=poll_interval, stop_event=stop_event):
                handle(record)
    except KeyboardInterrupt:
        pass
    finally:
        stats = dict(agent.stats)
        stats["malformed_lines"] = tailer.malformed_lines
        stats["baseline_events"] = agent.baseline.events_learned
        print(f"\nCloud Agent stopped. Stats: {stats}")
    return agent


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    def _graceful_stop(_signum, _frame):
        raise KeyboardInterrupt  # handled in run(): prints stats and exits cleanly

    signal.signal(signal.SIGTERM, _graceful_stop)  # e.g. `docker stop`

    parser = argparse.ArgumentParser(description="Run the Cloud Security Agent (pattern-based, continuous).")
    parser.add_argument("--path", type=Path, default=DEFAULT_EVENT_LOG_PATH, help="Event log to watch")
    parser.add_argument("--output", type=Path, default=DEFAULT_FLAG_LOG_PATH, help="Where to append flags (JSONL)")
    parser.add_argument("--no-output", action="store_true", help="Print flags only; don't write a flag file")
    parser.add_argument("--from-end", action="store_true",
                        help="Learn silently from the existing log, then report new events only")
    parser.add_argument("--once", action="store_true", help="Single pass over the log, then exit")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between checks for new events")
    args = parser.parse_args()
    run(args.path, None if args.no_output else args.output, args.from_end, args.once, args.poll_interval)
