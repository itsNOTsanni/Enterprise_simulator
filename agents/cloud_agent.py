"""
agents/cloud_agent.py

Monitoring Layer: the CLOUD SECURITY AGENT.

Watches the shared enterprise event log (storage/events.jsonl) that all
four simulators write to, picks out the events produced by the cloud
environment (CLOUD-01), and raises structured FLAGS when cloud activity
looks suspicious. Like the Network Agent, it never decides "this is an
incident" -- it produces leads for the future Coordinator Agent.

Differences from agents/network_agent.py (which is left untouched):
  - CONTINUOUS: it tails the log (shared.storage.event_tailer) and keeps
    running after raising flags, instead of reading once and exiting.
  - Each event is processed at most once (bounded event_id memory).
  - Flags carry the Network Agent's six keys unchanged (agent, rule,
    confidence, summary, event_ids, asset_id) PLUS extra fields
    (severity, timestamps, evidence, correlation_key, ...), so the
    Coordinator can read both agents' flags the same way.

It reads ONLY storage/events.jsonl and config/asset_registry.yaml.
It never reads storage/ground_truth.jsonl.

Detection rules (details and threshold sources are next to each rule):
  1. iam_privilege_escalation         role change INTO admin/owner
  2. mfa_disablement                  MFA device deactivated
  3. public_bucket_exposure           storage ACL changed to public
  4. security_group_misconfiguration  ingress opened to 0.0.0.0/0 (or ::/0)
  5. mass_data_exfiltration           rapid burst of object reads, or bulk bytes, by one user
  6. api_key_abuse                    reconnaissance/secrets API calls, and
                                      bursts of them from one API key

Supporting evidence (never a flag on its own):
  - unfamiliar caller location: source_ip is not the caller's registered
    workstation (external, or another internal host)
  - caller not privileged per the registry's access profiles
  - caller not found in the registry at all
These raise a flag's confidence; they do not create flags.

Usage:
    python -m agents.cloud_agent                  # catch up on the log, then keep watching
    python -m agents.cloud_agent --from-end       # ignore existing events, watch new ones only
    python -m agents.cloud_agent --once           # single pass over the log, then exit
"""

import argparse
import logging
import signal
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from shared.storage.event_tailer import EventTailer
from shared.storage.event_writer import DEFAULT_EVENT_LOG_PATH, STORAGE_DIR, _append_jsonl
from shared.utils.config_loader import load_registry

logger = logging.getLogger("cloud_agent")

DEFAULT_FLAG_LOG_PATH = STORAGE_DIR / "cloud_flags.jsonl"

CONFIDENCE_LEVELS = ["low", "medium", "high"]  # same scale as the Network Agent


# ----------------------------------------------------------------------
# Rule vocabulary and thresholds
#
# Each value says where it comes from. "SIMULATOR" = read directly from
# simulator/cloud/cloud_simulator.py. "HEURISTIC" = a judgement call the
# simulator doesn't pin down; kept conservative and documented.
# ----------------------------------------------------------------------

# Role ladder used to decide whether a role change is an escalation.
# SIMULATOR: normal changes are employee->manager and contractor->employee
# (ROLE_LEVELS_NORMAL); escalations end in admin or owner
# (ROLE_LEVELS_ESCALATION). HEURISTIC: the ordering itself.
ROLE_RANK = {"contractor": 0, "employee": 1, "manager": 2, "admin": 3, "owner": 4}
PRIVILEGED_ROLE_RANK = ROLE_RANK["admin"]

# SIMULATOR: the only API actions that change IAM / storage / security config.
ROLE_CHANGE_ACTIONS = {"iam:UpdateRole"}
MFA_DISABLE_ACTIONS = {"iam:DeactivateMFADevice"}
BUCKET_ACL_WRITE_ACTIONS = {"s3:PutBucketAcl", "s3:PutBucketPolicy"}  # PutBucketPolicy: HEURISTIC extra
SG_INGRESS_ACTIONS = {"ec2:AuthorizeSecurityGroupIngress"}
OPEN_TO_WORLD_CIDRS = ("0.0.0.0/0", "::/0")

# HEURISTIC: ports that are high-impact when exposed to the internet
# (remote admin + this enterprise's own DB port 5432 from the registry).
SENSITIVE_PORTS = {22, 3389, 5432, 3306, 1433}

# SIMULATOR: normal cloud_api_call actions are exactly these
# (API_ACTIONS_NORMAL). Anything else via cloud_api_call is off-baseline.
NORMAL_API_ACTIONS = {"reports:Generate", "orders:List", "profile:Get"}

# SIMULATOR + HEURISTIC: the abuse pool is iam:ListUsers, iam:ListRoles,
# s3:ListBuckets, ec2:DescribeInstances, secretsmanager:ListSecrets.
# Generalised to the enumeration/secrets families those belong to.
RECON_ACTION_PREFIXES = (
    "iam:List", "s3:List", "ec2:Describe", "secretsmanager:", "kms:List", "sts:GetCallerIdentity",
)

# Mass data exfiltration: per-user sliding windows over s3:GetObject reads.
# SIMULATOR: attack bursts are 5-20 reads (BURST_ATTACK_RANGES) spaced
#   ~0.15 s apart (trigger_attack's burst_delay_seconds), i.e. 5 reads in
#   under a second; each read is 0.5-20 MB. A normal read is a single
#   object of 10 KB-5 MB.
# Baseline: a normal event is 1 of 7 types, storage access reads half the
#   time and there are 4 users, so ~1/56 of cloud events is a GetObject by
#   a given user -- about one every ~2 minutes at the 2 s stream cadence.
#   Measured against 1,500-event normal runs, "5 reads in 60 s" still
#   happens by chance occasionally, so the COUNT rule uses a short burst
#   window instead:
EXFIL_WINDOW_SECONDS = 60                 # volume window, and burst "episode" length
EXFIL_BURST_WINDOW_SECONDS = 10           # HEURISTIC: burst window for the count rule
EXFIL_READ_COUNT_THRESHOLD = 5            # SIMULATOR: smallest attack burst
EXFIL_BYTES_THRESHOLD = 25_000_000        # HEURISTIC: 5 x the largest normal single read (5 MB), per 60 s

# API key abuse burst: per-api_key_id sliding window over off-baseline calls.
# SIMULATOR: attack bursts are 5-15 calls cycling through 5 distinct recon
# actions with one api_key_id. HEURISTIC: 3 distinct recon actions within
# 60 s is flagged as enumeration (below the 5-call minimum, so every
# simulated burst crosses it, while one-off lookups don't).
API_BURST_WINDOW_SECONDS = 60
API_BURST_DISTINCT_ACTIONS_THRESHOLD = 3

# Memory bound for "already processed" event IDs.
MAX_SEEN_EVENT_IDS = 200_000


# ----------------------------------------------------------------------
# Flag
# ----------------------------------------------------------------------

class CloudFlag:
    """
    One thing the Cloud Agent noticed. Not a verdict -- a lead.

    to_dict() starts with exactly the Network Agent's Flag keys
    (agent, rule, confidence, summary, event_ids, asset_id) so the
    Coordinator can treat both uniformly; everything after that is
    additional cloud context.
    """

    def __init__(
        self,
        rule: str,
        confidence: str,
        severity: str,
        summary: str,
        event_ids: List[str],
        asset_id: Optional[str],
        timestamp: Optional[str],
        resource: Optional[str] = None,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        correlation_key: Optional[str] = None,
    ):
        self.rule = rule
        self.confidence = confidence
        self.severity = severity
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
            f"[{self.confidence.upper():6s}|{self.severity.upper():8s}] {self.rule}: "
            f"{self.summary} | events: {shown}{more}"
        )


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


def _bump(confidence: str, steps: int = 1) -> str:
    index = min(CONFIDENCE_LEVELS.index(confidence) + steps, len(CONFIDENCE_LEVELS) - 1)
    return CONFIDENCE_LEVELS[index]


def _is_recon_action(api_action: str) -> bool:
    return api_action.startswith(RECON_ACTION_PREFIXES)


def _parse_exposed_port(config_after: str) -> Optional[int]:
    """'0.0.0.0/0:22' -> 22. Returns None if no port is present."""
    tail = config_after.rsplit(":", 1)[-1] if ":" in config_after else ""
    return int(tail) if tail.isdigit() else None


class _BurstTracker:
    """
    Sliding window of events per key (user, API key...), in EVENT time.

    add() returns:
      "crossed"   -- this event pushed the window over the threshold
                     (emit one flag covering the whole window)
      "continued" -- threshold already crossed in this burst and the
                     burst is still going (emit a short follow-up flag)
      None        -- below threshold
    A burst "episode" ends when the key goes quiet for episode_gap_seconds
    (defaults to the window), so ordinary activity after a burst is not
    mislabelled as a continuation of it.
    """

    def __init__(self, window_seconds: int, episode_gap_seconds: Optional[int] = None):
        self.window = timedelta(seconds=window_seconds)
        self.episode_gap = timedelta(seconds=episode_gap_seconds or window_seconds)
        self.items: Dict[str, Deque[dict]] = defaultdict(deque)
        self.in_episode: Dict[str, bool] = {}
        self.episode_ids: Dict[str, str] = {}
        self.episode_counter = 0

    def add(self, key: str, when: datetime, item: dict, is_over_threshold) -> Optional[str]:
        window = self.items[key]
        if window and when - window[-1]["when"] > self.episode_gap and self.in_episode.get(key):
            # Quiet period -> the burst is over. It has already been
            # reported, so drop its events; otherwise they would stay in
            # the window and re-trigger the rule on the next normal event.
            self.in_episode[key] = False
            window.clear()
        window.append({"when": when, **item})
        while window and when - window[0]["when"] > self.window:
            window.popleft()

        if self.in_episode.get(key):
            return "continued"
        if is_over_threshold(list(window)):
            self.in_episode[key] = True
            self.episode_counter += 1
            self.episode_ids[key] = f"{key}#{self.episode_counter}"
            return "crossed"
        return None

    def window_items(self, key: str) -> List[dict]:
        return list(self.items[key])


# ----------------------------------------------------------------------
# Agent
# ----------------------------------------------------------------------

class CloudAgent:
    """
    Analyses raw event dicts (as stored in events.jsonl) one at a time.

    process_event(event) -> list of CloudFlag   (streaming entry point)
    analyze(events)      -> list of CloudFlag   (batch convenience, like NetworkAgent.analyze)
    """

    def __init__(self, registry: Optional[dict] = None):
        registry = registry if registry is not None else load_registry()

        self.internal_net = ip_network(registry["network"]["cidr"])
        assets = {a["asset_id"]: a for a in registry.get("assets", [])}
        self.cloud_asset_ids = {
            aid for aid, a in assets.items() if a.get("asset_type") == "cloud_environment"
        }
        profiles = registry.get("access_profiles", {}) or {}

        # user_id -> what the registry says about that person
        self.identities: Dict[str, dict] = {}
        for emp in registry.get("employees", []):
            workstation = assets.get(emp.get("workstation_id"), {})
            profile = profiles.get(emp.get("access_profile"), {}) or {}
            self.identities[emp["employee_id"]] = {
                "username": emp.get("username"),
                "workstation_ip": workstation.get("ip_address"),
                "privileged": bool(profile.get("privileged", False)),
                "role": emp.get("role"),
            }

        self._seen_ids: set = set()
        self._seen_order: Deque[str] = deque()
        self.stats = defaultdict(int)

        self._exfil = _BurstTracker(EXFIL_WINDOW_SECONDS, episode_gap_seconds=EXFIL_BURST_WINDOW_SECONDS)
        self._api_keys = _BurstTracker(API_BURST_WINDOW_SECONDS)

    # ------------------------------------------------------------
    # Entry points
    # ------------------------------------------------------------

    def analyze(self, events: List[dict]) -> List[CloudFlag]:
        flags: List[CloudFlag] = []
        for event in events:
            flags += self.process_event(event)
        return flags

    def process_event(self, event: Any) -> List[CloudFlag]:
        """Analyse ONE event. Safe on any input: never raises, never double-processes."""
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
            ctx = self._caller_context(event)
            flags: List[CloudFlag] = []
            for rule in (
                self._rule_iam_privilege_escalation,
                self._rule_mfa_disablement,
                self._rule_public_bucket_exposure,
                self._rule_security_group_misconfiguration,
                self._rule_mass_data_exfiltration,
                self._rule_api_key_abuse,
            ):
                flags += rule(event, ctx)
        except Exception:  # defensive: one odd event must never stop monitoring
            logger.exception("Error analysing event %s; skipping it.", event_id)
            self.stats["errors"] += 1
            return []

        self.stats["flags_raised"] += len(flags)
        return flags

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
        """
        A cloud event is one LOGGED BY the cloud environment. Endpoint
        events that merely connect TO CLOUD-01 are the Endpoint/Network
        agents' concern and are ignored here.
        """
        source = event["source"]
        return (
            source.get("asset_type") == "cloud_environment"
            or source.get("asset_id") in self.cloud_asset_ids
        )

    def _caller_context(self, event: dict) -> dict:
        """Who made this cloud call and from where, checked against the registry."""
        user_id = (event.get("actor") or {}).get("user_id")
        source_ip = (event.get("network") or {}).get("source_ip")
        identity = self.identities.get(user_id)

        location = "unknown"
        if source_ip:
            try:
                is_internal = ip_address(str(source_ip)) in self.internal_net
            except ValueError:
                is_internal = False
            if identity and str(source_ip) == identity["workstation_ip"]:
                location = "registered_workstation"
            elif is_internal:
                location = "other_internal_host"
            else:
                location = "external"

        return {
            "user_id": user_id,
            "source_ip": str(source_ip) if source_ip else None,
            "known_user": identity is not None,
            "privileged": bool(identity and identity["privileged"]),
            "caller_location": location,
            "unfamiliar_location": location in ("external", "other_internal_host"),
            "when": _parse_timestamp(event.get("timestamp")),
        }

    def _supporting_signals(self, ctx: dict, needs_privilege: bool) -> List[str]:
        signals = []
        if ctx["unfamiliar_location"]:
            signals.append(f"caller_location={ctx['caller_location']}")
        if not ctx["known_user"]:
            signals.append("caller_not_in_registry")
        elif needs_privilege and not ctx["privileged"]:
            signals.append("caller_not_privileged")
        return signals

    def _make_flag(self, event, ctx, rule, base_confidence, severity, summary,
                   evidence, needs_privilege, event_ids=None, correlation_key=None) -> CloudFlag:
        signals = self._supporting_signals(ctx, needs_privilege)
        confidence = _bump(base_confidence, len(signals)) if signals else base_confidence
        target = event.get("target") or {}
        data = event.get("data") or {}
        full_evidence = {
            "api_action": data.get("api_action"),
            "event_type": event["event"].get("type"),
            "call_source": data.get("call_source"),
            "caller_location": ctx["caller_location"],
            "caller_privileged": ctx["privileged"],
            "supporting_signals": signals,
            **evidence,
        }
        return CloudFlag(
            rule=rule,
            confidence=confidence,
            severity=severity,
            summary=summary,
            event_ids=event_ids or [event["event_id"]],
            asset_id=target.get("asset_id") or event["source"].get("asset_id"),
            timestamp=str(event.get("timestamp")),
            resource=target.get("resource"),
            user_id=ctx["user_id"],
            source_ip=ctx["source_ip"],
            evidence=full_evidence,
            correlation_key=correlation_key,
        )

    # ------------------------------------------------------------
    # Rule 1: IAM privilege escalation
    # A role change is routine (the simulator's IT admin does
    # employee->manager); a change that ENDS in admin/owner from a lower
    # role is a privilege grab. Same event type either way -- the roles
    # in config_before/config_after are what separate them.
    # ------------------------------------------------------------

    def _rule_iam_privilege_escalation(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        if data.get("api_action") not in ROLE_CHANGE_ACTIONS:
            return []
        before = str(data.get("config_before", "")).lower()
        after = str(data.get("config_after", "")).lower()
        if before not in ROLE_RANK or after not in ROLE_RANK:
            return []
        if not (ROLE_RANK[after] >= PRIVILEGED_ROLE_RANK and ROLE_RANK[after] > ROLE_RANK[before]):
            return []
        jump = ROLE_RANK[after] - ROLE_RANK[before]
        return [self._make_flag(
            event, ctx,
            rule="iam_privilege_escalation",
            base_confidence="medium",
            severity="high",
            summary=f"{ctx['user_id']} changed a role {before} -> {after} ({jump}-level jump into a privileged role)",
            evidence={"config_before": before, "config_after": after, "privilege_jump": jump},
            needs_privilege=True,
        )]

    # ------------------------------------------------------------
    # Rule 2: MFA disablement
    # The simulator has no legitimate MFA-disable activity at all, and
    # turning MFA off is a classic account-takeover persistence step.
    # ------------------------------------------------------------

    def _rule_mfa_disablement(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        by_action = data.get("api_action") in MFA_DISABLE_ACTIONS
        by_state = (
            str(data.get("config_before", "")).lower() == "mfa_enabled"
            and str(data.get("config_after", "")).lower() == "mfa_disabled"
        )
        if not (by_action or by_state):
            return []
        return [self._make_flag(
            event, ctx,
            rule="mfa_disablement",
            base_confidence="high",
            severity="high",
            summary=f"MFA disabled via {data.get('api_action')} by {ctx['user_id']}",
            evidence={"config_before": data.get("config_before"), "config_after": data.get("config_after")},
            needs_privilege=True,
        )]

    # ------------------------------------------------------------
    # Rule 3: public bucket exposure
    # Normal storage config activity only READS the ACL (s3:GetBucketAcl).
    # A write that leaves the bucket public exposes enterprise files
    # (STORAGE-01) to the internet.
    # ------------------------------------------------------------

    def _rule_public_bucket_exposure(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        if data.get("api_action") not in BUCKET_ACL_WRITE_ACTIONS:
            return []
        after = str(data.get("config_after", "")).lower()
        if "public" not in after:
            return []
        return [self._make_flag(
            event, ctx,
            rule="public_bucket_exposure",
            base_confidence="high",
            severity="critical",
            summary=(
                f"Storage {(event.get('target') or {}).get('resource')} ACL changed "
                f"{data.get('config_before')} -> {data.get('config_after')}"
            ),
            evidence={"config_before": data.get("config_before"), "config_after": data.get("config_after")},
            needs_privilege=True,
        )]

    # ------------------------------------------------------------
    # Rule 4: security group misconfiguration
    # Normal activity only DESCRIBES security groups. Opening ingress to
    # the whole internet is flagged; a sensitive port (SSH 22 in the
    # simulator) raises severity to critical.
    # ------------------------------------------------------------

    def _rule_security_group_misconfiguration(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        if data.get("api_action") not in SG_INGRESS_ACTIONS:
            return []
        after = str(data.get("config_after", ""))
        if not any(cidr in after for cidr in OPEN_TO_WORLD_CIDRS):
            return []
        port = _parse_exposed_port(after)
        sensitive = port in SENSITIVE_PORTS
        return [self._make_flag(
            event, ctx,
            rule="security_group_misconfiguration",
            base_confidence="high",
            severity="critical" if sensitive else "high",
            summary=(
                f"Ingress opened to the internet ({after})"
                + (f" on sensitive port {port}" if sensitive else "")
            ),
            evidence={"config_before": data.get("config_before"), "config_after": after,
                      "exposed_port": port, "sensitive_port": sensitive},
            needs_privilege=True,
        )]

    # ------------------------------------------------------------
    # Rule 5: mass data exfiltration (stateful)
    # One object read is normal. Many reads / many bytes by the SAME user
    # in a short window is a sweep. Keyed by user, not session, so it
    # doesn't depend on the attacker reusing one session.
    # ------------------------------------------------------------

    def _rule_mass_data_exfiltration(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        if data.get("api_action") != "s3:GetObject" or ctx["when"] is None:
            return []
        key = f"exfil:{ctx['user_id']}"
        bytes_read = data.get("bytes_transferred") or 0
        if not isinstance(bytes_read, (int, float)):
            bytes_read = 0

        def over(window):
            latest = window[-1]["when"]
            burst = [i for i in window if (latest - i["when"]).total_seconds() <= EXFIL_BURST_WINDOW_SECONDS]
            return (len(burst) >= EXFIL_READ_COUNT_THRESHOLD
                    or sum(i["bytes"] for i in window) >= EXFIL_BYTES_THRESHOLD)

        state = self._exfil.add(key, ctx["when"], {"event_id": event["event_id"], "bytes": bytes_read,
                                                   "object": data.get("object_key")}, over)
        if state is None:
            return []

        window = self._exfil.window_items(key)
        total_bytes = sum(i["bytes"] for i in window)
        correlation_key = self._exfil.episode_ids[key]
        if state == "crossed":
            return [self._make_flag(
                event, ctx,
                rule="mass_data_exfiltration",
                base_confidence="medium",
                severity="high",
                summary=(
                    f"{ctx['user_id']} read {len(window)} objects ({total_bytes:,} bytes) "
                    f"within {EXFIL_WINDOW_SECONDS}s"
                ),
                evidence={"objects_read": len(window), "total_bytes": total_bytes,
                          "window_seconds": EXFIL_WINDOW_SECONDS,
                          "objects": sorted({i["object"] for i in window if i["object"]})},
                needs_privilege=False,
                event_ids=[i["event_id"] for i in window],
                correlation_key=correlation_key,
            )]
        return [self._make_flag(
            event, ctx,
            rule="mass_data_exfiltration",
            base_confidence="medium",
            severity="high",
            summary=f"Exfiltration burst continues: {ctx['user_id']} now at {len(window)} reads / {total_bytes:,} bytes",
            evidence={"objects_read": len(window), "total_bytes": total_bytes, "continuation": True},
            needs_privilege=False,
            correlation_key=correlation_key,
        )]

    # ------------------------------------------------------------
    # Rule 6: API key abuse (per event + stateful)
    # Normal cloud_api_call traffic uses a small, fixed set of business
    # actions. Enumeration/secrets calls are off-baseline (medium). The
    # same api_key_id sweeping several distinct recon actions quickly is
    # key abuse (high).
    # ------------------------------------------------------------

    def _rule_api_key_abuse(self, event, ctx) -> List[CloudFlag]:
        data = event.get("data") or {}
        if event["event"].get("type") != "cloud_api_call":
            return []
        api_action = str(data.get("api_action") or "")
        if not api_action or api_action in NORMAL_API_ACTIONS or not _is_recon_action(api_action):
            return []

        api_key_id = data.get("api_key_id")
        burst_key = f"apikey:{api_key_id or ctx['user_id']}"
        state = None
        if ctx["when"] is not None:
            def over(window):
                return len({i["action"] for i in window}) >= API_BURST_DISTINCT_ACTIONS_THRESHOLD
            state = self._api_keys.add(burst_key, ctx["when"],
                                       {"event_id": event["event_id"], "action": api_action}, over)

        if state == "crossed":
            window = self._api_keys.window_items(burst_key)
            actions = sorted({i["action"] for i in window})
            return [self._make_flag(
                event, ctx,
                rule="api_key_abuse",
                base_confidence="high",
                severity="high",
                summary=(
                    f"API key {api_key_id or '(none)'} made {len(window)} reconnaissance calls "
                    f"({len(actions)} distinct actions) within {API_BURST_WINDOW_SECONDS}s"
                ),
                evidence={"api_key_id": api_key_id, "distinct_actions": actions, "calls": len(window)},
                needs_privilege=False,
                event_ids=[i["event_id"] for i in window],
                correlation_key=self._api_keys.episode_ids[burst_key],
            )]

        return [self._make_flag(
            event, ctx,
            rule="api_key_abuse",
            base_confidence="high" if state == "continued" else "low",
            severity="high" if state == "continued" else "medium",
            summary=(
                f"Reconnaissance API call {api_action} (outside normal API baseline)"
                + (" -- part of an ongoing key-abuse burst" if state == "continued" else "")
            ),
            evidence={"api_key_id": api_key_id, "continuation": state == "continued"},
            needs_privilege=False,
            correlation_key=self._api_keys.episode_ids.get(burst_key) if state == "continued" else None,
        )]


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
    """
    Watch the event log and analyse every new event as it arrives.
    Keeps running after raising flags; stop with Ctrl+C (or stop_event).
    """
    agent = agent or CloudAgent()
    tailer = EventTailer(path, start_at_end=from_end)

    def handle(record: dict) -> None:
        for flag in agent.process_event(record):
            print(flag, flush=True)
            if output_path is not None:
                _append_jsonl(Path(output_path), flag.to_dict())

    mode = "single pass" if once else ("watching new events only" if from_end else "catching up, then watching")
    print(f"Cloud Agent: monitoring {path} ({mode})")
    if output_path is not None:
        print(f"Flags are also written to {output_path}")
    print("Press Ctrl+C to stop.\n" if not once else "", end="", flush=True)

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
        print(f"\nCloud Agent stopped. Stats: {stats}")
    return agent


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    def _graceful_stop(_signum, _frame):
        raise KeyboardInterrupt  # handled in run(): prints stats and exits cleanly

    signal.signal(signal.SIGTERM, _graceful_stop)  # e.g. `docker stop`
    parser = argparse.ArgumentParser(description="Run the Cloud Security Agent (continuous monitoring).")
    parser.add_argument("--path", type=Path, default=DEFAULT_EVENT_LOG_PATH,
                        help=f"Event log to watch (default: {DEFAULT_EVENT_LOG_PATH})")
    parser.add_argument("--output", type=Path, default=DEFAULT_FLAG_LOG_PATH,
                        help=f"Where to append flags as JSONL (default: {DEFAULT_FLAG_LOG_PATH})")
    parser.add_argument("--no-output", action="store_true", help="Print flags only; don't write a flag file")
    parser.add_argument("--from-end", action="store_true", help="Skip events already in the log; watch new ones only")
    parser.add_argument("--once", action="store_true", help="Single pass over the log, then exit")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between checks for new events")
    args = parser.parse_args()
    run(args.path, None if args.no_output else args.output, args.from_end, args.once, args.poll_interval)
