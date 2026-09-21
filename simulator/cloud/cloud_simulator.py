"""
simulator/cloud/cloud_simulator.py

Cloud Environment (CLOUD-01) simulator.

Generates normal and attack activity across CLOUD-01's sub-resources
(IAM-01, STORAGE-01, SEC-01, CLOUD-VM-01, API-01), using the shared
BaseSimulator interface and CommonEvent schema, so every event this
module produces is structurally identical to events from every other
asset simulator.

Integrates with:
    shared.base.base_simulator.BaseSimulator
    shared.schemas.event_schema.CommonEvent
    shared.utils.id_generator.generate_event_id
    shared.utils.timestamp.get_utc_timestamp
    shared.utils.config_loader.get_asset / get_employee / get_cloud_resource
    shared.constants.enums.EventCategory / EventStatus / Protocol / AssetType
"""

import random
import threading
import time
import uuid
from typing import Callable, Optional

from shared.base.base_simulator import BaseSimulator
from shared.schemas.event_schema import CommonEvent
from shared.utils.id_generator import generate_event_id
from shared.utils.timestamp import get_utc_timestamp
from shared.utils.config_loader import get_asset, get_employee, get_cloud_resource
from shared.constants.enums import EventCategory, EventStatus, Protocol, AssetType


class CloudSimulator(BaseSimulator):
    """
    Simulator for CLOUD-01, the simulated cloud environment, covering
    its sub-resources: IAM-01, STORAGE-01, SEC-01, CLOUD-VM-01, API-01.

    Normal activity: employees reading/writing storage, connecting to
    the cloud VM, calling the cloud API, IT reviewing security config,
    checking IAM policy, and IT admin performing a legitimate role
    change -- all attributed to real employees from the registry.

    Attack activity (cloud-specific, matching real CSPM/cloud-security
    findings): IAM privilege escalation, MFA disablement, public
    storage bucket exposure, security group misconfiguration, mass
    data exfiltration, and API key theft/abuse.

    Design notes:
        - Source IP models the CALLING CLIENT, not CLOUD-01 itself --
          exactly like the sample CLOUD-01 event in the project's
          event-schema reference doc (source_ip was the calling
          employee's workstation IP, network destination fields null).
          Normal activity uses the real employee's actual workstation
          IP; attacks (stolen/misused credentials) use an anomalous
          EXTERNAL source IP even though the user_id may be a real
          employee -- an unfamiliar-location signal, the cloud
          equivalent of WEB-01's external attacker IPs.
        - No MAC address here (unlike endpoints): CLOUD-01 is a
          logical environment, not a physical NIC-bearing device, so a
          MAC address wouldn't mean anything for this asset.
        - iam_privilege_escalation REUSES the normal "role_update"
          event type (matching the project's own sample event, which
          showed an employee->admin role change with no built-in
          judgment about whether it was legitimate) -- distinguishable
          only by who performed it, from where, and how large the
          privilege jump is, not by a giveaway label. mass_data_
          exfiltration and api_key_abuse similarly reuse their normal
          counterparts (cloud_storage_access, cloud_api_call).

    Generation model (same as WEB-01 / endpoints):
        Normal activity runs CONTINUOUSLY in the background -- start
        it with start_normal_stream(), stop with stop_normal_stream().
        Attacks fire only when explicitly selected via
        trigger_attack("mfa_disablement") -- never auto-injected.
    """

    # Employees with cloud access (all 4, per access_profiles in the registry)
    ALL_EMPLOYEE_IDS = ["EMP-001", "EMP-002", "EMP-003", "EMP-004"]
    IT_ADMIN_EMPLOYEE_ID = "EMP-003"  # only it_admin is privileged=true

    # Cloud sub-resources this simulator generates activity against
    STORAGE_RESOURCE_ID = "STORAGE-01"
    IAM_RESOURCE_ID = "IAM-01"
    SEC_RESOURCE_ID = "SEC-01"
    VM_RESOURCE_ID = "CLOUD-VM-01"
    API_RESOURCE_ID = "API-01"

    STORAGE_OBJECT_POOL = [
        "quarterly_report.xlsx", "client_contracts.pdf", "employee_records.csv",
        "backup_2026_08.tar.gz", "product_roadmap.pptx", "financial_summary.xlsx",
    ]

    API_ACTIONS_NORMAL = ["reports:Generate", "orders:List", "profile:Get"]
    API_ACTIONS_ABUSE = [
        "iam:ListUsers", "iam:ListRoles", "s3:ListBuckets",
        "ec2:DescribeInstances", "secretsmanager:ListSecrets",
    ]

    ROLE_LEVELS_NORMAL = [("employee", "manager"), ("contractor", "employee")]
    ROLE_LEVELS_ESCALATION = [("employee", "admin"), ("employee", "owner"), ("contractor", "admin")]

    # Anomalous external source IPs used for attacks -- the cloud
    # equivalent of WEB-01's EXTERNAL_SOURCE_IPS (RFC 5737 test-net
    # ranges, guaranteed never to be a real address).
    EXTERNAL_SOURCE_IPS = ["203.0.113.50", "198.51.100.77", "192.0.2.123", "203.0.113.201"]

    # Selectable attack types -> handler method name.
    ATTACK_GENERATORS = {
        "iam_privilege_escalation": "_attack_iam_privilege_escalation",
        "mfa_disablement": "_attack_mfa_disablement",
        "public_bucket_exposure": "_attack_public_bucket_exposure",
        "security_group_misconfiguration": "_attack_security_group_misconfiguration",
        "mass_data_exfiltration": "_attack_mass_data_exfiltration",
        "api_key_abuse": "_attack_api_key_abuse",
    }

    # Attack types that represent a BURST of related events rather
    # than a single one -- (min_events, max_events) per trigger.
    # Mass exfiltration downloads many objects rapidly; API key abuse
    # fires many unusual calls in a short window.
    BURST_ATTACK_RANGES = {
        "mass_data_exfiltration": (5, 20),
        "api_key_abuse": (5, 15),
    }

    def __init__(self, asset_id: str = "CLOUD-01"):
        super().__init__(asset_id)
        self.asset = get_asset(self.asset_id)
        self.hostname = self.asset["hostname"]

        # Background continuous normal-activity stream state
        self._stream_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @classmethod
    def available_attack_types(cls):
        """Attack type names accepted by generate_attack_event()/trigger_attack()."""
        return list(cls.ATTACK_GENERATORS.keys())

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _new_session_id(self) -> str:
        return f"CLOUD-SESSION-{uuid.uuid4().hex[:8].upper()}"

    def _random_employee(self):
        """Pick a random employee with cloud access, plus their real workstation IP."""
        employee_id = random.choice(self.ALL_EMPLOYEE_IDS)
        employee = get_employee(employee_id)
        workstation = get_asset(employee["workstation_id"])
        return employee_id, employee["username"], workstation["ip_address"]

    def _build_event(
        self,
        category: EventCategory,
        event_type: str,
        action: str,
        status: EventStatus,
        target_resource_id: str,
        source_ip: str,
        user_id: Optional[str],
        call_source: str,
        data: dict,
        session_id: Optional[str] = None,
    ) -> CommonEvent:
        resource = get_cloud_resource(target_resource_id)
        enriched_data = dict(data)
        enriched_data["call_source"] = call_source

        return CommonEvent(
            event_id=generate_event_id("CLOUD"),
            timestamp=get_utc_timestamp(),
            source={
                "asset_id": self.asset_id,
                "asset_type": AssetType.CLOUD_ENVIRONMENT.value,
                "hostname": self.hostname,
            },
            network={
                "source_ip": source_ip,
                "source_port": None,
                "destination_ip": None,
                "destination_port": None,
                "protocol": None,
            },
            actor={
                "user_id": user_id,
                "session_id": session_id or self._new_session_id(),
            },
            event={
                "category": category.value,
                "type": event_type,
                "action": action,
                "status": status.value,
            },
            target={
                "asset_id": self.asset_id,
                "resource": target_resource_id,
                "resource_type": resource["resource_type"],
            },
            data=enriched_data,
            context={
                "environment": "simulated_enterprise",
                "simulation": True,
            },
        )

    # ------------------------------------------------------------------
    # NORMAL EVENTS
    # ------------------------------------------------------------------

    def generate_normal_event(self) -> CommonEvent:
        generators = [
            self._normal_cloud_storage_access,
            self._normal_vm_session,
            self._normal_cloud_api_call,
            self._normal_security_config_review,
            self._normal_storage_config_review,
            self._normal_iam_policy_check,
            self._normal_role_update,
        ]
        return random.choice(generators)()

    def _normal_storage_config_review(self) -> CommonEvent:
        # Only IT reviews storage ACL/config in normal operation --
        # mirrors _normal_security_config_review for SEC-01.
        employee = get_employee(self.IT_ADMIN_EMPLOYEE_ID)
        workstation = get_asset(employee["workstation_id"])

        return self._build_event(
            category=EventCategory.STORAGE,
            event_type="storage_config_review",
            action="read",
            status=EventStatus.SUCCESS,
            target_resource_id=self.STORAGE_RESOURCE_ID,
            source_ip=workstation["ip_address"],
            user_id=self.IT_ADMIN_EMPLOYEE_ID,
            call_source=employee["username"],
            data={
                "api_action": "s3:GetBucketAcl",
            },
        )

    def _normal_cloud_storage_access(self) -> CommonEvent:
        employee_id, username, source_ip = self._random_employee()
        object_key = random.choice(self.STORAGE_OBJECT_POOL)
        operation = random.choice(["read", "write"])

        return self._build_event(
            category=EventCategory.STORAGE,
            event_type="cloud_storage_access",
            action=operation,
            status=EventStatus.SUCCESS,
            target_resource_id=self.STORAGE_RESOURCE_ID,
            source_ip=source_ip,
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "s3:GetObject" if operation == "read" else "s3:PutObject",
                "object_key": object_key,
                "bytes_transferred": random.randint(10_000, 5_000_000),
            },
        )

    def _normal_vm_session(self) -> CommonEvent:
        employee_id, username, source_ip = self._random_employee()

        return self._build_event(
            category=EventCategory.CLOUD,
            event_type="vm_session",
            action="connect",
            status=EventStatus.SUCCESS,
            target_resource_id=self.VM_RESOURCE_ID,
            source_ip=source_ip,
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "ec2:StartSession",
                "session_protocol": random.choice(["SSH", "RDP"]),
            },
        )

    def _normal_cloud_api_call(self) -> CommonEvent:
        employee_id, username, source_ip = self._random_employee()
        api_action = random.choice(self.API_ACTIONS_NORMAL)

        return self._build_event(
            category=EventCategory.API,
            event_type="cloud_api_call",
            action="request",
            status=EventStatus.SUCCESS,
            target_resource_id=self.API_RESOURCE_ID,
            source_ip=source_ip,
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": api_action,
                "response_time_ms": random.randint(30, 400),
            },
        )

    def _normal_security_config_review(self) -> CommonEvent:
        # Only IT reviews security config in normal operation
        employee = get_employee(self.IT_ADMIN_EMPLOYEE_ID)
        workstation = get_asset(employee["workstation_id"])

        return self._build_event(
            category=EventCategory.SECURITY_CONFIGURATION,
            event_type="security_config_review",
            action="read",
            status=EventStatus.SUCCESS,
            target_resource_id=self.SEC_RESOURCE_ID,
            source_ip=workstation["ip_address"],
            user_id=self.IT_ADMIN_EMPLOYEE_ID,
            call_source=employee["username"],
            data={
                "api_action": "ec2:DescribeSecurityGroups",
            },
        )

    def _normal_iam_policy_check(self) -> CommonEvent:
        employee_id, username, source_ip = self._random_employee()

        return self._build_event(
            category=EventCategory.IAM,
            event_type="iam_policy_check",
            action="read",
            status=EventStatus.SUCCESS,
            target_resource_id=self.IAM_RESOURCE_ID,
            source_ip=source_ip,
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "iam:GetUserPolicy",
            },
        )

    def _normal_role_update(self) -> CommonEvent:
        # Only the IT admin legitimately changes roles
        employee = get_employee(self.IT_ADMIN_EMPLOYEE_ID)
        workstation = get_asset(employee["workstation_id"])
        config_before, config_after = random.choice(self.ROLE_LEVELS_NORMAL)

        return self._build_event(
            category=EventCategory.IAM,
            event_type="role_update",
            action="modify",
            status=EventStatus.SUCCESS,
            target_resource_id=self.IAM_RESOURCE_ID,
            source_ip=workstation["ip_address"],
            user_id=self.IT_ADMIN_EMPLOYEE_ID,
            call_source=employee["username"],
            data={
                "api_action": "iam:UpdateRole",
                "config_before": config_before,
                "config_after": config_after,
            },
        )

    # ------------------------------------------------------------------
    # ATTACK EVENTS
    # ------------------------------------------------------------------

    def generate_attack_event(self, attack_type: Optional[str] = None) -> CommonEvent:
        """
        Generate one attack event.

        attack_type: one of CloudSimulator.available_attack_types(). If
        omitted, a random attack type is chosen -- this fallback exists
        only so this method still satisfies BaseSimulator's zero-arg
        abstract signature and BaseSimulator.generate_events("attack",
        ...). For deliberate, on-demand attacks, always pass
        attack_type explicitly (or use trigger_attack()).
        """
        if attack_type is None:
            method_name = random.choice(list(self.ATTACK_GENERATORS.values()))
        else:
            method_name = self.ATTACK_GENERATORS.get(attack_type.lower())
            if method_name is None:
                raise ValueError(
                    f"Unknown attack_type '{attack_type}'. "
                    f"Available: {', '.join(self.available_attack_types())}"
                )
        return getattr(self, method_name)()

    def trigger_attack(
        self,
        attack_type: str,
        on_event: Optional[Callable[[CommonEvent], None]] = None,
        burst_size: Optional[int] = None,
        burst_delay_seconds: float = 0.15,
    ) -> CommonEvent:
        """
        Fire a specific attack immediately, on demand. Never runs
        automatically and is independent of the continuous
        normal-activity stream below.

        Most attack types fire exactly ONE event (iam_privilege_
        escalation, mfa_disablement, public_bucket_exposure,
        security_group_misconfiguration -- each is a single discrete
        configuration change).

        BURST attack types (see BURST_ATTACK_RANGES:
        "mass_data_exfiltration", "api_key_abuse") fire a realistic
        SEQUENCE of related events instead -- mass exfiltration
        downloads many objects in a row, API key abuse fires many
        unusual calls in a short window -- each spaced
        burst_delay_seconds apart. Every event in the burst is passed
        to on_event as it's generated; the return value is the LAST
        event of the burst.

        burst_size overrides the default random event count for burst
        attack types (ignored for non-burst attack types).
        """
        key = attack_type.lower() if attack_type else None
        burst_range = self.BURST_ATTACK_RANGES.get(key)

        if burst_range is None:
            event = self.generate_attack_event(attack_type=attack_type)
            if on_event is not None:
                on_event(event)
            return event

        count = burst_size if burst_size is not None else random.randint(*burst_range)
        session_id = self._new_session_id()
        employee_id, username, _real_ip = self._random_employee()
        attacker_ip = random.choice(self.EXTERNAL_SOURCE_IPS)

        last_event: Optional[CommonEvent] = None

        if key == "mass_data_exfiltration":
            objects = self.STORAGE_OBJECT_POOL * (count // len(self.STORAGE_OBJECT_POOL) + 1)
            for i in range(count):
                event = self._attack_mass_data_exfiltration(
                    session_id=session_id,
                    employee_id=employee_id,
                    username=username,
                    source_ip=attacker_ip,
                    object_key=objects[i],
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        elif key == "api_key_abuse":
            actions = self.API_ACTIONS_ABUSE * (count // len(self.API_ACTIONS_ABUSE) + 1)
            api_key_id = f"AKIA{uuid.uuid4().hex[:12].upper()}"  # same stolen key for the whole burst
            for i in range(count):
                event = self._attack_api_key_abuse(
                    session_id=session_id,
                    employee_id=employee_id,
                    username=username,
                    source_ip=attacker_ip,
                    api_action=actions[i],
                    api_key_id=api_key_id,
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        return last_event

    def _attack_iam_privilege_escalation(self) -> CommonEvent:
        """
        A role change granting an implausibly large privilege jump
        (e.g. employee -> admin/owner), reusing the SAME "role_update"
        type as a legitimate role change -- what marks it as an attack
        is the anomalous source IP and the size of the jump, not the
        event type.
        """
        employee_id, username, _real_ip = self._random_employee()
        config_before, config_after = random.choice(self.ROLE_LEVELS_ESCALATION)

        return self._build_event(
            category=EventCategory.IAM,
            event_type="role_update",
            action="modify",
            status=EventStatus.BLOCKED,
            target_resource_id=self.IAM_RESOURCE_ID,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "iam:UpdateRole",
                "config_before": config_before,
                "config_after": config_after,
            },
        )

    def _attack_mfa_disablement(self) -> CommonEvent:
        # Reuses "role_update" -- both are IAM configuration changes
        # with the same config_before/config_after shape; api_action
        # is what actually reveals what changed.
        employee_id, username, _real_ip = self._random_employee()

        return self._build_event(
            category=EventCategory.IAM,
            event_type="role_update",
            action="modify",
            status=EventStatus.BLOCKED,
            target_resource_id=self.IAM_RESOURCE_ID,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "iam:DeactivateMFADevice",
                "config_before": "mfa_enabled",
                "config_after": "mfa_disabled",
            },
        )

    def _attack_public_bucket_exposure(self) -> CommonEvent:
        # Reuses "storage_config_review" -- same type as the benign
        # read-only review, just with action="modify" instead of
        # "read" and a status of blocked instead of success.
        employee_id, username, _real_ip = self._random_employee()

        return self._build_event(
            category=EventCategory.STORAGE,
            event_type="storage_config_review",
            action="modify",
            status=EventStatus.BLOCKED,
            target_resource_id=self.STORAGE_RESOURCE_ID,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "s3:PutBucketAcl",
                "config_before": "private",
                "config_after": "public-read",
            },
        )

    def _attack_security_group_misconfiguration(self) -> CommonEvent:
        # Reuses "security_config_review" -- same type as the benign
        # read-only review, just with action="modify" instead of
        # "read" and a status of blocked instead of success.
        employee_id, username, _real_ip = self._random_employee()

        return self._build_event(
            category=EventCategory.SECURITY_CONFIGURATION,
            event_type="security_config_review",
            action="modify",
            status=EventStatus.BLOCKED,
            target_resource_id=self.SEC_RESOURCE_ID,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            data={
                "api_action": "ec2:AuthorizeSecurityGroupIngress",
                "config_before": "restricted_to_internal_network",
                "config_after": "0.0.0.0/0:22",
            },
        )

    def _attack_mass_data_exfiltration(
        self,
        session_id: Optional[str] = None,
        employee_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        object_key: Optional[str] = None,
    ) -> CommonEvent:
        """
        One rapid object download as part of a data exfiltration
        sweep. Pass session_id/employee_id/username/source_ip to make
        several calls represent the SAME compromised session
        downloading many objects in a row (see trigger_attack's burst
        handling). Called with no arguments, it's a single independent
        download.
        """
        if employee_id is None:
            employee_id, username, _real_ip = self._random_employee()
        object_key = object_key or random.choice(self.STORAGE_OBJECT_POOL)

        return self._build_event(
            category=EventCategory.STORAGE,
            event_type="cloud_storage_access",
            action="read",
            status=EventStatus.BLOCKED,
            target_resource_id=self.STORAGE_RESOURCE_ID,
            source_ip=source_ip or random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            session_id=session_id,
            data={
                "api_action": "s3:GetObject",
                "object_key": object_key,
                "bytes_transferred": random.randint(500_000, 20_000_000),
            },
        )

    def _attack_api_key_abuse(
        self,
        session_id: Optional[str] = None,
        employee_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        api_action: Optional[str] = None,
        api_key_id: Optional[str] = None,
    ) -> CommonEvent:
        """
        One unusual API call made with a valid but likely-stolen key.
        Pass session_id/employee_id/username/source_ip/api_key_id to
        make several calls represent the SAME abused key firing a
        burst of unusual calls (see trigger_attack's burst handling).
        Called with no arguments, it's a single independent call with
        its own freshly generated key ID.
        """
        if employee_id is None:
            employee_id, username, _real_ip = self._random_employee()
        api_action = api_action or random.choice(self.API_ACTIONS_ABUSE)
        api_key_id = api_key_id or f"AKIA{uuid.uuid4().hex[:12].upper()}"

        return self._build_event(
            category=EventCategory.API,
            event_type="cloud_api_call",
            action="request",
            status=EventStatus.BLOCKED,
            target_resource_id=self.API_RESOURCE_ID,
            source_ip=source_ip or random.choice(self.EXTERNAL_SOURCE_IPS),
            user_id=employee_id,
            call_source=username,
            session_id=session_id,
            data={
                "api_action": api_action,
                "api_key_id": api_key_id,
                "response_time_ms": random.randint(10, 80),
            },
        )

    # ------------------------------------------------------------------
    # CONTINUOUS NORMAL ACTIVITY STREAM
    # ------------------------------------------------------------------

    def stream_normal_events(self, interval_seconds: float = 2.0):
        """Generator that yields normal events forever, one every interval_seconds."""
        while True:
            yield self.generate_normal_event()
            time.sleep(interval_seconds)

    def start_normal_stream(
        self,
        on_event: Callable[[CommonEvent], None],
        interval_seconds: float = 2.0,
        jitter_seconds: float = 0.5,
    ) -> None:
        """
        Start continuously generating normal activity in a background
        daemon thread, calling on_event(event) each time. Keeps running
        until stop_normal_stream() is called.
        """
        if self._stream_thread is not None and self._stream_thread.is_alive():
            raise RuntimeError("Normal event stream is already running.")

        self._stop_event.clear()

        def _worker():
            while not self._stop_event.is_set():
                on_event(self.generate_normal_event())
                wait_time = interval_seconds + random.uniform(-jitter_seconds, jitter_seconds)
                self._stop_event.wait(max(0.0, wait_time))

        self._stream_thread = threading.Thread(target=_worker, daemon=True)
        self._stream_thread.start()

    def stop_normal_stream(self, timeout: float = 5.0) -> None:
        """Stop the background normal-activity stream started above."""
        self._stop_event.set()
        if self._stream_thread is not None:
            self._stream_thread.join(timeout=timeout)
            self._stream_thread = None

    def is_streaming(self) -> bool:
        return self._stream_thread is not None and self._stream_thread.is_alive()


if __name__ == "__main__":
    # Demo: normal traffic runs continuously in the background; you
    # select attacks interactively while it keeps running. Every event
    # -- normal or attack -- is also persisted via
    # shared.storage.event_writer, exactly like run_soc_feed.py does,
    # so running this file directly saves data too, not just prints it.
    import json

    from shared.storage.event_writer import write_event, DEFAULT_EVENT_LOG_PATH, DEFAULT_GROUND_TRUTH_PATH

    def _print_event(event: CommonEvent, prefix: str = "") -> None:
        dump = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        print(prefix.strip())
        print(json.dumps(dump, indent=2, default=str))
        print("-" * 60)

    def _run_live_mode(sim: "CloudSimulator") -> None:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout

        print("(Live mode: normal traffic prints in real time as it happens.)\n")

        def normal_handler(e):
            write_event(e, is_attack=False)
            _print_event(e, prefix="[NORMAL] ")

        sim.start_normal_stream(on_event=normal_handler, interval_seconds=2.0)

        session: PromptSession = PromptSession()

        with patch_stdout():
            while True:
                selection = session.prompt("attack> ").strip()
                if selection.lower() in ("quit", "exit"):
                    break
                if not selection:
                    continue

                def attack_handler(e, _attack_type=selection):
                    write_event(e, is_attack=True, attack_type=_attack_type)
                    _print_event(e, prefix="[ATTACK] ")

                try:
                    sim.trigger_attack(selection, on_event=attack_handler)
                except ValueError as exc:
                    print(exc)

    def _run_buffered_mode(sim: "CloudSimulator") -> None:
        import queue

        event_queue: "queue.Queue[tuple[str, CommonEvent]]" = queue.Queue()

        def _drain_event_queue() -> None:
            while True:
                try:
                    prefix, event = event_queue.get_nowait()
                except queue.Empty:
                    break
                _print_event(event, prefix=prefix)

        print("(Buffered mode: normal traffic prints between prompts, not live.")
        print(" `pip install prompt_toolkit` for real-time output.)\n")

        def normal_handler(e):
            write_event(e, is_attack=False)
            event_queue.put(("[NORMAL] ", e))

        sim.start_normal_stream(on_event=normal_handler, interval_seconds=2.0)

        while True:
            _drain_event_queue()
            selection = input("attack> ").strip()
            _drain_event_queue()
            if selection.lower() in ("quit", "exit"):
                break
            if not selection:
                continue

            def attack_handler(e, _attack_type=selection):
                write_event(e, is_attack=True, attack_type=_attack_type)
                event_queue.put(("[ATTACK] ", e))

            try:
                sim.trigger_attack(selection, on_event=attack_handler)
                _drain_event_queue()
            except ValueError as exc:
                print(exc)

    _sim = CloudSimulator("CLOUD-01")

    print("Starting continuous CLOUD-01 normal activity (Ctrl+C / 'quit' to stop).")
    print("Available attacks:", ", ".join(_sim.available_attack_types()))
    print(f"Event log:        {DEFAULT_EVENT_LOG_PATH}")
    print(f"Ground truth log: {DEFAULT_GROUND_TRUTH_PATH}")

    try:
        try:
            _run_live_mode(_sim)
        except ImportError:
            _run_buffered_mode(_sim)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        _sim.stop_normal_stream()
        print("\nStopped.")