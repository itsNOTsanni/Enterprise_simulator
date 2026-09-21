"""
simulator/database/db_simulator.py

Database Server (DB-01) simulator.

Generates normal and attack activity on the enterprise PostgreSQL
database, using the shared BaseSimulator interface and CommonEvent
schema, so every event this module produces is structurally identical
to events from every other asset simulator.

Integrates with:
    shared.base.base_simulator.BaseSimulator
    shared.schemas.event_schema.CommonEvent
    shared.utils.id_generator.generate_event_id
    shared.utils.timestamp.get_utc_timestamp
    shared.utils.config_loader.get_asset / get_employee
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
from shared.utils.config_loader import get_asset, get_employee
from shared.constants.enums import EventCategory, EventStatus, Protocol, AssetType


class DatabaseSimulator(BaseSimulator):
    """
    Simulator for DB-01, the enterprise PostgreSQL database.

    Normal activity: application queries proxied through WEB-01 on
    behalf of real employees, plus direct administrative sessions from
    END-03 (the only workstation the registry allows to talk to DB-01
    directly) -- logins, maintenance operations, and backups.

    Attack activity (database-native, matching real DBA/DBSAT-style
    findings): credential brute force, privilege escalation,
    unauthorized configuration changes, mass data exfiltration,
    destructive queries, and PostgreSQL-specific stored-procedure abuse
    (COPY ... TO PROGRAM).

    Design notes:
        - Source IP modeling follows the project's own sample DB-01
          event: normal app traffic shows WEB-01's IP as the caller
          (the app tier proxies the query, but actor.user_id is still
          the real end user whose request triggered it); direct admin
          traffic shows END-03's IP.
        - "Unexpected source" signal: per the asset registry, DB-01
          only accepts connections from WEB-01 and END-03. Attacks are
          sourced from workstations NOT in that list (END-01, END-02,
          END-04) or from external test-net addresses -- an anomaly
          detectable from the connection topology alone, without
          needing a giveaway label. privilege_escalation is the
          deliberate exception: it's sourced from a normal internal
          workstation, because the anomaly there is the ACTION (a
          non-admin granting itself a higher role), not the source.
        - brute_force reuses the normal "db_login" type; mass_data_
          exfiltration reuses the normal "query_executed" type --
          distinguishable only by source, status, and pattern, matching
          the same discipline used in WEB-01/endpoints/CLOUD-01.

    Generation model (same as the other three simulators):
        Normal activity runs CONTINUOUSLY in the background -- start
        with start_normal_stream(), stop with stop_normal_stream().
        Attacks fire only when explicitly selected via
        trigger_attack("stored_procedure_abuse") -- never auto-injected.
    """

    ALL_EMPLOYEE_IDS = ["EMP-001", "EMP-002", "EMP-003", "EMP-004"]
    DB_ADMIN_EMPLOYEE_ID = "EMP-003"  # only END-03 is allowed to talk to DB-01 directly

    TABLES = ["orders_table", "users_table", "products_table", "customer_data", "financial_records"]
    QUERY_TYPES_NORMAL = ["SELECT", "INSERT", "UPDATE"]
    MAINTENANCE_OPERATIONS = ["VACUUM", "ANALYZE", "REINDEX"]

    STORED_PROCEDURE_COMMANDS = ["whoami", "cat /etc/passwd", "id", "uname -a"]
    CONFIG_PARAMETERS = [
        ("listen_addresses", "localhost", "*"),
        ("ssl", "on", "off"),
        ("password_encryption", "scram-sha-256", "md5"),
    ]
    PRIVILEGE_ESCALATION_TECHNIQUES = ["self_grant", "role_inheritance_abuse", "exploited_function"]

    # External source IPs, for attacks modeled as reaching DB-01 from
    # outside the internal network entirely (RFC 5737 test-net ranges,
    # same convention as WEB-01/CLOUD-01).
    EXTERNAL_SOURCE_IPS = ["203.0.113.30", "198.51.100.60", "192.0.2.90"]

    # Selectable attack types -> handler method name.
    ATTACK_GENERATORS = {
        "brute_force": "_attack_brute_force",
        "privilege_escalation": "_attack_privilege_escalation",
        "unauthorized_config_change": "_attack_unauthorized_config_change",
        "mass_data_exfiltration": "_attack_mass_data_exfiltration",
        "destructive_query": "_attack_destructive_query",
        "stored_procedure_abuse": "_attack_stored_procedure_abuse",
        "anomalous_query_flood": "_attack_anomalous_query_flood",
    }

    # Attack types that represent a BURST of related events rather
    # than a single one -- (min_events, max_events) per trigger.
    BURST_ATTACK_RANGES = {
        "brute_force": (5, 15),
        "mass_data_exfiltration": (5, 20),
        "anomalous_query_flood": (10, 30),
    }

    def __init__(self, asset_id: str = "DB-01"):
        super().__init__(asset_id)
        self.asset = get_asset(self.asset_id)
        self.hostname = self.asset["hostname"]
        self.ip_address = self.asset["ip_address"]

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
        return f"DB-SESSION-{uuid.uuid4().hex[:8].upper()}"

    def _random_web_user(self):
        """Pick a random employee whose web session triggers a proxied query via WEB-01."""
        employee_id = random.choice(self.ALL_EMPLOYEE_IDS)
        employee = get_employee(employee_id)
        return employee_id, employee["username"]

    def _unexpected_source_pool(self):
        """
        IPs that should never legitimately talk to DB-01, per the
        registry's communicates_with list (only WEB-01 and END-03 are
        allowed). Mixes wrong-but-internal endpoints with fully
        external addresses for variety.
        """
        wrong_endpoints = [get_asset(eid)["ip_address"] for eid in ("END-01", "END-02", "END-04")]
        return wrong_endpoints + self.EXTERNAL_SOURCE_IPS

    def _build_event(
        self,
        category: EventCategory,
        event_type: str,
        action: str,
        status: EventStatus,
        source_ip: str,
        user_id: Optional[str],
        resource: str,
        resource_type: str,
        data: dict,
        session_id: Optional[str] = None,
    ) -> CommonEvent:
        return CommonEvent(
            event_id=generate_event_id("DB"),
            timestamp=get_utc_timestamp(),
            source={
                "asset_id": self.asset_id,
                "asset_type": AssetType.DATABASE_SERVER.value,
                "hostname": self.hostname,
            },
            network={
                "source_ip": source_ip,
                "source_port": random.randint(49152, 65535),
                "destination_ip": self.ip_address,
                "destination_port": 5432,
                "protocol": Protocol.TCP.value,
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
                "resource": resource,
                "resource_type": resource_type,
            },
            data=data,
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
            self._normal_query_executed,
            self._normal_db_login,
            self._normal_db_logout,
            self._normal_maintenance_operation,
            self._normal_connection_established,
            self._normal_backup_created,
            self._normal_config_review,
        ]
        return random.choice(generators)()

    def _normal_query_executed(self) -> CommonEvent:
        # Application query proxied through WEB-01 on behalf of a real employee
        employee_id, username = self._random_web_user()
        web_asset = get_asset("WEB-01")
        table = random.choice(self.TABLES)
        query_type = random.choice(self.QUERY_TYPES_NORMAL)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="query_executed",
            action="query",
            status=EventStatus.SUCCESS,
            source_ip=web_asset["ip_address"],
            user_id=employee_id,
            resource=table,
            resource_type="table",
            data={
                "query_type": query_type,
                "rows_returned": random.randint(1, 100),
                "execution_time_ms": random.randint(5, 150),
                "call_source": username,
            },
        )

    def _normal_db_login(self) -> CommonEvent:
        admin = get_employee(self.DB_ADMIN_EMPLOYEE_ID)
        admin_workstation = get_asset("END-03")

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="db_login",
            action="authenticate",
            status=EventStatus.SUCCESS,
            source_ip=admin_workstation["ip_address"],
            user_id=self.DB_ADMIN_EMPLOYEE_ID,
            resource=admin["username"],
            resource_type="account",
            data={
                "auth_method": "password",
            },
        )

    def _normal_db_logout(self) -> CommonEvent:
        admin = get_employee(self.DB_ADMIN_EMPLOYEE_ID)
        admin_workstation = get_asset("END-03")

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="db_logout",
            action="terminate_session",
            status=EventStatus.SUCCESS,
            source_ip=admin_workstation["ip_address"],
            user_id=self.DB_ADMIN_EMPLOYEE_ID,
            resource=admin["username"],
            resource_type="account",
            data={},
        )

    def _normal_maintenance_operation(self) -> CommonEvent:
        admin_workstation = get_asset("END-03")
        operation = random.choice(self.MAINTENANCE_OPERATIONS)
        table = random.choice(self.TABLES)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="maintenance_operation",
            action="maintain",
            status=EventStatus.SUCCESS,
            source_ip=admin_workstation["ip_address"],
            user_id=self.DB_ADMIN_EMPLOYEE_ID,
            resource=table,
            resource_type="table",
            data={
                "operation": operation,
                "duration_ms": random.randint(100, 5000),
            },
        )

    def _normal_config_review(self) -> CommonEvent:
        # Only IT reviews DB configuration in normal operation --
        # mirrors CLOUD-01's security_config_review pattern.
        admin_workstation = get_asset("END-03")
        parameter, _before, _after = random.choice(self.CONFIG_PARAMETERS)

        return self._build_event(
            category=EventCategory.SECURITY_CONFIGURATION,
            event_type="config_review",
            action="read",
            status=EventStatus.SUCCESS,
            source_ip=admin_workstation["ip_address"],
            user_id=self.DB_ADMIN_EMPLOYEE_ID,
            resource=parameter,
            resource_type="configuration",
            data={
                "config_parameter": parameter,
            },
        )

    def _normal_connection_established(self) -> CommonEvent:
        web_asset = get_asset("WEB-01")

        return self._build_event(
            category=EventCategory.NETWORK,
            event_type="connection_established",
            action="connect",
            status=EventStatus.SUCCESS,
            source_ip=web_asset["ip_address"],
            user_id=None,
            resource="connection_pool",
            resource_type="connection",
            data={
                "pool_size": random.randint(5, 50),
            },
        )

    def _normal_backup_created(self) -> CommonEvent:
        admin_workstation = get_asset("END-03")

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="backup_created",
            action="backup",
            status=EventStatus.SUCCESS,
            source_ip=admin_workstation["ip_address"],
            user_id=self.DB_ADMIN_EMPLOYEE_ID,
            resource="full_database_backup",
            resource_type="backup",
            data={
                "backup_size_bytes": random.randint(50_000_000, 2_000_000_000),
                "backup_method": "pg_dump",
            },
        )

    # ------------------------------------------------------------------
    # ATTACK EVENTS
    # ------------------------------------------------------------------

    def generate_attack_event(self, attack_type: Optional[str] = None) -> CommonEvent:
        """
        Generate one attack event.

        attack_type: one of DatabaseSimulator.available_attack_types().
            If omitted, a random attack type is chosen -- this fallback
            exists only so this method still satisfies BaseSimulator's
            zero-arg abstract signature and BaseSimulator.generate_events
            ("attack", ...). For deliberate, on-demand attacks, always
            pass attack_type explicitly (or use trigger_attack()).
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

        Most attack types fire exactly ONE event (privilege_escalation,
        unauthorized_config_change, destructive_query,
        stored_procedure_abuse -- each is a single discrete action).

        BURST attack types (see BURST_ATTACK_RANGES: "brute_force",
        "mass_data_exfiltration", "anomalous_query_flood") fire a
        realistic SEQUENCE of related events instead, each spaced
        burst_delay_seconds apart (query floods use a shorter,
        harder-coded spacing to look like a real flood). Every event
        in the burst is passed to on_event as it's generated; the
        return value is the LAST event of the burst.

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
        source_ip = random.choice(self._unexpected_source_pool())

        last_event: Optional[CommonEvent] = None

        if key == "brute_force":
            for i in range(1, count + 1):
                event = self._attack_brute_force(
                    session_id=session_id, source_ip=source_ip, attempt_number=i
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count:
                    time.sleep(burst_delay_seconds)

        elif key == "mass_data_exfiltration":
            tables = self.TABLES * (count // len(self.TABLES) + 1)
            for i in range(count):
                event = self._attack_mass_data_exfiltration(
                    session_id=session_id, source_ip=source_ip, table=tables[i]
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        elif key == "anomalous_query_flood":
            for i in range(count):
                event = self._attack_anomalous_query_flood(session_id=session_id, source_ip=source_ip)
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds / 3)  # a flood is faster than a slow burst

        return last_event

    def _attack_brute_force(
        self,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        attempt_number: Optional[int] = None,
    ) -> CommonEvent:
        """
        One failed DB login attempt, reusing the normal "db_login"
        type. Pass session_id/source_ip/attempt_number to make several
        calls represent the SAME attacker session working through
        credentials (see trigger_attack's burst handling). Called with
        no arguments, it's a single independent attempt.
        """
        username_attempted = random.choice(["postgres", "admin", "root", "db_admin"])

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="db_login",
            action="authenticate",
            status=EventStatus.FAILURE,
            source_ip=source_ip or random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource=username_attempted,
            resource_type="account",
            session_id=session_id,
            data={
                "auth_method": "password",
                "username_attempted": username_attempted,
                "attempt_number_in_session": (
                    attempt_number if attempt_number is not None else random.randint(3, 40)
                ),
            },
        )

    def _attack_privilege_escalation(self) -> CommonEvent:
        # Sourced from a NORMAL internal workstation -- the anomaly
        # here is the action (self-granting a higher role), not the
        # source, unlike most other DB attacks. Reuses
        # "maintenance_operation" (action="grant" instead of
        # "maintain") since a role grant is, structurally, just
        # another administrative DB operation -- what's anomalous is
        # WHO performed it (not the DB admin) and the size of the
        # jump, not the type.
        employee_id, username = self._random_web_user()
        employee = get_employee(employee_id)
        workstation = get_asset(employee["workstation_id"])
        technique = random.choice(self.PRIVILEGE_ESCALATION_TECHNIQUES)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="maintenance_operation",
            action="grant",
            status=EventStatus.BLOCKED,
            source_ip=workstation["ip_address"],
            user_id=employee_id,
            resource=username,
            resource_type="db_role",
            data={
                "from_role": "read_only",
                "to_role": "superuser",
                "technique": technique,
            },
        )

    def _attack_unauthorized_config_change(self) -> CommonEvent:
        # Reuses "config_review" -- same type as the benign read-only
        # review, just with action="modify" instead of "read" and a
        # status of blocked instead of success.
        parameter, config_before, config_after = random.choice(self.CONFIG_PARAMETERS)

        return self._build_event(
            category=EventCategory.SECURITY_CONFIGURATION,
            event_type="config_review",
            action="modify",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource=parameter,
            resource_type="configuration",
            data={
                "config_parameter": parameter,
                "config_before": config_before,
                "config_after": config_after,
            },
        )

    def _attack_mass_data_exfiltration(
        self,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        table: Optional[str] = None,
    ) -> CommonEvent:
        """
        One abnormally large bulk read, reusing the normal
        "query_executed" type. Pass session_id/source_ip/table to make
        several calls represent the SAME session dumping many tables
        in a row (see trigger_attack's burst handling). Called with no
        arguments, it's a single independent bulk read.
        """
        table = table or random.choice(self.TABLES)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="query_executed",
            action="query",
            status=EventStatus.BLOCKED,
            source_ip=source_ip or random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource=table,
            resource_type="table",
            session_id=session_id,
            data={
                "query_type": "SELECT",
                "rows_returned": random.randint(50_000, 2_000_000),
                "execution_time_ms": random.randint(500, 8000),
            },
        )

    def _attack_destructive_query(self) -> CommonEvent:
        # Reuses "query_executed" -- a DROP/TRUNCATE is still, at the
        # type level, just a query being executed; query_type is what
        # reveals it, exactly like normal SELECT/INSERT/UPDATE values.
        table = random.choice(self.TABLES)
        query_type = random.choice(["DROP", "TRUNCATE"])

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="query_executed",
            action="query",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource=table,
            resource_type="table",
            data={
                "query_type": query_type,
            },
        )

    def _attack_stored_procedure_abuse(self) -> CommonEvent:
        # Reuses "query_executed" -- COPY ... TO PROGRAM is still,
        # structurally, a SQL statement being executed.
        command = random.choice(self.STORED_PROCEDURE_COMMANDS)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="query_executed",
            action="query",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource="COPY_TO_PROGRAM",
            resource_type="stored_procedure",
            data={
                "query_type": "COPY",
                "technique": "COPY ... TO PROGRAM",
                "command_attempted": command,
            },
        )

    def _attack_anomalous_query_flood(
        self,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> CommonEvent:
        """
        One query in a rapid-fire flood meant to exhaust DB resources.
        Pass session_id/source_ip to make several calls represent the
        SAME flooding session (see trigger_attack's burst handling).
        Called with no arguments, it's a single independent query.

        Reuses "query_executed" -- exactly like mass_data_exfiltration,
        this is fundamentally just many queries; the queries_per_second
        rate and burst pattern are the tell, not a special type.
        """
        table = random.choice(self.TABLES)

        return self._build_event(
            category=EventCategory.DATABASE,
            event_type="query_executed",
            action="query",
            status=EventStatus.BLOCKED,
            source_ip=source_ip or random.choice(self._unexpected_source_pool()),
            user_id=None,
            resource=table,
            resource_type="table",
            session_id=session_id,
            data={
                "query_type": "SELECT",
                "queries_per_second": random.randint(200, 2000),
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

    def _run_live_mode(sim: "DatabaseSimulator") -> None:
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

    def _run_buffered_mode(sim: "DatabaseSimulator") -> None:
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

    _sim = DatabaseSimulator("DB-01")

    print("Starting continuous DB-01 normal activity (Ctrl+C / 'quit' to stop).")
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