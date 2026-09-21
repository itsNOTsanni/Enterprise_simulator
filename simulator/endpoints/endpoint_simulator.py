"""
simulator/endpoints/endpoint_simulator.py

Employee Workstation (END-01..04) simulator.

Generates normal and attack activity on a single Windows employee
workstation, using the shared BaseSimulator interface and CommonEvent
schema, so every event this module produces is structurally identical
to events from every other asset simulator.

Unlike WEB-01 (a single server), there are FOUR employee workstations
in the registry (END-01..04). Each is its own EndpointSimulator
instance -- see the __main__ demo at the bottom for running all four
at once, the way a real fleet of employee PCs would behave.

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


class EndpointSimulator(BaseSimulator):
    """
    Simulator for ONE employee workstation (e.g. END-01).

    Normal activity: launching everyday apps, opening files, logon/
    logoff, outbound network use, USB file transfers, and approved
    software installs -- all tied to this machine's actual owner from
    the asset registry.

    Attack activity (endpoint/EDR-relevant, not web-layer): ransomware-
    style file encryption, LSASS credential dumping, privilege
    escalation, lateral movement to other internal assets, USB data
    exfiltration, and unauthorized/unsigned software installs.

    Design notes:
        - MAC address: the shared CommonEvent schema has no dedicated
          MAC field, so each event's source_mac_address is carried in
          the flexible `data` block instead, pulled from this asset's
          registry entry (config/asset_registry.yaml -> mac_address).
        - No separate "attacker device": every attack here is
          something happening ON this machine (a local process, a
          local privilege change) rather than an unknown external
          device connecting in, so events are attributed to this
          asset's own owner/session -- the same way a real EDR alert
          is tied to a specific host and logged-in user, not an
          anonymous IP. The one exception is lateral_movement, where
          the DESTINATION is another known internal asset (looked up
          from the registry), not a fake external one.
        - Where a normal activity has a natural malicious counterpart
          (network_connection / lateral_movement, usb_file_transfer /
          usb_data_exfiltration, software_installed / unauthorized_
          software_install), the attack REUSES the same event.type and
          is distinguishable only by status/pattern/target -- matching
          how WEB-01's brute_force reuses "login_attempt". A real
          detector never gets a label handed to it, so type alone must
          not be what gives an attack away.

    Generation model (same as WEB-01):
        Normal activity runs CONTINUOUSLY in the background at a fixed
        cadence -- start it with start_normal_stream() and it keeps
        producing events on its own until stop_normal_stream() is
        called.

        Attacks fire only when explicitly selected via
        trigger_attack("ransomware") (or generate_attack_event(
        attack_type=...) directly) -- never auto-injected into the
        normal stream.
    """

    ALL_ENDPOINT_IDS = ["END-01", "END-02", "END-03", "END-04"]

    # Everyday applications this employee might launch
    NORMAL_PROCESSES = [
        ("outlook.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
        ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        ("excel.exe", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
        ("winword.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
        ("teams.exe", r"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe"),
        ("notepad.exe", r"C:\Windows\System32\notepad.exe"),
    ]
    NORMAL_PARENT_PROCESS = "explorer.exe"

    NORMAL_FILES = [
        "Q3_Budget.xlsx", "Meeting_Notes.docx", "Client_List.csv",
        "Project_Plan.pptx", "Expense_Report.xlsx", "Onboarding_Guide.pdf",
    ]

    # Approved, IT-sanctioned software this employee might legitimately install
    APPROVED_SOFTWARE = [
        ("Zoom", "https://zoom.us/download"),
        ("Adobe Acrobat Reader", "https://get.adobe.com/reader"),
        ("7-Zip", "https://www.7-zip.org"),
    ]

    # Unsigned/unapproved software an attack might try to install
    UNAUTHORIZED_SOFTWARE = [
        ("CryptoMiner_Setup.exe", "unknown_web_download"),
        ("Free_VPN_Installer.exe", "torrent_download"),
        ("PDF_Toolkit_Free.exe", "email_attachment"),
        ("System_Optimizer_Pro.exe", "pop_up_advertisement"),
    ]

    RANSOMWARE_EXTENSIONS = [".locked", ".encrypted", ".crypt"]
    TARGET_FILE_POOL = [
        "Q3_Budget.xlsx", "Client_List.csv", "Payroll_2026.xlsx",
        "Contracts_Signed.pdf", "HR_Records.docx", "Sales_Pipeline.xlsx",
        "Project_Plan.pptx", "Customer_Database_Export.csv",
        "Meeting_Notes.docx", "Expense_Report.xlsx",
    ]

    # Process names malware might disguise itself as while dumping LSASS
    CREDENTIAL_DUMP_PROCESS_NAMES = [
        "svch0st.exe", "update_helper.exe", "rundll32_temp.exe", "dllhost32.exe",
    ]

    PRIVILEGE_ESCALATION_TECHNIQUES = [
        "uac_bypass", "token_impersonation", "exploited_vulnerable_service", "dll_hijacking",
    ]

    # Windows services commonly abused for lateral movement, with their ports
    LATERAL_MOVEMENT_SERVICES = [
        ("SMB", 445), ("RDP", 3389), ("WinRM", 5985), ("WMI", 135),
    ]

    USB_FILE_POOL = [
        "Client_List.csv", "Payroll_2026.xlsx", "Contracts_Signed.pdf",
        "HR_Records.docx", "Sales_Pipeline.xlsx", "Source_Code_Archive.zip",
        "Customer_Database_Export.csv", "Financial_Statements.xlsx",
    ]

    # Selectable attack types -> handler method name.
    ATTACK_GENERATORS = {
        "ransomware": "_attack_ransomware",
        "credential_dumping": "_attack_credential_dumping",
        "privilege_escalation": "_attack_privilege_escalation",
        "lateral_movement": "_attack_lateral_movement",
        "usb_data_exfiltration": "_attack_usb_data_exfiltration",
        "unauthorized_software_install": "_attack_unauthorized_software_install",
    }

    # Attack types that represent a BURST of related events rather
    # than a single one -- (min_events, max_events) per trigger.
    # Ransomware encrypts many files in quick succession; lateral
    # movement probes several internal targets; USB exfiltration
    # copies many files in one sweep.
    BURST_ATTACK_RANGES = {
        "ransomware": (10, 30),
        "lateral_movement": (3, 8),
        "usb_data_exfiltration": (5, 20),
    }

    def __init__(self, asset_id: str):
        super().__init__(asset_id)
        self.asset = get_asset(self.asset_id)
        self.hostname = self.asset["hostname"]
        self.ip_address = self.asset["ip_address"]
        self.mac_address = self.asset.get("mac_address")
        self.owner_employee_id = self.asset.get("owner_employee")
        employee = get_employee(self.owner_employee_id) if self.owner_employee_id else None
        self.owner_username = employee["username"] if employee else "unknown"

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
        return f"SESSION-{self.asset_id}-{uuid.uuid4().hex[:8].upper()}"

    def _fake_file_hash(self) -> str:
        return uuid.uuid4().hex + uuid.uuid4().hex[:32]  # 64 hex chars, SHA-256-shaped

    def _build_event(
        self,
        category: EventCategory,
        event_type: str,
        action: str,
        status: EventStatus,
        resource: str,
        resource_type: str,
        data: dict,
        destination_ip: Optional[str] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[Protocol] = None,
        target_asset_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> CommonEvent:
        enriched_data = dict(data)
        enriched_data["source_mac_address"] = self.mac_address

        return CommonEvent(
            event_id=generate_event_id(self.asset_id.split("-")[0]),
            timestamp=get_utc_timestamp(),
            source={
                "asset_id": self.asset_id,
                "asset_type": AssetType.EMPLOYEE_WORKSTATION.value,
                "hostname": self.hostname,
            },
            network={
                "source_ip": self.ip_address,
                "source_port": random.randint(49152, 65535) if destination_ip else None,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol.value if protocol else None,
            },
            actor={
                "user_id": user_id if user_id is not None else self.owner_employee_id,
                "session_id": session_id or self._new_session_id(),
            },
            event={
                "category": category.value,
                "type": event_type,
                "action": action,
                "status": status.value,
            },
            target={
                "asset_id": target_asset_id or self.asset_id,
                "resource": resource,
                "resource_type": resource_type,
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
            self._normal_process_started,
            self._normal_file_accessed,
            self._normal_user_logon,
            self._normal_user_logoff,
            self._normal_network_connection,
            self._normal_usb_file_transfer,
            self._normal_software_installed,
        ]
        return random.choice(generators)()

    def _normal_process_started(self) -> CommonEvent:
        process_name, file_path = random.choice(self.NORMAL_PROCESSES)
        file_path = file_path.replace("{user}", self.owner_username)

        return self._build_event(
            category=EventCategory.PROCESS,
            event_type="process_started",
            action="execute",
            status=EventStatus.SUCCESS,
            resource=process_name,
            resource_type="process",
            data={
                "process_name": process_name,
                "pid": random.randint(1000, 30000),
                "parent_process": self.NORMAL_PARENT_PROCESS,
                "command_line": process_name,
                "file_path": file_path,
                "file_hash": self._fake_file_hash(),
                "privilege_level": "user",
            },
        )

    def _normal_file_accessed(self) -> CommonEvent:
        filename = random.choice(self.NORMAL_FILES)

        return self._build_event(
            category=EventCategory.FILE,
            event_type="file_accessed",
            action="open",
            status=EventStatus.SUCCESS,
            resource=filename,
            resource_type="file",
            data={
                "file_path": rf"C:\Users\{self.owner_username}\Documents\{filename}",
                "access_type": "read_write",
                "file_size_bytes": random.randint(10_000, 5_000_000),
            },
        )

    def _normal_user_logon(self) -> CommonEvent:
        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="user_logon",
            action="authenticate",
            status=EventStatus.SUCCESS,
            resource=self.owner_username,
            resource_type="account",
            data={
                "logon_type": "interactive",
                "username": self.owner_username,
            },
        )

    def _normal_user_logoff(self) -> CommonEvent:
        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="user_logoff",
            action="terminate_session",
            status=EventStatus.SUCCESS,
            resource=self.owner_username,
            resource_type="account",
            data={
                "username": self.owner_username,
            },
        )

    def _normal_network_connection(self) -> CommonEvent:
        # Only connects to assets this workstation legitimately talks to
        allowed_targets = self.asset.get("communicates_with", [])
        target_id = random.choice(allowed_targets) if allowed_targets else "WEB-01"
        target_asset = get_asset(target_id)

        return self._build_event(
            category=EventCategory.NETWORK,
            event_type="network_connection",
            action="connect",
            status=EventStatus.SUCCESS,
            resource=target_asset["hostname"],
            resource_type="network_connection",
            destination_ip=target_asset["ip_address"],
            destination_port=443,
            protocol=Protocol.HTTPS,
            target_asset_id=target_id,
            data={
                "authentication_method": "existing_session",
            },
        )

    def _normal_usb_file_transfer(self) -> CommonEvent:
        filename = random.choice(self.NORMAL_FILES)

        return self._build_event(
            category=EventCategory.FILE,
            event_type="usb_file_transfer",
            action="copy",
            status=EventStatus.SUCCESS,
            resource=filename,
            resource_type="removable_media",
            data={
                "file_name": filename,
                "file_size_bytes": random.randint(20_000, 2_000_000),
                "destination_device": "USB",
                "data_classification": "internal",
            },
        )

    def _normal_software_installed(self) -> CommonEvent:
        software_name, source = random.choice(self.APPROVED_SOFTWARE)

        return self._build_event(
            category=EventCategory.PROCESS,
            event_type="software_installed",
            action="install",
            status=EventStatus.SUCCESS,
            resource=software_name,
            resource_type="software",
            data={
                "software_name": software_name,
                "installer_source": source,
                "publisher_verified": True,
                "approved_by_it": True,
            },
        )

    # ------------------------------------------------------------------
    # ATTACK EVENTS
    # ------------------------------------------------------------------

    def generate_attack_event(self, attack_type: Optional[str] = None) -> CommonEvent:
        """
        Generate one attack event.

        attack_type: one of EndpointSimulator.available_attack_types().
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
        credential_dumping, unauthorized_software_install -- each is a
        single discrete action).

        BURST attack types (see BURST_ATTACK_RANGES: "ransomware",
        "lateral_movement", "usb_data_exfiltration") fire a realistic
        SEQUENCE of related events instead -- ransomware encrypts many
        files in a row, lateral movement probes several internal
        targets, USB exfiltration copies many files -- each spaced
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

        last_event: Optional[CommonEvent] = None

        if key == "ransomware":
            process_name = f"{uuid.uuid4().hex[:8]}.exe"  # random malicious binary name
            files = self.TARGET_FILE_POOL * (count // len(self.TARGET_FILE_POOL) + 1)
            for i in range(count):
                event = self._attack_ransomware(
                    session_id=session_id,
                    process_name=process_name,
                    filename=files[i],
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        elif key == "lateral_movement":
            candidate_targets = [
                a for a in (self.ALL_ENDPOINT_IDS + ["DB-01"]) if a != self.asset_id
            ]
            targets = random.sample(candidate_targets, min(count, len(candidate_targets)))
            # If count exceeds the candidate pool, wrap around with repeats
            while len(targets) < count:
                targets.append(random.choice(candidate_targets))
            for i in range(count):
                event = self._attack_lateral_movement(session_id=session_id, target_id=targets[i])
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        elif key == "usb_data_exfiltration":
            files = self.USB_FILE_POOL * (count // len(self.USB_FILE_POOL) + 1)
            for i in range(count):
                event = self._attack_usb_data_exfiltration(session_id=session_id, filename=files[i])
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count - 1:
                    time.sleep(burst_delay_seconds)

        return last_event

    def _attack_ransomware(
        self,
        session_id: Optional[str] = None,
        process_name: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> CommonEvent:
        """
        One file being encrypted by ransomware. Pass session_id/
        process_name to make several calls represent the SAME
        ransomware process encrypting many files in one run (see
        trigger_attack's burst handling). Called with no arguments,
        it's a single independent encryption event.

        Reuses "file_accessed" -- a write to a file is, at the type
        level, indistinguishable from any normal document save; the
        new extension and rapid repetition are what give it away.
        """
        filename = filename or random.choice(self.TARGET_FILE_POOL)
        process_name = process_name or f"{uuid.uuid4().hex[:8]}.exe"
        new_extension = random.choice(self.RANSOMWARE_EXTENSIONS)

        return self._build_event(
            category=EventCategory.FILE,
            event_type="file_accessed",
            action="write",
            status=EventStatus.BLOCKED,
            resource=filename,
            resource_type="file",
            session_id=session_id,
            data={
                "file_path": rf"C:\Users\{self.owner_username}\Documents\{filename}",
                "new_extension": new_extension,
                "encrypting_process": process_name,
                "parent_process": "unknown",
            },
        )

    def _attack_credential_dumping(self) -> CommonEvent:
        # Reuses "process_started" -- a process reading LSASS memory
        # is still just a process starting/running at the type level;
        # the disguised process name and target_process are the tell.
        accessing_process = random.choice(self.CREDENTIAL_DUMP_PROCESS_NAMES)

        return self._build_event(
            category=EventCategory.PROCESS,
            event_type="process_started",
            action="execute",
            status=EventStatus.BLOCKED,
            resource=accessing_process,
            resource_type="process",
            data={
                "target_process": "lsass.exe",
                "accessing_process": accessing_process,
                "technique": "process_memory_read",
                "pid": random.randint(1000, 30000),
            },
        )

    def _attack_privilege_escalation(self) -> CommonEvent:
        # Reuses "user_logon" -- mirrors real Windows auditing, where
        # a privilege escalation shows up as a special/elevated logon
        # event, not a uniquely-named "escalation" event. The jump
        # from user to SYSTEM privilege is what's anomalous, not the
        # type.
        technique = random.choice(self.PRIVILEGE_ESCALATION_TECHNIQUES)

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="user_logon",
            action="authenticate",
            status=EventStatus.BLOCKED,
            resource=self.owner_username,
            resource_type="account",
            data={
                "from_privilege": "user",
                "to_privilege": "SYSTEM",
                "technique": technique,
            },
        )

    def _attack_lateral_movement(
        self,
        session_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> CommonEvent:
        """
        One connection attempt to another internal asset using stolen
        credentials. Pass session_id/target_id to make several calls
        represent the SAME compromised session probing multiple
        internal targets (see trigger_attack's burst handling). Called
        with no arguments, it's a single independent probe.
        """
        candidate_targets = [a for a in (self.ALL_ENDPOINT_IDS + ["DB-01"]) if a != self.asset_id]
        target_id = target_id or random.choice(candidate_targets)
        target_asset = get_asset(target_id)
        service_name, port = random.choice(self.LATERAL_MOVEMENT_SERVICES)

        return self._build_event(
            category=EventCategory.NETWORK,
            event_type="network_connection",
            action="connect",
            status=EventStatus.FAILURE,
            resource=target_asset["hostname"],
            resource_type="network_connection",
            destination_ip=target_asset["ip_address"],
            destination_port=port,
            protocol=Protocol.TCP,
            target_asset_id=target_id,
            session_id=session_id,
            data={
                "authentication_method": "stolen_credentials",
                "target_service": service_name,
                "remote_execution_attempted": True,
                "destination_mac_address": target_asset.get("mac_address"),
            },
        )

    def _attack_usb_data_exfiltration(
        self,
        session_id: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> CommonEvent:
        """
        One file being copied to removable media as part of a data
        exfiltration sweep. Pass session_id to make several calls
        represent the SAME USB session copying many files in a row
        (see trigger_attack's burst handling). Called with no
        arguments, it's a single independent copy event.
        """
        filename = filename or random.choice(self.USB_FILE_POOL)

        return self._build_event(
            category=EventCategory.FILE,
            event_type="usb_file_transfer",
            action="copy",
            status=EventStatus.BLOCKED,
            resource=filename,
            resource_type="removable_media",
            session_id=session_id,
            data={
                "file_name": filename,
                "file_size_bytes": random.randint(50_000, 10_000_000),
                "destination_device": "USB",
                "data_classification": "confidential",
            },
        )

    def _attack_unauthorized_software_install(self) -> CommonEvent:
        software_name, source = random.choice(self.UNAUTHORIZED_SOFTWARE)

        return self._build_event(
            category=EventCategory.PROCESS,
            event_type="software_installed",
            action="install",
            status=EventStatus.BLOCKED,
            resource=software_name,
            resource_type="software",
            data={
                "software_name": software_name,
                "installer_source": source,
                "publisher_verified": False,
                "approved_by_it": False,
            },
        )

    # ------------------------------------------------------------------
    # CONTINUOUS NORMAL ACTIVITY STREAM
    # ------------------------------------------------------------------

    def stream_normal_events(self, interval_seconds: float = 2.0):
        """
        Generator that yields normal events forever, one every
        interval_seconds, until the caller stops iterating.
        """
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
            raise RuntimeError(f"Normal event stream for {self.asset_id} is already running.")

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
    # Demo: all 4 endpoints run continuous normal activity in the
    # background simultaneously (a realistic fleet of employee PCs).
    # Trigger an attack with: "<attack_type> <asset_id>", e.g.
    # "ransomware END-02". asset_id defaults to END-01 if omitted.
    # Every event -- normal or attack -- is also persisted via
    # shared.storage.event_writer, exactly like run_soc_feed.py does,
    # so running this file directly saves data too, not just prints it.
    import json

    from shared.storage.event_writer import write_event, DEFAULT_EVENT_LOG_PATH, DEFAULT_GROUND_TRUTH_PATH

    def _print_event(event: CommonEvent, prefix: str = "") -> None:
        dump = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        print(prefix.strip())
        print(json.dumps(dump, indent=2, default=str))
        print("-" * 60)

    def _run_live_mode(sims: dict) -> None:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout

        print("(Live mode: normal activity prints in real time as it happens.)\n")

        def normal_handler(e):
            write_event(e, is_attack=False)
            _print_event(e, prefix="[NORMAL] ")

        for sim in sims.values():
            sim.start_normal_stream(on_event=normal_handler, interval_seconds=3.0)

        session: PromptSession = PromptSession()

        with patch_stdout():
            while True:
                raw = session.prompt("attack> ").strip()
                if raw.lower() in ("quit", "exit"):
                    break
                if not raw:
                    continue
                parts = raw.split()
                attack_type = parts[0]
                target_id = parts[1].upper() if len(parts) > 1 else "END-01"
                sim = sims.get(target_id)
                if sim is None:
                    print(f"Unknown endpoint '{target_id}'. Available: {', '.join(sims.keys())}")
                    continue

                def attack_handler(e, _attack_type=attack_type):
                    write_event(e, is_attack=True, attack_type=_attack_type)
                    _print_event(e, prefix="[ATTACK] ")

                try:
                    sim.trigger_attack(attack_type, on_event=attack_handler)
                except ValueError as exc:
                    print(exc)

    def _run_buffered_mode(sims: dict) -> None:
        import queue

        event_queue: "queue.Queue[tuple[str, CommonEvent]]" = queue.Queue()

        def _drain_event_queue() -> None:
            while True:
                try:
                    prefix, event = event_queue.get_nowait()
                except queue.Empty:
                    break
                _print_event(event, prefix=prefix)

        print("(Buffered mode: normal activity prints between prompts, not live.")
        print(" `pip install prompt_toolkit` for real-time output.)\n")

        def normal_handler(e):
            write_event(e, is_attack=False)
            event_queue.put(("[NORMAL] ", e))

        for sim in sims.values():
            sim.start_normal_stream(on_event=normal_handler, interval_seconds=3.0)

        while True:
            _drain_event_queue()
            raw = input("attack> ").strip()
            _drain_event_queue()
            if raw.lower() in ("quit", "exit"):
                break
            if not raw:
                continue
            parts = raw.split()
            attack_type = parts[0]
            target_id = parts[1].upper() if len(parts) > 1 else "END-01"
            sim = sims.get(target_id)
            if sim is None:
                print(f"Unknown endpoint '{target_id}'. Available: {', '.join(sims.keys())}")
                continue

            def attack_handler(e, _attack_type=attack_type):
                write_event(e, is_attack=True, attack_type=_attack_type)
                event_queue.put(("[ATTACK] ", e))

            try:
                sim.trigger_attack(attack_type, on_event=attack_handler)
                _drain_event_queue()
            except ValueError as exc:
                print(exc)

    _sims = {aid: EndpointSimulator(aid) for aid in EndpointSimulator.ALL_ENDPOINT_IDS}

    print("Starting continuous activity for:", ", ".join(_sims.keys()), "(Ctrl+C / 'quit' to stop).")
    print("Available attacks:", ", ".join(EndpointSimulator.available_attack_types()))
    print("Usage: <attack_type> <asset_id>   e.g. 'ransomware END-02'   (asset_id defaults to END-01)")
    print(f"Event log:        {DEFAULT_EVENT_LOG_PATH}")
    print(f"Ground truth log: {DEFAULT_GROUND_TRUTH_PATH}")

    try:
        try:
            _run_live_mode(_sims)
        except ImportError:
            _run_buffered_mode(_sims)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        for _sim in _sims.values():
            _sim.stop_normal_stream()
        print("\nStopped.")