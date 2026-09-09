
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


class WebServerSimulator(BaseSimulator):
    """
    Simulator for WEB-01, the enterprise web server.

    Normal activity: employee logins, page views, form submissions,
    internal API calls, static asset requests, logouts -- all sourced
    from the internal endpoints (END-01..04) that the asset registry
    lists under WEB-01's communicates_with.

    Attack activity: brute-force login attempts, SQL injection, XSS,
    path traversal, directory brute-forcing, and command injection --
    sourced from external IPs, reflecting an outside attacker hitting
    the Flask/Nginx front end.

    Generation model:
        Normal traffic runs CONTINUOUSLY in the background at a fixed
        cadence -- start it with start_normal_stream() and it keeps
        producing events on its own until stop_normal_stream() is
        called. This represents the constant baseline hum of a real
        web server.

        Attacks are NOT auto-injected into that stream. They only fire
        when explicitly selected via trigger_attack("sql_injection")
        (or generate_attack_event(attack_type=...) directly), so a
        human operator or an orchestrating script decides exactly when
        and what attack occurs -- the timing is meaningful, not random
        background noise.
    """

    # Internal endpoints that legitimately talk to WEB-01
    # (config/asset_registry.yaml -> WEB-01.communicates_with)
    INTERNAL_ENDPOINTS = ["END-01", "END-02", "END-03", "END-04"]

    NORMAL_PAGES = ["/", "/dashboard", "/profile", "/orders", "/reports", "/settings"]
    STATIC_ASSETS = ["/static/css/main.css", "/static/js/app.js", "/static/img/logo.png", "/favicon.ico"]
    API_ENDPOINTS = ["/api/v1/orders", "/api/v1/profile", "/api/v1/reports"]

    # External source IPs simulating an outside attacker (outside 10.10.1.0/24)
    EXTERNAL_SOURCE_IPS = ["203.0.113.15", "198.51.100.42", "192.0.2.77", "203.0.113.99"]

    SQLI_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users;--", "' UNION SELECT NULL--", "admin'--"]
    XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "<svg/onload=alert('xss')>"]
    PATH_TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//boot.ini"]
    COMMAND_INJECTION_PAYLOADS = ["; cat /etc/passwd", "| whoami", "&& id"]

    # CSRF: state-changing endpoints an attacker could try to forge a
    # request against using a logged-in victim's browser.
    CSRF_TARGET_ENDPOINTS = ["/orders/create", "/settings", "/profile"]

    # SSRF: internal/sensitive URLs an attacker tries to make WEB-01
    # itself fetch on their behalf via a vulnerable endpoint.
    SSRF_TARGET_URLS = [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata endpoint
        "http://10.10.1.20:5432/",                    # DB-01
        "http://10.10.1.40/",                          # CLOUD-01
        "http://127.0.0.1:22/",                        # localhost SSH
    ]

    # Insecure file upload: filenames disguising an executable payload
    # as an innocuous document/image.
    MALICIOUS_UPLOAD_FILENAMES = [
        ("invoice.pdf.php", "image/png", "application/x-php"),
        ("profile.jpg.exe", "image/jpeg", "application/x-msdownload"),
        ("resume.docx.jsp", "application/msword", "application/x-jsp"),
        ("photo.png.sh", "image/png", "application/x-sh"),
    ]

    # Selectable attack types -> handler method name.
    # Used by generate_attack_event(attack_type=...) / trigger_attack(...)
    # so a caller can name exactly which attack to fire on demand.
    ATTACK_GENERATORS = {
        "brute_force": "_attack_brute_force",
        "sql_injection": "_attack_sql_injection",
        "xss": "_attack_xss",
        "path_traversal": "_attack_path_traversal",
        "command_injection": "_attack_command_injection",
        "csrf": "_attack_csrf",
        "ssrf": "_attack_ssrf",
        "insecure_file_upload": "_attack_insecure_file_upload",
    }

    # Attack types that represent a BURST of related attempts rather
    # than a single request -- (min_events, max_events) per trigger.
    # A real brute force tries many passwords in one session; a real
    # directory scan probes many paths in one sweep; a real IDOR/
    # broken-access-control attack enumerates many resource IDs in
    # one session.
    BURST_ATTACK_RANGES = {
        "brute_force": (5, 15),
    }

    def __init__(self, asset_id: str = "WEB-01"):
        super().__init__(asset_id)
        self.asset = get_asset(self.asset_id)
        self.hostname = self.asset["hostname"]
        self.ip_address = self.asset["ip_address"]

        # Background continuous normal-traffic stream state
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
        return f"SESSION-WEB-{uuid.uuid4().hex[:8].upper()}"

    def _random_internal_source(self):
        """Pick a random internal endpoint + its owning employee_id."""
        endpoint_id = random.choice(self.INTERNAL_ENDPOINTS)
        endpoint_asset = get_asset(endpoint_id)
        employee_id = endpoint_asset.get("owner_employee")
        return endpoint_asset["ip_address"], employee_id

    def _build_event(
        self,
        category: EventCategory,
        event_type: str,
        action: str,
        status: EventStatus,
        source_ip: str,
        destination_port: int,
        protocol: Protocol,
        user_id,
        session_id: str,
        resource: str,
        resource_type: str,
        data: dict,
    ) -> CommonEvent:
        return CommonEvent(
            event_id=generate_event_id("WEB"),
            timestamp=get_utc_timestamp(),
            source={
                "asset_id": self.asset_id,
                "asset_type": AssetType.WEB_SERVER.value,
                "hostname": self.hostname,
            },
            network={
                "source_ip": source_ip,
                "source_port": random.randint(49152, 65535),
                "destination_ip": self.ip_address,
                "destination_port": destination_port,
                "protocol": protocol.value,
            },
            actor={
                "user_id": user_id,
                "session_id": session_id,
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
            self._normal_login_success,
            self._normal_page_view,
            self._normal_form_submission,
            self._normal_api_call,
            self._normal_static_asset_request,
            self._normal_logout,
        ]
        return random.choice(generators)()

    def _normal_login_success(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()
        employee = get_employee(employee_id) if employee_id else None
        username = employee["username"] if employee else "unknown"

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="login_attempt",
            action="authenticate",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource="/login",
            resource_type="endpoint",
            data={
                "http_method": "POST",
                "http_status": 200,
                "username_attempted": username,
                "request_input_length": len(username) + 10,
                "special_characters_present": False,
                "attempt_number_in_session": 1,
            },
        )

    def _normal_page_view(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()
        page = random.choice(self.NORMAL_PAGES)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="page_view",
            action="view",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource=page,
            resource_type="page",
            data={
                "http_method": "GET",
                "http_status": 200,
                "response_size_bytes": random.randint(1500, 45000),
                "referrer": random.choice(self.NORMAL_PAGES),
            },
        )

    def _normal_form_submission(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()

        return self._build_event(
            category=EventCategory.WEB,
            event_type="form_submission",
            action="submit",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource="/orders/create",
            resource_type="form",
            data={
                "http_method": "POST",
                "http_status": 201,
                "fields_submitted": random.randint(3, 8),
                "special_characters_present": False,
            },
        )

    def _normal_api_call(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()
        endpoint = random.choice(self.API_ENDPOINTS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="api_call",
            action="request",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource=endpoint,
            resource_type="api_endpoint",
            data={
                "http_method": random.choice(["GET", "POST"]),
                "http_status": 200,
                "response_time_ms": random.randint(20, 300),
            },
        )

    def _normal_static_asset_request(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()
        asset_path = random.choice(self.STATIC_ASSETS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="static_asset_request",
            action="fetch",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource=asset_path,
            resource_type="static_asset",
            data={
                "http_method": "GET",
                "http_status": 200,
                "cached": random.choice([True, False]),
            },
        )

    def _normal_logout(self) -> CommonEvent:
        source_ip, employee_id = self._random_internal_source()

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="logout",
            action="terminate_session",
            status=EventStatus.SUCCESS,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource="/logout",
            resource_type="endpoint",
            data={
                "http_method": "POST",
                "http_status": 200,
            },
        )

    # ------------------------------------------------------------------
    # ATTACK EVENTS
    # ------------------------------------------------------------------

    def generate_attack_event(self, attack_type: Optional[str] = None) -> CommonEvent:
        """
        Generate one attack event.

        attack_type: one of WebServerSimulator.available_attack_types()
            (e.g. "sql_injection", "brute_force"). If omitted, a random
            attack type is chosen -- this fallback exists only so this
            method still satisfies BaseSimulator's zero-arg abstract
            signature and BaseSimulator.generate_events("attack", ...).
            For deliberate, on-demand attacks, always pass attack_type
            explicitly (or use trigger_attack(), which requires it).
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
        Fire a specific attack immediately, on demand.

        This is the entry point a dashboard, CLI, or orchestrating
        script should call when a user/operator selects an attack --
        it never runs automatically and is independent of the
        continuous normal-traffic stream below.

        Most attack types fire exactly ONE event (one malicious
        request is the whole attack: one SQLi payload, one XSS
        payload, etc).

        BURST attack types (see BURST_ATTACK_RANGES: currently
        "brute_force", "directory_brute_force", and
        "broken_access_control") instead fire a
        realistic SEQUENCE of related events from the same attacker
        session -- a brute force tries several different
        usernames/passwords in a row, a directory scan probes several
        paths in a row -- each spaced burst_delay_seconds apart. Every
        event in the burst is passed to on_event as it's generated (in
        order); the return value is the LAST event of the burst.

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
        source_ip = random.choice(self.EXTERNAL_SOURCE_IPS)

        last_event: Optional[CommonEvent] = None

        if key == "brute_force":
            usernames = ["admin", "root", "administrator", "employee01", "employee02", "test"]
            for i in range(1, count + 1):
                event = self._attack_brute_force(
                    session_id=session_id,
                    source_ip=source_ip,
                    attempt_number=i,
                    username_attempted=usernames[(i - 1) % len(usernames)],
                )
                if on_event is not None:
                    on_event(event)
                last_event = event
                if i < count:
                    time.sleep(burst_delay_seconds)

        return last_event

    # ------------------------------------------------------------------
    # CONTINUOUS NORMAL TRAFFIC STREAM
    # ------------------------------------------------------------------

    def stream_normal_events(self, interval_seconds: float = 2.0):
        """
        Generator that yields normal events forever, one every
        interval_seconds, until the caller stops iterating (e.g. via
        `break` or by not calling next() again). Use this for simple
        single-threaded loops:

            for event in sim.stream_normal_events(interval_seconds=1.0):
                handle(event)
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
        Start continuously generating normal traffic in a background
        daemon thread, calling on_event(event) each time. Keeps running
        until stop_normal_stream() is called -- this is the "always on"
        baseline traffic; attacks are layered on top only when
        trigger_attack()/generate_attack_event() is called separately.

        jitter_seconds randomizes the interval slightly (+/-) so
        traffic doesn't look like an artificial metronome.
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
        """Stop the background normal-traffic stream started above."""
        self._stop_event.set()
        if self._stream_thread is not None:
            self._stream_thread.join(timeout=timeout)
            self._stream_thread = None

    def is_streaming(self) -> bool:
        return self._stream_thread is not None and self._stream_thread.is_alive()

    def _attack_brute_force(
        self,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        attempt_number: Optional[int] = None,
        username_attempted: Optional[str] = None,
    ) -> CommonEvent:
        """
        One failed login attempt. Pass session_id/source_ip/attempt_number
        to make several calls represent the SAME attacker session working
        through a password list (see trigger_attack's burst handling).
        Called with no arguments, it's a single independent attempt.
        """
        username_attempted = username_attempted or random.choice(
            ["admin", "root", "administrator", "employee01"]
        )

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="login_attempt",
            action="authenticate",
            status=EventStatus.FAILURE,
            source_ip=source_ip or random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=session_id or self._new_session_id(),
            resource="/login",
            resource_type="endpoint",
            data={
                "http_method": "POST",
                "http_status": 401,
                "username_attempted": username_attempted,
                "request_input_length": len(username_attempted) + 8,
                "special_characters_present": False,
                "attempt_number_in_session": (
                    attempt_number if attempt_number is not None else random.randint(3, 40)
                ),
            },
        )

    def _attack_sql_injection(self) -> CommonEvent:
        # Targets the login form, so it reuses "login_attempt" -- an
        # attempted SQLi in the username field looks, at the type
        # level, exactly like a real login. Only the payload details
        # and lack of a real username give it away.
        payload = random.choice(self.SQLI_PAYLOADS)

        return self._build_event(
            category=EventCategory.AUTHENTICATION,
            event_type="login_attempt",
            action="authenticate",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource="/login",
            resource_type="endpoint",
            data={
                "http_method": "POST",
                "http_status": 403,
                "injection_vector": "username_field",
                "payload_sample": payload,
                "request_input_length": len(payload),
                "special_characters_present": True,
            },
        )

    def _attack_xss(self) -> CommonEvent:
        # A form submission carrying an XSS payload -- reuses
        # "form_submission" so it's structurally identical to a normal
        # order/profile form post at the type level.
        payload = random.choice(self.XSS_PAYLOADS)
        target_page = random.choice(["/orders/create", "/profile", "/reports"])

        return self._build_event(
            category=EventCategory.WEB,
            event_type="form_submission",
            action="submit",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource=target_page,
            resource_type="form",
            data={
                "http_method": "POST",
                "http_status": 403,
                "injection_vector": "form_field",
                "payload_sample": payload,
                "request_input_length": len(payload),
                "special_characters_present": True,
            },
        )

    def _attack_path_traversal(self) -> CommonEvent:
        # A GET request for a file -- reuses "page_view" so it's
        # structurally identical to browsing to any page.
        payload = random.choice(self.PATH_TRAVERSAL_PAYLOADS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="page_view",
            action="view",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource=f"/download?file={payload}",
            resource_type="endpoint",
            data={
                "http_method": "GET",
                "http_status": 403,
                "payload_sample": payload,
                "request_input_length": len(payload),
                "special_characters_present": True,
            },
        )

    def _attack_command_injection(self) -> CommonEvent:
        # Reuses "api_call" -- structurally the same as any other API
        # request; the payload in the input field is what's malicious.
        payload = random.choice(self.COMMAND_INJECTION_PAYLOADS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="api_call",
            action="request",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource="/api/v1/reports",
            resource_type="api_endpoint",
            data={
                "http_method": "POST",
                "http_status": 403,
                "payload_sample": payload,
                "request_input_length": len(payload),
                "special_characters_present": True,
            },
        )

    def _attack_csrf(self) -> CommonEvent:
        """
        Cross-Site Request Forgery: a victim's already-authenticated
        browser is tricked (by a malicious third-party site) into
        submitting a state-changing request to WEB-01 without the
        victim's intent. Source IP is the VICTIM's internal machine
        (their browser really did send it) -- what marks it as CSRF is
        the missing/invalid token and the cross-site referrer, not the
        type: it reuses "form_submission" since that's literally what
        it is.
        """
        source_ip, employee_id = self._random_internal_source()
        target = random.choice(self.CSRF_TARGET_ENDPOINTS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="form_submission",
            action="submit",
            status=EventStatus.BLOCKED,
            source_ip=source_ip,
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=employee_id,
            session_id=self._new_session_id(),
            resource=target,
            resource_type="form",
            data={
                "http_method": "POST",
                "http_status": 403,
                "csrf_token_present": False,
                "cross_site_referrer": "https://malicious-site.example",
            },
        )

    def _attack_ssrf(self) -> CommonEvent:
        """
        Server-Side Request Forgery: an external attacker abuses a
        vulnerable endpoint to make WEB-01 ITSELF issue a request to an
        internal/sensitive target (cloud metadata, DB-01, localhost)
        that the attacker couldn't reach directly. Reuses "api_call"
        since, at the type level, it's just another API request.
        """
        target_url = random.choice(self.SSRF_TARGET_URLS)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="api_call",
            action="request",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource="/api/v1/fetch",
            resource_type="api_endpoint",
            data={
                "http_method": "POST",
                "http_status": 403,
                "requested_target_url": target_url,
                "blocked_reason": "internal_address_blocked",
            },
        )

    def _attack_insecure_file_upload(self) -> CommonEvent:
        """
        Attacker uploads a file whose real content type doesn't match
        its declared type/extension (e.g. a PHP/EXE script disguised
        as an image or document) via an upload endpoint. Reuses
        "form_submission" -- an upload is, structurally, just a form
        post; the content-type mismatch is what's malicious.
        """
        filename, declared_type, actual_type = random.choice(self.MALICIOUS_UPLOAD_FILENAMES)

        return self._build_event(
            category=EventCategory.WEB,
            event_type="form_submission",
            action="submit",
            status=EventStatus.BLOCKED,
            source_ip=random.choice(self.EXTERNAL_SOURCE_IPS),
            destination_port=443,
            protocol=Protocol.HTTPS,
            user_id=None,
            session_id=self._new_session_id(),
            resource="/upload",
            resource_type="endpoint",
            data={
                "http_method": "POST",
                "http_status": 403,
                "filename": filename,
                "declared_content_type": declared_type,
                "actual_content_type": actual_type,
                "file_size_bytes": random.randint(2_000, 500_000),
                "upload_blocked_reason": "content_type_mismatch",
            },
        )


if __name__ == "__main__":
    # Demo: normal traffic runs continuously in the background; you
    # select attacks interactively while it keeps running.
    import json

    def _print_event(event: CommonEvent, prefix: str = "") -> None:
        dump = event.model_dump() if hasattr(event, "model_dump") else event.dict()
        print(prefix.strip())
        print(json.dumps(dump, indent=2, default=str))
        print("-" * 60)

    def _run_live_mode(sim: "WebServerSimulator") -> None:
        """
        Uses prompt_toolkit so the background thread can print events
        the instant they happen -- even mid-keystroke -- while safely
        redrawing whatever you're typing at the prompt around them.
        """
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout

        print("(Live mode: normal traffic prints in real time as it happens.)\n")

        sim.start_normal_stream(
            on_event=lambda e: _print_event(e, prefix="[NORMAL] "),
            interval_seconds=2.0,
        )

        session: PromptSession = PromptSession()

        with patch_stdout():
            while True:
                selection = session.prompt("attack> ").strip()
                if selection.lower() in ("quit", "exit"):
                    break
                if not selection:
                    continue
                try:
                    sim.trigger_attack(
                        selection,
                        on_event=lambda e: _print_event(e, prefix="[ATTACK] "),
                    )
                except ValueError as exc:
                    print(exc)

    def _run_buffered_mode(sim: "WebServerSimulator") -> None:
        """
        Fallback when prompt_toolkit isn't installed. Events queue up
        and only flush right before/after each input() call, so normal
        traffic won't appear until you press Enter -- but typing stays
        clean either way. `pip install prompt_toolkit` for live mode.
        """
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

        sim.start_normal_stream(
            on_event=lambda e: event_queue.put(("[NORMAL] ", e)),
            interval_seconds=2.0,
        )

        while True:
            _drain_event_queue()
            selection = input("attack> ").strip()
            _drain_event_queue()
            if selection.lower() in ("quit", "exit"):
                break
            if not selection:
                continue
            try:
                sim.trigger_attack(
                    selection,
                    on_event=lambda e: event_queue.put(("[ATTACK] ", e)),
                )
                _drain_event_queue()
            except ValueError as exc:
                print(exc)

    _sim = WebServerSimulator("WEB-01")

    print("Starting continuous WEB-01 normal traffic (Ctrl+C / 'quit' to stop).")
    print("Available attacks:", ", ".join(_sim.available_attack_types()))

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