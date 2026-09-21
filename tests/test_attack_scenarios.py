from simulator.attacker.attack_scenarios import AttackScenarios


# ============================================================
# EVENT DISPLAY HELPER
# ============================================================

def print_attack_event(event):
    """
    Print an attack event in a clear vertical format.
    """

    print()
    print("------------------------------------------------------------")
    print(f"EVENT ID: {event.event_id}")
    print(f"TIMESTAMP: {event.timestamp}")

    print()
    print("SOURCE")
    print(f"  Asset ID:   {event.source.asset_id}")
    print(f"  Asset Type: {event.source.asset_type}")
    print(f"  Hostname:   {event.source.hostname}")

    print()
    print("NETWORK")
    print(f"  Source IP:        {event.network.source_ip}")
    print(f"  Source Port:      {event.network.source_port}")
    print(f"  Destination IP:   {event.network.destination_ip}")
    print(f"  Destination Port: {event.network.destination_port}")
    print(f"  Protocol:         {event.network.protocol}")

    print()
    print("ACTOR")
    print(f"  User ID:    {event.actor.user_id}")
    print(f"  Session ID: {event.actor.session_id}")

    print()
    print("EVENT DETAILS")
    print(f"  Category: {event.event.category}")
    print(f"  Type:     {event.event.type}")
    print(f"  Action:   {event.event.action}")
    print(f"  Status:   {event.event.status}")

    print()
    print("TARGET")
    print(f"  Asset ID:      {event.target.asset_id}")
    print(f"  Resource:      {event.target.resource}")
    print(f"  Resource Type: {event.target.resource_type}")

    print()
    print("DATA")

    for key, value in event.data.items():
        formatted_key = key.replace("_", " ").title()
        print(f"  {formatted_key}: {value}")

    print()
    print("CONTEXT")
    print(f"  Environment: {event.context.environment}")
    print(f"  Simulation:  {event.context.simulation}")

    print("------------------------------------------------------------")


# ============================================================
# BRUTE FORCE ATTACK TEST
# ============================================================

def test_brute_force_attack():

    attack_scenarios = AttackScenarios()

    attempts = 10

    events = attack_scenarios.brute_force_attack(
        attempts=attempts,
        interval_seconds=2
    )

    # --------------------------------------------------------
    # CHECK TOTAL NUMBER OF EVENTS
    # --------------------------------------------------------

    assert len(events) == attempts

    # --------------------------------------------------------
    # CHECK EVERY GENERATED EVENT
    # --------------------------------------------------------

    for index, event in enumerate(events, start=1):

        # ----------------------------------------------------
        # SOURCE VALIDATION
        # ----------------------------------------------------

        assert event.source.asset_id == "WEB-01"

        assert event.source.asset_type == (
            "web_server"
        )

        assert event.source.hostname == "web-01"

        # ----------------------------------------------------
        # NETWORK VALIDATION
        # ----------------------------------------------------

        assert str(
            event.network.source_ip
        ) == "10.10.2.10"

        assert str(
            event.network.destination_ip
        ) == "10.10.1.10"

        assert event.network.destination_port == 443

        assert event.network.protocol == "HTTPS"

        # ----------------------------------------------------
        # ACTOR VALIDATION
        # ----------------------------------------------------

        assert event.actor.user_id is None

        assert event.actor.session_id == (
            "ATTACK-BRUTE-001"
        )

        # ----------------------------------------------------
        # EVENT VALIDATION
        # ----------------------------------------------------

        assert event.event.category == (
            "authentication"
        )

        assert event.event.type == (
            "login_attempt"
        )

        assert event.event.action == (
            "authenticate"
        )

        assert event.event.status == "failure"

        # ----------------------------------------------------
        # TARGET VALIDATION
        # ----------------------------------------------------

        assert event.target.asset_id == "WEB-01"

        assert event.target.resource == "/login"

        assert event.target.resource_type == (
            "endpoint"
        )

        # ----------------------------------------------------
        # ATTACK DATA VALIDATION
        # ----------------------------------------------------

        assert event.data.get(
            "attack_type"
        ) == "brute_force"

        assert event.data.get(
            "scenario_id"
        ) == "SCENARIO-BRUTE-001"

        assert event.data.get(
            "attempt_number_in_session"
        ) == index

        assert event.data.get(
            "total_attempts"
        ) == attempts

        # ----------------------------------------------------
        # CONTEXT VALIDATION
        # ----------------------------------------------------

        assert event.context.environment == (
            "simulated_enterprise"
        )

        assert event.context.simulation is True

        # ----------------------------------------------------
        # DISPLAY EVENT
        # ----------------------------------------------------

        print_attack_event(event)

    print()
    print("Brute Force Attack Scenario: PASSED")


# ============================================================
# TIMESTAMP SEQUENCE TEST
# ============================================================

def test_brute_force_timestamp_sequence():

    attack_scenarios = AttackScenarios()

    interval_seconds = 2

    events = attack_scenarios.brute_force_attack(
        attempts=5,
        interval_seconds=interval_seconds
    )

    for index in range(1, len(events)):

        previous_timestamp = (
            events[index - 1].timestamp
        )

        current_timestamp = (
            events[index].timestamp
        )

        difference = (
            current_timestamp
            - previous_timestamp
        )

        assert difference.total_seconds() == (
            interval_seconds
        )

    print(
        "Brute Force Timestamp Sequence: PASSED"
    )


# ============================================================
# INVALID ATTEMPTS TEST
# ============================================================

def test_invalid_attempts():

    attack_scenarios = AttackScenarios()

    try:

        attack_scenarios.brute_force_attack(
            attempts=0
        )

        assert False

    except ValueError:

        pass

    try:

        attack_scenarios.brute_force_attack(
            attempts=-5
        )

        assert False

    except ValueError:

        pass

    print("Invalid Attempts Validation: PASSED")


# ============================================================
# INVALID INTERVAL TEST
# ============================================================

def test_invalid_interval():

    attack_scenarios = AttackScenarios()

    try:

        attack_scenarios.brute_force_attack(
            attempts=5,
            interval_seconds=-1
        )

        assert False

    except ValueError:

        pass

    print("Invalid Interval Validation: PASSED")

def test_path_traversal_attack():

    attack_scenarios = AttackScenarios()

    events = (
        attack_scenarios.path_traversal_attack(
            attempts=5,
            interval_seconds=2
        )
    )

    assert len(events) == 5

    for index, event in enumerate(
        events,
        start=1
    ):

        assert event.source.asset_id == "WEB-01"

        assert (
            event.data.get("attack_type")
            == "path_traversal"
        )

        assert (
            event.data.get("scenario_id")
            == "SCENARIO-PATH-001"
        )

        assert (
            event.actor.session_id
            == "ATTACK-PATH-001"
        )

        assert (
            str(event.network.source_ip)
            == "10.10.2.11"
        )

        assert (
            event.data.get(
                "attempt_number_in_session"
            )
            == index
        )

        assert (
            event.data.get("total_attempts")
            == 5
        )

        print_event(event)

    print()
    print(
        "Path Traversal Attack Scenario: PASSED"
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("ATTACK SCENARIOS TEST")
    print("=" * 60)

    test_brute_force_attack()

    print()

    test_brute_force_timestamp_sequence()

    test_invalid_attempts()

    test_invalid_interval()

    print()
    print("=" * 60)
    print("ALL ATTACK SCENARIO TESTS PASSED")
    print("=" * 60)
