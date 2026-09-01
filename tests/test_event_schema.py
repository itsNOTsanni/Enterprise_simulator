from shared.schemas.event_schema import (
    Actor,
    CommonEvent,
    Context,
    EventDetails,
    Network,
    Source,
    Target,
)


event = CommonEvent(
    event_id="EVT-WEB-000001",
    timestamp="2026-08-22T10:15:01.123Z",

    source=Source(
        asset_id="WEB-01",
        asset_type="web_server",
        hostname="web-01"
    ),

    network=Network(
        source_ip="10.10.2.10",
        source_port=52341,
        destination_ip="10.10.1.10",
        destination_port=443,
        protocol="HTTPS"
    ),

    actor=Actor(
        user_id=None,
        session_id="SESSION-WEB-0001"
    ),

    event=EventDetails(
        category="authentication",
        type="login_attempt",
        action="authenticate",
        status="failure"
    ),

    target=Target(
        asset_id="WEB-01",
        resource="/login",
        resource_type="endpoint"
    ),

    data={
        "http_method": "POST",
        "http_status": 401,
        "username_attempted": "admin",
        "request_input_length": 12,
        "special_characters_present": False,
        "attempt_number_in_session": 1
    },

    context=Context(
        environment="simulated_enterprise",
        simulation=True
    )
)


print(event.model_dump_json(indent=2))