from uuid import uuid4


def generate_event_id(source: str) -> str:
    """
    Generate a unique event ID.

    Example:
    EVT-WEB-a1b2c3d4
    """

    unique_id = uuid4().hex[:8].upper()

    return f"EVT-{source.upper()}-{unique_id}"