from datetime import datetime, timezone


def get_utc_timestamp() -> datetime:
    """
    Return the current timestamp in UTC.
    """

    return datetime.now(timezone.utc)