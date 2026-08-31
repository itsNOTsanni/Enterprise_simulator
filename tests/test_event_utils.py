from shared.utils import (
    generate_event_id,
    get_utc_timestamp,
)


print("========== EVENT IDs ==========")

web_event = generate_event_id("WEB")
db_event = generate_event_id("DB")
endpoint_event = generate_event_id("END")
cloud_event = generate_event_id("CLOUD")

print(web_event)
print(db_event)
print(endpoint_event)
print(cloud_event)


print("\n========== UTC TIMESTAMP ==========")

timestamp = get_utc_timestamp()

print(timestamp)
print(timestamp.isoformat())