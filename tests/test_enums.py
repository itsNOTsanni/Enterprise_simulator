from shared.constants import (
    SimulationMode,
    EventStatus,
    EventCategory,
    Protocol,
    AssetType,
)


print("========== SIMULATION MODES ==========")

for mode in SimulationMode:
    print(mode.value)


print("\n========== EVENT STATUS ==========")

for status in EventStatus:
    print(status.value)


print("\n========== EVENT CATEGORIES ==========")

for category in EventCategory:
    print(category.value)


print("\n========== PROTOCOLS ==========")

for protocol in Protocol:
    print(protocol.value)


print("\n========== ASSET TYPES ==========")

for asset_type in AssetType:
    print(asset_type.value)