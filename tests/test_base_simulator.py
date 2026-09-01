from shared.base import BaseSimulator
from shared.schemas.event_schema import (
    Actor,
    CommonEvent,
    Context,
    EventDetails,
    Network,
    Source,
    Target,
)
from shared.utils import (
    generate_event_id,
    get_utc_timestamp,
)


class TestSimulator(BaseSimulator):

    def generate_normal_event(self) -> CommonEvent:

        return CommonEvent(
            event_id=generate_event_id("TEST"),

            timestamp=get_utc_timestamp(),

            source=Source(
                asset_id=self.asset_id,
                asset_type="test_asset",
                hostname="test-host"
            ),

            network=Network(),

            actor=Actor(),

            event=EventDetails(
                category="test",
                type="normal_event",
                action="simulate",
                status="success"
            ),

            target=Target(
                asset_id=self.asset_id
            ),

            data={
                "message": "Normal test event"
            },

            context=Context(
                environment="simulated_enterprise",
                simulation=True
            )
        )

    def generate_attack_event(self) -> CommonEvent:

        return CommonEvent(
            event_id=generate_event_id("TEST"),

            timestamp=get_utc_timestamp(),

            source=Source(
                asset_id=self.asset_id,
                asset_type="test_asset",
                hostname="test-host"
            ),

            network=Network(),

            actor=Actor(),

            event=EventDetails(
                category="test",
                type="attack_event",
                action="simulate",
                status="failure"
            ),

            target=Target(
                asset_id=self.asset_id
            ),

            data={
                "message": "Simulated attack event"
            },

            context=Context(
                environment="simulated_enterprise",
                simulation=True
            )
        )


simulator = TestSimulator("TEST-01")


print("========== NORMAL EVENTS ==========")

normal_events = simulator.generate_events(
    mode="normal",
    count=2
)

for event in normal_events:
    print(event.model_dump_json(indent=2))


print("\n========== ATTACK EVENTS ==========")

attack_events = simulator.generate_events(
    mode="attack",
    count=2
)

for event in attack_events:
    print(event.model_dump_json(indent=2))