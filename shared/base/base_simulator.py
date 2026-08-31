from abc import ABC, abstractmethod
from typing import List
import random

from shared.schemas.event_schema import CommonEvent


class BaseSimulator(ABC):
    """
    Base interface for all enterprise asset simulators.

    Every simulator must implement:
    - generate_normal_event()
    - generate_attack_event()

    Supported modes:
    - normal
    - attack
    - mixed
    """

    def __init__(self, asset_id: str):
        """
        Initialize the simulator with its enterprise asset ID.

        Example:
        WEB-01
        DB-01
        END-01
        CLOUD-01
        """

        self.asset_id = asset_id

    @abstractmethod
    def generate_normal_event(self) -> CommonEvent:
        """
        Generate one normal/benign enterprise event.

        This method must be implemented by each simulator.
        """

        pass

    @abstractmethod
    def generate_attack_event(self) -> CommonEvent:
        """
        Generate one simulated attack or suspicious event.

        This method must be implemented by each simulator.
        """

        pass

    def generate_events(
        self,
        mode: str,
        count: int
    ) -> List[CommonEvent]:
        """
        Generate multiple events based on the selected simulation mode.

        Supported modes:

        normal:
            Generate only normal events.

        attack:
            Generate only simulated attack events.

        mixed:
            Generate a random mixture of normal and attack events.
        """

        if count <= 0:
            raise ValueError(
                "Event count must be greater than zero."
            )

        mode = mode.lower()

        valid_modes = [
            "normal",
            "attack",
            "mixed"
        ]

        if mode not in valid_modes:
            raise ValueError(
                f"Unsupported simulation mode: {mode}. "
                f"Supported modes: {', '.join(valid_modes)}"
            )

        events = []

        for _ in range(count):

            if mode == "normal":

                event = self.generate_normal_event()

            elif mode == "attack":

                event = self.generate_attack_event()

            elif mode == "mixed":

                event_generator = random.choice(
                    [
                        self.generate_normal_event,
                        self.generate_attack_event
                    ]
                )

                event = event_generator()

            events.append(event)

        return events