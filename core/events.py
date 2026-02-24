from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List
import time
import uuid


@dataclass
class Event:
    event_id: str
    timestamp: float
    type: str
    payload: Dict[str, Any]

    @classmethod
    def create(cls, type_: str, payload: Dict[str, Any]) -> "Event":
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            type=type_,
            payload=payload,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


Subscriber = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Subscriber]] = {}

    def subscribe(self, event_type: str, callback: Subscriber) -> None:
        self._subscribers.setdefault(event_type, []).append(callback)

    def publish(self, event: Event) -> None:
        for callback in self._subscribers.get(event.type, []):
            callback(event)

