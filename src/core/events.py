from collections import defaultdict
from typing import Callable


class EventBus:
    """
    Simple publish/subscribe event system.
    """

    def __init__(self):
        self._subscribers = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable):
        self._subscribers[event_name].append(handler)

    def publish(self, event_name: str, data=None):
        for handler in self._subscribers[event_name]:
            handler(data)

def audit_log_handler(event_data):
    # Placeholder for Sprint 5
    print(f"[AUDIT] Event recorded: {event_data}")
