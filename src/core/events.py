from collections import defaultdict
from typing import Callable


class EventBus:

    def __init__(self):
        self._subscribers = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable):
        self._subscribers[event_name].append(handler)

    def publish(self, event_name: str, data=None):
        for handler in self._subscribers[event_name]:
            handler(data)

def audit_log_handler(event_data):
    print(f"[AUDIT] Event recorded: {event_data}")
