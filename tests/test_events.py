from src.core.events import EventBus

def test_multiple_event():
    bus = EventBus()
    received1 = []
    received2 = []

    bus.subscribe("EntryAdded", lambda data: received1.append(data))
    bus.subscribe("EntryAdded", lambda data: received2.append(data))

    bus.publish("EntryAdded", {"id": 42, "title": "test"})

    assert len(received1) == 1
    assert len(received2) == 1
    assert received1[0]["id"] == 42