from src.core.events import EventBus


def test_event_publish_subscribe():
    bus = EventBus()
    result = []

    def handler(data):
        result.append(data)

    bus.subscribe("TestEvent", handler)
    bus.publish("TestEvent", 123)

    assert result == [123]
