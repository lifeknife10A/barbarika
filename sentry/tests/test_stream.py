"""SSE endpoint replays recent events, masked, in text/event-stream format."""

from __future__ import annotations

import json


def test_stream_replays_recent_events_masked(client):
    client.post(
        "/ingest",
        json={
            "event_type": "ssh_auth_failure",
            "source": "primary-01/auth.log",
            "raw_message": "Failed password for admin from 203.0.113.7",
            "payload": {"src_ip": "203.0.113.7"},
        },
    )

    with client.stream("GET", "/events/stream", params={"replay": 10, "once": True}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")

        saw_event = None
        for line in resp.iter_lines():
            if line.startswith("data:"):
                saw_event = json.loads(line[len("data:"):].strip())
                break

    assert saw_event is not None
    assert saw_event["masked"] is True
    assert "203.0.113.7" not in saw_event["raw_message"]
    assert saw_event["payload"]["src_ip"] == "«masked»"
