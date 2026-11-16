from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

def append_event(path: str | Path, event: dict, previous_hash: str = "") -> str:
    payload = dict(event)
    payload.setdefault("ts", datetime.now(timezone.utc).isoformat())
    payload["previous_hash"] = previous_hash
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    payload["event_hash"] = digest
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return digest

def replay(path: str | Path) -> list[dict]:
    events = []
    previous = ""
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        event = json.loads(raw)
        expected = event.pop("event_hash", None)
        canonical = json.dumps(event, sort_keys=True, ensure_ascii=False).encode()
        actual = hashlib.sha256(canonical).hexdigest()
        event["valid_hash"] = actual == expected and event.get("previous_hash", "") == previous
        event["event_hash"] = expected
        previous = expected or ""
        events.append(event)
    return events
