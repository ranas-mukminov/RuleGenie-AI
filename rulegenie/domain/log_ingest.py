import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def parse_event(raw_log: str) -> Dict[str, Any]:
    """Parse a raw log line into a dict; fallback to message wrapper."""
    if not raw_log:
        return {}
    try:
        parsed = json.loads(raw_log)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    if "=" in raw_log:
        parsed: Dict[str, Any] = {}
        for token in raw_log.split():
            if "=" in token:
                key, value = token.split("=", 1)
                parsed[key] = value
        if parsed:
            return parsed
    return {"message": raw_log}


def load_events_from_jsonl(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(parse_event(line))
    return events


def load_samples_from_jsonl(path: Path, malicious: bool = False) -> List[Dict[str, Any]]:
    events = load_events_from_jsonl(path)
    return [{"raw_log": json.dumps(event), "is_malicious": malicious} for event in events]
