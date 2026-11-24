"""Parsing and deterministic detections. No network calls or external packages."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from typing import TextIO

MAX_LINE_CHARS = 65536
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$")


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source_ip: str
    user: str
    outcome: str
    service: str
    line: int


@dataclass(frozen=True)
class Config:
    window_seconds: int = 300
    failure_threshold: int = 5
    spray_users: int = 5
    max_lines: int = 200000

    def __post_init__(self):
        for name in ("window_seconds", "failure_threshold", "spray_users", "max_lines"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.failure_threshold < 2 or self.spray_users < 2:
            raise ValueError("detection thresholds must be at least 2")


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _label(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{name} must be a nonempty string of at most 128 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} cannot contain control characters")
    return value.strip()


def parse_event(raw: str, line: int) -> Event:
    try:
        obj = json.loads(raw, object_pairs_hook=_object)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid JSON object or duplicate key") from exc
    if not isinstance(obj, dict):
        raise ValueError("each record must be an object")
    required = {"timestamp", "source_ip", "user", "outcome"}
    if not required.issubset(obj):
        raise ValueError("missing required field: timestamp, source_ip, user or outcome")
    if set(obj) - required - {"service"}:
        raise ValueError("unknown field; normalize the source to the documented schema")
    stamp = obj["timestamp"]
    if not isinstance(stamp, str) or not TIMESTAMP.fullmatch(stamp):
        raise ValueError("timestamp must include seconds and Z or a numeric UTC offset")
    try:
        timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError("invalid timestamp") from exc
    try:
        if not isinstance(obj["source_ip"], str):
            raise ValueError()
        source_ip = str(ipaddress.ip_address(obj["source_ip"]))
        if "%" in source_ip:
            raise ValueError()
    except ValueError as exc:
        raise ValueError("source_ip must be an IPv4 or IPv6 address without a zone ID") from exc
    if obj["outcome"] not in ("failure", "success"):
        raise ValueError("outcome must be failure or success")
    return Event(timestamp, source_ip, _label(obj["user"], "user"), obj["outcome"],
                 _label(obj.get("service", "unknown"), "service"), line)


def read_events(stream: TextIO, config: Config):
    """Read bounded physical lines; never echo malformed content in diagnostics."""
    events, issues = [], []
    lines = 0
    while True:
        raw = stream.readline(MAX_LINE_CHARS + 2)
        if not raw:
            break
        lines += 1
        if lines > config.max_lines:
            raise ValueError("input exceeds max_lines; split the export or raise the limit")
        if len(raw.rstrip("\r\n")) > MAX_LINE_CHARS:
            while raw and not raw.endswith("\n"):
                raw = stream.readline(MAX_LINE_CHARS + 2)
            issues.append({"line": lines, "reason": "record exceeds 65536 characters"})
            continue
        if not raw.strip():
            continue
        try:
            events.append(parse_event(raw, lines))
        except ValueError as exc:
            issues.append({"line": lines, "reason": str(exc)})
    return events, issues, lines


def _evidence(event: Event):
    return {"line": event.line, "timestamp": utc_text(event.timestamp),
            "source_ip": event.source_ip, "user": event.user,
            "service": event.service, "outcome": event.outcome}


def analyze(events: list[Event], config: Config, issues=None, lines_read=None):
    """Apply inclusive [t-window, t] windows after stable event-time sorting.

    Burst and spray rules alert on below-to-above transitions, not every row.
    All state is local to this report. Service names and users are case-sensitive.
    """
    ordered = sorted(events, key=lambda event: (event.timestamp, event.line))
    pair_failures = defaultdict(deque)
    source_failures = defaultdict(deque)
    pair_active, source_active = {}, {}
    findings = []
    window = timedelta(seconds=config.window_seconds)

    def trim(queue, now):
        # Difference arithmetic avoids datetime underflow near year 1.
        while queue and now - queue[0].timestamp > window:
            queue.popleft()

    def add(rule, severity, key, evidence, reason):
        findings.append({"rule": rule, "severity": severity, "key": key,
                         "detected_at": utc_text(evidence[-1].timestamp),
                         "reason": reason, "evidence": [_evidence(e) for e in evidence]})

    for event in ordered:
        pair = (event.source_ip, event.user, event.service)
        source = (event.source_ip, event.service)
        pq, sq = pair_failures[pair], source_failures[source]
        trim(pq, event.timestamp)
        trim(sq, event.timestamp)
        # Re-arm only when the current window falls below threshold.
        if len(pq) < config.failure_threshold:
            pair_active[pair] = False
        if len({e.user for e in sq}) < config.spray_users:
            source_active[source] = False
        if event.outcome == "success":
            if len(pq) >= config.failure_threshold:
                add("success_after_failures", "high", dict(source_ip=pair[0], user=pair[1], service=pair[2]),
                    list(pq) + [event],
                    f"Success after {len(pq)} failures for this source/user/service within {config.window_seconds}s; verify whether expected.")
            # A successful login closes the pair episode, not the source's spray history.
            pq.clear()
            pair_active[pair] = False
            continue
        pq.append(event)
        sq.append(event)
        if len(pq) >= config.failure_threshold and not pair_active.get(pair, False):
            add("repeated_failures", "medium", dict(source_ip=pair[0], user=pair[1], service=pair[2]),
                list(pq), f"At least {config.failure_threshold} failures for one source/user/service within {config.window_seconds}s.")
            pair_active[pair] = True
        users = len({e.user for e in sq})
        if users >= config.spray_users and not source_active.get(source, False):
            add("multi_user_failures", "medium", dict(source_ip=source[0], service=source[1]),
                list(sq), f"Failures against {users} distinct users from one source/service within {config.window_seconds}s; possible spray pattern, not proof.")
            source_active[source] = True
    for number, finding in enumerate(findings, 1):
        finding["id"] = f"A{number:04d}"
    return {"schema_version": "1.0", "config": {"window_seconds": config.window_seconds,
            "failure_threshold": config.failure_threshold, "spray_users": config.spray_users},
            "summary": {"lines_read": lines_read if lines_read is not None else len(events),
                        "valid_events": len(events), "invalid_records": len(issues or []),
                        "findings": len(findings),
                        "first_event": utc_text(ordered[0].timestamp) if ordered else None,
                        "last_event": utc_text(ordered[-1].timestamp) if ordered else None},
            "issues": issues or [], "findings": findings}
