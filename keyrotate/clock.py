from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any


_EXTENDED_RFC3339 = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_BASIC_ISO8601 = re.compile(
    r"^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})T"
    r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})Z$"
)


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise TypeError(f"unsupported timestamp: {value!r}")

    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0)

    basic_match = _BASIC_ISO8601.fullmatch(value)
    if basic_match:
        parts = {name: int(part) for name, part in basic_match.groupdict().items()}
        return datetime(
            parts["year"],
            parts["month"],
            parts["day"],
            parts["hour"],
            parts["minute"],
            parts["second"],
            tzinfo=timezone.utc,
        )

    extended_match = _EXTENDED_RFC3339.fullmatch(value)
    if not extended_match:
        raise ValueError(f"unsupported timestamp: {value!r}")

    base = f"{extended_match.group('date')}T{extended_match.group('time')}"
    parsed = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    zone = extended_match.group("zone")

    if zone == "Z":
        zone_info = timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        zone_info = timezone(sign * offset)

    return parsed.replace(tzinfo=zone_info).astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
