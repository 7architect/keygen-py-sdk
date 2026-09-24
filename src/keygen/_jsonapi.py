from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

CONTENT_TYPE = "application/vnd.api+json"

_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[Tt ](?P<time>\d{2}:\d{2}(?::\d{2})?)"
    r"(?:\.(?P<fraction>\d+))?(?P<tz>[Zz]|[+-]\d{2}:?\d{2})?$"
)


def parse_time(value: Any) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp into an aware datetime. Returns None for empty or bad input."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None

    match = _TIMESTAMP.match(value.strip())
    if not match:
        return None

    clock = match.group("time")
    if clock.count(":") == 1:
        clock += ":00"

    fraction = (match.group("fraction") or "0")[:6].ljust(6, "0")

    tz = match.group("tz")
    if not tz or tz in ("Z", "z"):
        tzinfo = timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        tzinfo = timezone(sign * offset)

    try:
        parsed = datetime.strptime(f"{match.group('date')}T{clock}", "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None

    return parsed.replace(microsecond=int(fraction), tzinfo=tzinfo)


def as_str(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def as_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def as_bool(value: Any) -> bool:
    return value is True


def as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def attributes(resource: Mapping[str, Any]) -> Dict[str, Any]:
    return as_dict(resource.get("attributes"))


def relationship_id(resource: Mapping[str, Any], name: str) -> str:
    relationships = resource.get("relationships")
    if not isinstance(relationships, Mapping):
        return ""
    relationship = relationships.get(name)
    if not isinstance(relationship, Mapping):
        return ""
    data = relationship.get("data")
    if not isinstance(data, Mapping):
        return ""
    return as_str(data.get("id"))


def primary(document: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the primary resource of a document when it is a single object."""
    if not isinstance(document, Mapping):
        return None
    data = document.get("data")
    return dict(data) if isinstance(data, Mapping) else None


def primary_list(document: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(document, Mapping):
        return []
    data = document.get("data")
    if not isinstance(data, list):
        return []
    return [dict(item) for item in data if isinstance(item, Mapping)]


def included(document: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(document, Mapping):
        return []
    items = document.get("included")
    if not isinstance(items, list):
        return []
    return [dict(item) for item in items if isinstance(item, Mapping)]


def meta(document: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(document, Mapping):
        return {}
    return as_dict(document.get("meta"))


def identifier(type_: str, id_: str) -> Dict[str, Any]:
    return {"data": {"type": type_, "id": id_}}
