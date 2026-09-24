from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

from ._jsonapi import as_dict, as_str, attributes, parse_time


@dataclass
class Entitlement:
    id: str = ""
    type: str = "entitlements"
    name: str = ""
    code: str = ""
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Entitlement":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "entitlements",
            name=as_str(attrs.get("name")),
            code=as_str(attrs.get("code")),
            created=parse_time(attrs.get("created")),
            updated=parse_time(attrs.get("updated")),
            metadata=as_dict(attrs.get("metadata")),
            attributes=attrs,
        )
