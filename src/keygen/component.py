from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Union

from ._jsonapi import as_dict, as_str, attributes, parse_time, relationship_id


@dataclass
class Component:
    """A hardware component of a machine, such as a disk, a CPU or a motherboard."""

    fingerprint: str = ""
    name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = ""
    type: str = "components"
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    machine_id: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Component":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "components",
            fingerprint=as_str(attrs.get("fingerprint")),
            name=as_str(attrs.get("name")),
            created=parse_time(attrs.get("created")),
            updated=parse_time(attrs.get("updated")),
            metadata=as_dict(attrs.get("metadata")),
            machine_id=relationship_id(resource, "machine"),
            attributes=attrs,
        )

    @classmethod
    def coerce(cls, value: Union["Component", Mapping[str, Any]]) -> "Component":
        if isinstance(value, Component):
            return value
        if isinstance(value, Mapping):
            return cls(
                fingerprint=as_str(value.get("fingerprint")),
                name=as_str(value.get("name")),
                metadata=as_dict(value.get("metadata")),
            )
        raise TypeError(f"expected a Component or a mapping, got {type(value).__name__}")

    def to_resource(self) -> Dict[str, Any]:
        if not self.fingerprint:
            raise ValueError("component fingerprint is required")
        attrs: Dict[str, Any] = {"fingerprint": self.fingerprint, "name": self.name}
        if self.metadata:
            attrs["metadata"] = self.metadata
        resource: Dict[str, Any] = {"type": "components", "attributes": attrs}
        if self.machine_id:
            resource["relationships"] = {
                "machine": {"data": {"type": "machines", "id": self.machine_id}}
            }
        return resource
