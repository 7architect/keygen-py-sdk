from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

from ._jsonapi import as_int, as_str, attributes, parse_time, relationship_id


@dataclass
class Artifact:
    id: str = ""
    type: str = "artifacts"
    filename: str = ""
    filetype: str = ""
    filesize: int = 0
    platform: str = ""
    arch: str = ""
    signature: str = ""
    checksum: str = ""
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    release_id: str = ""
    url: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Artifact":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "artifacts",
            filename=as_str(attrs.get("filename")),
            filetype=as_str(attrs.get("filetype")),
            filesize=as_int(attrs.get("filesize")),
            platform=as_str(attrs.get("platform")),
            arch=as_str(attrs.get("arch")),
            signature=as_str(attrs.get("signature")),
            checksum=as_str(attrs.get("checksum")),
            created=parse_time(attrs.get("created")),
            updated=parse_time(attrs.get("updated")),
            release_id=relationship_id(resource, "release"),
            attributes=attrs,
        )
