from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

from ._jsonapi import as_dict, as_int, as_str, attributes, parse_time, primary, relationship_id
from .client import Client, segment
from .heartbeat import ErrorHandler, HeartbeatMonitor


class ProcessStatus:
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    RESURRECTED = "RESURRECTED"


@dataclass
class Process:
    id: str = ""
    type: str = "processes"
    pid: str = ""
    status: str = ""
    interval: int = 0
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    machine_id: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)
    heartbeat: Optional[HeartbeatMonitor] = field(default=None, repr=False, compare=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Process":
        process = cls()
        process._load(resource)
        return process

    def _load(self, resource: Mapping[str, Any]) -> None:
        attrs = attributes(resource)
        self.id = as_str(resource.get("id"))
        self.type = as_str(resource.get("type")) or "processes"
        self.pid = as_str(attrs.get("pid"))
        self.status = as_str(attrs.get("status"))
        self.interval = as_int(attrs.get("interval"))
        self.created = parse_time(attrs.get("created"))
        self.updated = parse_time(attrs.get("updated"))
        self.metadata = as_dict(attrs.get("metadata"))
        self.machine_id = relationship_id(resource, "machine") or self.machine_id
        self.attributes = attrs

    def _require_id(self) -> str:
        if not self.id:
            raise ValueError("process id is required")
        return self.id

    def ping(self) -> None:
        """Send a single heartbeat ping and refresh the process attributes."""
        response = Client().post(f"processes/{segment(self._require_id())}/actions/ping")
        resource = primary(response.document)
        if resource is not None:
            self._load(resource)

    def monitor(self, on_error: Optional[ErrorHandler] = None) -> HeartbeatMonitor:
        """Ping now, then keep pinging in the background according to the process interval."""
        if self.heartbeat is not None and self.heartbeat.running:
            return self.heartbeat
        self.ping()
        self.heartbeat = HeartbeatMonitor(
            self.ping, self.interval, on_error=on_error, name=f"keygen-process-{self.id}"
        ).start()
        return self.heartbeat

    def kill(self) -> None:
        """Stop the heartbeat monitor and delete the process."""
        if self.heartbeat is not None:
            self.heartbeat.stop()
        Client().delete(f"processes/{segment(self._require_id())}")
