from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Union

from ._checkout import TTL, Include, checkout_query
from ._jsonapi import (
    as_bool,
    as_dict,
    as_int,
    as_str,
    attributes,
    primary,
    primary_list,
    relationship_id,
    parse_time,
)
from .client import Client, expect_resource, segment
from .component import Component
from .heartbeat import ErrorHandler, HeartbeatMonitor
from .process import Process

if TYPE_CHECKING:
    from .files import MachineFile


class HeartbeatStatus:
    NOT_STARTED = "NOT_STARTED"
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    RESURRECTED = "RESURRECTED"


LIST_LIMIT = 100


@dataclass
class Machine:
    id: str = ""
    type: str = "machines"
    name: str = ""
    fingerprint: str = ""
    hostname: str = ""
    platform: str = ""
    ip: str = ""
    cores: int = 0
    require_heartbeat: bool = False
    heartbeat_status: str = ""
    heartbeat_duration: int = 0
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    license_id: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)
    heartbeat: Optional[HeartbeatMonitor] = field(default=None, repr=False, compare=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Machine":
        machine = cls()
        machine._load(resource)
        return machine

    def _load(self, resource: Mapping[str, Any]) -> None:
        attrs = attributes(resource)
        self.id = as_str(resource.get("id"))
        self.type = as_str(resource.get("type")) or "machines"
        self.name = as_str(attrs.get("name"))
        self.fingerprint = as_str(attrs.get("fingerprint"))
        self.hostname = as_str(attrs.get("hostname"))
        self.platform = as_str(attrs.get("platform"))
        self.ip = as_str(attrs.get("ip"))
        self.cores = as_int(attrs.get("cores"))
        self.require_heartbeat = as_bool(attrs.get("requireHeartbeat"))
        self.heartbeat_status = as_str(attrs.get("heartbeatStatus"))
        self.heartbeat_duration = as_int(attrs.get("heartbeatDuration"))
        self.created = parse_time(attrs.get("created"))
        self.updated = parse_time(attrs.get("updated"))
        self.metadata = as_dict(attrs.get("metadata"))
        self.license_id = relationship_id(resource, "license") or self.license_id
        self.attributes = attrs

    def _require_id(self) -> str:
        if not self.id:
            raise ValueError("machine id is required")
        return self.id

    def _path(self, suffix: str = "") -> str:
        return f"machines/{segment(self._require_id())}{suffix}"

    def deactivate(self) -> None:
        """Stop the heartbeat monitor, if any, and deactivate the machine."""
        if self.heartbeat is not None:
            self.heartbeat.stop()
        Client().delete(self._path())

    def ping(self) -> None:
        """Send a single heartbeat ping and refresh the machine attributes."""
        response = Client().post(self._path("/actions/ping"))
        resource = primary(response.document)
        if resource is not None:
            self._load(resource)

    def monitor(self, on_error: Optional[ErrorHandler] = None) -> HeartbeatMonitor:
        """Ping now, then keep pinging in the background within the heartbeat window.

        The first ping is sent right away and raises on failure. Later failures
        stop the monitor and are passed to ``on_error``.
        """
        if self.heartbeat is not None and self.heartbeat.running:
            return self.heartbeat
        self.ping()
        self.heartbeat = HeartbeatMonitor(
            self.ping, self.heartbeat_duration, on_error=on_error, name=f"keygen-machine-{self.id}"
        ).start()
        return self.heartbeat

    def checkout(
        self,
        *,
        include: Include = ("license", "license.entitlements"),
        ttl: TTL = None,
        encrypt: bool = True,
        algorithm: Optional[str] = None,
    ) -> "MachineFile":
        """Generate a machine file. Encrypted files are decrypted with the license key plus the fingerprint."""
        from .files import MachineFile

        query = checkout_query(include=include, ttl=ttl, encrypt=encrypt, algorithm=algorithm)
        response = Client().post(self._path("/actions/check-out"), query=query)
        return MachineFile.from_resource(expect_resource(response, "machine file"))

    def components(self) -> List[Component]:
        """List up to 100 components of the machine."""
        response = Client().get(self._path("/components"), query={"limit": LIST_LIMIT})
        return [Component.from_resource(item) for item in primary_list(response.document)]

    def spawn(self, pid: Union[str, int], on_error: Optional[ErrorHandler] = None) -> Process:
        """Create a process for the machine and start its heartbeat monitor."""
        pid = str(pid)
        if not pid:
            raise ValueError("process pid is required")
        body = {
            "data": {
                "type": "processes",
                "attributes": {"pid": pid},
                "relationships": {"machine": {"data": {"type": "machines", "id": self._require_id()}}},
            }
        }
        response = Client().post("processes", body)
        process = Process.from_resource(expect_resource(response, "process"))
        process.machine_id = process.machine_id or self.id
        try:
            process.monitor(on_error)
        except Exception as err:
            err.process = process
            raise
        return process

    def processes(self) -> List[Process]:
        """List up to 100 processes of the machine."""
        response = Client().get(self._path("/processes"), query={"limit": LIST_LIMIT})
        return [Process.from_resource(item) for item in primary_list(response.document)]
