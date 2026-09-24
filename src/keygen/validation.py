from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from ._jsonapi import as_bool, as_dict, as_str


class ValidationCode:
    VALID = "VALID"
    NOT_FOUND = "NOT_FOUND"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"
    OVERDUE = "OVERDUE"
    BANNED = "BANNED"
    NO_MACHINE = "NO_MACHINE"
    NO_MACHINES = "NO_MACHINES"
    TOO_MANY_MACHINES = "TOO_MANY_MACHINES"
    TOO_MANY_CORES = "TOO_MANY_CORES"
    TOO_MANY_PROCESSES = "TOO_MANY_PROCESSES"
    TOO_MANY_USERS = "TOO_MANY_USERS"
    FINGERPRINT_SCOPE_REQUIRED = "FINGERPRINT_SCOPE_REQUIRED"
    FINGERPRINT_SCOPE_MISMATCH = "FINGERPRINT_SCOPE_MISMATCH"
    FINGERPRINT_SCOPE_EMPTY = "FINGERPRINT_SCOPE_EMPTY"
    COMPONENTS_SCOPE_REQUIRED = "COMPONENTS_SCOPE_REQUIRED"
    COMPONENTS_SCOPE_MISMATCH = "COMPONENTS_SCOPE_MISMATCH"
    COMPONENTS_SCOPE_EMPTY = "COMPONENTS_SCOPE_EMPTY"
    HEARTBEAT_NOT_STARTED = "HEARTBEAT_NOT_STARTED"
    HEARTBEAT_DEAD = "HEARTBEAT_DEAD"
    PRODUCT_SCOPE_REQUIRED = "PRODUCT_SCOPE_REQUIRED"
    PRODUCT_SCOPE_MISMATCH = "PRODUCT_SCOPE_MISMATCH"
    PRODUCT_SCOPE_EMPTY = "PRODUCT_SCOPE_EMPTY"
    POLICY_SCOPE_REQUIRED = "POLICY_SCOPE_REQUIRED"
    POLICY_SCOPE_MISMATCH = "POLICY_SCOPE_MISMATCH"
    MACHINE_SCOPE_REQUIRED = "MACHINE_SCOPE_REQUIRED"
    MACHINE_SCOPE_MISMATCH = "MACHINE_SCOPE_MISMATCH"
    ENTITLEMENTS_MISSING = "ENTITLEMENTS_MISSING"
    ENTITLEMENTS_SCOPE_EMPTY = "ENTITLEMENTS_SCOPE_EMPTY"


@dataclass
class ValidationScope:
    fingerprint: str = ""
    components: List[str] = field(default_factory=list)
    product: str = ""
    environment: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ValidationScope":
        components = data.get("components")
        environment = data.get("environment")
        return cls(
            fingerprint=as_str(data.get("fingerprint")),
            components=[as_str(c) for c in components] if isinstance(components, list) else [],
            product=as_str(data.get("product")),
            environment=None if environment is None else as_str(environment),
            raw=dict(data),
        )


@dataclass
class ValidationResult:
    detail: str = ""
    valid: bool = False
    code: str = ""
    scope: Optional[ValidationScope] = None

    @classmethod
    def from_meta(cls, meta: Mapping[str, Any]) -> "ValidationResult":
        scope = meta.get("scope")
        return cls(
            detail=as_str(meta.get("detail")),
            valid=as_bool(meta.get("valid")),
            code=as_str(meta.get("code")),
            scope=ValidationScope.from_dict(as_dict(scope)) if isinstance(scope, Mapping) else None,
        )
