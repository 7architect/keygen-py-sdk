from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Type, Union

from . import errors
from ._checkout import TTL, Include, checkout_query
from ._config import settings
from ._jsonapi import (
    as_bool,
    as_dict,
    as_str,
    attributes,
    meta,
    parse_time,
    primary,
    primary_list,
    relationship_id,
)
from ._platform import cpu_count, current_platform
from .client import Client, expect_resource, segment
from .component import Component
from .entitlement import Entitlement
from .machine import LIST_LIMIT, Machine
from .validation import ValidationCode, ValidationResult
from .verifier import Verifier

if TYPE_CHECKING:
    from .files import LicenseFile


_VALIDATION_ERRORS: Dict[str, Type[errors.LicenseValidationError]] = {
    ValidationCode.FINGERPRINT_SCOPE_MISMATCH: errors.LicenseNotActivatedError,
    ValidationCode.NO_MACHINES: errors.LicenseNotActivatedError,
    ValidationCode.NO_MACHINE: errors.LicenseNotActivatedError,
    ValidationCode.EXPIRED: errors.LicenseExpiredError,
    ValidationCode.SUSPENDED: errors.LicenseSuspendedError,
    ValidationCode.TOO_MANY_MACHINES: errors.LicenseTooManyMachinesError,
    ValidationCode.TOO_MANY_CORES: errors.LicenseTooManyCoresError,
    ValidationCode.TOO_MANY_PROCESSES: errors.LicenseTooManyProcessesError,
    ValidationCode.FINGERPRINT_SCOPE_REQUIRED: errors.ValidationFingerprintMissingError,
    ValidationCode.FINGERPRINT_SCOPE_EMPTY: errors.ValidationFingerprintMissingError,
    ValidationCode.COMPONENTS_SCOPE_REQUIRED: errors.ValidationComponentsMissingError,
    ValidationCode.COMPONENTS_SCOPE_EMPTY: errors.ValidationComponentsMissingError,
    ValidationCode.COMPONENTS_SCOPE_MISMATCH: errors.ComponentNotActivatedError,
    ValidationCode.HEARTBEAT_NOT_STARTED: errors.HeartbeatRequiredError,
    ValidationCode.HEARTBEAT_DEAD: errors.HeartbeatDeadError,
    ValidationCode.PRODUCT_SCOPE_REQUIRED: errors.ValidationProductMissingError,
    ValidationCode.PRODUCT_SCOPE_MISMATCH: errors.ValidationProductMissingError,
    ValidationCode.PRODUCT_SCOPE_EMPTY: errors.ValidationProductMissingError,
}


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return ""


@dataclass
class License:
    id: str = ""
    type: str = "licenses"
    name: str = ""
    key: str = ""
    expiry: Optional[datetime] = None
    scheme: str = ""
    require_heartbeat: bool = False
    last_validated: Optional[datetime] = None
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    policy_id: str = ""
    last_validation: Optional[ValidationResult] = None
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "License":
        license = cls()
        license._load(resource)
        return license

    def _load(self, resource: Mapping[str, Any]) -> None:
        attrs = attributes(resource)
        self.id = as_str(resource.get("id"))
        self.type = as_str(resource.get("type")) or "licenses"
        self.name = as_str(attrs.get("name"))
        self.key = as_str(attrs.get("key"))
        self.expiry = parse_time(attrs.get("expiry"))
        self.scheme = as_str(attrs.get("scheme"))
        self.require_heartbeat = as_bool(attrs.get("requireHeartbeat"))
        self.last_validated = parse_time(attrs.get("lastValidated"))
        self.created = parse_time(attrs.get("created"))
        self.updated = parse_time(attrs.get("updated"))
        self.metadata = as_dict(attrs.get("metadata"))
        self.policy_id = relationship_id(resource, "policy")
        self.attributes = attrs

    def _require_id(self) -> str:
        if not self.id:
            raise ValueError("license id is required")
        return self.id

    def validate(self, *fingerprints: str) -> ValidationResult:
        """Validate the license, optionally scoped to a machine and its components.

        The first fingerprint is the machine fingerprint and the rest are
        component fingerprints. Returns the validation result when the license
        is valid and raises a LicenseValidationError subclass otherwise, e.g.
        LicenseNotActivatedError or LicenseExpiredError. The license itself is
        refreshed with the data returned by the API either way.
        """
        scope: Dict[str, Any] = {}
        fingerprint = fingerprints[0] if fingerprints else ""
        components = [str(c) for c in fingerprints[1:] if c]
        if fingerprint:
            scope["fingerprint"] = str(fingerprint)
        if components:
            scope["components"] = components
        if settings.product:
            scope["product"] = settings.product
        if settings.environment:
            scope["environment"] = settings.environment

        body = {"meta": {"scope": scope}}

        try:
            response = Client().post(f"licenses/{segment(self._require_id())}/actions/validate", body)
        except errors.NotFoundError as err:
            raise errors.LicenseInvalidError(response=err.response, license=self) from err

        resource = primary(response.document)
        if resource is not None:
            self._load(resource)

        result = ValidationResult.from_meta(meta(response.document))
        self.last_validation = result

        if result.code == ValidationCode.VALID:
            return result

        error_class = _VALIDATION_ERRORS.get(result.code, errors.LicenseInvalidError)
        raise error_class(response=response, license=self, result=result)

    def verify(self, public_key: Optional[str] = None) -> bytes:
        """Check that the license key is genuine and return the dataset embedded in it."""
        if not self.scheme:
            raise errors.LicenseNotSignedError()
        return Verifier(public_key).verify_license_key(self.scheme, self.key)

    def activate(self, fingerprint: str, *components: Union[Component, Mapping[str, Any]]) -> Machine:
        """Activate a machine for the license, identified by its fingerprint."""
        if not fingerprint:
            raise ValueError("machine fingerprint is required")

        relationships: Dict[str, Any] = {
            "license": {"data": {"type": "licenses", "id": self._require_id()}}
        }
        if components:
            relationships["components"] = {
                "data": [Component.coerce(c).to_resource() for c in components]
            }

        attrs: Dict[str, Any] = {
            "fingerprint": str(fingerprint),
            "platform": current_platform(),
            "cores": cpu_count(),
        }
        hostname = _hostname()
        if hostname:
            attrs["hostname"] = hostname

        body = {"data": {"type": "machines", "attributes": attrs, "relationships": relationships}}
        response = Client().post("machines", body)
        machine = Machine.from_resource(expect_resource(response, "machine"))
        machine.license_id = machine.license_id or self.id
        return machine

    def deactivate(self, id: str) -> None:
        """Deactivate a machine by its ID or fingerprint."""
        if not id:
            raise ValueError("machine id is required")
        Client().delete(f"machines/{segment(id)}")

    def machine(self, id: str) -> Machine:
        """Retrieve a machine by its ID or fingerprint."""
        if not id:
            raise ValueError("machine id is required")
        response = Client().get(f"machines/{segment(id)}")
        return Machine.from_resource(expect_resource(response, "machine"))

    def machines(self) -> List[Machine]:
        """List up to 100 machines of the license."""
        response = Client().get(
            f"licenses/{segment(self._require_id())}/machines", query={"limit": LIST_LIMIT}
        )
        return [Machine.from_resource(item) for item in primary_list(response.document)]

    def entitlements(self) -> List[Entitlement]:
        """List up to 100 entitlements of the license."""
        response = Client().get(
            f"licenses/{segment(self._require_id())}/entitlements", query={"limit": LIST_LIMIT}
        )
        return [Entitlement.from_resource(item) for item in primary_list(response.document)]

    def checkout(
        self,
        *,
        include: Include = ("entitlements",),
        ttl: TTL = None,
        encrypt: bool = True,
        algorithm: Optional[str] = None,
    ) -> "LicenseFile":
        """Generate a license file. Encrypted files are decrypted with the license key."""
        from .files import LicenseFile

        query = checkout_query(include=include, ttl=ttl, encrypt=encrypt, algorithm=algorithm)
        response = Client().post(
            f"licenses/{segment(self._require_id())}/actions/check-out", query=query
        )
        return LicenseFile.from_resource(expect_resource(response, "license file"))


def me() -> License:
    """Retrieve the license that the configured license key or token belongs to."""
    response = Client().get("me")
    resource = expect_resource(response, "license")
    if as_str(resource.get("type")) != "licenses":
        raise errors.LicenseInvalidError(
            "the configured credentials do not belong to a license", response=response
        )
    return License.from_resource(resource)


def validate(*fingerprints: str) -> License:
    """Validate the license that belongs to the configured license key or token.

    The first fingerprint is the machine fingerprint and the rest are
    component fingerprints. Returns the license when it is valid. When it is
    not, a LicenseValidationError subclass is raised, and its ``license``
    attribute still gives access to the license, e.g. to activate a machine.
    """
    license = me()
    license.validate(*fingerprints)
    return license
