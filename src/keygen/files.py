from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List, Mapping, Optional, Type

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import errors
from ._config import clock_drift
from ._encoding import b64decode
from ._jsonapi import as_int, as_str, attributes, included, meta, parse_time, primary, relationship_id
from .component import Component
from .entitlement import Entitlement
from .license import License
from .machine import Machine
from .verifier import (
    LICENSE_FILE_SIGNING_PREFIX,
    MACHINE_FILE_SIGNING_PREFIX,
    EncodingAlgorithm,
    SigningAlgorithm,
    Verifier,
)

_SUPPORTED_SIGNING = (SigningAlgorithm.ED25519.value, SigningAlgorithm.P256.value)


@dataclass
class Certificate:
    enc: str
    sig: str
    alg: str

    @property
    def encoding_algorithm(self) -> str:
        encoding, sep, _ = self.alg.partition("+")
        return encoding if sep else ""

    @property
    def signing_algorithm(self) -> str:
        _, sep, signing = self.alg.partition("+")
        return signing if sep else ""


def _decrypt(cert: Certificate, secret: str) -> bytes:
    parts = cert.enc.split(".")
    if len(parts) != 3:
        raise ValueError("encrypted payload must have three parts")
    ciphertext, iv, tag = (b64decode(part, strict_padding=True) for part in parts)
    if not iv or len(tag) != 16:
        raise ValueError("encrypted payload has a malformed nonce or tag")
    key = hashlib.sha256(secret.encode()).digest()
    return AESGCM(key).decrypt(iv, ciphertext + tag, None)




class _SignedFile:
    LABEL: ClassVar[str]
    SIGNING_PREFIX: ClassVar[str]
    Error: ClassVar[Type[errors.KeygenError]]
    NotSupported: ClassVar[Type[errors.KeygenError]]
    Encrypted: ClassVar[Type[errors.KeygenError]]
    NotEncrypted: ClassVar[Type[errors.KeygenError]]
    NotGenuine: ClassVar[Type[errors.KeygenError]]
    Expired: ClassVar[Type[errors.KeygenError]]
    SecretMissing: ClassVar[Type[errors.KeygenError]]

    certificate: str

    def _certificate(self) -> Certificate:
        text = self.certificate
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", errors="replace")
        payload = (text or "").strip()

        header = f"-----BEGIN {self.LABEL}-----"
        footer = f"-----END {self.LABEL}-----"
        if payload.startswith(header):
            payload = payload[len(header) :]
        if payload.endswith(footer):
            payload = payload[: -len(footer)]
        payload = payload.strip()

        if not payload:
            raise self.Error(f"{self.LABEL.lower()} is empty")

        try:
            decoded = b64decode(payload, strict_padding=True)
            data = json.loads(decoded.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as err:
            raise self.Error() from err

        if not isinstance(data, dict):
            raise self.Error()

        enc, sig, alg = data.get("enc"), data.get("sig"), data.get("alg")
        if not all(isinstance(value, str) for value in (enc, sig, alg)):
            raise self.Error()

        return Certificate(enc=enc, sig=sig, alg=alg)

    def verify(self, public_key: Optional[str] = None) -> None:
        """Check that the file is genuine. Raises when the signature does not match."""
        cert = self._certificate()
        if cert.signing_algorithm not in _SUPPORTED_SIGNING:
            raise self.NotSupported()
        Verifier(public_key).verify_certificate(
            enc=cert.enc,
            sig=cert.sig,
            algorithm=cert.signing_algorithm,
            prefix=self.SIGNING_PREFIX,
            not_genuine=self.NotGenuine,
            not_supported=self.NotSupported,
        )

    def _load_dataset(self, data: bytes) -> Any:
        try:
            document = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as err:
            raise self.Error() from err
        if not isinstance(document, dict) or primary(document) is None:
            raise self.Error()

        dataset = self._build_dataset(document)

        drift = clock_drift()
        now = datetime.now(timezone.utc)
        if drift is not None and dataset.issued is not None and dataset.issued - now > drift:
            raise errors.SystemClockUnsyncedError(dataset=dataset)

        if dataset.ttl and dataset.expiry is not None and now > dataset.expiry:
            raise self.Expired(dataset=dataset)

        return dataset

    def _build_dataset(self, document: Dict[str, Any]) -> Any:
        raise NotImplementedError

    def decode(self) -> Any:
        """Decode an unencrypted file. The signature is not checked, call verify first."""
        cert = self._certificate()
        encoding = cert.encoding_algorithm
        if encoding == EncodingAlgorithm.AES256.value:
            raise self.Encrypted()
        if encoding != EncodingAlgorithm.BASE64.value or cert.signing_algorithm not in _SUPPORTED_SIGNING:
            raise self.NotSupported()

        try:
            data = b64decode(cert.enc, strict_padding=True)
        except ValueError as err:
            raise self.Error() from err

        return self._load_dataset(data)

    def decrypt(self, key: str) -> Any:
        """Decrypt an encrypted file. The signature is not checked, call verify first."""
        if not key:
            raise self.SecretMissing()

        cert = self._certificate()
        encoding = cert.encoding_algorithm
        if encoding == EncodingAlgorithm.BASE64.value:
            raise self.NotEncrypted()
        if encoding != EncodingAlgorithm.AES256.value or cert.signing_algorithm not in _SUPPORTED_SIGNING:
            raise self.NotSupported()

        try:
            data = _decrypt(cert, key)
        except InvalidTag as err:
            raise self.Error(f"{self.LABEL.lower()} could not be decrypted, the key is probably wrong") from err
        except ValueError as err:
            raise self.Error() from err

        return self._load_dataset(data)


def _meta_fields(document: Mapping[str, Any]) -> Dict[str, Any]:
    info = meta(document)
    return {
        "issued": parse_time(info.get("issued")),
        "expiry": parse_time(info.get("expiry")),
        "ttl": as_int(info.get("ttl")),
    }


@dataclass
class LicenseFileDataset:
    license: License
    entitlements: List[Entitlement] = field(default_factory=list)
    issued: Optional[datetime] = None
    expiry: Optional[datetime] = None
    ttl: int = 0


@dataclass
class MachineFileDataset:
    machine: Machine
    license: License = field(default_factory=License)
    entitlements: List[Entitlement] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    issued: Optional[datetime] = None
    expiry: Optional[datetime] = None
    ttl: int = 0


@dataclass
class LicenseFile(_SignedFile):
    """A signed, optionally encrypted snapshot of a license for offline use."""

    LABEL: ClassVar[str] = "LICENSE FILE"
    SIGNING_PREFIX: ClassVar[str] = LICENSE_FILE_SIGNING_PREFIX
    Error: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileError
    NotSupported: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileNotSupportedError
    Encrypted: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileEncryptedError
    NotEncrypted: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileNotEncryptedError
    NotGenuine: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileNotGenuineError
    Expired: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileExpiredError
    SecretMissing: ClassVar[Type[errors.KeygenError]] = errors.LicenseFileSecretMissingError

    certificate: str = ""
    id: str = ""
    type: str = "license-files"
    issued: Optional[datetime] = None
    expiry: Optional[datetime] = None
    ttl: int = 0
    license_id: str = ""

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "LicenseFile":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "license-files",
            certificate=as_str(attrs.get("certificate")),
            issued=parse_time(attrs.get("issued")),
            expiry=parse_time(attrs.get("expiry")),
            ttl=as_int(attrs.get("ttl")),
            license_id=relationship_id(resource, "license"),
        )

    def _build_dataset(self, document: Dict[str, Any]) -> LicenseFileDataset:
        resource = primary(document) or {}
        entitlements = [
            Entitlement.from_resource(item)
            for item in included(document)
            if item.get("type") == "entitlements"
        ]
        return LicenseFileDataset(
            license=License.from_resource(resource), entitlements=entitlements, **_meta_fields(document)
        )

    def decode(self) -> LicenseFileDataset:
        return super().decode()

    def decrypt(self, key: str) -> LicenseFileDataset:
        """Decrypt the license file using the license key."""
        return super().decrypt(key)


@dataclass
class MachineFile(_SignedFile):
    """A signed, optionally encrypted snapshot of a machine and its license for offline use."""

    LABEL: ClassVar[str] = "MACHINE FILE"
    SIGNING_PREFIX: ClassVar[str] = MACHINE_FILE_SIGNING_PREFIX
    Error: ClassVar[Type[errors.KeygenError]] = errors.MachineFileError
    NotSupported: ClassVar[Type[errors.KeygenError]] = errors.MachineFileNotSupportedError
    Encrypted: ClassVar[Type[errors.KeygenError]] = errors.MachineFileEncryptedError
    NotEncrypted: ClassVar[Type[errors.KeygenError]] = errors.MachineFileNotEncryptedError
    NotGenuine: ClassVar[Type[errors.KeygenError]] = errors.MachineFileNotGenuineError
    Expired: ClassVar[Type[errors.KeygenError]] = errors.MachineFileExpiredError
    SecretMissing: ClassVar[Type[errors.KeygenError]] = errors.MachineFileSecretMissingError

    certificate: str = ""
    id: str = ""
    type: str = "machine-files"
    issued: Optional[datetime] = None
    expiry: Optional[datetime] = None
    ttl: int = 0
    machine_id: str = ""
    license_id: str = ""

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "MachineFile":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "machine-files",
            certificate=as_str(attrs.get("certificate")),
            issued=parse_time(attrs.get("issued")),
            expiry=parse_time(attrs.get("expiry")),
            ttl=as_int(attrs.get("ttl")),
            machine_id=relationship_id(resource, "machine"),
            license_id=relationship_id(resource, "license"),
        )

    def _build_dataset(self, document: Dict[str, Any]) -> MachineFileDataset:
        resource = primary(document) or {}
        dataset = MachineFileDataset(machine=Machine.from_resource(resource), **_meta_fields(document))
        for item in included(document):
            kind = item.get("type")
            if kind == "licenses":
                dataset.license = License.from_resource(item)
            elif kind == "entitlements":
                dataset.entitlements.append(Entitlement.from_resource(item))
            elif kind == "components":
                dataset.components.append(Component.from_resource(item))
        return dataset

    def decode(self) -> MachineFileDataset:
        return super().decode()

    def decrypt(self, key: str) -> MachineFileDataset:
        """Decrypt the machine file using the license key followed by the machine fingerprint."""
        return super().decrypt(key)


