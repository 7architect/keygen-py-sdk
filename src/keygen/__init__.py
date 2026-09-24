"""Keygen SDK for Python.

Lets Python programs license and remotely update themselves using the
keygen.sh service. Configure the SDK through module attributes::

    import keygen

    keygen.account = "YOUR_KEYGEN_ACCOUNT_ID"
    keygen.product = "YOUR_KEYGEN_PRODUCT_ID"
    keygen.license_key = "A_KEYGEN_LICENSE_KEY"

    license = keygen.validate(fingerprint)
"""

from __future__ import annotations

import sys
import types
from typing import Any

from ._config import SDK_VERSION, Settings, settings
from .artifact import Artifact
from .client import Client, Response
from .component import Component
from .entitlement import Entitlement
from .errors import *
from .errors import __all__ as _error_names
from .files import Certificate, LicenseFile, LicenseFileDataset, MachineFile, MachineFileDataset
from .heartbeat import HeartbeatMonitor
from .license import License, me, validate
from .machine import HeartbeatStatus, Machine
from .process import Process, ProcessStatus
from .release import Release, UpgradeOptions, default_filename, upgrade
from .validation import ValidationCode, ValidationResult, ValidationScope
from .verifier import (
    LICENSE_FILE_SIGNING_PREFIX,
    LICENSE_KEY_SIGNING_PREFIX,
    MACHINE_FILE_SIGNING_PREFIX,
    EncodingAlgorithm,
    SchemeCode,
    SigningAlgorithm,
    Verifier,
)
from .webhook import verify_webhook

__version__ = SDK_VERSION

__all__ = [
    "Artifact",
    "Certificate",
    "Client",
    "Component",
    "EncodingAlgorithm",
    "Entitlement",
    "HeartbeatMonitor",
    "HeartbeatStatus",
    "LICENSE_FILE_SIGNING_PREFIX",
    "LICENSE_KEY_SIGNING_PREFIX",
    "License",
    "LicenseFile",
    "LicenseFileDataset",
    "MACHINE_FILE_SIGNING_PREFIX",
    "Machine",
    "MachineFile",
    "MachineFileDataset",
    "Process",
    "ProcessStatus",
    "Release",
    "Response",
    "SchemeCode",
    "SigningAlgorithm",
    "UpgradeOptions",
    "ValidationCode",
    "ValidationResult",
    "ValidationScope",
    "Verifier",
    "default_filename",
    "me",
    "upgrade",
    "validate",
    "verify_webhook",
    *_error_names,
]


class _KeygenModule(types.ModuleType):
    """Routes configuration attributes such as keygen.account to the shared settings."""

    def __getattr__(self, name: str) -> Any:
        if name in Settings.FIELDS:
            return getattr(settings, name)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        if name in Settings.FIELDS:
            setattr(settings, name, value)
        else:
            super().__setattr__(name, value)

    def __dir__(self) -> list:
        return sorted(set(super().__dir__()) | set(Settings.FIELDS))


sys.modules[__name__].__class__ = _KeygenModule
