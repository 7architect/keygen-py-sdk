from __future__ import annotations

import logging
import threading
from datetime import timedelta
from typing import Any, Optional, Union

import requests

from ._platform import default_ext, default_program

SDK_VERSION = "1.0.0"

logger = logging.getLogger("keygen")
logger.addHandler(logging.NullHandler())


class Settings:
    """Global SDK configuration shared by every client created without explicit options."""

    FIELDS = (
        "api_url",
        "api_version",
        "api_prefix",
        "account",
        "product",
        "package",
        "environment",
        "license_key",
        "token",
        "public_key",
        "signature_scheme",
        "user_agent",
        "logger",
        "program",
        "ext",
        "max_clock_drift",
        "http_client",
        "timeout",
    )

    def __init__(self) -> None:
        self.api_url: str = "https://api.keygen.sh"
        self.api_version: str = "1.8"
        self.api_prefix: str = "v1"
        self.account: str = ""
        self.product: str = ""
        self.package: str = ""
        self.environment: str = ""
        self.license_key: str = ""
        self.token: str = ""
        self.public_key: str = ""
        self.signature_scheme: str = "ed25519"
        self.user_agent: str = ""
        self.logger: Any = logger
        self.program: str = default_program()
        self.ext: str = default_ext()
        self.max_clock_drift: Optional[Union[timedelta, int, float]] = timedelta(minutes=5)
        self.timeout: Optional[Union[float, tuple]] = 30.0
        self._http_client: Optional[requests.Session] = None
        self._http_lock = threading.Lock()

    @property
    def http_client(self) -> requests.Session:
        with self._http_lock:
            if self._http_client is None:
                self._http_client = requests.Session()
            return self._http_client

    @http_client.setter
    def http_client(self, session: Optional[requests.Session]) -> None:
        with self._http_lock:
            self._http_client = session


settings = Settings()

request_lock = threading.RLock()


def clock_drift() -> Optional[timedelta]:
    """Return the allowed clock drift, or None when the check is disabled."""
    drift = settings.max_clock_drift
    if drift is None:
        return None
    if not isinstance(drift, timedelta):
        drift = timedelta(seconds=float(drift))
    if drift < timedelta(0):
        return None
    return drift
