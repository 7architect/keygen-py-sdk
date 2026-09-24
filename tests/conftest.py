from __future__ import annotations

import base64
import io
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict

import keygen
from keygen._config import Settings, settings

Handler = Union[Tuple[int, Dict[str, str], Any], Callable[[requests.PreparedRequest], Tuple[int, Dict[str, str], Any]]]


@dataclass
class Route:
    method: str
    pattern: str
    handler: Handler
    calls: int = 0


@dataclass
class MockAdapter(BaseAdapter):
    routes: List[Route] = field(default_factory=list)
    requests: List[requests.PreparedRequest] = field(default_factory=list)
    error: Optional[Exception] = None

    def __post_init__(self) -> None:
        super().__init__()

    def add(self, method: str, pattern: str, handler: Handler) -> Route:
        route = Route(method.upper(), pattern, handler)
        self.routes.insert(0, route)
        return route

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        for route in self.routes:
            if route.method == request.method and re.search(route.pattern, request.url):
                route.calls += 1
                handler = route.handler
                status, headers, body = handler(request) if callable(handler) else handler
                return self._build(request, status, headers, body)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    def _build(self, request, status, headers, body):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        elif body is None:
            body = b""
        response = requests.Response()
        response.status_code = status
        response.headers = CaseInsensitiveDict(headers or {})
        response.raw = io.BytesIO(body)
        response.request = request
        response.url = request.url
        return response

    def close(self) -> None:
        pass

    @property
    def last(self) -> requests.PreparedRequest:
        return self.requests[-1]


@pytest.fixture(autouse=True)
def reset_settings():
    fresh = Settings()
    saved = {name: getattr(settings, name) for name in Settings.FIELDS if name != "http_client"}
    for name in Settings.FIELDS:
        if name != "http_client":
            setattr(settings, name, getattr(fresh, name))
    settings.http_client = None
    yield
    for name, value in saved.items():
        setattr(settings, name, value)
    settings.http_client = None


@pytest.fixture
def api() -> MockAdapter:
    adapter = MockAdapter()
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    keygen.http_client = session
    keygen.account = "acct"
    keygen.product = "prod"
    keygen.license_key = "LICENSE-KEY"
    return adapter


def body_of(request: requests.PreparedRequest) -> Dict[str, Any]:
    return json.loads(request.body)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def digest_of(body: bytes) -> str:
    return "sha-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()
