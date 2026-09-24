from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional
from urllib.parse import quote, urlencode, urlsplit

import requests

from . import errors
from ._config import SDK_VERSION, request_lock, settings
from ._jsonapi import CONTENT_TYPE
from ._platform import current_platform
from .errors import ErrorCode
from .verifier import Verifier

_UNSET: Any = object()

_BODY_METHODS = ("POST", "PUT", "PATCH")


@dataclass
class Response:
    """A raw API response along with its parsed JSON:API document."""

    request: Any
    id: str
    status: int
    headers: Mapping[str, str]
    body: bytes = b""
    document: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def size(self) -> int:
        return len(self.body)

    def tldr(self) -> str:
        text = self.body.decode("utf-8", errors="replace")
        if len(text) > 500:
            text = text[:500] + "..."
        return text.replace("\r", "\\r").replace("\n", "\\n")


def segment(value: Any) -> str:
    """Escape a value so it can be used as a single URL path segment."""
    return quote(str(value), safe="")


def expect_resource(response: Response, what: str) -> Dict[str, Any]:
    """Return the primary resource of a response, raising when the API sent none."""
    document = response.document
    data = document.get("data") if isinstance(document, dict) else None
    if not isinstance(data, dict):
        raise errors.APIError(f"the API response did not include a {what}", response=response)
    return data


def _encode_query(query: Optional[Mapping[str, Any]]) -> str:
    if not query:
        return ""
    pairs = []
    for key in sorted(query):
        value = query[key]
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        pairs.append((key, str(value)))
    return urlencode(pairs)


def _header_int(headers: Mapping[str, str], name: str) -> int:
    try:
        return int(str(headers.get(name, "")).strip())
    except ValueError:
        return 0


class Client:
    """HTTP client for the Keygen API.

    Any option left as None falls back to the global configuration at the
    moment the client is created.
    """

    def __init__(
        self,
        *,
        account: Optional[str] = None,
        environment: Optional[str] = None,
        license_key: Optional[str] = None,
        token: Optional[str] = None,
        public_key: Optional[str] = None,
        accept_signature: Optional[str] = None,
        user_agent: Optional[str] = None,
        api_version: Optional[str] = None,
        api_prefix: Optional[str] = None,
        api_url: Optional[str] = None,
        http_client: Optional[requests.Session] = None,
        timeout: Any = _UNSET,
    ) -> None:
        self.account = settings.account if account is None else account
        self.environment = settings.environment if environment is None else environment
        self.license_key = settings.license_key if license_key is None else license_key
        self.token = settings.token if token is None else token
        self.public_key = settings.public_key if public_key is None else public_key
        self.accept_signature = str(
            settings.signature_scheme if accept_signature is None else accept_signature
        )
        self.user_agent = settings.user_agent if user_agent is None else user_agent
        self.api_version = api_version or settings.api_version
        self.api_prefix = api_prefix or settings.api_prefix
        self.api_url = api_url or settings.api_url
        self._http_client = http_client
        self.timeout = settings.timeout if timeout is _UNSET else timeout

    @property
    def http_client(self) -> requests.Session:
        return self._http_client or settings.http_client

    def get(self, path: str, *, query: Optional[Mapping[str, Any]] = None) -> Response:
        return self.request("GET", path, query=query)

    def post(
        self, path: str, body: Any = None, *, query: Optional[Mapping[str, Any]] = None
    ) -> Response:
        return self.request("POST", path, body, query=query)

    def put(
        self, path: str, body: Any = None, *, query: Optional[Mapping[str, Any]] = None
    ) -> Response:
        return self.request("PUT", path, body, query=query)

    def patch(
        self, path: str, body: Any = None, *, query: Optional[Mapping[str, Any]] = None
    ) -> Response:
        return self.request("PATCH", path, body, query=query)

    def delete(self, path: str, *, query: Optional[Mapping[str, Any]] = None) -> Response:
        return self.request("DELETE", path, query=query)

    def url(self, path: str, query: Optional[Mapping[str, Any]] = None) -> str:
        host = (self.api_url or "").strip().rstrip("/")
        if not host.startswith(("https://", "http://")):
            host = "https://" + host

        prefix = self.api_prefix.strip("/")
        path = path.lstrip("/")

        parts = urlsplit(host)
        if parts.scheme == "https" and parts.netloc.lower() == "api.keygen.sh" and not parts.path:
            if not self.account:
                raise errors.KeygenError("account is required when using api.keygen.sh")
            url = f"{host}/{prefix}/accounts/{segment(self.account)}/{path}"
        else:
            url = f"{host}/{prefix}/{path}"

        encoded = _encode_query(query)
        if encoded:
            url += "?" + encoded

        return url

    def _headers(self, has_body: bool) -> Dict[str, str]:
        agent = " ".join(
            part
            for part in (
                f"keygen/{self.api_version}",
                f"sdk/{SDK_VERSION}",
                f"python/{platform.python_version()}",
                current_platform(),
                (self.user_agent or "").strip(),
            )
            if part
        )

        headers = {
            "Accept": CONTENT_TYPE,
            "User-Agent": agent,
            "Keygen-Version": self.api_version,
        }

        if self.license_key:
            headers["Authorization"] = "License " + self.license_key
        elif self.token:
            headers["Authorization"] = "Bearer " + self.token

        if self.environment:
            headers["Keygen-Environment"] = self.environment

        if self.accept_signature:
            headers["Keygen-Accept-Signature"] = f'algorithm="{self.accept_signature}"'

        if has_body:
            headers["Content-Type"] = CONTENT_TYPE

        return headers

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        query: Optional[Mapping[str, Any]] = None,
    ) -> Response:
        """Perform an API request and return the verified, parsed response."""
        method = method.upper()
        url = self.url(path, query)
        log = settings.logger

        data: Optional[bytes] = None
        if body is not None and method in _BODY_METHODS:
            data = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode()

        log.info("Request: method=%s url=%s size=%d", method, url, len(data or b""))
        if data:
            log.debug("        body=%s", data.decode("utf-8", errors="replace"))

        try:
            with request_lock:
                res = self.http_client.request(
                    method,
                    url,
                    data=data,
                    headers=self._headers(bool(data)),
                    allow_redirects=False,
                    timeout=self.timeout,
                )
                content = res.content
        except requests.RequestException as err:
            log.error("Error performing request: method=%s url=%s err=%s", method, url, err)
            raise errors.NetworkError(f"request failed: method={method} url={url} err={err}") from err

        response = Response(
            request=res.request,
            id=res.headers.get("x-request-id", ""),
            status=res.status_code,
            headers=res.headers,
            body=content or b"",
        )

        log.info("Response: id=%s status=%d size=%d", response.id, response.status, response.size)
        if response.size:
            log.debug("         body=%s", response.body.decode("utf-8", errors="replace"))

        if response.status == 429:
            reset_at = _header_int(response.headers, "X-RateLimit-Reset")
            raise errors.RateLimitError(
                response=response,
                window=response.headers.get("X-RateLimit-Window", ""),
                count=_header_int(response.headers, "X-RateLimit-Count"),
                limit=_header_int(response.headers, "X-RateLimit-Limit"),
                remaining=_header_int(response.headers, "X-RateLimit-Remaining"),
                reset=_timestamp(reset_at),
                retry_after=_header_int(response.headers, "Retry-After"),
            )

        if response.status >= 500:
            log.error(
                "An unexpected API error occurred: id=%s status=%d size=%d body=%s",
                response.id,
                response.status,
                response.size,
                response.tldr(),
            )
            first = _first_error(_try_json(response.body))
            raise errors.APIError(response=response, **first)

        if self.public_key:
            try:
                Verifier(self.public_key).verify_response(response)
            except errors.KeygenError as err:
                log.error(
                    "Error verifying response signature: id=%s status=%d size=%d body=%s err=%s",
                    response.id,
                    response.status,
                    response.size,
                    response.tldr(),
                    err,
                )
                err.response = response
                raise

        if response.status == 204 or response.size == 0:
            if response.status == 404:
                raise errors.NotFoundError(response=response)
            if response.status >= 400:
                raise errors.APIError(response=response)
            return response

        document = _try_json(response.body)
        if not isinstance(document, dict):
            log.error(
                "Error parsing response JSON: id=%s status=%d size=%d body=%s",
                response.id,
                response.status,
                response.size,
                response.tldr(),
            )
            raise errors.APIError("response body is not a valid JSON:API document", response=response)

        response.document = document

        api_errors = document.get("errors")
        if isinstance(api_errors, list) and api_errors:
            raise _map_error(response, _first_error(document))

        if response.status == 404:
            raise errors.NotFoundError(response=response)
        if response.status >= 400:
            raise errors.APIError(response=response)

        return response


def _timestamp(seconds: int) -> Optional[datetime]:
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"unsupported JSON constant {name}")


def _try_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        return None


def _first_error(document: Any) -> Dict[str, Optional[str]]:
    empty: Dict[str, Optional[str]] = {"title": None, "detail": None, "code": None, "source": None}
    if not isinstance(document, dict):
        return empty
    items = document.get("errors")
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return empty
    item = items[0]
    source = item.get("source")
    pointer = None
    if isinstance(source, dict):
        pointer = source.get("pointer") or source.get("parameter") or source.get("header")
    return {
        "title": _opt_str(item.get("title")),
        "detail": _opt_str(item.get("detail")),
        "code": _opt_str(item.get("code")),
        "source": _opt_str(pointer),
    }


def _opt_str(value: Any) -> Optional[str]:
    return None if value is None else str(value)


_FORBIDDEN_ERRORS = {
    ErrorCode.TOKEN_NOT_ALLOWED: errors.TokenNotAllowedError,
    ErrorCode.TOKEN_FORMAT_INVALID: errors.TokenFormatInvalidError,
    ErrorCode.TOKEN_INVALID: errors.TokenInvalidError,
    ErrorCode.TOKEN_EXPIRED: errors.TokenExpiredError,
    ErrorCode.LICENSE_NOT_ALLOWED: errors.LicenseNotAllowedError,
    ErrorCode.LICENSE_SUSPENDED: errors.LicenseSuspendedError,
    ErrorCode.LICENSE_EXPIRED: errors.LicenseExpiredError,
}

_SIMPLE_ERRORS = {
    ErrorCode.MACHINE_HEARTBEAT_DEAD: errors.HeartbeatDeadError,
    ErrorCode.PROCESS_HEARTBEAT_DEAD: errors.HeartbeatDeadError,
    ErrorCode.FINGERPRINT_TAKEN: errors.MachineAlreadyActivatedError,
    ErrorCode.MACHINE_LIMIT_EXCEEDED: errors.MachineLimitExceededError,
    ErrorCode.PROCESS_LIMIT_EXCEEDED: errors.ProcessLimitExceededError,
    ErrorCode.COMPONENT_FINGERPRINT_CONFLICT: errors.ComponentConflictError,
    ErrorCode.COMPONENT_FINGERPRINT_TAKEN: errors.ComponentAlreadyActivatedError,
}

_WRAPPED_ERRORS = {
    ErrorCode.ENVIRONMENT_INVALID: errors.InvalidEnvironmentError,
    ErrorCode.ENVIRONMENT_NOT_SUPPORTED: errors.InvalidEnvironmentError,
    ErrorCode.TOKEN_INVALID: errors.LicenseTokenError,
    ErrorCode.LICENSE_INVALID: errors.LicenseKeyError,
    ErrorCode.NOT_FOUND: errors.NotFoundError,
}


def _map_error(response: Response, details: Dict[str, Optional[str]]) -> errors.KeygenError:
    api_error = errors.APIError(response=response, **details)
    code = details["code"]

    if response.status == 403:
        cls: Optional[type] = _FORBIDDEN_ERRORS.get(code) if code else None
        if cls is not None:
            err = cls(response=response)
            err.__cause__ = api_error
            return err
        return errors.NotAuthorizedError(response=response, **details)

    simple = _SIMPLE_ERRORS.get(code) if code else None
    if simple is not None:
        err = simple(response=response)
        err.__cause__ = api_error
        return err

    wrapped = _WRAPPED_ERRORS.get(code) if code else None
    if wrapped is not None:
        return wrapped(response=response, **details)

    if response.status == 404:
        return errors.NotFoundError(response=response, **details)

    return api_error

