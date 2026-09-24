from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Dict, Mapping, Optional, Type
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from . import errors
from ._config import clock_drift, settings
from ._encoding import b64decode

LICENSE_FILE_SIGNING_PREFIX = "license/"
MACHINE_FILE_SIGNING_PREFIX = "machine/"
LICENSE_KEY_SIGNING_PREFIX = "key/"


class SigningAlgorithm(str, Enum):
    ED25519 = "ed25519"
    P256 = "ecdsa-p256"

    def __str__(self) -> str:
        return self.value


class EncodingAlgorithm(str, Enum):
    AES256 = "aes-256-gcm"
    BASE64 = "base64"

    def __str__(self) -> str:
        return self.value


class SchemeCode(str, Enum):
    ED25519 = "ED25519_SIGN"
    P256 = "ECDSA_P256_SIGN"

    def __str__(self) -> str:
        return self.value


def _ed25519_public_key(public_key: str) -> Ed25519PublicKey:
    if not public_key:
        raise errors.PublicKeyMissingError()
    try:
        raw = binascii.unhexlify(public_key.strip())
    except (binascii.Error, ValueError):
        raise errors.PublicKeyInvalidError() from None
    if len(raw) != 32:
        raise errors.PublicKeyInvalidError()
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        raise errors.PublicKeyInvalidError() from None


def _ecdsa_public_key(public_key: str) -> ec.EllipticCurvePublicKey:
    if not public_key:
        raise errors.PublicKeyMissingError()
    try:
        key = load_pem_public_key(public_key.strip().encode())
    except (ValueError, TypeError):
        raise errors.PublicKeyInvalidError() from None
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise errors.PublicKeyInvalidError()
    return key


def _verify(algorithm: str, public_key: str, message: bytes, signature: bytes) -> Optional[bool]:
    """Return whether the signature is valid, or None when the algorithm is unsupported."""
    if algorithm == SigningAlgorithm.ED25519.value:
        ed_key = _ed25519_public_key(public_key)
        try:
            ed_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
    if algorithm == SigningAlgorithm.P256.value:
        ec_key = _ecdsa_public_key(public_key)
        try:
            ec_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False
    return None


def parse_signature_header(header: str) -> Dict[str, str]:
    """Parse a Keygen-Signature header into its parameters."""
    params: Dict[str, str] = {}
    for part in header.split(","):
        key, sep, value = part.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if key:
            params[key] = value
    return params


def _sha256_digest(body: bytes) -> str:
    return "sha-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def _digest_matches(header: str, body: bytes) -> bool:
    expected = _sha256_digest(body)
    for candidate in header.split(","):
        algorithm, sep, _ = candidate.strip().partition("=")
        if sep and algorithm.lower() == "sha-256":
            actual = "sha-256=" + candidate.strip()[len(algorithm) + 1 :]
            return hmac.compare_digest(actual.encode(), expected.encode())
    return False


def _escaped_target(path: str, query: str) -> str:
    target = quote(path or "/", safe="/%:@!$&'()*+,;=-._~") or "/"
    if query:
        target += "?" + query
    return target


class _Headers:
    def __init__(self, headers: Mapping[str, str]) -> None:
        self._headers = {str(k).lower(): v for k, v in headers.items()}

    def get(self, name: str) -> str:
        value = self._headers.get(name.lower())
        if isinstance(value, (list, tuple)):
            value = value[0] if value else ""
        return value.strip() if isinstance(value, str) else ""


_REQUEST_ERRORS: Dict[str, Type[errors.KeygenError]] = {
    "missing_digest": errors.RequestDigestMissingError,
    "invalid_digest": errors.RequestDigestInvalidError,
    "missing_date": errors.RequestDateMissingError,
    "invalid_date": errors.RequestDateInvalidError,
    "old_date": errors.RequestDateTooOldError,
    "missing_sig": errors.RequestSignatureMissingError,
    "invalid_sig": errors.RequestSignatureInvalidError,
    "unsupported_sig": errors.RequestSignatureNotSupportedError,
}

_RESPONSE_ERRORS: Dict[str, Type[errors.KeygenError]] = {
    "missing_digest": errors.ResponseDigestMissingError,
    "invalid_digest": errors.ResponseDigestInvalidError,
    "missing_date": errors.ResponseDateMissingError,
    "invalid_date": errors.ResponseDateInvalidError,
    "old_date": errors.ResponseDateTooOldError,
    "missing_sig": errors.ResponseSignatureMissingError,
    "invalid_sig": errors.ResponseSignatureInvalidError,
    "unsupported_sig": errors.ResponseSignatureNotSupportedError,
}


def _verify_http_signature(
    *,
    public_key: str,
    method: str,
    target: str,
    host: str,
    headers: Mapping[str, str],
    body: bytes,
    kind: str,
) -> None:
    e = _REQUEST_ERRORS if kind == "request" else _RESPONSE_ERRORS

    lookup = _Headers(headers)

    digest_header = lookup.get("Keygen-Digest") or lookup.get("Digest")
    if not digest_header:
        raise e["missing_digest"]()
    if not _digest_matches(digest_header, body):
        raise e["invalid_digest"]()

    date = lookup.get("Keygen-Date") or lookup.get("Date")
    if not date:
        raise e["missing_date"]()
    try:
        sent = parsedate_to_datetime(date)
    except (TypeError, ValueError, IndexError):
        raise e["invalid_date"]() from None
    if sent is None:
        raise e["invalid_date"]()
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)

    drift = clock_drift()
    if drift is not None and datetime.now(timezone.utc) - sent > drift:
        raise e["old_date"]()

    signature_header = lookup.get("Keygen-Signature")
    if not signature_header:
        raise e["missing_sig"]()

    params = parse_signature_header(signature_header)
    algorithm = params.get("algorithm", "")
    encoded = params.get("signature", "")
    if not encoded:
        raise e["missing_sig"]()

    try:
        signature = b64decode(encoded)
    except ValueError:
        raise e["invalid_sig"]() from None

    message = (
        f"(request-target): {method.lower()} {target}\n"
        f"host: {host}\n"
        f"date: {date}\n"
        f"digest: {_sha256_digest(body)}"
    ).encode()

    result = _verify(algorithm, public_key, message, signature)
    if result is None:
        raise e["unsupported_sig"]()
    if not result:
        raise e["invalid_sig"]()


class Verifier:
    """Checks signatures on license keys, license files, machine files and HTTP messages."""

    def __init__(self, public_key: Optional[str] = None) -> None:
        self.public_key = settings.public_key if public_key is None else public_key

    def verify_license_key(self, scheme: str, key: str) -> bytes:
        """Verify a signed license key and return its embedded dataset."""
        if not scheme:
            raise errors.LicenseSchemeMissingError()
        if not key:
            raise errors.LicenseKeyMissingError()

        scheme = str(scheme)
        if scheme == SchemeCode.ED25519.value:
            algorithm = SigningAlgorithm.ED25519.value
        elif scheme == SchemeCode.P256.value:
            algorithm = SigningAlgorithm.P256.value
        else:
            raise errors.SchemeNotSupportedError()

        signing_data, sep, encoded_signature = key.strip().partition(".")
        if not sep or not encoded_signature:
            raise errors.LicenseKeyNotGenuineError()

        prefix, sep, encoded_dataset = signing_data.partition("/")
        if not sep or prefix != "key":
            raise errors.LicenseKeyNotGenuineError()

        try:
            signature = b64decode(encoded_signature, urlsafe=True)
            dataset = b64decode(encoded_dataset, urlsafe=True)
        except ValueError:
            raise errors.LicenseKeyNotGenuineError() from None

        message = (LICENSE_KEY_SIGNING_PREFIX + encoded_dataset).encode()
        if not _verify(algorithm, self.public_key, message, signature):
            raise errors.LicenseKeyNotGenuineError()

        return dataset

    def verify_certificate(
        self,
        *,
        enc: str,
        sig: str,
        algorithm: str,
        prefix: str,
        not_genuine: Type[errors.KeygenError],
        not_supported: Type[errors.KeygenError],
    ) -> None:
        try:
            signature = b64decode(sig, strict_padding=True)
        except ValueError:
            raise not_genuine() from None

        result = _verify(algorithm, self.public_key, (prefix + enc).encode(), signature)
        if result is None:
            raise not_supported()
        if not result:
            raise not_genuine()

    def verify_response(self, response) -> None:
        """Verify the signature of an API response. Raises when it is not genuine."""
        url = urlsplit(response.request.url)
        _verify_http_signature(
            public_key=self.public_key,
            method=response.request.method or "GET",
            target=_escaped_target(url.path, url.query),
            host=url.netloc.rpartition("@")[2],
            headers=response.headers,
            body=response.body,
            kind="response",
        )

    def verify_request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        host: Optional[str] = None,
    ) -> None:
        """Verify the signature of an incoming HTTP request, such as a webhook."""
        parts = urlsplit(url)
        request_host = host or parts.netloc.rpartition("@")[2]
        if not request_host:
            request_host = _Headers(headers).get("Host")
        if isinstance(body, str):
            body = body.encode()
        _verify_http_signature(
            public_key=self.public_key,
            method=method,
            target=_escaped_target(parts.path, parts.query),
            host=request_host,
            headers=headers,
            body=bytes(body or b""),
            kind="request",
        )
