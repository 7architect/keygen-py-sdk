from __future__ import annotations

import base64
import hashlib
import json
import os
import textwrap
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keygen import _ed25519
from conftest import digest_of


class Keys:
    def __init__(self) -> None:
        self.ed25519 = Ed25519PrivateKey.generate()
        self.ecdsa = ec.generate_private_key(ec.SECP256R1())

    @property
    def ed25519_public(self) -> str:
        raw = self.ed25519.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw.hex()

    @property
    def ecdsa_public(self) -> str:
        return self.ecdsa.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign(self, algorithm: str, message: bytes) -> bytes:
        if algorithm == "ed25519":
            return self.ed25519.sign(message)
        return self.ecdsa.sign(message, ec.ECDSA(hashes.SHA256()))


def http_date(when: Optional[datetime] = None) -> str:
    return format_datetime(when or datetime.now(timezone.utc), usegmt=True)


def signed_headers(
    keys: Keys,
    method: str,
    url: str,
    body: bytes,
    *,
    algorithm: str = "ed25519",
    date: Optional[str] = None,
) -> Dict[str, str]:
    parts = urlsplit(url)
    target = parts.path + ("?" + parts.query if parts.query else "")
    date = date or http_date()
    digest = digest_of(body)
    message = (
        f"(request-target): {method.lower()} {target}\n"
        f"host: {parts.netloc}\n"
        f"date: {date}\n"
        f"digest: {digest}"
    ).encode()
    signature = base64.b64encode(keys.sign(algorithm, message)).decode()
    return {
        "Date": date,
        "Digest": digest,
        "Keygen-Signature": (
            f'keyid="acct", algorithm="{algorithm}", signature="{signature}", '
            'headers="(request-target) host date digest"'
        ),
    }


def make_certificate(
    label: str,
    prefix: str,
    document: Dict[str, Any],
    keys: Keys,
    *,
    algorithm: str = "ed25519",
    secret: Optional[str] = None,
) -> str:
    plaintext = json.dumps(document).encode()
    if secret is None:
        enc = base64.b64encode(plaintext).decode()
        encoding = "base64"
    else:
        iv = os.urandom(12)
        sealed = AESGCM(hashlib.sha256(secret.encode()).digest()).encrypt(iv, plaintext, None)
        ciphertext, tag = sealed[:-16], sealed[-16:]
        enc = ".".join(base64.b64encode(p).decode() for p in (ciphertext, iv, tag))
        encoding = "aes-256-gcm"

    sig = base64.b64encode(keys.sign(algorithm, (prefix + enc).encode())).decode()
    payload = json.dumps({"enc": enc, "sig": sig, "alg": f"{encoding}+{algorithm}"}).encode()
    body = "\n".join(textwrap.wrap(base64.b64encode(payload).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def ed25519ph_sign(secret: bytes, digest: bytes, context: bytes = b"") -> bytes:
    """Test only Ed25519ph signer following RFC 8032."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = _compress(_ed25519._multiply(a, _ed25519._BASE))
    dom = _ed25519._domain(True, context)
    r = int.from_bytes(hashlib.sha512(dom + h[32:] + digest).digest(), "little") % _ed25519._L
    r_bytes = _compress(_ed25519._multiply(r, _ed25519._BASE))
    k = int.from_bytes(hashlib.sha512(dom + r_bytes + public + digest).digest(), "little") % _ed25519._L
    s = (r + k * a) % _ed25519._L
    return r_bytes + s.to_bytes(32, "little")


def ed25519ph_public(secret: bytes) -> bytes:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_ed25519._multiply(a, _ed25519._BASE))


def _compress(point) -> bytes:
    p = _ed25519._P
    zinv = pow(point[2], p - 2, p)
    x = point[0] * zinv % p
    y = point[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def license_resource(id_: str = "lic-1", **attrs: Any) -> Dict[str, Any]:
    base = {
        "name": "Demo License",
        "key": "LICENSE-KEY",
        "expiry": None,
        "scheme": None,
        "requireHeartbeat": False,
        "lastValidated": "2023-02-09T21:20:13.679Z",
        "metadata": {"email": "user@example.com"},
        "created": "2020-09-14T21:18:08.990Z",
        "updated": "2023-02-09T21:20:13.691Z",
    }
    base.update(attrs)
    return {
        "id": id_,
        "type": "licenses",
        "attributes": base,
        "relationships": {"policy": {"data": {"type": "policies", "id": "pol-1"}}},
    }


def machine_resource(id_: str = "mach-1", fingerprint: str = "fp", **attrs: Any) -> Dict[str, Any]:
    base = {
        "fingerprint": fingerprint,
        "name": None,
        "hostname": "host",
        "platform": "linux/amd64",
        "ip": None,
        "cores": 8,
        "requireHeartbeat": True,
        "heartbeatStatus": "ALIVE",
        "heartbeatDuration": 600,
        "metadata": {},
        "created": "2023-01-01T00:00:00Z",
        "updated": "2023-01-01T00:00:00Z",
    }
    base.update(attrs)
    return {
        "id": id_,
        "type": "machines",
        "attributes": base,
        "relationships": {"license": {"data": {"type": "licenses", "id": "lic-1"}}},
    }
