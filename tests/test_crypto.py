from __future__ import annotations

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import keygen
from keygen import _ed25519
from keygen.verifier import parse_signature_header

from conftest import b64url
from helpers import Keys, ed25519ph_public, ed25519ph_sign


RFC8032_PH_PUBLIC = bytes.fromhex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
RFC8032_PH_SECRET = bytes.fromhex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
RFC8032_PH_SIGNATURE = bytes.fromhex(
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
    "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
)


class TestEd25519:
    def test_rfc8032_ed25519ph_vector(self):
        digest = hashlib.sha512(b"abc").digest()
        assert _ed25519.verify(RFC8032_PH_PUBLIC, digest, RFC8032_PH_SIGNATURE, prehashed=True)

    def test_test_signer_matches_rfc_vector(self):
        digest = hashlib.sha512(b"abc").digest()
        assert ed25519ph_public(RFC8032_PH_SECRET) == RFC8032_PH_PUBLIC
        assert ed25519ph_sign(RFC8032_PH_SECRET, digest) == RFC8032_PH_SIGNATURE

    def test_rejects_tampered_digest(self):
        digest = hashlib.sha512(b"abd").digest()
        assert not _ed25519.verify(RFC8032_PH_PUBLIC, digest, RFC8032_PH_SIGNATURE, prehashed=True)

    def test_rejects_wrong_context(self):
        digest = hashlib.sha512(b"abc").digest()
        assert not _ed25519.verify(
            RFC8032_PH_PUBLIC, digest, RFC8032_PH_SIGNATURE, prehashed=True, context=b"product"
        )

    def test_context_roundtrip(self):
        secret = os.urandom(32)
        digest = hashlib.sha512(b"binary").digest()
        signature = ed25519ph_sign(secret, digest, b"product-id")
        public = ed25519ph_public(secret)
        assert _ed25519.verify(public, digest, signature, prehashed=True, context=b"product-id")
        assert not _ed25519.verify(public, digest, signature, prehashed=True, context=b"other")

    @pytest.mark.parametrize("n", range(5))
    def test_pure_mode_matches_cryptography(self, n):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        message = os.urandom(n * 17)
        signature = key.sign(message)
        assert _ed25519.verify(public, message, signature)
        assert not _ed25519.verify(public, message + b"x", signature)

    def test_rejects_malformed_inputs(self):
        digest = hashlib.sha512(b"abc").digest()
        assert not _ed25519.verify(b"short", digest, RFC8032_PH_SIGNATURE, prehashed=True)
        assert not _ed25519.verify(RFC8032_PH_PUBLIC, digest, b"short", prehashed=True)
        assert not _ed25519.verify(RFC8032_PH_PUBLIC, b"not a digest", RFC8032_PH_SIGNATURE, prehashed=True)
        assert not _ed25519.verify(RFC8032_PH_PUBLIC, digest, RFC8032_PH_SIGNATURE, prehashed=True, context=b"x" * 256)
        high_s = RFC8032_PH_SIGNATURE[:32] + b"\xff" * 32
        assert not _ed25519.verify(RFC8032_PH_PUBLIC, digest, high_s, prehashed=True)
        assert not _ed25519.verify(b"\xff" * 32, digest, RFC8032_PH_SIGNATURE, prehashed=True)


def signed_key(keys: Keys, algorithm: str, dataset: bytes) -> str:
    encoded = b64url(dataset)
    signature = keys.sign(algorithm, ("key/" + encoded).encode())
    return f"key/{encoded}.{b64url(signature)}"


class TestLicenseKeys:
    def test_ed25519_key(self):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        key = signed_key(keys, "ed25519", b'{"user":"a@b.c"}')
        license = keygen.License(scheme=keygen.SchemeCode.ED25519, key=key)
        assert license.verify() == b'{"user":"a@b.c"}'

    def test_ecdsa_key_with_explicit_public_key(self):
        keys = Keys()
        key = signed_key(keys, "ecdsa-p256", b"dataset")
        license = keygen.License(scheme="ECDSA_P256_SIGN", key=key)
        assert license.verify(public_key=keys.ecdsa_public) == b"dataset"

    def test_unpadded_base64url_is_accepted(self):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        encoded = b64url(b"ab").rstrip("=")
        signature = b64url(keys.sign("ed25519", ("key/" + encoded).encode())).rstrip("=")
        license = keygen.License(scheme="ED25519_SIGN", key=f"key/{encoded}.{signature}")
        assert license.verify() == b"ab"

    def test_tampered_key(self):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        key = signed_key(keys, "ed25519", b"dataset")
        dataset, signature = key.split(".")
        tampered = f"key/{b64url(b'datasex')}.{signature}"
        with pytest.raises(keygen.LicenseKeyNotGenuineError):
            keygen.License(scheme="ED25519_SIGN", key=tampered).verify()

    def test_key_from_other_keypair(self):
        keygen.public_key = Keys().ed25519_public
        key = signed_key(Keys(), "ed25519", b"dataset")
        with pytest.raises(keygen.LicenseKeyNotGenuineError):
            keygen.License(scheme="ED25519_SIGN", key=key).verify()

    @pytest.mark.parametrize(
        "key",
        ["", "no-dot-at-all", "key/abc", "nope/YWJj.YWJj", "key/!!!.YWJj", "key/YWJj.!!!", "key/YWJj."],
    )
    def test_malformed_keys(self, key):
        keygen.public_key = Keys().ed25519_public
        expected = keygen.LicenseKeyMissingError if not key else keygen.LicenseKeyNotGenuineError
        with pytest.raises(expected):
            keygen.License(scheme="ED25519_SIGN", key=key).verify()

    def test_unsigned_license(self):
        with pytest.raises(keygen.LicenseNotSignedError):
            keygen.License(key="ABC").verify()

    def test_unsupported_scheme(self):
        with pytest.raises(keygen.SchemeNotSupportedError):
            keygen.License(scheme="RSA_2048_PKCS1_SIGN_V2", key="key/YWJj.YWJj").verify()

    def test_missing_public_key(self):
        key = signed_key(Keys(), "ed25519", b"dataset")
        with pytest.raises(keygen.PublicKeyMissingError):
            keygen.License(scheme="ED25519_SIGN", key=key).verify()

    @pytest.mark.parametrize("public_key", ["zz", "abcd", "e8601e48b69383ba"])
    def test_invalid_ed25519_public_key(self, public_key):
        key = signed_key(Keys(), "ed25519", b"dataset")
        with pytest.raises(keygen.PublicKeyInvalidError):
            keygen.License(scheme="ED25519_SIGN", key=key).verify(public_key=public_key)

    def test_invalid_ecdsa_public_key(self):
        keys = Keys()
        key = signed_key(keys, "ecdsa-p256", b"dataset")
        with pytest.raises(keygen.PublicKeyInvalidError):
            keygen.License(scheme="ECDSA_P256_SIGN", key=key).verify(public_key=keys.ed25519_public)


class TestSignatureHeader:
    def test_parses_quoted_params(self):
        params = parse_signature_header(
            'keyid="abc", algorithm="ed25519", signature="a+b/c==", headers="(request-target) host date digest"'
        )
        assert params == {
            "keyid": "abc",
            "algorithm": "ed25519",
            "signature": "a+b/c==",
            "headers": "(request-target) host date digest",
        }

    def test_ignores_malformed_params(self):
        assert parse_signature_header('garbage, algorithm=ed25519,,') == {"algorithm": "ed25519"}
