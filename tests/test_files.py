from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

import keygen

import fixtures
from helpers import Keys, license_resource, machine_resource, make_certificate


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def license_document(*, ttl=3600, issued=None, expiry=None, entitlements=("FEATURE_A",)):
    now = datetime.now(timezone.utc)
    issued = issued or now
    expiry = expiry or (now + timedelta(seconds=ttl or 3600))
    return {
        "data": license_resource(),
        "included": [
            {"id": f"ent-{code}", "type": "entitlements", "attributes": {"code": code, "metadata": {}}}
            for code in entitlements
        ]
        + [{"id": "pol-1", "type": "policies", "attributes": {}}],
        "meta": {"issued": iso(issued), "expiry": iso(expiry) if ttl else None, "ttl": ttl},
    }


def machine_document(*, ttl=3600):
    now = datetime.now(timezone.utc)
    return {
        "data": machine_resource(),
        "included": [
            license_resource(),
            {"id": "ent-1", "type": "entitlements", "attributes": {"code": "FEATURE_A"}},
            {"id": "cmp-1", "type": "components", "attributes": {"fingerprint": "disk", "name": "Disk"}},
            {"id": "cmp-2", "type": "components", "attributes": {"fingerprint": "cpu", "name": "CPU"}},
        ],
        "meta": {"issued": iso(now), "expiry": iso(now + timedelta(seconds=ttl)), "ttl": ttl},
    }


def license_file(keys, document=None, **kwargs):
    cert = make_certificate("LICENSE FILE", "license/", document or license_document(), keys, **kwargs)
    return keygen.LicenseFile(certificate=cert)


class TestRealFixtures:
    def test_license_file_is_genuine(self):
        keygen.LicenseFile(certificate=fixtures.LICENSE_FILE).verify(fixtures.ED25519_PUBLIC_KEY)

    def test_license_file_without_ttl_is_genuine(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.LicenseFile(certificate=fixtures.LICENSE_FILE_NO_TTL).verify()

    def test_machine_file_is_genuine(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.MachineFile(certificate=fixtures.MACHINE_FILE).verify()

    def test_license_file_with_other_key_is_not_genuine(self):
        with pytest.raises(keygen.LicenseFileNotGenuineError) as info:
            keygen.LicenseFile(certificate=fixtures.LICENSE_FILE).verify(Keys().ed25519_public)
        assert isinstance(info.value, keygen.LicenseFileError)

    def test_machine_certificate_is_not_a_license_file(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        with pytest.raises(keygen.LicenseFileError):
            keygen.LicenseFile(certificate=fixtures.MACHINE_FILE).verify()

    def test_encrypted_file_cannot_be_decoded(self):
        with pytest.raises(keygen.LicenseFileEncryptedError):
            keygen.LicenseFile(certificate=fixtures.LICENSE_FILE).decode()

    def test_wrong_decryption_key(self):
        with pytest.raises(keygen.LicenseFileError, match="decrypted"):
            keygen.LicenseFile(certificate=fixtures.LICENSE_FILE).decrypt("wrong")

    def test_missing_decryption_key(self):
        with pytest.raises(keygen.LicenseFileSecretMissingError):
            keygen.LicenseFile(certificate=fixtures.LICENSE_FILE).decrypt("")
        with pytest.raises(keygen.MachineFileSecretMissingError):
            keygen.MachineFile(certificate=fixtures.MACHINE_FILE).decrypt("")

    def test_windows_line_endings(self):
        cert = fixtures.LICENSE_FILE.replace("\n", "\r\n")
        keygen.LicenseFile(certificate=cert).verify(fixtures.ED25519_PUBLIC_KEY)

    def test_bytes_certificate(self):
        keygen.LicenseFile(certificate=fixtures.LICENSE_FILE.encode()).verify(fixtures.ED25519_PUBLIC_KEY)


class TestLicenseFiles:
    def test_encrypted_roundtrip(self):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        lic = license_file(keys, secret="LICENSE-KEY")
        lic.verify()
        with pytest.raises(keygen.LicenseFileEncryptedError):
            lic.decode()
        dataset = lic.decrypt("LICENSE-KEY")
        assert dataset.license.id == "lic-1"
        assert dataset.license.policy_id == "pol-1"
        assert dataset.license.metadata == {"email": "user@example.com"}
        assert [e.code for e in dataset.entitlements] == ["FEATURE_A"]
        assert dataset.ttl == 3600
        assert dataset.issued is not None and dataset.expiry is not None

    def test_unencrypted_ecdsa_roundtrip(self):
        keys = Keys()
        lic = license_file(keys, algorithm="ecdsa-p256", document=license_document(entitlements=()))
        lic.verify(keys.ecdsa_public)
        with pytest.raises(keygen.LicenseFileNotEncryptedError):
            lic.decrypt("LICENSE-KEY")
        dataset = lic.decode()
        assert dataset.entitlements == []

    def test_ecdsa_file_with_ed25519_key(self):
        keys = Keys()
        lic = license_file(keys, algorithm="ecdsa-p256")
        with pytest.raises(keygen.PublicKeyInvalidError):
            lic.verify(keys.ed25519_public)

    def test_tampered_payload(self):
        keys = Keys()
        cert = make_certificate("LICENSE FILE", "license/", license_document(), keys)
        body = cert.split("-----")[2]
        payload = json.loads(base64.b64decode("".join(body.split())))
        payload["enc"] = base64.b64encode(b'{"data":{"id":"forged","type":"licenses"}}').decode()
        forged = base64.b64encode(json.dumps(payload).encode()).decode()
        lic = keygen.LicenseFile(certificate=f"-----BEGIN LICENSE FILE-----\n{forged}\n-----END LICENSE FILE-----")
        with pytest.raises(keygen.LicenseFileNotGenuineError):
            lic.verify(keys.ed25519_public)
        assert lic.decode().license.id == "forged"

    def test_expired(self):
        keys = Keys()
        past = datetime.now(timezone.utc) - timedelta(days=2)
        document = license_document(issued=past, expiry=past + timedelta(hours=1))
        with pytest.raises(keygen.LicenseFileExpiredError) as info:
            license_file(keys, document=document).decode()
        assert info.value.dataset.license.id == "lic-1"

    def test_without_ttl_never_expires(self):
        keys = Keys()
        past = datetime.now(timezone.utc) - timedelta(days=400)
        document = license_document(issued=past, ttl=None)
        dataset = license_file(keys, document=document).decode()
        assert dataset.ttl == 0 and dataset.expiry is None

    def test_issued_in_the_future(self):
        keys = Keys()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        document = license_document(issued=future)
        with pytest.raises(keygen.SystemClockUnsyncedError) as info:
            license_file(keys, document=document).decode()
        assert info.value.dataset is not None

    def test_clock_check_can_be_disabled(self):
        keygen.max_clock_drift = None
        keys = Keys()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        license_file(keys, document=license_document(issued=future)).decode()
        keygen.max_clock_drift = -1
        license_file(keys, document=license_document(issued=future)).decode()

    def test_clock_drift_within_limit(self):
        keygen.max_clock_drift = timedelta(hours=2)
        keys = Keys()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        license_file(keys, document=license_document(issued=future)).decode()

    @pytest.mark.parametrize(
        "cert",
        [
            "",
            "-----BEGIN LICENSE FILE-----\n-----END LICENSE FILE-----",
            "-----BEGIN LICENSE FILE-----\nnot base64!\n-----END LICENSE FILE-----",
            "-----BEGIN LICENSE FILE-----\n" + base64.b64encode(b"not json").decode() + "\n-----END LICENSE FILE-----",
            "-----BEGIN LICENSE FILE-----\n" + base64.b64encode(b"[1,2]").decode() + "\n-----END LICENSE FILE-----",
            "-----BEGIN LICENSE FILE-----\n" + base64.b64encode(b'{"enc":1,"sig":"","alg":""}').decode() + "\n-----END LICENSE FILE-----",
        ],
    )
    def test_malformed_certificates(self, cert):
        lic = keygen.LicenseFile(certificate=cert)
        for action in (lic.verify, lic.decode, lambda: lic.decrypt("k")):
            with pytest.raises(keygen.LicenseFileError):
                action()

    @pytest.mark.parametrize("alg", ["base64", "rot13+ed25519", "base64+rsa", "aes-256-gcm+rsa"])
    def test_unsupported_algorithms(self, alg):
        payload = json.dumps({"enc": "e30=", "sig": "", "alg": alg}).encode()
        cert = "-----BEGIN LICENSE FILE-----\n" + base64.b64encode(payload).decode() + "\n-----END LICENSE FILE-----"
        lic = keygen.LicenseFile(certificate=cert)
        with pytest.raises(keygen.LicenseFileError):
            lic.verify(Keys().ed25519_public)
        with pytest.raises(keygen.LicenseFileNotSupportedError):
            if alg.startswith("aes"):
                lic.decrypt("key")
            else:
                lic.decode()

    def test_malformed_encrypted_payload(self):
        payload = json.dumps({"enc": "abc.def", "sig": "", "alg": "aes-256-gcm+ed25519"}).encode()
        cert = base64.b64encode(payload).decode()
        with pytest.raises(keygen.LicenseFileError):
            keygen.LicenseFile(certificate=cert).decrypt("key")

    def test_decoded_payload_is_not_a_document(self):
        payload = json.dumps(
            {"enc": base64.b64encode(b'{"data": null}').decode(), "sig": "", "alg": "base64+ed25519"}
        ).encode()
        with pytest.raises(keygen.LicenseFileError):
            keygen.LicenseFile(certificate=base64.b64encode(payload).decode()).decode()


class TestMachineFiles:
    def test_encrypted_roundtrip(self):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        cert = make_certificate("MACHINE FILE", "machine/", machine_document(), keys, secret="LICENSE-KEYfp")
        mic = keygen.MachineFile(certificate=cert)
        mic.verify()
        dataset = mic.decrypt("LICENSE-KEYfp")
        assert dataset.machine.id == "mach-1"
        assert dataset.machine.license_id == "lic-1"
        assert dataset.license.id == "lic-1"
        assert [e.code for e in dataset.entitlements] == ["FEATURE_A"]
        assert [c.fingerprint for c in dataset.components] == ["disk", "cpu"]

    def test_signed_with_license_prefix_is_not_genuine(self):
        keys = Keys()
        cert = make_certificate("MACHINE FILE", "license/", machine_document(), keys)
        with pytest.raises(keygen.MachineFileNotGenuineError):
            keygen.MachineFile(certificate=cert).verify(keys.ed25519_public)

    def test_expired(self):
        keys = Keys()
        document = machine_document()
        past = datetime.now(timezone.utc) - timedelta(days=1)
        document["meta"] = {"issued": iso(past), "expiry": iso(past + timedelta(minutes=1)), "ttl": 60}
        cert = make_certificate("MACHINE FILE", "machine/", document, keys)
        with pytest.raises(keygen.MachineFileExpiredError) as info:
            keygen.MachineFile(certificate=cert).decode()
        assert info.value.dataset.machine.id == "mach-1"
