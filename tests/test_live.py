"""End to end tests against a real Keygen server.

They are skipped unless KEYGEN_HOST and KEYGEN_ADMIN_TOKEN are set. The admin
token is only used to create a throwaway product, policy, entitlement and
license, and to remove them afterwards. Everything else runs through the SDK
exactly as an end user program would, authenticated with the license key.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from datetime import timedelta
from typing import Any, Dict, Iterator

import pytest

import keygen
from keygen.client import Client

HOST = os.environ.get("KEYGEN_HOST", "")
ADMIN_TOKEN = os.environ.get("KEYGEN_ADMIN_TOKEN", "")
ACCOUNT = os.environ.get("KEYGEN_ACCOUNT_ID", "")

pytestmark = pytest.mark.skipif(
    not (HOST and ADMIN_TOKEN), reason="set KEYGEN_HOST and KEYGEN_ADMIN_TOKEN to run live tests"
)


def admin() -> Client:
    return Client(api_url=HOST, account=ACCOUNT, token=ADMIN_TOKEN, license_key="", public_key="")


def create(path: str, type_: str, attributes: Dict[str, Any], relationships: Dict[str, Any] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {"type": type_, "attributes": attributes}
    if relationships:
        data["relationships"] = relationships
    return admin().post(path, {"data": data}).document["data"]


def ref(type_: str, id_: str) -> Dict[str, Any]:
    return {"data": {"type": type_, "id": id_}}


def decode_key(value: Any) -> str:
    return base64.b64decode(value).decode() if isinstance(value, str) and value else ""


@pytest.fixture(scope="module")
def world() -> Iterator[Dict[str, Any]]:
    suffix = uuid.uuid4().hex[:8]
    created = []
    try:
        product = create("products", "products", {"name": f"sdk-live-{suffix}"})
        created.append(f"products/{product['id']}")

        entitlement = create("entitlements", "entitlements", {"name": "Live", "code": f"LIVE_{suffix.upper()}"})
        created.append(f"entitlements/{entitlement['id']}")

        policy = create(
            "policies",
            "policies",
            {
                "name": f"sdk-live-{suffix}",
                "scheme": "ED25519_SIGN",
                "authenticationStrategy": "LICENSE",
                "maxMachines": 1,
                "maxProcesses": 5,
                "requireHeartbeat": True,
                "heartbeatDuration": 600,
                "requireFingerprintScope": True,
                "protected": False,
            },
            {"product": ref("products", product["id"])},
        )
        created.append(f"policies/{policy['id']}")

        admin().post(
            f"policies/{policy['id']}/entitlements",
            {"data": [{"type": "entitlements", "id": entitlement["id"]}]},
        )

        license = create(
            "licenses",
            "licenses",
            {"name": f"sdk-live-{suffix}"},
            {"policy": ref("policies", policy["id"])},
        )
        created.append(f"licenses/{license['id']}")

        account_id = ACCOUNT or admin().get("me").headers.get("Keygen-Account", "")
        account = admin().get(f"accounts/{account_id}").document["data"] if account_id else {}
        keys = (account.get("meta") or {}).get("keys") or {}

        yield {
            "product": product["id"],
            "policy": policy["id"],
            "license": license["id"],
            "key": license["attributes"]["key"],
            "entitlement": entitlement["attributes"]["code"],
            "ed25519": decode_key(keys.get("ed25519")),
            "ecdsa": decode_key(keys.get("ecdsa")),
        }
    finally:
        for path in reversed(created):
            try:
                admin().delete(path)
            except keygen.KeygenError:
                pass


def discard(machine: keygen.Machine) -> None:
    if machine.heartbeat is not None:
        machine.heartbeat.stop()
    try:
        machine.deactivate()
    except keygen.NotFoundError:
        pass


@pytest.fixture(autouse=True)
def configure(world, reset_settings):
    keygen.api_url = HOST
    keygen.account = ACCOUNT
    keygen.product = world["product"]
    keygen.license_key = world["key"]
    keygen.public_key = world["ed25519"]


def test_full_licensing_flow(world):
    assert world["ed25519"], "the account did not expose an ed25519 public key"
    fingerprint = str(uuid.uuid4())

    with pytest.raises(keygen.ValidationFingerprintMissingError):
        keygen.validate()

    with pytest.raises(keygen.LicenseNotActivatedError) as info:
        keygen.validate(fingerprint)
    license = info.value.license
    assert license.id == world["license"]
    assert license.last_validation.code == keygen.ValidationCode.NO_MACHINE
    assert license.last_validation.valid is False
    assert license.policy_id == world["policy"]

    assert license.verify()

    lic = license.checkout()
    lic.verify()
    with pytest.raises(keygen.LicenseFileEncryptedError):
        lic.decode()
    dataset = lic.decrypt(license.key)
    assert dataset.license.id == license.id
    assert [e.code for e in dataset.entitlements] == [world["entitlement"]]
    assert dataset.ttl > 0 and dataset.issued and dataset.expiry

    lic = license.checkout(include=(), encrypt=False, ttl=timedelta(days=1))
    lic.verify()
    with pytest.raises(keygen.LicenseFileNotEncryptedError):
        lic.decrypt(license.key)
    dataset = lic.decode()
    assert dataset.entitlements == []

    machine = license.activate(fingerprint)
    try:
        assert machine.fingerprint == fingerprint
        assert machine.require_heartbeat is True

        with pytest.raises(keygen.MachineLimitExceededError):
            license.activate(str(uuid.uuid4()))

        mic = machine.checkout()
        mic.verify()
        with pytest.raises(keygen.MachineFileEncryptedError):
            mic.decode()
        dataset = mic.decrypt(license.key + machine.fingerprint)
        assert dataset.machine.id == machine.id
        assert dataset.license.id == license.id
        assert [e.code for e in dataset.entitlements] == [world["entitlement"]]

        try:
            keygen.validate(fingerprint)
        except keygen.HeartbeatRequiredError as err:
            assert err.result.code == keygen.ValidationCode.HEARTBEAT_NOT_STARTED

        monitor = machine.monitor()
        assert monitor.running
        assert machine.heartbeat_status == keygen.HeartbeatStatus.ALIVE

        processes = [machine.spawn(str(uuid.uuid4())) for _ in range(5)]
        assert all(p.status == keygen.ProcessStatus.ALIVE for p in processes)
        with pytest.raises(keygen.ProcessLimitExceededError):
            machine.spawn(str(uuid.uuid4()))
        assert len(machine.processes()) == 5
        for process in processes:
            process.kill()
        assert machine.processes() == []

        assert license.machine(fingerprint).id == machine.id
        with pytest.raises(keygen.NotFoundError):
            license.machine("<invalid>")

        valid = keygen.validate(fingerprint)
        assert valid.last_validation.valid is True
        assert valid.last_validation.code == keygen.ValidationCode.VALID
        assert valid.last_validation.scope.fingerprint == fingerprint

        assert [e.code for e in license.entitlements()] == [world["entitlement"]]
        assert [m.id for m in license.machines()] == [machine.id]

        machine.deactivate()
        assert not monitor.running
        with pytest.raises(keygen.NotFoundError):
            license.deactivate(fingerprint)
    finally:
        discard(machine)


def test_components(world):
    fingerprint = str(uuid.uuid4())
    board, disk = str(uuid.uuid4()), str(uuid.uuid4())

    license = keygen.me()
    machine = license.activate(
        fingerprint,
        keygen.Component(name="Board", fingerprint=board),
        keygen.Component(name="Disk", fingerprint=disk),
    )
    try:
        machine.monitor()
        components = machine.components()
        assert sorted(c.fingerprint for c in components) == sorted([board, disk])

        valid = keygen.validate(fingerprint, board, disk)
        assert sorted(valid.last_validation.scope.components) == sorted([board, disk])

        with pytest.raises(keygen.ComponentNotActivatedError):
            license.validate(fingerprint, str(uuid.uuid4()))

        mic = machine.checkout(include=("components", "license", "license.entitlements"))
        mic.verify()
        dataset = mic.decrypt(license.key + fingerprint)
        assert sorted(c.fingerprint for c in dataset.components) == sorted([board, disk])
    finally:
        discard(machine)


def test_bad_credentials(world):
    keygen.license_key = "NOT-A-REAL-KEY"
    with pytest.raises(keygen.LicenseKeyError):
        keygen.validate()

    keygen.license_key = ""
    with pytest.raises(keygen.APIError) as info:
        keygen.validate()
    assert info.value.status == 401


def test_tampered_public_key_is_rejected(world):
    keygen.public_key = "00" * 32
    with pytest.raises(keygen.SignatureVerificationError):
        keygen.me()


def test_ecdsa_signatures(world):
    assert world["ecdsa"], "the account did not expose an ecdsa public key"
    keygen.signature_scheme = keygen.SigningAlgorithm.P256
    keygen.public_key = world["ecdsa"]

    license = keygen.me()
    lic = license.checkout(encrypt=False)
    lic.verify()
    assert lic.decode().license.id == license.id

    with pytest.raises(keygen.PublicKeyInvalidError):
        lic.verify(world["ed25519"])


def test_heartbeat_keeps_machine_alive(world, monkeypatch):
    from keygen import heartbeat

    monkeypatch.setattr(heartbeat, "schedule", lambda duration: (1.0, 5.0))
    fingerprint = str(uuid.uuid4())
    machine = keygen.me().activate(fingerprint)
    try:
        monitor = machine.monitor()
        time.sleep(3.5)
        assert monitor.running and monitor.error is None
        keygen.validate(fingerprint)
    finally:
        discard(machine)
