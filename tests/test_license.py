from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import pytest

import keygen

from conftest import body_of
from helpers import license_resource, machine_resource


def validation(code, valid=False, scope=None):
    meta = {"valid": valid, "code": code, "detail": code.lower()}
    if scope is not None:
        meta["scope"] = scope
    return {"data": license_resource(lastValidated="2024-01-01T00:00:00Z"), "meta": meta}


def query_of(request):
    return {k: v[0] for k, v in parse_qs(urlsplit(request.url).query, keep_blank_values=True).items()}


class TestValidate:
    def test_valid_with_scope(self, api):
        keygen.environment = "env-1"
        scope = {"fingerprint": "fp", "components": ["a", "b"], "product": "prod", "environment": "env-1"}
        api.add("GET", r"/me$", (200, {}, {"data": license_resource()}))
        api.add("POST", r"/licenses/lic-1/actions/validate$", (200, {}, validation("VALID", True, scope)))

        license = keygen.validate("fp", "a", "b")

        assert body_of(api.last) == {"meta": {"scope": scope}}
        assert license.last_validation.scope.fingerprint == "fp"
        assert license.last_validation.scope.components == ["a", "b"]
        assert license.last_validated.year == 2024

    def test_no_scope(self, api):
        keygen.product = ""
        api.add("POST", r"/validate$", (200, {}, validation("VALID", True)))
        result = keygen.License(id="lic-1").validate()
        assert body_of(api.last) == {"meta": {"scope": {}}}
        assert result.valid and result.scope is None

    def test_empty_fingerprint_is_not_sent(self, api):
        api.add("POST", r"/validate$", (200, {}, validation("VALID", True)))
        keygen.License(id="lic-1").validate("", "cpu", "")
        assert body_of(api.last)["meta"]["scope"] == {"components": ["cpu"], "product": "prod"}

    @pytest.mark.parametrize(
        "code,error",
        [
            ("NO_MACHINE", keygen.LicenseNotActivatedError),
            ("NO_MACHINES", keygen.LicenseNotActivatedError),
            ("FINGERPRINT_SCOPE_MISMATCH", keygen.LicenseNotActivatedError),
            ("EXPIRED", keygen.LicenseExpiredError),
            ("SUSPENDED", keygen.LicenseSuspendedError),
            ("TOO_MANY_MACHINES", keygen.LicenseTooManyMachinesError),
            ("TOO_MANY_CORES", keygen.LicenseTooManyCoresError),
            ("TOO_MANY_PROCESSES", keygen.LicenseTooManyProcessesError),
            ("FINGERPRINT_SCOPE_REQUIRED", keygen.ValidationFingerprintMissingError),
            ("FINGERPRINT_SCOPE_EMPTY", keygen.ValidationFingerprintMissingError),
            ("COMPONENTS_SCOPE_REQUIRED", keygen.ValidationComponentsMissingError),
            ("COMPONENTS_SCOPE_EMPTY", keygen.ValidationComponentsMissingError),
            ("COMPONENTS_SCOPE_MISMATCH", keygen.ComponentNotActivatedError),
            ("HEARTBEAT_NOT_STARTED", keygen.HeartbeatRequiredError),
            ("HEARTBEAT_DEAD", keygen.HeartbeatDeadError),
            ("PRODUCT_SCOPE_REQUIRED", keygen.ValidationProductMissingError),
            ("PRODUCT_SCOPE_MISMATCH", keygen.ValidationProductMissingError),
            ("OVERDUE", keygen.LicenseInvalidError),
            ("BANNED", keygen.LicenseInvalidError),
            ("SOMETHING_NEW", keygen.LicenseInvalidError),
            ("", keygen.LicenseInvalidError),
        ],
    )
    def test_invalid_codes(self, api, code, error):
        api.add("GET", r"/me$", (200, {}, {"data": license_resource()}))
        api.add("POST", r"/validate$", (200, {}, validation(code)))

        with pytest.raises(error) as info:
            keygen.validate("fp")

        err = info.value
        assert isinstance(err, keygen.LicenseValidationError)
        assert err.license is not None and err.license.id == "lic-1"
        assert err.license.last_validation is err.result
        assert err.result.code == code

    def test_valid_flag_does_not_override_code(self, api):
        api.add("POST", r"/validate$", (200, {}, validation("EXPIRED", True)))
        with pytest.raises(keygen.LicenseExpiredError):
            keygen.License(id="lic-1").validate()

    def test_missing_license(self, api):
        api.add("POST", r"/validate$", (404, {}, {"errors": [{"code": "NOT_FOUND", "title": "Not found"}]}))
        license = keygen.License(id="gone")
        with pytest.raises(keygen.LicenseInvalidError) as info:
            license.validate()
        assert info.value.license is license

    def test_requires_id(self):
        with pytest.raises(ValueError):
            keygen.License().validate()

    def test_me_must_be_a_license(self, api):
        api.add("GET", r"/me$", (200, {}, {"data": {"id": "u", "type": "users", "attributes": {}}}))
        with pytest.raises(keygen.LicenseInvalidError, match="do not belong"):
            keygen.validate()

    def test_me_without_data(self, api):
        api.add("GET", r"/me$", (200, {}, {"data": None}))
        with pytest.raises(keygen.APIError):
            keygen.me()

    def test_bad_credentials(self, api):
        api.add("GET", r"/me$", (401, {}, {"errors": [{"code": "LICENSE_INVALID"}]}))
        with pytest.raises(keygen.LicenseKeyError):
            keygen.validate()


class TestMachines:
    def test_activate(self, api, monkeypatch):
        monkeypatch.setattr("keygen.license._hostname", lambda: "box")
        api.add("POST", r"/machines$", (201, {}, {"data": machine_resource(fingerprint="fp")}))

        machine = keygen.License(id="lic-1").activate(
            "fp",
            keygen.Component(fingerprint="disk", name="Disk"),
            {"fingerprint": "cpu", "name": "CPU", "metadata": {"cores": 8}},
        )

        body = body_of(api.last)["data"]
        assert body["type"] == "machines"
        assert body["attributes"]["fingerprint"] == "fp"
        assert body["attributes"]["hostname"] == "box"
        assert "/" in body["attributes"]["platform"]
        assert body["attributes"]["cores"] >= 1
        assert body["relationships"]["license"] == {"data": {"type": "licenses", "id": "lic-1"}}
        assert body["relationships"]["components"]["data"] == [
            {"type": "components", "attributes": {"fingerprint": "disk", "name": "Disk"}},
            {"type": "components", "attributes": {"fingerprint": "cpu", "name": "CPU", "metadata": {"cores": 8}}},
        ]
        assert machine.id == "mach-1"
        assert machine.license_id == "lic-1"
        assert machine.require_heartbeat is True

    def test_activate_without_components(self, api):
        api.add("POST", r"/machines$", (201, {}, {"data": machine_resource()}))
        keygen.License(id="lic-1").activate("fp")
        assert "components" not in body_of(api.last)["data"]["relationships"]

    def test_activate_validation(self):
        with pytest.raises(ValueError):
            keygen.License(id="lic-1").activate("")
        with pytest.raises(ValueError):
            keygen.License(id="lic-1").activate("fp", keygen.Component(name="nameless"))
        with pytest.raises(TypeError):
            keygen.License(id="lic-1").activate("fp", "not a component")

    def test_activation_limits(self, api):
        api.add("POST", r"/machines$", (422, {}, {"errors": [{"code": "MACHINE_LIMIT_EXCEEDED"}]}))
        with pytest.raises(keygen.MachineLimitExceededError):
            keygen.License(id="lic-1").activate("fp")
        api.add("POST", r"/machines$", (422, {}, {"errors": [{"code": "FINGERPRINT_TAKEN"}]}))
        with pytest.raises(keygen.MachineAlreadyActivatedError):
            keygen.License(id="lic-1").activate("fp")

    def test_ids_are_escaped(self, api):
        api.add("GET", r"/machines/", (200, {}, {"data": machine_resource()}))
        keygen.License(id="lic-1").machine("a/b?c <d>")
        assert api.last.url.endswith("/machines/a%2Fb%3Fc%20%3Cd%3E")

    def test_deactivate(self, api):
        api.add("DELETE", r"/machines/fp$", (204, {}, ""))
        keygen.License(id="lic-1").deactivate("fp")
        with pytest.raises(ValueError):
            keygen.License(id="lic-1").deactivate("")

    def test_deactivate_missing(self, api):
        api.add("DELETE", r"/machines/fp$", (404, {}, {"errors": [{"code": "NOT_FOUND"}]}))
        with pytest.raises(keygen.NotFoundError):
            keygen.License(id="lic-1").deactivate("fp")

    def test_lists(self, api):
        api.add("GET", r"/licenses/lic-1/machines\?limit=100$", (200, {}, {"data": [machine_resource("m1"), machine_resource("m2")]}))
        api.add(
            "GET",
            r"/licenses/lic-1/entitlements\?limit=100$",
            (200, {}, {"data": [{"id": "e1", "type": "entitlements", "attributes": {"code": "PRO", "name": "Pro"}}]}),
        )
        license = keygen.License(id="lic-1")
        assert [m.id for m in license.machines()] == ["m1", "m2"]
        entitlements = license.entitlements()
        assert entitlements[0].code == "PRO" and entitlements[0].name == "Pro"

    def test_list_with_unexpected_payload(self, api):
        api.add("GET", r"/machines\?limit=100$", (200, {}, {"data": {"not": "a list"}}))
        assert keygen.License(id="lic-1").machines() == []


class TestCheckout:
    def file_response(self):
        return {
            "data": {
                "id": "lf-1",
                "type": "license-files",
                "attributes": {"certificate": "CERT", "ttl": 3600, "issued": "2024-01-01T00:00:00Z", "expiry": "2024-01-01T01:00:00Z"},
                "relationships": {"license": {"data": {"type": "licenses", "id": "lic-1"}}},
            }
        }

    def test_defaults(self, api):
        api.add("POST", r"/licenses/lic-1/actions/check-out", (200, {}, self.file_response()))
        lic = keygen.License(id="lic-1").checkout()
        assert query_of(api.last) == {"algorithm": "aes-256-gcm+ed25519", "encrypt": "true", "include": "entitlements"}
        assert api.last.body is None
        assert (lic.id, lic.certificate, lic.ttl, lic.license_id) == ("lf-1", "CERT", 3600, "lic-1")

    def test_options(self, api):
        api.add("POST", r"/check-out", (200, {}, self.file_response()))
        keygen.License(id="lic-1").checkout(
            include=(), ttl=timedelta(days=1), encrypt=False, algorithm=keygen.SigningAlgorithm.P256
        )
        assert query_of(api.last) == {"algorithm": "base64+ecdsa-p256", "encrypt": "false", "ttl": "86400"}

    def test_signature_scheme_is_the_default_algorithm(self, api):
        keygen.signature_scheme = "ecdsa-p256"
        api.add("POST", r"/check-out", (200, {}, self.file_response()))
        keygen.License(id="lic-1").checkout(include="entitlements,product")
        assert query_of(api.last)["algorithm"] == "aes-256-gcm+ecdsa-p256"
        assert query_of(api.last)["include"] == "entitlements,product"

    @pytest.mark.parametrize("ttl,error", [(0, ValueError), (-5, ValueError), (True, TypeError)])
    def test_invalid_ttl(self, ttl, error):
        with pytest.raises(error):
            keygen.License(id="lic-1").checkout(ttl=ttl)
