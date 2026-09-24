from __future__ import annotations

import json
from datetime import timedelta

import pytest
import requests

import keygen
from keygen.client import Client

import fixtures
from conftest import body_of
from helpers import Keys, http_date, license_resource, signed_headers


def error_body(code, title="Error", detail="detail", pointer=None):
    error = {"title": title, "detail": detail, "code": code}
    if pointer:
        error["source"] = {"pointer": pointer}
    return {"errors": [error], "meta": {"id": "req"}}


class TestUrls:
    def test_hosted_api_includes_account(self):
        assert Client(account="acct").url("me") == "https://api.keygen.sh/v1/accounts/acct/me"

    def test_hosted_api_requires_account(self):
        with pytest.raises(keygen.KeygenError, match="account"):
            Client(account="").url("me")

    @pytest.mark.parametrize(
        "api_url,expected",
        [
            ("https://licensing.example.com", "https://licensing.example.com/v1/me"),
            ("licensing.example.com", "https://licensing.example.com/v1/me"),
            ("http://localhost:3000/", "http://localhost:3000/v1/me"),
            ("https://api.keygen.sh/", "https://api.keygen.sh/v1/accounts/acct/me"),
        ],
    )
    def test_custom_hosts(self, api_url, expected):
        assert Client(account="acct", api_url=api_url).url("me") == expected

    def test_query_is_sorted_and_skips_empty_values(self):
        url = Client(account="a").url("x", {"z": 1, "a": "b c", "e": "", "n": None, "t": True, "f": False})
        assert url.endswith("/x?a=b+c&f=false&t=true&z=1")

    def test_global_config_is_read_at_creation(self):
        keygen.account = "first"
        client = Client()
        keygen.account = "second"
        assert "/accounts/first/" in client.url("me")


class TestHeaders:
    def test_license_key_auth(self, api):
        keygen.environment = "staging"
        keygen.user_agent = "MyApp/1.0"
        api.add("GET", r"/me$", (200, {}, {"data": license_resource()}))
        Client().get("me")
        headers = api.last.headers
        assert headers["Authorization"] == "License LICENSE-KEY"
        assert headers["Keygen-Environment"] == "staging"
        assert headers["Keygen-Version"] == "1.8"
        assert headers["Keygen-Accept-Signature"] == 'algorithm="ed25519"'
        assert headers["Accept"] == "application/vnd.api+json"
        assert headers["User-Agent"].startswith("keygen/1.8 sdk/")
        assert headers["User-Agent"].endswith(" MyApp/1.0")
        assert "Content-Type" not in headers

    def test_token_auth_when_no_license_key(self, api):
        keygen.license_key = ""
        keygen.token = "activ-123"
        api.add("GET", r"/me$", (200, {}, {"data": license_resource()}))
        Client().get("me")
        assert api.last.headers["Authorization"] == "Bearer activ-123"

    def test_license_key_takes_precedence(self, api):
        keygen.token = "activ-123"
        api.add("GET", r"/me$", (200, {}, {"data": license_resource()}))
        Client().get("me")
        assert api.last.headers["Authorization"] == "License LICENSE-KEY"

    def test_json_body(self, api):
        api.add("POST", r"/things$", (201, {}, {"data": {"id": "1", "type": "things"}}))
        Client().post("things", {"data": {"type": "things"}})
        assert api.last.headers["Content-Type"] == "application/vnd.api+json"
        assert body_of(api.last) == {"data": {"type": "things"}}

    def test_redirects_are_not_followed(self, api):
        api.add(
            "GET",
            r"/artifacts/app$",
            (303, {"Location": "https://cdn.example/app"}, {"data": {"id": "a", "type": "artifacts"}}),
        )
        response = Client().get("releases/r/artifacts/app")
        assert response.status == 303
        assert response.headers["Location"] == "https://cdn.example/app"


class TestErrors:
    @pytest.mark.parametrize(
        "code,error",
        [
            ("TOKEN_NOT_ALLOWED", keygen.TokenNotAllowedError),
            ("TOKEN_FORMAT_INVALID", keygen.TokenFormatInvalidError),
            ("TOKEN_INVALID", keygen.TokenInvalidError),
            ("TOKEN_EXPIRED", keygen.TokenExpiredError),
            ("LICENSE_NOT_ALLOWED", keygen.LicenseNotAllowedError),
            ("LICENSE_SUSPENDED", keygen.LicenseSuspendedError),
            ("LICENSE_EXPIRED", keygen.LicenseExpiredError),
            ("SOMETHING_ELSE", keygen.NotAuthorizedError),
            (None, keygen.NotAuthorizedError),
        ],
    )
    def test_forbidden(self, api, code, error):
        api.add("GET", r"/me$", (403, {}, error_body(code)))
        with pytest.raises(error) as info:
            Client().get("me")
        assert info.value.response.status == 403

    @pytest.mark.parametrize(
        "status,code,error",
        [
            (422, "ENVIRONMENT_INVALID", keygen.InvalidEnvironmentError),
            (400, "ENVIRONMENT_NOT_SUPPORTED", keygen.InvalidEnvironmentError),
            (422, "MACHINE_HEARTBEAT_DEAD", keygen.HeartbeatDeadError),
            (422, "PROCESS_HEARTBEAT_DEAD", keygen.HeartbeatDeadError),
            (422, "FINGERPRINT_TAKEN", keygen.MachineAlreadyActivatedError),
            (422, "MACHINE_LIMIT_EXCEEDED", keygen.MachineLimitExceededError),
            (422, "MACHINE_PROCESS_LIMIT_EXCEEDED", keygen.ProcessLimitExceededError),
            (422, "COMPONENTS_FINGERPRINT_CONFLICT", keygen.ComponentConflictError),
            (422, "COMPONENTS_FINGERPRINT_TAKEN", keygen.ComponentAlreadyActivatedError),
            (401, "TOKEN_INVALID", keygen.LicenseTokenError),
            (401, "LICENSE_INVALID", keygen.LicenseKeyError),
            (404, "NOT_FOUND", keygen.NotFoundError),
            (404, None, keygen.NotFoundError),
            (422, "UNKNOWN", keygen.APIError),
        ],
    )
    def test_error_codes(self, api, status, code, error):
        api.add("GET", r"/me$", (status, {}, error_body(code, pointer="/data/attributes/x")))
        with pytest.raises(error) as info:
            Client().get("me")
        assert isinstance(info.value, keygen.KeygenError)
        assert info.value.response.status == status

    def test_wrapped_errors_keep_details(self, api):
        api.add("GET", r"/me$", (404, {}, error_body("NOT_FOUND", "Not found", "missing", "/data")))
        with pytest.raises(keygen.NotFoundError) as info:
            Client().get("me")
        err = info.value
        assert (err.title, err.detail, err.code, err.source, err.status) == ("Not found", "missing", "NOT_FOUND", "/data", 404)
        assert str(err) == "resource was not found"

    def test_unknown_error_message_includes_response(self, api):
        api.add("GET", r"/me$", (422, {"x-request-id": "rid"}, error_body("UNKNOWN")))
        with pytest.raises(keygen.APIError, match="id=rid status=422"):
            Client().get("me")

    def test_rate_limit(self, api):
        headers = {
            "Retry-After": "42",
            "X-RateLimit-Window": "30s",
            "X-RateLimit-Count": "61",
            "X-RateLimit-Limit": "60",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1700000000",
        }
        api.add("GET", r"/me$", (429, headers, error_body("TOO_MANY_REQUESTS")))
        with pytest.raises(keygen.RateLimitError) as info:
            Client().get("me")
        err = info.value
        assert (err.retry_after, err.window, err.count, err.limit, err.remaining) == (42, "30s", 61, 60, 0)
        assert int(err.reset.timestamp()) == 1700000000

    def test_rate_limit_with_bad_headers(self, api):
        api.add("GET", r"/me$", (429, {"Retry-After": "soon"}, ""))
        with pytest.raises(keygen.RateLimitError) as info:
            Client().get("me")
        assert info.value.retry_after == 0 and info.value.reset is None

    def test_server_error(self, api):
        api.add("GET", r"/me$", (503, {}, "<html>\nBad gateway\n</html>"))
        with pytest.raises(keygen.APIError, match=r"status=503.*Bad gateway") as info:
            Client().get("me")
        assert "\n" not in str(info.value)

    def test_long_body_is_truncated(self, api):
        api.add("GET", r"/me$", (500, {}, "x" * 2000))
        with pytest.raises(keygen.APIError) as info:
            Client().get("me")
        assert str(info.value).endswith("x" * 10 + "...")

    def test_invalid_json(self, api):
        api.add("GET", r"/me$", (200, {}, "not json"))
        with pytest.raises(keygen.APIError, match="JSON"):
            Client().get("me")

    def test_empty_error_response(self, api):
        api.add("DELETE", r"/machines/x$", (400, {}, ""))
        with pytest.raises(keygen.APIError):
            Client().delete("machines/x")

    def test_error_status_without_errors(self, api):
        api.add("GET", r"/me$", (400, {}, {"meta": {}}))
        with pytest.raises(keygen.APIError):
            Client().get("me")

    def test_no_content(self, api):
        api.add("DELETE", r"/machines/x$", (204, {}, ""))
        response = Client().delete("machines/x")
        assert response.status == 204 and response.document is None

    def test_network_error(self, api):
        api.error = requests.ConnectionError("boom")
        with pytest.raises(keygen.NetworkError, match="boom") as info:
            Client().get("me")
        assert isinstance(info.value.__cause__, requests.ConnectionError)


class TestResponseSignatures:
    def test_real_signed_response(self, api):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.account = fixtures.ACCOUNT_ID
        keygen.license_key = fixtures.DEMO_LICENSE_KEY
        keygen.max_clock_drift = None
        mock = fixtures.ME_RESPONSE
        headers = {"Keygen-Signature": mock["signature"], "Digest": mock["digest"], "Date": mock["date"]}
        api.add("GET", r"/me$", (200, headers, mock["body"]))

        license = keygen.me()
        assert license.id == "218810ed-2ac8-4c26-a725-a6da67500561"
        assert license.key == fixtures.DEMO_LICENSE_KEY
        assert license.policy_id == "629307fb-331d-430b-978a-44d45d9de133"
        assert license.metadata == {"email": "user@example.com"}
        assert license.expiry is None

    def test_signed_validation_flow(self, api):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        base = "https://api.keygen.sh/v1/accounts/acct"
        me = json.dumps({"data": license_resource()}).encode()
        validation = json.dumps(
            {"data": license_resource(), "meta": {"valid": True, "code": "VALID", "detail": "is valid"}}
        ).encode()
        api.add("GET", r"/me$", (200, signed_headers(keys, "GET", base + "/me", me), me))
        api.add(
            "POST",
            r"/actions/validate$",
            (200, signed_headers(keys, "POST", base + "/licenses/lic-1/actions/validate", validation), validation),
        )

        license = keygen.validate()
        assert license.last_validation.valid is True
        assert license.last_validation.code == keygen.ValidationCode.VALID

    def test_old_response_is_rejected(self, api):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.account = fixtures.ACCOUNT_ID
        mock = fixtures.ME_RESPONSE
        headers = {"Keygen-Signature": mock["signature"], "Digest": mock["digest"], "Date": mock["date"]}
        api.add("GET", r"/me$", (200, headers, mock["body"]))
        with pytest.raises(keygen.ResponseDateTooOldError):
            keygen.me()

    def test_tampered_body(self, api):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.account = fixtures.ACCOUNT_ID
        keygen.max_clock_drift = None
        mock = fixtures.ME_RESPONSE
        headers = {"Keygen-Signature": mock["signature"], "Digest": mock["digest"], "Date": mock["date"]}
        api.add("GET", r"/me$", (200, headers, mock["body"].replace("Demo License", "Free License")))
        with pytest.raises(keygen.ResponseDigestInvalidError):
            keygen.me()

    def test_replayed_to_other_path(self, api):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        body = json.dumps({"data": license_resource()}).encode()
        headers = signed_headers(keys, "GET", "https://api.keygen.sh/v1/accounts/acct/me", body)
        api.add("GET", r"/licenses/lic-1$", (200, headers, body))
        with pytest.raises(keygen.ResponseSignatureInvalidError):
            Client().get("licenses/lic-1")

    @pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa-p256"])
    def test_signed_response_with_query(self, api, algorithm):
        keys = Keys()
        keygen.public_key = keys.ed25519_public if algorithm == "ed25519" else keys.ecdsa_public
        keygen.signature_scheme = algorithm
        body = json.dumps({"data": []}).encode()
        url = "https://api.keygen.sh/v1/accounts/acct/licenses/lic-1/machines?limit=100"
        api.add("GET", r"/machines\?limit=100$", (200, signed_headers(keys, "GET", url, body, algorithm=algorithm), body))
        Client().get("licenses/lic-1/machines", query={"limit": 100})
        assert api.last.headers["Keygen-Accept-Signature"] == f'algorithm="{algorithm}"'

    def test_error_responses_are_verified_too(self, api):
        keygen.public_key = Keys().ed25519_public
        api.add("GET", r"/me$", (404, {}, error_body("NOT_FOUND")))
        with pytest.raises(keygen.ResponseDigestMissingError):
            Client().get("me")

    @pytest.mark.parametrize(
        "mutate,error",
        [
            (lambda h: h.pop("Digest"), keygen.ResponseDigestMissingError),
            (lambda h: h.pop("Date"), keygen.ResponseDateMissingError),
            (lambda h: h.update(Date="yesterday"), keygen.ResponseDateInvalidError),
            (lambda h: h.pop("Keygen-Signature"), keygen.ResponseSignatureMissingError),
            (lambda h: h.update({"Keygen-Signature": 'algorithm="ed25519"'}), keygen.ResponseSignatureMissingError),
            (lambda h: h.update({"Keygen-Signature": 'algorithm="rsa", signature="YWJj"'}), keygen.ResponseSignatureNotSupportedError),
            (lambda h: h.update({"Keygen-Signature": 'algorithm="ed25519", signature="!!"'}), keygen.ResponseSignatureInvalidError),
        ],
    )
    def test_broken_signature_headers(self, api, mutate, error):
        keys = Keys()
        keygen.public_key = keys.ed25519_public
        body = json.dumps({"data": license_resource()}).encode()
        headers = signed_headers(keys, "GET", "https://api.keygen.sh/v1/accounts/acct/me", body)
        mutate(headers)
        api.add("GET", r"/me$", (200, headers, body))
        with pytest.raises(error):
            Client().get("me")

    def test_clock_drift_window(self, api):
        from datetime import datetime, timezone

        keys = Keys()
        keygen.public_key = keys.ed25519_public
        body = json.dumps({"data": license_resource()}).encode()
        date = http_date(datetime.now(timezone.utc) - timedelta(minutes=3))
        headers = signed_headers(keys, "GET", "https://api.keygen.sh/v1/accounts/acct/me", body, date=date)
        api.add("GET", r"/me$", (200, headers, body))
        Client().get("me")
        keygen.max_clock_drift = timedelta(minutes=1)
        with pytest.raises(keygen.ResponseDateTooOldError):
            Client().get("me")
        keygen.max_clock_drift = 600
        Client().get("me")


class TestWebhooks:
    URL = "https://5173-2600-1700-3e90-a450-533-a11e-339-f87b.ngrok.io/webhooks"

    def headers(self):
        return {
            "Keygen-Signature": fixtures.WEBHOOK_SIGNATURE,
            "Digest": fixtures.WEBHOOK_DIGEST,
            "Date": fixtures.WEBHOOK_DATE,
        }

    def test_real_webhook(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.max_clock_drift = -1
        keygen.verify_webhook("POST", self.URL, self.headers(), fixtures.WEBHOOK_BODY)

    def test_lowercase_headers_and_str_body(self):
        keygen.max_clock_drift = None
        headers = {k.lower(): v for k, v in self.headers().items()}
        keygen.verify_webhook(
            "post", self.URL, headers, fixtures.WEBHOOK_BODY.decode(), public_key=fixtures.ED25519_PUBLIC_KEY
        )

    def test_host_override(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.max_clock_drift = None
        keygen.verify_webhook(
            "POST",
            "http://127.0.0.1:8000/webhooks",
            self.headers(),
            fixtures.WEBHOOK_BODY,
            host="5173-2600-1700-3e90-a450-533-a11e-339-f87b.ngrok.io",
        )

    def test_old_webhook_is_rejected(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        with pytest.raises(keygen.RequestDateTooOldError):
            keygen.verify_webhook("POST", self.URL, self.headers(), fixtures.WEBHOOK_BODY)

    def test_forged_body(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.max_clock_drift = None
        with pytest.raises(keygen.RequestDigestInvalidError):
            keygen.verify_webhook("POST", self.URL, self.headers(), fixtures.WEBHOOK_BODY + b" ")

    def test_wrong_path(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        keygen.max_clock_drift = None
        with pytest.raises(keygen.RequestSignatureInvalidError):
            keygen.verify_webhook("POST", self.URL + "/other", self.headers(), fixtures.WEBHOOK_BODY)

    def test_missing_headers(self):
        keygen.public_key = fixtures.ED25519_PUBLIC_KEY
        with pytest.raises(keygen.RequestDigestMissingError):
            keygen.verify_webhook("POST", self.URL, {}, fixtures.WEBHOOK_BODY)

    def test_missing_public_key(self):
        keygen.max_clock_drift = None
        with pytest.raises(keygen.PublicKeyMissingError):
            keygen.verify_webhook("POST", self.URL, self.headers(), fixtures.WEBHOOK_BODY)
