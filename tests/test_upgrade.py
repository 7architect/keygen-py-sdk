from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

import keygen
from keygen import _platform

from helpers import ed25519ph_public, ed25519ph_sign

SECRET = bytes(range(32))
PERSONAL_KEY = ed25519ph_public(SECRET).hex()
BINARY = b"\x7fELF new version" * 1000


def release_resource(version="1.0.1"):
    return {
        "id": "rel-1",
        "type": "releases",
        "attributes": {"name": "v" + version, "version": version, "channel": "stable", "metadata": {}},
    }


def artifact_resource(**attrs):
    base = {"filename": "app_linux_amd64", "filesize": len(BINARY), "platform": "linux", "arch": "amd64"}
    base.update(attrs)
    return {"id": "art-1", "type": "artifacts", "attributes": base,
            "relationships": {"release": {"data": {"type": "releases", "id": "rel-1"}}}}


def raw_b64(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


@pytest.fixture
def platform(monkeypatch):
    monkeypatch.setattr("keygen.release.current_os", lambda: "linux")
    monkeypatch.setattr("keygen.release.current_arch", lambda: "amd64")
    keygen.program = "app"
    keygen.ext = ""


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "app"
    path.write_bytes(b"old version")
    path.chmod(0o750)
    return path


def serve(api, *, artifact=None, body=BINARY, download_status=200, location="https://cdn.example.com/app"):
    api.add("GET", r"/releases/1\.0\.0/upgrade", (200, {}, {"data": release_resource()}))
    headers = {"Location": location} if location else {}
    api.add("GET", r"/releases/rel-1/artifacts/", (303, headers, {"data": artifact or artifact_resource()}))
    api.add("GET", r"^https://cdn\.example\.com/app$", (download_status, {}, body))


class TestUpgrade:
    def test_query(self, api):
        keygen.package = "pkg"
        api.add("GET", r"/upgrade", (200, {}, {"data": release_resource()}))
        release = keygen.upgrade("1.0.0", constraint="1.0")
        query = {k: v[0] for k, v in parse_qs(urlsplit(api.last.url).query).items()}
        assert query == {"channel": "stable", "constraint": "1.0", "package": "pkg", "product": "prod"}
        assert release.version == "1.0.1"
        assert release.options.product == "prod"

    def test_options_object(self, api):
        api.add("GET", r"/releases/2\.0\.0-beta%2B1/upgrade", (200, {}, {"data": release_resource()}))
        options = keygen.UpgradeOptions(current_version="2.0.0-beta+1", channel="beta", product="other")
        keygen.upgrade(options)
        assert "channel=beta" in api.last.url and "product=other" in api.last.url
        assert options.package == ""

    @pytest.mark.parametrize(
        "status,body",
        [(404, {"errors": [{"code": "NOT_FOUND"}]}), (204, ""), (200, {"data": None})],
    )
    def test_not_available(self, api, status, body):
        api.add("GET", r"/upgrade", (status, {}, body))
        with pytest.raises(keygen.UpgradeNotAvailableError):
            keygen.upgrade("1.0.0")

    def test_invalid_version_is_escaped(self, api):
        api.add("GET", r"/upgrade", (404, {}, {"errors": [{"code": "NOT_FOUND"}]}))
        with pytest.raises(keygen.UpgradeNotAvailableError):
            keygen.upgrade("<not set>")
        assert "/releases/%3Cnot%20set%3E/upgrade" in api.last.url

    def test_requires_version(self):
        with pytest.raises(ValueError):
            keygen.upgrade("")

    def test_rejects_account_public_key(self):
        keygen.public_key = PERSONAL_KEY
        with pytest.raises(ValueError, match="personal public key"):
            keygen.upgrade("1.0.0", public_key=PERSONAL_KEY.upper())

    def test_missing_keys_are_fine(self, api):
        api.add("GET", r"/upgrade", (200, {}, {"data": release_resource()}))
        keygen.upgrade("1.0.0")


class TestFilename:
    def test_default(self, platform):
        assert keygen.Release(version="1.0.1").filename() == "app_linux_amd64"
        keygen.ext = "exe"
        assert keygen.Release(version="1.0.1").filename() == "app_linux_amd64.exe"

    def test_format_string(self, platform):
        release = keygen.Release(version="1.0.1", channel="beta")
        release.options = keygen.UpgradeOptions("1.0.0", filename="{program}-{version}-{channel}-{platform}-{arch}")
        assert release.filename() == "app-1.0.1-beta-linux-amd64"

    def test_callable(self, platform):
        release = keygen.Release(version="1.0.1")
        release.options = keygen.UpgradeOptions("1.0.0", filename=lambda v: f"{v['program']}.tar.gz")
        assert release.filename() == "app.tar.gz"

    @pytest.mark.parametrize("template", ["{unknown}", "{", "", "{0}"])
    def test_bad_templates(self, platform, template):
        release = keygen.Release(version="1.0.1")
        release.options = keygen.UpgradeOptions("1.0.0", filename=template)
        if template == "":
            assert release.filename() == "app_linux_amd64"
            return
        with pytest.raises(ValueError):
            release.filename()


class TestInstall:
    def test_install_with_checksum_and_signature(self, api, platform, target):
        digest = hashlib.sha512(BINARY).digest()
        signature = ed25519ph_sign(SECRET, digest, b"prod")
        serve(api, artifact=artifact_resource(checksum=raw_b64(digest), signature=raw_b64(signature)))

        release = keygen.upgrade("1.0.0", public_key=PERSONAL_KEY)
        path = release.install(str(target))

        assert path == os.path.realpath(target)
        assert target.read_bytes() == BINARY
        if sys.platform != "win32":
            assert stat.S_IMODE(target.stat().st_mode) == 0o750
        assert sorted(os.listdir(target.parent)) == ["app"]
        download = api.last
        assert download.url == "https://cdn.example.com/app"
        assert "Authorization" not in download.headers
        artifact_request = [r for r in api.requests if "/artifacts/" in r.url][0]
        assert artifact_request.url.endswith("/releases/rel-1/artifacts/app_linux_amd64")

    def test_padded_and_hex_checksums(self, api, platform, target):
        digest = hashlib.sha256(BINARY).hexdigest()
        serve(api, artifact=artifact_resource(checksum=digest))
        keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == BINARY

        target.write_bytes(b"old")
        api.routes.clear()
        serve(api, artifact=artifact_resource(checksum=base64.b64encode(hashlib.sha512(BINARY).digest()).decode()))
        keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == BINARY

    def test_checksum_mismatch_keeps_old_version(self, api, platform, target):
        serve(api, artifact=artifact_resource(checksum=raw_b64(hashlib.sha512(b"other").digest())))
        with pytest.raises(keygen.ArtifactChecksumInvalidError):
            keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == b"old version"
        assert sorted(os.listdir(target.parent)) == ["app"]

    def test_malformed_checksum(self, api, platform, target):
        serve(api, artifact=artifact_resource(checksum="!!!"))
        with pytest.raises(keygen.ArtifactChecksumInvalidError):
            keygen.upgrade("1.0.0").install(str(target))
        serve(api, artifact=artifact_resource(checksum=raw_b64(b"short")))
        with pytest.raises(keygen.ArtifactChecksumInvalidError):
            keygen.upgrade("1.0.0").install(str(target))

    def test_signature_from_other_product(self, api, platform, target):
        digest = hashlib.sha512(BINARY).digest()
        signature = ed25519ph_sign(SECRET, digest, b"another-product")
        serve(api, artifact=artifact_resource(signature=raw_b64(signature)))
        with pytest.raises(keygen.ArtifactSignatureInvalidError):
            keygen.upgrade("1.0.0", public_key=PERSONAL_KEY).install(str(target))
        assert target.read_bytes() == b"old version"

    def test_signature_uses_upgrade_product(self, api, platform, target):
        digest = hashlib.sha512(BINARY).digest()
        signature = ed25519ph_sign(SECRET, digest, b"another-product")
        serve(api, artifact=artifact_resource(signature=raw_b64(signature)))
        keygen.upgrade("1.0.0", public_key=PERSONAL_KEY, product="another-product").install(str(target))
        assert target.read_bytes() == BINARY

    def test_tampered_binary(self, api, platform, target):
        digest = hashlib.sha512(BINARY).digest()
        signature = ed25519ph_sign(SECRET, digest, b"prod")
        serve(api, artifact=artifact_resource(signature=raw_b64(signature), filesize=0), body=BINARY + b"!")
        with pytest.raises(keygen.ArtifactSignatureInvalidError):
            keygen.upgrade("1.0.0", public_key=PERSONAL_KEY).install(str(target))

    def test_unsigned_artifact_with_personal_key(self, api, platform, target):
        serve(api)
        with pytest.raises(keygen.ArtifactSignatureMissingError):
            keygen.upgrade("1.0.0", public_key=PERSONAL_KEY).install(str(target))
        assert not any(r.url.startswith("https://cdn.example.com") for r in api.requests)

    def test_invalid_personal_key(self, api, platform, target):
        serve(api, artifact=artifact_resource(signature="abc"))
        with pytest.raises(keygen.PublicKeyInvalidError):
            keygen.upgrade("1.0.0", public_key="nothex").install(str(target))

    def test_size_mismatch(self, api, platform, target):
        serve(api, body=BINARY[:-1])
        with pytest.raises(keygen.ArtifactDownloadError, match="size"):
            keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == b"old version"

    def test_download_failure(self, api, platform, target):
        serve(api, download_status=403, body="denied")
        with pytest.raises(keygen.ArtifactDownloadError, match="403"):
            keygen.upgrade("1.0.0").install(str(target))
        assert sorted(os.listdir(target.parent)) == ["app"]

    def test_location_from_links(self, api, platform, target):
        artifact = artifact_resource()
        artifact["links"] = {"redirect": "https://cdn.example.com/app"}
        serve(api, artifact=artifact, location=None)
        keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == BINARY

    def test_missing_location(self, api, platform, target):
        serve(api, location=None)
        with pytest.raises(keygen.ReleaseLocationMissingError):
            keygen.upgrade("1.0.0").install(str(target))

    def test_missing_artifact(self, api, platform, target):
        api.add("GET", r"/upgrade", (200, {}, {"data": release_resource()}))
        api.add("GET", r"/artifacts/", (404, {}, {"errors": [{"code": "NOT_FOUND"}]}))
        with pytest.raises(keygen.NotFoundError):
            keygen.upgrade("1.0.0").install(str(target))

    def test_missing_directory(self, api, platform, tmp_path):
        serve(api)
        with pytest.raises(keygen.UpgradeInstallError, match="staged"):
            keygen.upgrade("1.0.0").install(str(tmp_path / "missing" / "app"))

    def test_new_target(self, api, platform, tmp_path):
        serve(api)
        path = tmp_path / "fresh"
        keygen.upgrade("1.0.0").install(str(path))
        assert path.read_bytes() == BINARY
        if sys.platform != "win32":
            assert stat.S_IMODE(path.stat().st_mode) == 0o755

    def test_symlink_target(self, api, platform, target, tmp_path):
        if sys.platform == "win32":
            pytest.skip("symlinks need extra privileges on Windows")
        link = tmp_path / "link"
        link.symlink_to(target)
        serve(api)
        keygen.upgrade("1.0.0").install(str(link))
        assert link.is_symlink()
        assert target.read_bytes() == BINARY

    def test_failed_swap_restores_original(self, api, platform, target, monkeypatch):
        serve(api)
        real_replace = os.replace
        calls = []

        def flaky_replace(src, dst):
            calls.append((src, dst))
            if len(calls) == 2:
                raise OSError("disk full")
            return real_replace(src, dst)

        monkeypatch.setattr("keygen.release.os.replace", flaky_replace)
        with pytest.raises(keygen.UpgradeInstallError, match="disk full"):
            keygen.upgrade("1.0.0").install(str(target))
        assert target.read_bytes() == b"old version"
        assert sorted(os.listdir(target.parent)) == ["app"]


class TestPlatform:
    def test_names_follow_go_conventions(self, monkeypatch):
        monkeypatch.setattr(_platform.platform, "system", lambda: "Windows")
        monkeypatch.setattr(_platform.platform, "machine", lambda: "AMD64")
        assert _platform.current_os() == "windows"
        assert _platform.default_ext() == "exe"
        monkeypatch.setattr(_platform.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(_platform.platform, "machine", lambda: "arm64")
        assert _platform.current_platform() == "darwin/arm64"
        monkeypatch.setattr(_platform.platform, "system", lambda: "Linux")
        monkeypatch.setattr(_platform.platform, "machine", lambda: "aarch64")
        assert _platform.current_platform() == "linux/arm64"
        monkeypatch.setattr(_platform.platform, "machine", lambda: "")
        assert _platform.current_arch() == "unknown"


def test_install_refuses_to_guess_target(api, platform, monkeypatch):
    monkeypatch.setattr("keygen.release.current_executable", lambda: "")
    serve(api)
    with pytest.raises(keygen.UpgradeInstallError, match="explicit install target"):
        keygen.upgrade("1.0.0").install()


def test_interactive_session_has_no_executable(monkeypatch):
    monkeypatch.setattr(_platform.sys, "argv", [""])
    monkeypatch.delattr(_platform.sys, "frozen", raising=False)
    assert _platform.current_executable() == ""
    assert _platform.default_program() == "python"
