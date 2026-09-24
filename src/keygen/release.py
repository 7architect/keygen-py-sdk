from __future__ import annotations

import binascii
import hashlib
import hmac
import os
import re
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Mapping, Optional, Union

import requests

from . import _ed25519, errors
from ._config import settings
from ._encoding import b64decode
from ._jsonapi import as_dict, as_str, attributes, parse_time
from ._platform import current_arch, current_executable, current_os
from .artifact import Artifact
from .client import Client, expect_resource, segment

FilenameTemplate = Union[str, Callable[[Dict[str, str]], str]]

_CHUNK_SIZE = 64 * 1024
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def default_filename(variables: Mapping[str, str]) -> str:
    """Build the default artifact filename, e.g. myapp_linux_amd64 or myapp_windows_amd64.exe."""
    name = f"{variables['program']}_{variables['platform']}_{variables['arch']}"
    if variables.get("ext"):
        name += "." + variables["ext"]
    return name


@dataclass
class UpgradeOptions:
    """Options for checking and installing upgrades.

    ``public_key`` is your personal hex encoded Ed25519ph public key, used to
    verify release artifacts before install. It must not be your Keygen account
    public key.

    ``filename`` resolves the artifact to download. It is either a format string
    with the placeholders {program}, {ext}, {platform}, {arch}, {channel} and
    {version}, or a callable that receives those values as a dict. By default it
    resolves to {program}_{platform}_{arch} followed by .{ext} when ext is set.
    """

    current_version: str
    product: str = ""
    package: str = ""
    constraint: str = ""
    channel: str = "stable"
    public_key: str = ""
    filename: Optional[FilenameTemplate] = None


@dataclass
class Release:
    id: str = ""
    type: str = "releases"
    name: str = ""
    description: str = ""
    version: str = ""
    channel: str = ""
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict, repr=False)
    options: Optional[UpgradeOptions] = field(default=None, repr=False)

    @classmethod
    def from_resource(cls, resource: Mapping[str, Any]) -> "Release":
        attrs = attributes(resource)
        return cls(
            id=as_str(resource.get("id")),
            type=as_str(resource.get("type")) or "releases",
            name=as_str(attrs.get("name")),
            description=as_str(attrs.get("description")),
            version=as_str(attrs.get("version")),
            channel=as_str(attrs.get("channel")),
            created=parse_time(attrs.get("created")),
            updated=parse_time(attrs.get("updated")),
            metadata=as_dict(attrs.get("metadata")),
            attributes=attrs,
        )

    def _options(self) -> UpgradeOptions:
        return self.options or UpgradeOptions(current_version="")

    def filename(self) -> str:
        """Resolve the artifact filename for the current platform."""
        template = self._options().filename or default_filename
        variables = {
            "program": settings.program,
            "ext": settings.ext,
            "platform": current_os(),
            "arch": current_arch(),
            "channel": self.channel,
            "version": self.version,
        }
        if callable(template):
            name = template(dict(variables))
        else:
            try:
                name = template.format_map(variables)
            except (KeyError, IndexError, ValueError) as err:
                raise ValueError(f"invalid artifact filename template {template!r}: {err}") from err
        if not isinstance(name, str) or not name:
            raise ValueError("artifact filename template produced an empty filename")
        return name

    def artifact(self) -> Artifact:
        """Retrieve the artifact for the current platform, including its download URL."""
        if not self.id:
            raise ValueError("release id is required")
        response = Client().get(f"releases/{segment(self.id)}/artifacts/{segment(self.filename())}")
        resource = expect_resource(response, "artifact")
        artifact = Artifact.from_resource(resource)

        location = response.headers.get("Location", "")
        if not location:
            location = as_str(as_dict(resource.get("links")).get("redirect"))
        if not location:
            raise errors.ReleaseLocationMissingError(response=response)

        artifact.url = location
        return artifact

    def install(self, target: Optional[str] = None) -> str:
        """Download the release artifact and replace the target file with it.

        The target defaults to the running program. When a personal public key
        was given in the upgrade options, the artifact must carry a valid
        Ed25519ph signature. Returns the path of the installed file.
        """
        options = self._options()
        artifact = self.artifact()

        checksum = _decode_checksum(artifact.checksum) if artifact.checksum else None

        signature: Optional[bytes] = None
        public_key: Optional[bytes] = None
        if options.public_key:
            public_key = _decode_personal_key(options.public_key)
            if not artifact.signature:
                raise errors.ArtifactSignatureMissingError()
            try:
                signature = b64decode(artifact.signature)
            except ValueError as err:
                raise errors.ArtifactSignatureInvalidError() from err

        path = os.path.realpath(target or current_executable())
        directory, name = os.path.split(path)

        try:
            fd, staged = tempfile.mkstemp(prefix=f".{name}.", suffix=".new", dir=directory)
        except OSError as err:
            raise errors.UpgradeInstallError(f"upgrade could not be staged next to {path}: {err}") from err
        try:
            with os.fdopen(fd, "wb") as out:
                digests = _download(artifact, out)

            if artifact.filesize > 0 and digests["size"] != artifact.filesize:
                raise errors.ArtifactDownloadError(
                    f"artifact size does not match: expected={artifact.filesize} actual={digests['size']}"
                )

            if checksum is not None:
                actual = digests["sha512"] if len(checksum) == 64 else digests["sha256"]
                if not hmac.compare_digest(actual, checksum):
                    raise errors.ArtifactChecksumInvalidError()

            if public_key is not None and signature is not None:
                context = (options.product or settings.product).encode()
                if not _ed25519.verify(public_key, digests["sha512"], signature, prehashed=True, context=context):
                    raise errors.ArtifactSignatureInvalidError()

            _replace(path, staged)
        finally:
            if os.path.exists(staged):
                try:
                    os.remove(staged)
                except OSError:
                    pass

        return path


def _decode_checksum(value: str) -> bytes:
    value = value.strip()
    if _HEX.match(value) and len(value) in (64, 128):
        return binascii.unhexlify(value)
    try:
        decoded = b64decode(value)
    except ValueError as err:
        raise errors.ArtifactChecksumInvalidError("artifact checksum is malformed") from err
    if len(decoded) not in (32, 64):
        raise errors.ArtifactChecksumInvalidError("artifact checksum has an unsupported length")
    return decoded


def _decode_personal_key(value: str) -> bytes:
    try:
        key = binascii.unhexlify(value.strip())
    except (binascii.Error, ValueError):
        raise errors.PublicKeyInvalidError("personal public key is not valid hex") from None
    if len(key) != 32:
        raise errors.PublicKeyInvalidError("personal public key must be 32 bytes")
    return key


def _download(artifact: Artifact, out: Any) -> Dict[str, Any]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    try:
        with settings.http_client.get(artifact.url, stream=True, timeout=settings.timeout) as res:
            if res.status_code != 200:
                raise errors.ArtifactDownloadError(f"artifact download failed: status={res.status_code}")
            for chunk in res.iter_content(_CHUNK_SIZE):
                if not chunk:
                    continue
                out.write(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
                size += len(chunk)
    except requests.RequestException as err:
        raise errors.ArtifactDownloadError(f"artifact download failed: {err}") from err
    return {"sha256": sha256.digest(), "sha512": sha512.digest(), "size": size}


def _replace(path: str, staged: str) -> None:
    directory, name = os.path.split(path)
    backup = os.path.join(directory, f".{name}.old")

    if os.path.exists(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
    else:
        mode = 0o755
    os.chmod(staged, mode)

    try:
        if os.path.exists(backup):
            os.remove(backup)
    except OSError:
        pass

    had_original = os.path.exists(path)
    try:
        if had_original:
            os.replace(path, backup)
        try:
            os.replace(staged, path)
        except OSError:
            if had_original:
                os.replace(backup, path)
            raise
    except OSError as err:
        raise errors.UpgradeInstallError(f"upgrade could not be installed: {err}") from err

    if had_original:
        try:
            os.remove(backup)
        except OSError:
            settings.logger.warning("Could not remove the previous version at %s", backup)


def upgrade(options: Union[UpgradeOptions, str], **overrides: Any) -> Release:
    """Check for an upgrade of the current version.

    Accepts UpgradeOptions, or the current version followed by option keywords.
    Returns the release to upgrade to, or raises UpgradeNotAvailableError when
    the current version is already the latest.
    """
    if isinstance(options, str):
        options = UpgradeOptions(current_version=options, **overrides)
    elif overrides:
        options = UpgradeOptions(**{**options.__dict__, **overrides})
    else:
        options = UpgradeOptions(**options.__dict__)

    personal_key = options.public_key.strip().lower()
    if personal_key and personal_key == settings.public_key.strip().lower():
        raise ValueError(
            "you must use a personal public key for upgrades, not your Keygen account public key"
        )
    if not options.current_version:
        raise ValueError("current version is required")

    options.product = options.product or settings.product
    options.package = options.package or settings.package
    options.channel = options.channel or "stable"

    query = {
        "product": options.product,
        "package": options.package,
        "constraint": options.constraint,
        "channel": options.channel,
    }

    try:
        response = Client().get(f"releases/{segment(options.current_version)}/upgrade", query=query)
    except errors.NotFoundError as err:
        raise errors.UpgradeNotAvailableError(response=err.response) from err

    document = response.document
    if not isinstance(document, dict) or not isinstance(document.get("data"), dict):
        raise errors.UpgradeNotAvailableError(response=response)

    release = Release.from_resource(document["data"])
    release.options = options
    return release
