from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .client import Response
    from .license import License
    from .validation import ValidationResult


class ErrorCode:
    ENVIRONMENT_INVALID = "ENVIRONMENT_INVALID"
    ENVIRONMENT_NOT_SUPPORTED = "ENVIRONMENT_NOT_SUPPORTED"
    TOKEN_FORMAT_INVALID = "TOKEN_FORMAT_INVALID"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_NOT_ALLOWED = "TOKEN_NOT_ALLOWED"
    LICENSE_INVALID = "LICENSE_INVALID"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_SUSPENDED = "LICENSE_SUSPENDED"
    LICENSE_NOT_ALLOWED = "LICENSE_NOT_ALLOWED"
    FINGERPRINT_TAKEN = "FINGERPRINT_TAKEN"
    MACHINE_LIMIT_EXCEEDED = "MACHINE_LIMIT_EXCEEDED"
    PROCESS_LIMIT_EXCEEDED = "MACHINE_PROCESS_LIMIT_EXCEEDED"
    COMPONENT_FINGERPRINT_CONFLICT = "COMPONENTS_FINGERPRINT_CONFLICT"
    COMPONENT_FINGERPRINT_TAKEN = "COMPONENTS_FINGERPRINT_TAKEN"
    MACHINE_HEARTBEAT_DEAD = "MACHINE_HEARTBEAT_DEAD"
    PROCESS_HEARTBEAT_DEAD = "PROCESS_HEARTBEAT_DEAD"
    NOT_FOUND = "NOT_FOUND"
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"


class KeygenError(Exception):
    """Base class for every error raised by the SDK."""

    message = "an error occurred"

    def __init__(self, message: Optional[str] = None, *, response: Optional[Response] = None) -> None:
        super().__init__(message or self.message)
        self.response = response


class APIError(KeygenError):
    """An error response returned by the Keygen API."""

    message = ""

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        response: Optional[Response] = None,
        title: Optional[str] = None,
        detail: Optional[str] = None,
        code: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        self.title = title
        self.detail = detail
        self.code = code
        self.source = source
        if not message and not self.message:
            message = _describe(response, code, detail)
        super().__init__(message, response=response)

    @property
    def status(self) -> Optional[int]:
        return self.response.status if self.response is not None else None


def _describe(response: Optional[Response], code: Optional[str], detail: Optional[str]) -> str:
    if response is None:
        return f"an error occurred: code={code} detail={detail}"
    return (
        f"an error occurred: id={response.id} status={response.status} "
        f"size={response.size} body={response.tldr()}"
    )


class InvalidEnvironmentError(APIError):
    message = "environment is invalid"


class LicenseTokenError(APIError):
    message = "license token is invalid"


class LicenseKeyError(APIError):
    message = "license key is invalid"


class NotAuthorizedError(APIError):
    message = "not authorized to perform the request"


class NotFoundError(APIError):
    message = "resource was not found"


class RateLimitError(APIError):
    message = "rate limit has been exceeded"

    def __init__(
        self,
        *,
        response: Optional[Response] = None,
        window: str = "",
        count: int = 0,
        limit: int = 0,
        remaining: int = 0,
        reset: Optional[datetime] = None,
        retry_after: int = 0,
    ) -> None:
        super().__init__(response=response, code=ErrorCode.TOO_MANY_REQUESTS)
        self.window = window
        self.count = count
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        self.retry_after = retry_after


class SignatureVerificationError(KeygenError):
    message = "signature verification failed"


class ResponseSignatureMissingError(SignatureVerificationError):
    message = "response signature is missing"


class ResponseSignatureInvalidError(SignatureVerificationError):
    message = "response signature is invalid"


class ResponseSignatureNotSupportedError(SignatureVerificationError):
    message = "response signature is not supported"


class ResponseDigestMissingError(SignatureVerificationError):
    message = "response digest is missing"


class ResponseDigestInvalidError(SignatureVerificationError):
    message = "response digest is invalid"


class ResponseDateMissingError(SignatureVerificationError):
    message = "response date is missing"


class ResponseDateInvalidError(SignatureVerificationError):
    message = "response date is invalid"


class ResponseDateTooOldError(SignatureVerificationError):
    message = "response date is too old"


class RequestSignatureMissingError(SignatureVerificationError):
    message = "request signature is missing"


class RequestSignatureInvalidError(SignatureVerificationError):
    message = "request signature is invalid"


class RequestSignatureNotSupportedError(SignatureVerificationError):
    message = "request signature is not supported"


class RequestDigestMissingError(SignatureVerificationError):
    message = "request digest is missing"


class RequestDigestInvalidError(SignatureVerificationError):
    message = "request digest is invalid"


class RequestDateMissingError(SignatureVerificationError):
    message = "request date is missing"


class RequestDateInvalidError(SignatureVerificationError):
    message = "request date is invalid"


class RequestDateTooOldError(SignatureVerificationError):
    message = "request date is too old"


class PublicKeyMissingError(KeygenError):
    message = "public key is missing"


class PublicKeyInvalidError(KeygenError):
    message = "public key is invalid"


class SchemeNotSupportedError(KeygenError):
    message = "cryptographic scheme is not supported"


class LicenseValidationError(KeygenError):
    """Raised when a license does not pass validation.

    When raised by a validation request, ``license`` holds the license as
    returned by the API and ``result`` holds the validation result, so the
    caller can react to it, e.g. by activating the current machine.
    """

    message = "license is invalid"

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        response: Optional[Response] = None,
        license: Optional[License] = None,
        result: Optional[ValidationResult] = None,
    ) -> None:
        super().__init__(message, response=response)
        self.license = license
        self.result = result


class ValidationFingerprintMissingError(LicenseValidationError):
    message = "validation fingerprint scope is missing"


class ValidationComponentsMissingError(LicenseValidationError):
    message = "validation components scope is missing"


class ValidationProductMissingError(LicenseValidationError):
    message = "validation product scope is missing"


class HeartbeatPingFailedError(KeygenError):
    message = "heartbeat ping failed"


class HeartbeatRequiredError(LicenseValidationError):
    message = "heartbeat is required"


class HeartbeatDeadError(LicenseValidationError):
    message = "heartbeat is dead"


class MachineAlreadyActivatedError(KeygenError):
    message = "machine is already activated"


class MachineLimitExceededError(KeygenError):
    message = "machine limit has been exceeded"


class MachineNotFoundError(KeygenError):
    message = "machine no longer exists"


class ProcessNotFoundError(KeygenError):
    message = "process no longer exists"


class ProcessLimitExceededError(KeygenError):
    message = "process limit has been exceeded"


class ComponentNotActivatedError(LicenseValidationError):
    message = "component is not activated"


class ComponentAlreadyActivatedError(KeygenError):
    message = "component is already activated"


class ComponentConflictError(KeygenError):
    message = "component is duplicated"


class LicenseSchemeNotSupportedError(KeygenError):
    message = "license scheme is not supported"


class LicenseSchemeMissingError(KeygenError):
    message = "license scheme is missing"


class LicenseKeyMissingError(KeygenError):
    message = "license key is missing"


class LicenseKeyNotGenuineError(KeygenError):
    message = "license key is not genuine"


class LicenseNotSignedError(KeygenError):
    message = "license is not signed"


class LicenseNotActivatedError(LicenseValidationError):
    message = "license is not activated"


class LicenseNotAllowedError(KeygenError):
    message = "license authentication is not allowed by policy"


class LicenseExpiredError(LicenseValidationError):
    message = "license is expired"


class LicenseSuspendedError(LicenseValidationError):
    message = "license is suspended"


class LicenseTooManyMachinesError(LicenseValidationError):
    message = "license has too many machines"


class LicenseTooManyCoresError(LicenseValidationError):
    message = "license has too many cores"


class LicenseTooManyProcessesError(LicenseValidationError):
    message = "license has too many processes"


class LicenseInvalidError(LicenseValidationError):
    message = "license is invalid"


class TokenNotAllowedError(KeygenError):
    message = "token authentication is not allowed by policy"


class TokenFormatInvalidError(KeygenError):
    message = "token format is invalid"


class TokenInvalidError(KeygenError):
    message = "token is invalid"


class TokenExpiredError(KeygenError):
    message = "token is expired"


class _DatasetError(KeygenError):
    def __init__(self, message: Optional[str] = None, *, dataset: Any = None) -> None:
        super().__init__(message)
        self.dataset = dataset


class SystemClockUnsyncedError(_DatasetError):
    """The file was issued in the future, which points at a tampered system clock.

    The decoded dataset is still available through ``dataset``.
    """

    message = "system clock is out of sync"


class LicenseFileError(_DatasetError):
    message = "license file is invalid"


class LicenseFileNotSupportedError(LicenseFileError):
    message = "license file is not supported"


class LicenseFileNotEncryptedError(LicenseFileError):
    message = "license file is not encrypted"


class LicenseFileEncryptedError(LicenseFileError):
    message = "license file is encrypted"


class LicenseFileNotGenuineError(LicenseFileError):
    message = "license file is not genuine"


class LicenseFileExpiredError(LicenseFileError):
    message = "license file is expired"


class LicenseFileSecretMissingError(LicenseFileError):
    message = "license file secret is missing"


class MachineFileError(_DatasetError):
    message = "machine file is invalid"


class MachineFileNotSupportedError(MachineFileError):
    message = "machine file is not supported"


class MachineFileNotEncryptedError(MachineFileError):
    message = "machine file is not encrypted"


class MachineFileEncryptedError(MachineFileError):
    message = "machine file is encrypted"


class MachineFileNotGenuineError(MachineFileError):
    message = "machine file is not genuine"


class MachineFileExpiredError(MachineFileError):
    message = "machine file is expired"


class MachineFileSecretMissingError(MachineFileError):
    message = "machine file secret is missing"


class UpgradeError(KeygenError):
    message = "upgrade failed"


class UpgradeNotAvailableError(UpgradeError):
    message = "no upgrades available (already up-to-date)"


class ReleaseLocationMissingError(UpgradeError):
    message = "release has no download URL"


class ArtifactDownloadError(UpgradeError):
    message = "artifact download failed"


class ArtifactChecksumInvalidError(UpgradeError):
    message = "artifact checksum does not match"


class ArtifactSignatureMissingError(UpgradeError):
    message = "artifact signature is missing"


class ArtifactSignatureInvalidError(UpgradeError):
    message = "artifact signature is invalid"


class UpgradeInstallError(UpgradeError):
    message = "upgrade could not be installed"


class NetworkError(KeygenError):
    """The request could not be completed, e.g. a connection failure or a timeout."""

    message = "network request failed"


__all__ = ["ErrorCode"] + [
    name
    for name, value in list(globals().items())
    if isinstance(value, type) and issubclass(value, KeygenError) and not name.startswith("_")
]
