# Keygen Python SDK

Package `keygen` lets Python programs license and remotely update themselves using the
[keygen.sh](https://keygen.sh) service. It is a Python port of the official
[Keygen Go SDK](https://github.com/keygen-sh/keygen-go) and follows the same concepts,
with names adapted to Python conventions.

## Installing

```
pip install keygen-sdk
```

Python 3.8 or newer is required. The SDK depends on `requests` and `cryptography`.

## Config

The SDK is configured through module attributes. Every client created afterwards picks
up the values that are set at that moment.

### keygen.account

`account` is your Keygen account ID used globally in the SDK. All requests will be made
to this account. This should be hard-coded into your app.

```python
keygen.account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
```

### keygen.product

`product` is your Keygen product ID used globally in the SDK. All license validations and
upgrade requests will be scoped to this product. This should be hard-coded into your app.

```python
keygen.product = "1f086ec9-a943-46ea-9da4-e62c2180c2f4"
```

### keygen.license_key

`license_key` is a license key belonging to the end-user (licensee). This will be used for
license validations, activations, deactivations and upgrade requests. You will need to
prompt the end-user for this value.

You will need to set the license policy's authentication strategy to `LICENSE` or `MIXED`.

Setting `license_key` takes precedence over `token`.

```python
keygen.license_key = "C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3"
```

### keygen.token

`token` is an activation token belonging to the licensee. This will be used for license
validations, activations, deactivations and upgrade requests. You will need to prompt the
end-user for this.

You will need to set the license policy's authentication strategy to `TOKEN` or `MIXED`.

```python
keygen.token = "activ-d66e044ddd7dcc4169ca9492888435d3v3"
```

### keygen.public_key

`public_key` is your Keygen account's hex encoded Ed25519 public key, used for verifying
signed license keys, license files, machine files, webhooks and API response signatures.
When set, API response signatures are verified automatically. You may leave it blank to
skip verifying response signatures. This should be hard-coded into your app.

```python
keygen.public_key = "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788"
```

When using ECDSA, set `keygen.signature_scheme = "ecdsa-p256"` and provide the PEM encoded
ECDSA public key instead.

### Other settings

| Setting | Default | Description |
| --- | --- | --- |
| `keygen.environment` | `""` | Keygen environment ID or code for requests and validation scopes. |
| `keygen.package` | `""` | Package ID to scope upgrades to. |
| `keygen.signature_scheme` | `"ed25519"` | `"ed25519"` or `"ecdsa-p256"`. Used for response signatures and checkouts. |
| `keygen.api_url` | `"https://api.keygen.sh"` | API host. Set it for custom domains and self-hosted Keygen. |
| `keygen.api_version` | `"1.8"` | API version sent with every request. |
| `keygen.user_agent` | `""` | Extra user agent string identifying your integration. |
| `keygen.max_clock_drift` | 5 minutes | Allowed clock difference for signed responses, webhooks and files. Accepts a `timedelta` or seconds. `None` or a negative value disables the check. |
| `keygen.timeout` | `30.0` | Request timeout in seconds, passed to `requests`. |
| `keygen.http_client` | new `requests.Session` | Session used for every request. Replace it to add retries, proxies or mocks. |
| `keygen.logger` | `logging.getLogger("keygen")` | Any object with `error`, `warning`, `info` and `debug` methods. |
| `keygen.program` | name of the running program | Used to resolve upgrade artifact filenames. |
| `keygen.ext` | `"exe"` on Windows, else `""` | Used to resolve upgrade artifact filenames. |

### Logging

The SDK logs to the standard `keygen` logger and stays silent until logging is configured:

```python
import logging

logging.basicConfig()
logging.getLogger("keygen").setLevel(logging.DEBUG)
```

## Usage

The following top-level functions are available. We recommend starting here.

### keygen.validate(*fingerprints)

To validate a license, configure `keygen.account` and `keygen.product` with your Keygen
account details. Then prompt the end-user for their license key or token and set
`keygen.license_key` or `keygen.token`, respectively.

`validate` accepts zero or more fingerprints, which can be used to scope a license
validation to a particular device fingerprint and its hardware components. The first
fingerprint should be a machine fingerprint, and the rest are optional component
fingerprints.

It returns a `License` when the license is valid. Otherwise it raises a
`LicenseValidationError` subclass. The error keeps the license in `err.license` and the
validation result in `err.result`, so the license can still be used to perform additional
actions, such as `err.license.activate(fingerprint)`.

```python
try:
    license = keygen.validate(fingerprint)
except keygen.LicenseNotActivatedError:
    raise SystemExit("license is not activated!")
except keygen.LicenseExpiredError:
    raise SystemExit("license is expired!")
except keygen.KeygenError:
    raise SystemExit("license is invalid!")

print("License is valid!")
```

### keygen.upgrade(current_version, **options)

Check for an upgrade. When an upgrade is available, a `Release` is returned which allows
the update to be installed, replacing the currently running program. When an upgrade is
not available, `UpgradeNotAvailableError` is raised, indicating the current version is up
to date.

When a `public_key` is provided, the release artifact must carry a signature, which is
cryptographically verified using Ed25519ph before installing. The `public_key` must be a
personal Ed25519ph public key. It must not be your Keygen account's public key, and
`upgrade` raises `ValueError` when the two keys match.

You can read more about generating a personal keypair and about code signing
[here](https://keygen.sh/docs/cli/#code-signing).

```python
try:
    release = keygen.upgrade(
        "1.0.0",
        channel="stable",
        public_key="5ec69b78d4b5d4b624699cef5faf3347dc4b06bb807ed4a2c6740129f1db7159",
    )
except keygen.UpgradeNotAvailableError:
    print("No upgrade available, already at the latest version!")
else:
    release.install()
    print("Upgrade complete! Please restart.")
```

The options can also be passed as a `keygen.UpgradeOptions` object. Available options are
`product`, `package`, `constraint`, `channel`, `public_key` and `filename`.

`filename` controls which artifact gets downloaded. By default it resolves to
`{program}_{platform}_{arch}`, followed by `.{ext}` when an extension is set, e.g.
`myapp_linux_amd64` or `myapp_windows_amd64.exe`. Platform and architecture names follow
Go conventions (`linux`, `darwin`, `windows`, `amd64`, `arm64`, `386`, ...) so artifacts
can be shared with Go programs. Pass a format string using the placeholders `{program}`,
`{ext}`, `{platform}`, `{arch}`, `{channel}` and `{version}`, or a callable receiving those
values as a dict:

```python
keygen.upgrade("1.0.0", filename="{program}-{version}-{platform}-{arch}.bin")
keygen.upgrade("1.0.0", filename=lambda v: f"{v['program']}_{v['platform']}.zip")
```

`release.install(target=None)` replaces the running program by default. For frozen
executables, e.g. built with PyInstaller, that is `sys.executable`. Pass `target` to
install to another path. The new file is downloaded next to the target, checked against
the artifact size, checksum and signature, and only then swapped in, keeping the file
permissions. When anything fails, the previous version stays in place.

To quickly generate a keypair, use [Keygen's CLI](https://github.com/keygen-sh/keygen-cli):

```bash
keygen genkey
```

## Examples

Below are various implementation examples, covering common licensing scenarios and use cases.

### License Activation

Validate the license for a particular device fingerprint, and activate when needed. Any
stable, unique machine identifier works as a fingerprint, for example a hash of the
operating system's machine GUID.

```python
import hashlib
import uuid

import keygen

keygen.account = "YOUR_KEYGEN_ACCOUNT_ID"
keygen.product = "YOUR_KEYGEN_PRODUCT_ID"
keygen.license_key = "A_KEYGEN_LICENSE_KEY"

fingerprint = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()

try:
    keygen.validate(fingerprint)
except keygen.LicenseNotActivatedError as err:
    try:
        err.license.activate(fingerprint)
    except keygen.MachineLimitExceededError:
        raise SystemExit("machine limit has been exceeded!")
except keygen.LicenseExpiredError:
    raise SystemExit("license is expired!")
except keygen.KeygenError:
    raise SystemExit("license is invalid!")

print("License is activated!")
```

### Hardware Components

Components let you fingerprint individual pieces of hardware and scope validations to them.

```python
machine = license.activate(
    fingerprint,
    keygen.Component(name="Board", fingerprint=board_id),
    keygen.Component(name="Disk", fingerprint=disk_id),
)

keygen.validate(fingerprint, board_id, disk_id)
```

### Automatic Upgrades

Check for an upgrade and automatically replace the current program with the newest version.

```python
import keygen

CURRENT_VERSION = "1.0.0"

keygen.public_key = "YOUR_KEYGEN_PUBLIC_KEY"
keygen.account = "YOUR_KEYGEN_ACCOUNT_ID"
keygen.product = "YOUR_KEYGEN_PRODUCT_ID"
keygen.license_key = "A_KEYGEN_LICENSE_KEY"

print(f"Current version: {CURRENT_VERSION}")
print("Checking for upgrades...")

try:
    release = keygen.upgrade(CURRENT_VERSION, channel="stable", public_key="YOUR_COMPANY_PUBLIC_KEY")
except keygen.UpgradeNotAvailableError:
    print("No upgrade available, already at the latest version!")
except keygen.KeygenError:
    print("Upgrade check failed!")
else:
    print(f"Upgrade available! Newest version: {release.version}")
    print("Installing upgrade...")

    release.install()

    print(f"Upgrade complete! Installed version: {release.version}")
    print("Restart to finish installation...")
```

### Monitor Machine Heartbeats

Monitor a machine's heartbeat, and automatically deactivate machines in case of a crash or
an unresponsive node. We recommend using a random UUID fingerprint for activating nodes in
cloud based scenarios, since nodes may share underlying hardware.

`machine.monitor()` sends the first ping right away and raises if it fails. After that it
keeps pinging on a background thread, 30 seconds before each heartbeat window closes.
Network errors, rate limits and server errors are retried while the window still allows
it. If a ping fails for good, the monitor stops, keeps the exception in `monitor.error`
and calls `on_error` when one is given.

```python
import signal
import threading
import uuid

import keygen

keygen.account = "YOUR_KEYGEN_ACCOUNT_ID"
keygen.product = "YOUR_KEYGEN_PRODUCT_ID"
keygen.license_key = "A_KEYGEN_LICENSE_KEY"

fingerprint = str(uuid.uuid4())
done = threading.Event()

try:
    keygen.validate(fingerprint)
except keygen.LicenseNotActivatedError as err:
    machine = err.license.activate(fingerprint)

    def shutdown(signum, frame):
        print("Deactivating machine and gracefully exiting...")
        machine.deactivate()
        done.set()

    signal.signal(signal.SIGINT, shutdown)

    def heartbeat_failed(error):
        print(f"Heartbeat failed: {error}")
        done.set()

    machine.monitor(on_error=heartbeat_failed)

    print("Machine is activated and monitored!")
    done.wait()
```

### Processes

Processes let you limit how many copies of a program run concurrently on a machine.
`machine.spawn(pid)` creates a process and starts its heartbeat monitor. `process.kill()`
stops the monitor and removes the process.

```python
import os

try:
    process = machine.spawn(os.getpid())
except keygen.ProcessLimitExceededError:
    raise SystemExit("too many running copies!")

try:
    run_app()
finally:
    process.kill()
```

### Offline License Files

Cryptographically verify and decrypt an encrypted license file. This is useful for checking
if a license file is genuine in offline or air-gapped environments. Returns the license
file's dataset and raises on any error that occurred during verification and decryption,
e.g. `LicenseFileNotGenuineError`.

When decrypting a license file, you must provide the license's key as the decryption key.

Requires that `keygen.public_key` is set, or pass the key to `verify(public_key=...)`.

```python
from pathlib import Path

import keygen

keygen.public_key = "YOUR_KEYGEN_PUBLIC_KEY"

lic = keygen.LicenseFile(certificate=Path("/etc/example/license.lic").read_text())

try:
    lic.verify()
except keygen.LicenseFileNotGenuineError:
    raise SystemExit("license file is not genuine!")

try:
    dataset = lic.decrypt("A_KEYGEN_LICENSE_KEY")
except keygen.SystemClockUnsyncedError:
    raise SystemExit("system clock tampering detected!")
except keygen.LicenseFileExpiredError:
    raise SystemExit("license file is expired!")

print("License file is genuine!")
print(f"Decrypted dataset: {dataset}")
```

The dataset holds `license`, `entitlements`, `issued`, `expiry` and `ttl`. Expired and clock
errors carry the decoded dataset in `err.dataset`.

To create license files, call `license.checkout()`. It accepts `include`, `ttl` (seconds or
a `timedelta`), `encrypt` and `algorithm` keyword arguments.

### Offline Machine Files

Machine files work the same way. The decryption key is the license key followed by the
machine fingerprint.

```python
mic = keygen.MachineFile(certificate=Path("/etc/example/machine.lic").read_text())
mic.verify()

dataset = mic.decrypt(license_key + fingerprint)
print(dataset.machine, dataset.license, dataset.entitlements, dataset.components)
```

To create machine files, call `machine.checkout()`.

### Offline License Keys

Cryptographically verify and decode a signed license key. This is useful for checking if a
license key is genuine in offline or air-gapped environments. Returns the key's decoded
dataset and raises on any error that occurred during cryptographic verification, e.g.
`LicenseKeyNotGenuineError`.

When initializing a `License`, `scheme` and `key` are required.

```python
import keygen

keygen.public_key = "YOUR_KEYGEN_PUBLIC_KEY"

license = keygen.License(scheme=keygen.SchemeCode.ED25519, key="A_SIGNED_KEYGEN_LICENSE_KEY")

try:
    dataset = license.verify()
except keygen.LicenseKeyNotGenuineError:
    raise SystemExit("license key is not genuine!")

print("License is genuine!")
print(f"Decoded dataset: {dataset}")
```

### Verify Webhooks

When listening for webhook events from Keygen, you can verify that requests came from
Keygen's servers by using `keygen.verify_webhook`. This protects your webhook endpoint from
event forgery and replay attacks. Pass the request method, the full URL, the headers and
the raw body. If a proxy in front of your app rewrites the host, pass the public host
through `host=`.

Requires that `keygen.public_key` is set.

```python
from flask import Flask, request

import keygen

keygen.public_key = "YOUR_KEYGEN_PUBLIC_KEY"

app = Flask(__name__)


@app.post("/webhooks")
def webhooks():
    try:
        keygen.verify_webhook(request.method, request.url, request.headers, request.get_data())
    except keygen.KeygenError:
        return "", 400

    return "", 204
```

## Error Handling

The SDK raises meaningful exceptions which can be handled in your integration. Every
exception derives from `keygen.KeygenError`. Errors returned by the API derive from
`keygen.APIError`, which exposes `status`, `code`, `title`, `detail`, `source` and the raw
`response`. Connection failures and timeouts raise `keygen.NetworkError`.

Below are a handful of recipes for the more common errors.

### Invalid License Key

When authenticating with a license key, you may receive a `LicenseKeyError` when the
license key does not exist. You can handle this accordingly.

```python
def get_license():
    while True:
        keygen.license_key = prompt_for_license_key()

        try:
            return keygen.validate()
        except keygen.LicenseKeyError:
            print("License key does not exist!")
```

### Invalid License Token

When authenticating with a license token, you may receive a `LicenseTokenError` when the
license token does not exist or has expired.

```python
def get_license():
    while True:
        keygen.token = prompt_for_license_token()

        try:
            return keygen.validate()
        except keygen.LicenseTokenError:
            print("License token does not exist!")
```

### Rate Limiting

When your integration makes too many requests too quickly, the IP address may be
[rate limited](https://keygen.sh/docs/api/rate-limiting/). You can handle this via
`RateLimitError`, which exposes `retry_after`, `window`, `count`, `limit`, `remaining`
and `reset`.

```python
import time


def validate(attempts=3):
    for _ in range(attempts):
        try:
            return keygen.validate()
        except keygen.RateLimitError as err:
            time.sleep(err.retry_after or 1)

    raise SystemExit("still rate limited")
```

### Automatic Retries

When your integration has less than stellar network connectivity, or you simply want to
ensure that failed requests are retried, mount a retrying adapter on the SDK's session.

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import keygen

session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=Retry(total=5, backoff_factor=0.5, allowed_methods=None)))

keygen.http_client = session
```

## Testing

When implementing a testing strategy for your licensing integration, we recommend that you
fully mock our APIs. This is especially important for CI/CD environments, to prevent
unneeded load on our servers. Mocking our APIs will also allow you to more easily stay
within your account's daily request limits.

Any `requests` mocking library works, e.g. [`responses`](https://github.com/getsentry/responses)
or [`requests-mock`](https://github.com/jamielennox/requests-mock). Set
`keygen.max_clock_drift = None` to accept recorded response signatures.

```python
import responses

import keygen


@responses.activate
def test_validation():
    keygen.account = "1fddcec8-8dd3-4d8d-9b16-215cac0f9b52"
    keygen.license_key = "C1B6DE-39A6E3-DE1529-8559A0-4AF593-V3"

    license = {"id": "218810ed-2ac8-4c26-a725-a6da67500561", "type": "licenses", "attributes": {}}

    responses.get(
        "https://api.keygen.sh/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/me",
        json={"data": license},
    )
    responses.post(
        "https://api.keygen.sh/v1/accounts/1fddcec8-8dd3-4d8d-9b16-215cac0f9b52/licenses/218810ed-2ac8-4c26-a725-a6da67500561/actions/validate",
        json={"data": license, "meta": {"valid": True, "code": "VALID", "detail": "is valid"}},
    )

    assert keygen.validate().last_validation.valid
```

## Differences from the Go SDK

The API mirrors the Go SDK, with these deliberate changes:

- Errors are exceptions. Where Go returns a value together with an error, the value is
  attached to the exception (`err.license`, `err.dataset`).
- Heartbeat failures after the first ping do not crash the program. The monitor stops and
  reports the error through `on_error`. Killing a process or deactivating a machine stops
  its monitor first.
- IDs, fingerprints and versions are escaped before they are placed in request paths.
- Installing an upgrade with a personal public key requires the artifact to be signed, and
  the artifact size and checksum are checked before the swap.
- Malformed license keys, certificates and signature headers raise errors instead of
  crashing.
- Response and webhook signatures are checked against the `Keygen-Date` and
  `Keygen-Digest` headers when present. Proxies in front of self-hosted Keygen may
  rewrite `Date`, which makes signature checks fail now and then when only `Date` is used.

## Development

```
pip install -e ".[test]"
pytest
```

End to end tests in `tests/test_live.py` run against a real Keygen server when
`KEYGEN_HOST` and `KEYGEN_ADMIN_TOKEN` are set. They create a throwaway product,
policy, entitlement and license, run the SDK against them with the license key, and
delete everything afterwards. Set `KEYGEN_ACCOUNT_ID` too when using api.keygen.sh.

```
KEYGEN_HOST=https://api.example.com KEYGEN_ADMIN_TOKEN=admin-... pytest tests/test_live.py
```

## License

MIT, see [LICENSE](LICENSE).
