from __future__ import annotations

from typing import Mapping, Optional, Union

from .verifier import Verifier


def verify_webhook(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: Union[bytes, str],
    *,
    host: Optional[str] = None,
    public_key: Optional[str] = None,
) -> None:
    """Verify that a webhook request was sent by Keygen.

    Pass the request method, the full request URL as received, the request
    headers and the raw body. When the app runs behind a proxy that rewrites
    the Host header, pass the public host explicitly. Raises a
    SignatureVerificationError subclass when the request is not genuine.

    Example with Flask::

        @app.post("/webhooks")
        def webhooks():
            try:
                keygen.verify_webhook(request.method, request.url, request.headers, request.get_data())
            except keygen.KeygenError:
                return "", 400
            return "", 204
    """
    Verifier(public_key).verify_request(
        method=method, url=url, headers=headers, body=body, host=host
    )
