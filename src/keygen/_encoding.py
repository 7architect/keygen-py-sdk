from __future__ import annotations

import base64
import binascii
import re

_WHITESPACE = re.compile(r"\s+")


def b64decode(value: str, *, urlsafe: bool = False, strict_padding: bool = False) -> bytes:
    """Decode base64 text, raising ValueError on malformed input.

    Whitespace such as line breaks is ignored. Missing padding is tolerated
    unless ``strict_padding`` is set.
    """
    if not isinstance(value, str):
        raise ValueError("base64 input must be a string")

    data = _WHITESPACE.sub("", value)
    if not strict_padding:
        data = data.rstrip("=")
        data += "=" * (-len(data) % 4)

    try:
        if urlsafe:
            if re.search(r"[^A-Za-z0-9_\-=]", data):
                raise ValueError("invalid base64url data")
            return base64.urlsafe_b64decode(data)
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as err:
        raise ValueError(str(err)) from err
