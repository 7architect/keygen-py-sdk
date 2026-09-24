from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Iterable, Optional, Union

from ._config import settings
from .verifier import EncodingAlgorithm

Include = Union[str, Iterable[str], None]
TTL = Union[int, float, timedelta, None]


def checkout_query(
    *,
    include: Include,
    ttl: TTL,
    encrypt: bool,
    algorithm: Optional[str],
) -> Dict[str, Any]:
    sign = str(algorithm or settings.signature_scheme)
    encoding = EncodingAlgorithm.AES256 if encrypt else EncodingAlgorithm.BASE64

    if include is None:
        includes = ""
    elif isinstance(include, str):
        includes = include
    else:
        includes = ",".join(str(item) for item in include if item)

    seconds: Optional[int] = None
    if ttl is not None:
        if isinstance(ttl, bool):
            raise TypeError("ttl must be a number of seconds or a timedelta")
        seconds = int(ttl.total_seconds()) if isinstance(ttl, timedelta) else int(ttl)
        if seconds <= 0:
            raise ValueError("ttl must be positive")

    return {
        "algorithm": f"{encoding.value}+{sign}",
        "encrypt": bool(encrypt),
        "include": includes,
        "ttl": seconds,
    }
