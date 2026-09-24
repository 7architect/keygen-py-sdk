from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Tuple

from . import errors
from ._config import settings

DEFAULT_HEARTBEAT_DURATION = 600
HEARTBEAT_LEEWAY = 30

ErrorHandler = Callable[[BaseException], None]


def schedule(duration: int) -> Tuple[float, float]:
    """Return the ping interval and the retry window for a heartbeat duration in seconds.

    Pings are sent 30 seconds before the window closes to absorb network lag.
    Very short windows are pinged at half their length instead.
    """
    if duration <= 0:
        duration = DEFAULT_HEARTBEAT_DURATION
    if duration > 2 * HEARTBEAT_LEEWAY:
        interval = float(duration - HEARTBEAT_LEEWAY)
    else:
        interval = max(duration / 2.0, 1.0)
    slack = max(duration - interval, 0.0)
    return interval, slack * 0.8


def _is_transient(err: BaseException) -> bool:
    if isinstance(err, (errors.NetworkError, errors.RateLimitError)):
        return True
    if isinstance(err, errors.APIError) and err.status is not None and err.status >= 500:
        return True
    return False


class HeartbeatMonitor:
    """Sends heartbeat pings on a background thread until stopped.

    If a ping fails for good, the monitor stops, keeps the exception in
    ``error`` and hands it to ``on_error`` when one was given. Transient
    failures such as network errors are retried while the heartbeat window
    still allows it.
    """

    def __init__(
        self,
        ping: Callable[[], None],
        duration: int,
        *,
        on_error: Optional[ErrorHandler] = None,
        name: str = "keygen-heartbeat",
    ) -> None:
        self._ping = ping
        self.interval, self.retry_window = schedule(duration)
        self.on_error = on_error
        self.error: Optional[BaseException] = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)

    def start(self) -> "HeartbeatMonitor":
        if not self._thread.is_alive() and not self._stop.is_set():
            self._thread.start()
        return self

    def stop(self, timeout: Optional[float] = None) -> None:
        self._stop.set()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread.is_alive() and not self._stop.is_set()

    def __enter__(self) -> "HeartbeatMonitor":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._ping_with_retries()
            except BaseException as err:
                if self._stop.is_set():
                    return
                self.error = err
                self._stop.set()
                settings.logger.error("Heartbeat monitor stopped: err=%s", err)
                if self.on_error is not None:
                    try:
                        self.on_error(err)
                    except Exception as handler_err:
                        settings.logger.error("Heartbeat error handler failed: err=%s", handler_err)
                return

    def _ping_with_retries(self) -> None:
        deadline = time.monotonic() + self.retry_window
        delay = 1.0
        while True:
            try:
                self._ping()
                return
            except Exception as err:
                remaining = deadline - time.monotonic()
                if not _is_transient(err) or remaining <= 0:
                    raise
                wait = delay
                if isinstance(err, errors.RateLimitError) and err.retry_after > 0:
                    wait = float(err.retry_after)
                wait = min(wait, remaining)
                settings.logger.warning("Heartbeat ping failed, retrying in %.1fs: err=%s", wait, err)
                if self._stop.wait(wait):
                    return
                delay = min(delay * 2, 8.0)
