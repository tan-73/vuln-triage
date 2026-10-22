"""HTTP plumbing for external feeds: retries with backoff, ``Retry-After`` and rate limits."""

from __future__ import annotations

import logging
import random
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from vulntriage import __version__

log = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({403, 408, 429, 500, 502, 503, 504})
"""NVD answers 403 when rate-limited, so it is retried too."""

USER_AGENT = f"vulntriage/{__version__} (homelab vulnerability triage)"


class FeedError(RuntimeError):
    """A feed request failed after all retries."""


class RateLimiter:
    """Sliding-window limiter: at most ``max_calls`` per ``period`` seconds."""

    def __init__(
        self,
        max_calls: int,
        period: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.max_calls = max_calls
        self.period = period
        self._clock = clock
        self._sleep = sleep
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until another call is allowed, then record it."""
        with self._lock:
            now = self._clock()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                wait = self.period - (now - self._calls[0])
                if wait > 0:
                    log.debug("rate limit: sleeping %.1fs", wait)
                    self._sleep(wait)
                self._calls.popleft()
            self._calls.append(self._clock())


class FeedClient:
    """Thin wrapper over :class:`httpx.Client` used by every feed fetcher."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        max_retries: int = 4,
        backoff_base: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._http = client or httpx.Client(
            timeout=timeout, headers={"User-Agent": USER_AGENT}, follow_redirects=True
        )
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._sleep = sleep

    def _delay(self, attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                return min(float(retry_after), 120.0)
        return float(self.backoff_base * (2**attempt) + random.uniform(0, self.backoff_base))  # noqa: S311

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        limiter: RateLimiter | None = None,
        allow_404: bool = False,
    ) -> Any:
        """Send a request and return the decoded JSON body.

        Retries transport errors and :data:`RETRYABLE_STATUS` with exponential backoff.
        Returns ``None`` for a 404 when ``allow_404`` is set.

        Raises:
            FeedError: when retries are exhausted or the response is not JSON.
        """
        last_error = "no attempt made"
        for attempt in range(self.max_retries + 1):
            if limiter is not None:
                limiter.acquire()
            response: httpx.Response | None = None
            try:
                response = self._http.request(
                    method, url, params=params, json=json, headers=headers
                )
            except httpx.TransportError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code == 404 and allow_404:
                    return None
                if response.is_success:
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise FeedError(f"{url}: response is not JSON") from exc
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in RETRYABLE_STATUS:
                    break
            if attempt < self.max_retries:
                delay = self._delay(attempt, response)
                log.info("%s failed (%s); retry %d in %.1fs", url, last_error, attempt + 1, delay)
                self._sleep(delay)
        raise FeedError(f"{url}: {last_error}")

    def get_json(self, url: str, **kwargs: Any) -> Any:
        """Shorthand for ``request_json("GET", ...)``."""
        return self.request_json("GET", url, **kwargs)

    def close(self) -> None:
        """Close the connection pool."""
        self._http.close()
