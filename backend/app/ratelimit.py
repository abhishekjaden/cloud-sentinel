"""
A per-user request limit.

The WAF in front of the load balancer limits what one address may send
(cdk/lib/stacks/api-stack.ts); this limits what one identity may send, which
is the thing the WAF cannot see. A stolen session, a runaway script, or an
operator's tab left reloading in a loop is bounded here, at the API, by the
subject of the verified token: RATE_LIMIT_PER_MINUTE requests in any sliding
sixty seconds, then 429 with a Retry-After that says when the oldest request
leaves the window.

The console polls five routes every thirty seconds — ten requests a minute
per operator — so the default of 120 is an order of magnitude above normal
use and below anything that looks like scraping. The counters are in the
process's memory, which is exact for the one task this API runs as; a second
task would count separately, and the limit would then be per task rather
than per user, which is a known property, not a bug to be hidden.
"""
import os
import threading
import time
from collections import deque

LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "120"))
WINDOW_SECONDS = 60.0


class SlidingWindow:
    """At most `limit` hits per key in any `window` seconds."""

    def __init__(self, limit=LIMIT_PER_MINUTE, window=WINDOW_SECONDS, clock=time.monotonic):
        self.limit = int(limit)
        self.window = float(window)
        self._clock = clock
        self._hits = {}
        self._lock = threading.Lock()

    def hit(self, key):
        """Record one request for `key`. Returns None if it is allowed, or the
        number of seconds until the oldest request in the window expires —
        the earliest moment a retry could succeed — if it is not. A refused
        request is not recorded, so a caller who keeps retrying does not push
        their own window further out."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = self._hits[key] = deque()
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return self.window - (now - hits[0])
            hits.append(now)
            return None

    def forget(self, key):
        with self._lock:
            self._hits.pop(key, None)


limiter = SlidingWindow()
