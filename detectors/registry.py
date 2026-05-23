# detectors/registry.py
# Plugin registry (active/passive) + shared per-host token-bucket helper.

import time
import asyncio
from typing import Callable, List

ACTIVE_DETECTORS: List[Callable] = []   # async def fn(session, url, context) -> list[dict]
PASSIVE_DETECTORS: List[Callable] = []  # def fn(text, context) -> list[dict]


class DetectorSkip(Exception):
    """Signal that a detector intentionally skipped execution.

    Used for cases like missing external binaries, missing API keys, or other
    preconditions not met. The scanner should record these as 'skipped' in
    metadata instead of treating them as failures.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def register_active(fn):
    ACTIVE_DETECTORS.append(fn)
    return fn


def register_passive(fn):
    PASSIVE_DETECTORS.append(fn)
    return fn


# Shared host token-bucket state for detectors that need to throttle internal requests
_host_tokens = {}  # host -> {"tokens": float, "last": float}


async def await_host_token(host: str, rate: float, capacity: float = 1.0):
    """
    Async token-bucket for a host.
    - host: hostname (netloc)
    - rate: tokens/sec (requests/sec)
    - capacity: max burst tokens
    If rate <= 0 or None -> no throttling.
    """
    if not rate or rate <= 0:
        return
    now = time.time()
    hs = _host_tokens.setdefault(host, {"tokens": capacity, "last": now})
    elapsed = now - hs["last"]
    refill = elapsed * rate
    hs["tokens"] = min(capacity, hs["tokens"] + refill)
    hs["last"] = now
    if hs["tokens"] >= 1.0:
        hs["tokens"] -= 1.0
        return
    need = (1.0 - hs["tokens"]) / rate
    await asyncio.sleep(need)
    hs["tokens"] = 0.0
    hs["last"] = time.time()
    return
