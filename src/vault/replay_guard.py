"""
Replay protection (D5 feedback).

Threat: an attacker with access to the shared storage re-delivers an OLD, genuinely
signed package (for example last month's "payment instructions") so the recipient
treats it as new. The signature is valid, so signatures alone cannot detect it.

Two complementary checks, applied AFTER the signature is verified:
  1. Freshness window: the signed timestamp must not be older than `max_age_seconds`
     (default 30 days) nor more than `max_future_skew` seconds in the future.
  2. Seen-package cache: the identifier of every accepted package is stored; the same
     package is refused the second time ("already received").

The window also bounds the cache: entries older than the window can be deleted,
because such packages are rejected by the freshness check anyway.

The package identifier is SHA-256 of the signed data (everything except the signature),
so it does not depend on the signature encoding.
"""
import hashlib
import json
import os
import time
from datetime import datetime, timezone

from vault.crypto_module import SecureEncryptionModule
from vault.errors import ReplayError, StaleContainerError
from vault.keystore import _atomic_write_private

CACHE_FORMAT = "SDDV-REPLAY-CACHE"
CACHE_VERSION = 1
DEFAULT_MAX_AGE = 30 * 24 * 3600      # 30 days
DEFAULT_FUTURE_SKEW = 5 * 60           # 5 minutes of clock difference tolerated


def container_id(container: dict) -> str:
    """Stable identifier of a (verified) container."""
    return hashlib.sha256(SecureEncryptionModule._signed_digest(container)).hexdigest()


class ReplayGuard:
    def __init__(self, path: str, max_age_seconds: int = DEFAULT_MAX_AGE,
                 max_future_skew: int = DEFAULT_FUTURE_SKEW, clock=time.time):
        self.path = path
        self.max_age = max_age_seconds
        self.max_future_skew = max_future_skew
        self.clock = clock
        self.seen = {}
        if os.path.exists(path):
            self._load()

    def _load(self):
        try:
            with open(self.path, "rb") as f:
                data = json.loads(f.read().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            # A corrupted cache must not silently disable the protection
            raise ReplayError(f"The replay cache could not be read: {self.path}") from None
        if not isinstance(data, dict) or data.get("format") != CACHE_FORMAT \
                or not isinstance(data.get("seen"), dict):
            raise ReplayError("Invalid replay cache file.")
        self.seen = data["seen"]

    def _save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        data = {"format": CACHE_FORMAT, "version": CACHE_VERSION, "seen": self.seen}
        _atomic_write_private(self.path, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))

    def check(self, container: dict) -> str:
        """Raises if the (already verified) container is stale or was already accepted."""
        now = self.clock()
        timestamp = container["metadata"]["timestamp"]
        if timestamp < now - self.max_age:
            days = int((now - timestamp) // 86400)
            raise StaleContainerError(
                f"Package rejected: it was signed {days} days ago (maximum {self.max_age // 86400} days).")
        if timestamp > now + self.max_future_skew:
            raise StaleContainerError("Package rejected: its signed timestamp is in the future.")
        cid = container_id(container)
        if cid in self.seen:
            raise ReplayError(f"Package rejected: it was already received on {self.seen[cid]['received_at']} "
                              "(possible replay).")
        return cid

    def record(self, container: dict):
        """Stores the container as accepted. Call it only after a successful decryption."""
        now = self.clock()
        self.seen[container_id(container)] = {
            "received_at": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timestamp": container["metadata"]["timestamp"],
            "signer_id": container["signer_id"],
        }
        # Entries outside the window are useless: those packages are rejected as stale anyway
        self.seen = {k: v for k, v in self.seen.items()
                     if isinstance(v, dict) and v.get("timestamp", 0) >= now - self.max_age}
        self._save()

    def received_before(self, container: dict) -> bool:
        return container_id(container) in self.seen
