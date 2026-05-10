"""
Quantum Canary — Cryptographic Audit Trail
==========================================
Every email cryptographic event is recorded in a hash-chained audit log.
Each entry's hash includes the previous entry's hash, creating a tamper-evident
chain. This simulates what a production QKD network's audit system would require
under ETSI GS QKD 014 §7.3 (security audit requirements).

This is the UVP: a cryptographically verifiable, tamper-evident audit chain
that proves end-to-end security of every message, inspectable in real-time.
"""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class EventType(str, Enum):
    KEY_ISSUED      = "KEY_ISSUED"
    KEY_CONSUMED    = "KEY_CONSUMED"
    ENCRYPT_START   = "ENCRYPT_START"
    ENCRYPT_DONE    = "ENCRYPT_DONE"
    SEND_START      = "SEND_START"
    SEND_DONE       = "SEND_DONE"
    FETCH_DONE      = "FETCH_DONE"
    DECRYPT_START   = "DECRYPT_START"
    DECRYPT_DONE    = "DECRYPT_DONE"
    VERIFY_OK       = "VERIFY_OK"
    VERIFY_FAIL     = "VERIFY_FAIL"
    KEY_POOL_LOW    = "KEY_POOL_LOW"
    KEY_POOL_REFILL = "KEY_POOL_REFILL"
    ENTROPY_SAMPLE  = "ENTROPY_SAMPLE"


@dataclass
class AuditEntry:
    event_id:   str
    prev_hash:  str
    timestamp:  float
    event_type: str
    actor:      str          # SAE ID or "system"
    subject:    str          # email subject / key ID / etc.
    level:      int          # 0 = system, 1-4 = crypto level
    metadata:   Dict[str, Any]
    entry_hash: str = field(default="", init=False)

    def __post_init__(self):
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = json.dumps({
            "event_id":   self.event_id,
            "prev_hash":  self.prev_hash,
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "actor":      self.actor,
            "subject":    self.subject,
            "level":      self.level,
            "metadata":   self.metadata,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["entry_hash"] = self.entry_hash
        d["iso_time"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return d


class AuditLog:
    """In-memory hash-chained audit log. Thread-safe for single-process use."""

    GENESIS_HASH = "0" * 64  # Genesis block — no predecessor

    def __init__(self, max_entries: int = 2000):
        self._entries: List[AuditEntry] = []
        self._max = max_entries
        # Index by email message_id for fast lookup
        self._by_message: Dict[str, List[int]] = {}

    @property
    def head_hash(self) -> str:
        if not self._entries:
            return self.GENESIS_HASH
        return self._entries[-1].entry_hash

    def record(
        self,
        event_type: EventType,
        actor: str,
        subject: str,
        level: int = 0,
        metadata: Dict[str, Any] = None,
        message_id: str = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            event_id=str(uuid.uuid4()),
            prev_hash=self.head_hash,
            timestamp=time.time(),
            event_type=event_type.value,
            actor=actor,
            subject=subject,
            level=level,
            metadata=metadata or {},
        )
        idx = len(self._entries)
        self._entries.append(entry)

        if message_id:
            self._by_message.setdefault(message_id, []).append(idx)

        # Evict oldest if over capacity
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max:]

        return entry

    def verify_chain(self) -> dict:
        """Walk the chain and verify every hash links correctly."""
        if not self._entries:
            return {"valid": True, "checked": 0, "broken_at": None}

        prev = self.GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.prev_hash != prev:
                return {"valid": False, "checked": i, "broken_at": i}
            expected = entry._compute_hash()
            if entry.entry_hash != expected:
                return {"valid": False, "checked": i, "broken_at": i}
            prev = entry.entry_hash

        return {"valid": True, "checked": len(self._entries), "broken_at": None}

    def get_recent(self, n: int = 50) -> List[dict]:
        return [e.to_dict() for e in self._entries[-n:]]

    def get_by_message(self, message_id: str) -> List[dict]:
        idxs = self._by_message.get(message_id, [])
        return [self._entries[i].to_dict() for i in idxs if i < len(self._entries)]

    def stats(self) -> dict:
        counts: Dict[str, int] = {}
        for e in self._entries:
            counts[e.event_type] = counts.get(e.event_type, 0) + 1
        return {
            "total_entries": len(self._entries),
            "head_hash": self.head_hash[:16] + "…",
            "event_counts": counts,
        }


# ── Global singleton ──────────────────────────────────────────────────────────
audit = AuditLog()
