"""
KM Simulator - mocks ETSI GS QKD 014 REST API
Each "SAE ID" pair shares a pre-generated symmetric key pool.
Real QKD hardware would replace this module entirely — interface stays identical.
"""
import os
import secrets
import uuid
from typing import Dict, List, Optional
from datetime import datetime

# In-memory key store — persists for process lifetime
# key_pools[sae_id][key_id] = hex_key_bytes
key_pools: Dict[str, Dict[str, str]] = {}
key_metadata: Dict[str, dict] = {}

POOL_SIZE = 100_000     # 100k × 32 B = 3.2 MB key material; supports ~4 MB bundles after zlib
KEY_SIZE_BYTES = 32     # 256-bit keys


def _pool_id(master_sae_id: str, slave_sae_id: str) -> str:
    """Canonical pool ID — same regardless of who asks."""
    return "|".join(sorted([master_sae_id, slave_sae_id]))


def ensure_pool(master_sae_id: str, slave_sae_id: str):
    """Generate a key pool for a SAE pair if it doesn't exist."""
    pid = _pool_id(master_sae_id, slave_sae_id)
    if pid not in key_pools:
        key_pools[pid] = {}
        for _ in range(POOL_SIZE):
            kid = str(uuid.uuid4())
            key_pools[pid][kid] = secrets.token_hex(KEY_SIZE_BYTES)
            key_metadata[kid] = {
                "key_id": kid,
                "pool_id": pid,
                "created_at": datetime.utcnow().isoformat(),
                "used": False,
            }


def get_keys(master_sae_id: str, slave_sae_id: str, number: int = 1, size: int = 256) -> Optional[dict]:
    """
    ETSI QKD 014 - GET /api/v1/keys/{slave_sae_id}/enc_keys
    Returns a block of fresh keys, marks them used.
    """
    ensure_pool(master_sae_id, slave_sae_id)
    pid = _pool_id(master_sae_id, slave_sae_id)
    pool = key_pools[pid]

    available = [kid for kid, _ in pool.items() if not key_metadata[kid]["used"]]
    if len(available) < number:
        return None  # Key exhaustion — caller should downgrade security level

    selected = available[:number]
    result_keys = []
    for kid in selected:
        key_metadata[kid]["used"] = True
        result_keys.append({
            "key_ID": kid,
            "key": pool[kid],   # hex string
        })

    return {
        "keys": result_keys,
        "key_ID_extension": {"master_SAE_ID": master_sae_id, "slave_SAE_ID": slave_sae_id},
    }


def get_key_by_id(slave_sae_id: str, master_sae_id: str, key_ids: List[str]) -> Optional[dict]:
    """
    ETSI QKD 014 - POST /api/v1/keys/{master_sae_id}/dec_keys
    Recipient fetches the key by ID that the sender embedded in the email header.
    """
    ensure_pool(master_sae_id, slave_sae_id)
    pid = _pool_id(master_sae_id, slave_sae_id)
    pool = key_pools[pid]

    result_keys = []
    for kid in key_ids:
        if kid in pool:
            result_keys.append({
                "key_ID": kid,
                "key": pool[kid],
            })

    if not result_keys:
        return None

    return {"keys": result_keys}


def get_status(master_sae_id: str, slave_sae_id: str) -> dict:
    """ETSI QKD 014 - GET /api/v1/keys/{slave_sae_id}/status"""
    ensure_pool(master_sae_id, slave_sae_id)
    pid = _pool_id(master_sae_id, slave_sae_id)
    pool = key_pools[pid]
    available = sum(1 for kid in pool if not key_metadata[kid]["used"])
    used = len(pool) - available

    return {
        "source_KME_ID": "KME-SIM-001",
        "target_KME_ID": "KME-SIM-002",
        "master_SAE_ID": master_sae_id,
        "slave_SAE_ID": slave_sae_id,
        "key_size": KEY_SIZE_BYTES * 8,
        "stored_key_count": available,
        "max_key_count": POOL_SIZE,
        "max_key_per_request": 10,
        "max_key_size": KEY_SIZE_BYTES * 8,
        "min_key_size": 64,
        "used_key_count": used,
        "status": "ACTIVE" if available > 5 else ("LOW" if available > 0 else "EXHAUSTED"),
    }


def refill_pool(master_sae_id: str, slave_sae_id: str):
    """Demo helper — refill key pool (simulates new QKD session)."""
    pid = _pool_id(master_sae_id, slave_sae_id)
    if pid in key_pools:
        del key_pools[pid]
        for kid in list(key_metadata.keys()):
            if key_metadata[kid]["pool_id"] == pid:
                del key_metadata[kid]
    ensure_pool(master_sae_id, slave_sae_id)