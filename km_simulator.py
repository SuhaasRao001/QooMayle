"""
Key Manager (KM) Simulator
Simulates a QKD (Quantum Key Distribution) key management server.
Maintains a pool of pre-generated quantum-safe random keys per SAE pair.
"""

import os
import uuid
import secrets
import threading
from typing import List, Dict, Tuple
from dotenv import load_dotenv

load_dotenv()

POOL_SIZE = int(os.getenv("KM_POOL_SIZE", "100000"))
KEY_SIZE = int(os.getenv("KEY_SIZE_BYTES", "32"))

# Thread-safe in-memory key store: {(master_sae, slave_sae): [{"key_ID": str, "key": hex, "used": bool}]}
_lock = threading.Lock()
_pools: Dict[Tuple[str, str], List[dict]] = {}


def _pool_key(master_sae: str, slave_sae: str) -> Tuple[str, str]:
    """Canonical key: always sorted so A↔B == B↔A for same pool."""
    return tuple(sorted([master_sae, slave_sae]))


def ensure_pool(master_sae: str, slave_sae: str) -> None:
    """Initialize key pool for a SAE pair if not already present."""
    pk = _pool_key(master_sae, slave_sae)
    with _lock:
        if pk not in _pools:
            _pools[pk] = [
                {
                    "key_ID": str(uuid.uuid4()),
                    "key": secrets.token_hex(KEY_SIZE),
                    "used": False
                }
                for _ in range(POOL_SIZE)
            ]


def get_keys(master_sae: str, slave_sae: str, number: int = 1) -> List[dict]:
    """
    Retrieve fresh (unused) keys from the pool.
    Returns list of {key_ID, key} dicts.
    Raises ValueError if pool exhausted.
    """
    ensure_pool(master_sae, slave_sae)
    pk = _pool_key(master_sae, slave_sae)

    with _lock:
        pool = _pools[pk]
        available = [k for k in pool if not k["used"]]

        if len(available) < number:
            raise ValueError(
                f"KM pool exhausted: requested {number}, available {len(available)}. "
                "Consider upgrading to Level 2 (QAES) which reuses keys via HKDF."
            )

        selected = available[:number]
        for k in selected:
            k["used"] = True

        return [{"key_ID": k["key_ID"], "key": k["key"]} for k in selected]


def get_key_by_id(master_sae: str, slave_sae: str, key_ids: List[str]) -> List[dict]:
    """
    Retrieve specific keys by their IDs (for decryption).
    Returns list of {key_ID, key} dicts.
    """
    ensure_pool(master_sae, slave_sae)
    pk = _pool_key(master_sae, slave_sae)

    with _lock:
        pool = _pools[pk]
        id_map = {k["key_ID"]: k for k in pool}

        result = []
        for kid in key_ids:
            if kid in id_map:
                result.append({"key_ID": kid, "key": id_map[kid]["key"]})
            else:
                raise ValueError(f"Key ID not found: {kid}")

        return result


def get_status(master_sae: str, slave_sae: str) -> dict:
    """Return pool statistics for a SAE pair."""
    ensure_pool(master_sae, slave_sae)
    pk = _pool_key(master_sae, slave_sae)

    with _lock:
        pool = _pools[pk]
        total = len(pool)
        used = sum(1 for k in pool if k["used"])
        available = total - used
        percent = round((available / total) * 100, 2) if total > 0 else 0

    return {
        "pool_size": total,
        "available": available,
        "used": used,
        "percent_available": percent
    }


def get_keys_for_otp(master_sae: str, slave_sae: str, byte_count: int) -> List[dict]:
    """
    For OTP: fetch enough keys to cover byte_count bytes.
    Each key is KEY_SIZE bytes (32). Returns multiple keys if needed.
    """
    keys_needed = -(-byte_count // KEY_SIZE)  # ceiling division
    return get_keys(master_sae, slave_sae, keys_needed)


def combine_key_material(keys: List[dict]) -> bytes:
    """Concatenate multiple key hex strings into a single byte stream."""
    combined = b""
    for k in keys:
        combined += bytes.fromhex(k["key"])
    return combined