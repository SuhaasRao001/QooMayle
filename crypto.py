"""
Crypto Engine — All 4 QuMail security levels + utilities.
"""
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Check if liboqs is available (Kyber)
try:
    import liboqs
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False


# ─── Helper functions ──────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode()


def _unb64(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s.encode())


def compute_bundle(body: str, attachments: list = None) -> str:
    """Create JSON bundle of message body + attachments before encryption."""
    return json.dumps({"body": body, "attachments": attachments or []})


def unpack_bundle(decrypted_text: str) -> tuple:
    """Extract body + attachments from decrypted bundle. Graceful fallback for legacy plaintext."""
    try:
        obj = json.loads(decrypted_text)
        if isinstance(obj, dict) and "body" in obj:
            return obj["body"], obj.get("attachments", [])
    except Exception:
        pass
    # Legacy message — treat as body only
    return decrypted_text, []


# ─── Level 1: One-Time Pad ─────────────────────────────────────────────────────

def otp_encrypt(plaintext: str, key_hex: str) -> dict:
    """Encrypt via XOR with quantum key. Requires key length >= message length."""
    pt_bytes = plaintext.encode("utf-8")
    key_bytes = bytes.fromhex(key_hex)
    
    if len(key_bytes) < len(pt_bytes):
        raise ValueError(
            f"OTP requires key >= message length. "
            f"Key: {len(key_bytes)}B, Message: {len(pt_bytes)}B"
        )
    
    key_slice = key_bytes[:len(pt_bytes)]
    ciphertext = bytes(a ^ b for a, b in zip(pt_bytes, key_slice))
    
    return {
        "level": 1,
        "ciphertext_b64": _b64(ciphertext),
        "msg_len": len(pt_bytes),
    }


def otp_decrypt(ciphertext_b64: str, key_hex: str, msg_len: int) -> str:
    """Decrypt OTP ciphertext."""
    ct = _unb64(ciphertext_b64)
    key_bytes = bytes.fromhex(key_hex)[:msg_len]
    return bytes(a ^ b for a, b in zip(ct, key_bytes)).decode("utf-8")


# ─── Level 2: Quantum-Seeded AES-256-GCM ───────────────────────────────────────

def qaes_encrypt(plaintext: str, key_hex: str) -> dict:
    """Encrypt with AES-256-GCM derived from quantum seed via HKDF."""
    quantum_seed = bytes.fromhex(key_hex)
    pt_bytes = plaintext.encode("utf-8")
    
    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level2-AES",
    ).derive(quantum_seed)
    
    # Generate nonce and encrypt
    nonce = os.urandom(12)
    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(nonce, pt_bytes, None)
    
    return {
        "level": 2,
        "ciphertext_b64": _b64(ciphertext),
        "nonce_b64": _b64(nonce),
    }


def qaes_decrypt(ciphertext_b64: str, nonce_b64: str, key_hex: str) -> str:
    """Decrypt QAES message."""
    quantum_seed = bytes.fromhex(key_hex)
    ciphertext = _unb64(ciphertext_b64)
    nonce = _unb64(nonce_b64)
    
    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level2-AES",
    ).derive(quantum_seed)
    
    cipher = AESGCM(aes_key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# ─── Level 3: Kyber-768 + AES-256-GCM ──────────────────────────────────────────

def kyber_generate_keypair() -> tuple:
    """Generate Kyber-768 keypair (public_key, secret_key) as hex strings."""
    if not KYBER_AVAILABLE:
        raise RuntimeError("liboqs not installed. Install with: pip install liboqs-python")
    
    kem = liboqs.OQS_KEM("Kyber768")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    
    return _b64(public_key), _b64(secret_key)


def kyber_encrypt(plaintext: str, server_public_key_b64: str) -> dict:
    """Encrypt plaintext using Kyber-768 + AES-256-GCM."""
    if not KYBER_AVAILABLE:
        raise RuntimeError("liboqs not installed")
    
    pt_bytes = plaintext.encode("utf-8")
    server_public_key = _unb64(server_public_key_b64)
    
    kem = liboqs.OQS_KEM("Kyber768")
    ciphertext, shared_secret = kem.encap(server_public_key)
    
    # Derive AES key from shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level3-Kyber",
    ).derive(shared_secret)
    
    # Encrypt message
    nonce = os.urandom(12)
    cipher = AESGCM(aes_key)
    encrypted_msg = cipher.encrypt(nonce, pt_bytes, None)
    
    return {
        "level": 3,
        "encapsulated_secret_b64": _b64(ciphertext),
        "encrypted_body_b64": _b64(encrypted_msg),
        "nonce_b64": _b64(nonce),
    }


def kyber_decrypt(encapsulated_secret_b64: str, encrypted_body_b64: str, 
                  nonce_b64: str, secret_key_b64: str) -> str:
    """Decrypt Kyber-768 + AES-256-GCM message."""
    if not KYBER_AVAILABLE:
        raise RuntimeError("liboqs not installed")
    
    encapsulated_secret = _unb64(encapsulated_secret_b64)
    encrypted_body = _unb64(encrypted_body_b64)
    nonce = _unb64(nonce_b64)
    secret_key = _unb64(secret_key_b64)
    
    kem = liboqs.OQS_KEM("Kyber768")
    kem.secret_key = secret_key
    shared_secret = kem.decap(encapsulated_secret)
    
    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"QuMail-Level3-Kyber",
    ).derive(shared_secret)
    
    cipher = AESGCM(aes_key)
    plaintext = cipher.decrypt(nonce, encrypted_body, None)
    return plaintext.decode("utf-8")


# ─── Level 4: Plaintext (debug only) ────────────────────────────────────────────

def plaintext_encrypt(plaintext: str) -> dict:
    """No encryption. Debug/testing only."""
    return {
        "level": 4,
        "body_b64": _b64(plaintext.encode("utf-8")),
    }


def plaintext_decrypt(body_b64: str) -> str:
    """Decrypt plaintext (no-op)."""
    return _unb64(body_b64).decode("utf-8")