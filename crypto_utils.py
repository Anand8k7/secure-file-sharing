"""
Cryptographic utilities for Secure File Sharing.

Implements:
  - AES-256-CBC     : Symmetric file encryption/decryption
  - RSA-2048 (OAEP) : Asymmetric key wrapping (encrypt AES key with receiver's public key)
  - RSA-PSS         : Digital signatures (owner signs file hash, receiver verifies)
  - HMAC-SHA256     : Tamper-proof audit log entries
  - TOTP (RFC 6238) : Time-based one-time passwords for two-factor authentication
  - Password entropy: Strength estimation for user passwords
"""

import os
import time
import hmac
import math
import struct
import hashlib
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ═══════════════════════════════════════════════════════════════════
# AES-256-CBC — Symmetric File Encryption
# ═══════════════════════════════════════════════════════════════════

def encrypt_file(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt file bytes with AES-256-CBC. Returns (ciphertext, iv)."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, iv


def decrypt_file(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext. Returns plaintext bytes."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


# ═══════════════════════════════════════════════════════════════════
# RSA-2048 — Key Pair Generation & Key Wrapping
# ═══════════════════════════════════════════════════════════════════

def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate an RSA-2048 key pair.
    Returns (private_key_pem, public_key_pem) as strings.
    """
    key = RSA.generate(2048)
    private_pem = key.export_key().decode("utf-8")
    public_pem = key.publickey().export_key().decode("utf-8")
    return private_pem, public_pem


def rsa_encrypt_key(aes_key: bytes, public_key_pem: str) -> bytes:
    """
    Wrap (encrypt) an AES key using the receiver's RSA public key.
    Uses OAEP padding with SHA-256 for security.
    """
    rsa_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.encrypt(aes_key)


def rsa_decrypt_key(encrypted_key: bytes, private_key_pem: str) -> bytes:
    """
    Unwrap (decrypt) an AES key using the receiver's RSA private key.
    """
    rsa_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.decrypt(encrypted_key)


# ═══════════════════════════════════════════════════════════════════
# RSA-PSS — Digital Signatures
# ═══════════════════════════════════════════════════════════════════

def sign_data(data_hash_hex: str, private_key_pem: str) -> str:
    """
    Sign a SHA-256 hash using RSA-PSS with the owner's private key.
    Returns base64-encoded signature string.
    """
    rsa_key = RSA.import_key(private_key_pem)
    h = SHA256.new(bytes.fromhex(data_hash_hex))
    signature = pss.new(rsa_key).sign(h)
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(data_hash_hex: str, signature_b64: str, public_key_pem: str) -> bool:
    """
    Verify an RSA-PSS signature using the owner's public key.
    Returns True if valid, False otherwise.
    """
    try:
        rsa_key = RSA.import_key(public_key_pem)
        h = SHA256.new(bytes.fromhex(data_hash_hex))
        sig_bytes = base64.b64decode(signature_b64)
        pss.new(rsa_key).verify(h, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False


# ═══════════════════════════════════════════════════════════════════
# HMAC-SHA256 — Tamper-Proof Audit Logs
# ═══════════════════════════════════════════════════════════════════

def compute_hmac(message: str, secret_key: str) -> str:
    """
    Compute HMAC-SHA256 for an audit log entry.
    If someone modifies the log in the database, the HMAC won't match.
    """
    return hmac.new(
        secret_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(message: str, expected_hmac: str, secret_key: str) -> bool:
    """Verify HMAC-SHA256 for an audit log entry."""
    computed = compute_hmac(message, secret_key)
    return hmac.compare_digest(computed, expected_hmac)


# ═══════════════════════════════════════════════════════════════════
# TOTP (RFC 6238) — Two-Factor Authentication
# ═══════════════════════════════════════════════════════════════════

def generate_totp_secret() -> str:
    """Generate a random 20-byte base32-encoded TOTP secret."""
    return base64.b32encode(os.urandom(20)).decode("utf-8").rstrip("=")


def get_totp_uri(secret: str, username: str, issuer: str = "SecureFileShare") -> str:
    """
    Generate otpauth:// URI for QR code generation.
    Compatible with Google Authenticator, Authy, etc.
    """
    # Pad secret to multiple of 8 for base32
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    return f"otpauth://totp/{issuer}:{username}?secret={padded}&issuer={issuer}&digits=6&period=30"


def generate_totp_code(secret: str, time_step: int = 30) -> str:
    """
    Generate current 6-digit TOTP code from secret.
    Uses HMAC-SHA1 as per RFC 6238.
    """
    # Pad secret for base32 decoding
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)

    # Time counter
    counter = int(time.time()) // time_step
    counter_bytes = struct.pack(">Q", counter)

    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
    code = (code & 0x7FFFFFFF) % 1000000

    return f"{code:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a TOTP code. Allows ±window time steps (default ±30 seconds).
    """
    for offset in range(-window, window + 1):
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded, casefold=True)
        counter = (int(time.time()) // 30) + offset
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        o = hmac_hash[-1] & 0x0F
        c = struct.unpack(">I", hmac_hash[o : o + 4])[0]
        c = (c & 0x7FFFFFFF) % 1000000
        if f"{c:06d}" == code:
            return True
    return False


# ═══════════════════════════════════════════════════════════════════
# Password Strength — Entropy Estimation
# ═══════════════════════════════════════════════════════════════════

def check_password_strength(password: str) -> dict:
    """
    Estimate password strength using character-class entropy.
    Returns dict with score (0-4), label, entropy bits, and feedback.
    """
    charset_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    if charset_size == 0:
        charset_size = 1

    entropy = len(password) * math.log2(charset_size)

    if entropy < 28:
        score, label = 0, "Very Weak"
    elif entropy < 36:
        score, label = 1, "Weak"
    elif entropy < 50:
        score, label = 2, "Fair"
    elif entropy < 65:
        score, label = 3, "Strong"
    else:
        score, label = 4, "Very Strong"

    feedback = []
    if len(password) < 8:
        feedback.append("Use at least 8 characters")
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters (!@#$...)")

    return {
        "score": score,
        "label": label,
        "entropy": round(entropy, 1),
        "feedback": feedback,
    }
