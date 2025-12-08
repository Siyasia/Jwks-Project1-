# app/crypto_utils.py
from __future__ import annotations

import hashlib
import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_aes_key() -> bytes:
    """
    Derive a 256-bit AES key from the NOT_MY_KEY env var using SHA-256.
    """
    secret = os.environ.get("NOT_MY_KEY")
    if not secret:
        raise RuntimeError("Environment variable NOT_MY_KEY is not set")
    return hashlib.sha256(secret.encode("utf-8")).digest()  # 32-byte key


def encrypt_private_key(plaintext: str) -> Tuple[bytes, bytes]:
    """
    Encrypt the private key JSON string using AES-GCM.

    Returns (iv, ciphertext).
    """
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit IV/nonce
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return iv, ciphertext


def decrypt_private_key(iv: bytes, ciphertext: bytes) -> str:
    """
    Decrypt the AES-GCM ciphertext back into the private key JSON string.
    """
    key = _get_aes_key()
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")
