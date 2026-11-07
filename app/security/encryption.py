"""AES GCM file encryption with the master key (spec 0001)."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

KEY_ID = "master"
KEY_VERSION = "1"
_NONCE_SIZE = 12


def _key() -> bytes:
    return base64.b64decode(get_settings().master_key.get_secret_value())


def seal(plaintext: bytes) -> bytes:
    """Return nonce || ciphertext+tag."""
    nonce = os.urandom(_NONCE_SIZE)
    return nonce + AESGCM(_key()).encrypt(nonce, plaintext, None)


def open_blob(blob: bytes) -> bytes:
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)
