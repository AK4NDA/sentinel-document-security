"""Content addressed encrypted blob storage under UPLOAD_DIR (spec 0001)."""

import asyncio
import hashlib
import os
from pathlib import Path

from app.core.config import get_settings
from app.security import encryption


def blob_path_for(plaintext_sha256: str) -> Path:
    return get_settings().upload_dir / plaintext_sha256[:2] / f"{plaintext_sha256}.enc"


def _digest(plaintext: bytes) -> str:
    return hashlib.sha256(plaintext).hexdigest()


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _claim_existing(path: Path) -> bool:
    """Refresh mtime on an existing blob so retention sees it as in use."""
    try:
        os.utime(path, None)
    except OSError:
        return False
    return True


async def store(plaintext: bytes) -> tuple[str, str]:
    """Encrypt and persist; returns (relative blob_path, plaintext sha256)."""
    digest = await asyncio.to_thread(_digest, plaintext)
    path = blob_path_for(digest)
    if await asyncio.to_thread(_claim_existing, path):
        relative = path.relative_to(get_settings().upload_dir).as_posix()
        return relative, digest
    path.parent.mkdir(parents=True, exist_ok=True)
    ciphertext = await asyncio.to_thread(encryption.seal, plaintext)
    await asyncio.to_thread(_write_atomic, path, ciphertext)
    relative = path.relative_to(get_settings().upload_dir).as_posix()
    return relative, digest


async def load(relative_path: str) -> bytes:
    """Read and decrypt a blob, returning plaintext."""
    path = get_settings().upload_dir / relative_path
    ciphertext = await asyncio.to_thread(path.read_bytes)
    return await asyncio.to_thread(encryption.open_blob, ciphertext)
