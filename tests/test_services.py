"""Unit tests for security, audit, session, and document helpers (spec 0003)."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from fastapi import HTTPException

from app.core.config import get_settings
from app.models import ClassificationLevel, User, UserRole
from app.security import encryption, passwords
from app.security import totp as totp_security
from app.services import audit, blob_store, documents, lockout, sessions

# passwords (AC-2, AC-4, AC-16)


def test_password_hash_roundtrip():
    hashed = passwords.hash_password("a correct horse battery")
    assert hashed != "a correct horse battery"
    assert passwords.verify_password(hashed, "a correct horse battery")
    assert not passwords.verify_password(hashed, "wrong password")


# encryption (AC-6)


def test_encryption_seal_open_roundtrip():
    blob = encryption.seal(b"classified bytes")
    assert b"classified bytes" not in blob
    assert encryption.open_blob(blob) == b"classified bytes"


def test_encryption_tampered_blob_fails():
    blob = bytearray(encryption.seal(b"data"))
    blob[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        encryption.open_blob(bytes(blob))


# blob store (AC-6, AC-10)


async def test_blob_store_roundtrip_and_dedup():
    path1, digest1 = await blob_store.store(b"same content")
    path2, digest2 = await blob_store.store(b"same content")
    assert path1 == path2
    assert digest1 == digest2
    assert len(digest1) == 64

    loaded = await blob_store.load(path1)
    assert loaded == b"same content"


# audit canonicalization (AC-14, AC-15)


def test_genesis_prev_hash_is_64_zeros():
    assert audit.GENESIS_PREV_HASH == "0" * 64


def test_canonical_payload_exact_format():
    fields = {
        "occurred_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "actor_id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
        "actor_username": "alice",
        "actor_role": "user",
        "action": "document.upload",
        "outcome": "allowed",
        "target_type": "document",
        "target_id": "abc",
        "details": {"b": 1, "a": [True, None]},
        "prev_hash": "0" * 64,
    }
    payload = audit.canonical_payload(fields)
    assert '"occurred_at":"2026-01-02T03:04:05Z"' in payload
    assert '"actor_id":"12345678-1234-5678-1234-567812345678"' in payload
    assert '"details":{"a":[true,null],"b":1}' in payload
    # sorted keys, compact separators
    assert payload.index('"action"') < payload.index('"outcome"')
    assert ", " not in payload and ": " not in payload


def test_compute_hash_is_stable_and_hex():
    fields = {
        "occurred_at": datetime(2026, 1, 1, tzinfo=UTC),
        "actor_id": None,
        "actor_username": None,
        "actor_role": None,
        "action": "auth.login",
        "outcome": "denied",
        "target_type": "user",
        "target_id": None,
        "details": {"attempted_username": "ghost"},
        "prev_hash": "0" * 64,
    }
    h1 = audit.compute_hash(fields)
    h2 = audit.compute_hash(dict(fields))
    assert h1 == h2
    assert len(h1) == 64
    int(h1, 16)  # valid hex


async def test_audit_append_genesis_and_verify(session_factory):
    async with session_factory() as session:
        entry = await audit.append(
            session,
            action="auth.login",
            outcome="denied",
            details={"attempted_username": "ghost"},
        )
        await session.commit()
        assert entry.prev_hash == "0" * 64
        assert entry.seq is not None

        bad = await audit.verify_chain(session)
        assert bad == []

        entry.action = "document.delete"
        await session.commit()
        bad = await audit.verify_chain(session)
        assert bad == [entry.seq]


# sessions (AC-2, AC-3, AC-18)


def _user(**kwargs) -> User:
    defaults = {
        "username": "u",
        "email": "u@example.com",
        "password_hash": "x",
        "role": UserRole.USER,
        "clearance": ClassificationLevel.UNCLASSIFIED,
        "is_active": True,
    }
    return User(**(defaults | kwargs))


async def test_session_create_and_validate(session_factory):
    user = _user()
    async with session_factory() as session:
        session.add(user)
        await session.commit()

        token, row = await sessions.create(session, user, ip_address="1.2.3.4")
        await session.commit()
        assert len(token) > 20
        assert row.token_hash != token
        assert len(row.token_hash) == 64

        result = await sessions.validate(session, token)
        assert result is not None
        session_row, returned_user = result
        assert returned_user.username == "u"
        assert session_row.ip_address == "1.2.3.4"

        # unknown token rejected
        assert await sessions.validate(session, "bogus-token") is None


async def test_session_sliding_expiry(session_factory):
    user = _user()
    async with session_factory() as session:
        session.add(user)
        await session.commit()
        token, row = await sessions.create(session, user)
        await session.commit()

        original_expiry = row.expires_at
        # push last_seen back beyond the one minute write throttle
        row.last_seen_at = datetime.now(UTC) - timedelta(minutes=2)
        await session.commit()

        await sessions.validate(session, token)
        await session.refresh(row)
        # SQLite returns naive datetimes; normalize before comparing
        assert row.expires_at.replace(tzinfo=UTC) > original_expiry


async def test_session_revoked_and_expired_rejected(session_factory):
    user = _user()
    async with session_factory() as session:
        session.add(user)
        await session.commit()
        token, _row = await sessions.create(session, user)
        await session.commit()

        await sessions.revoke(session, token)
        await session.commit()
        assert await sessions.validate(session, token) is None

    user2 = _user(username="u2", email="u2@example.com")
    async with session_factory() as session:
        session.add(user2)
        await session.commit()
        token2, row2 = await sessions.create(session, user2)
        row2.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
        assert await sessions.validate(session, token2) is None


async def test_inactive_user_session_rejected(session_factory):
    user = _user(is_active=False)
    async with session_factory() as session:
        session.add(user)
        await session.commit()
        # sessions.validate checks user.is_active; login also blocks, but a
        # session created before deactivation must stop working
        user.is_active = True
        token, _ = await sessions.create(session, user)
        await session.commit()
        user.is_active = False
        await session.commit()
        assert await sessions.validate(session, token) is None


# document helpers (AC-7, AC-9, AC-10)


def test_check_upload_size_boundary():
    limit = documents.MAX_UPLOAD_BYTES
    assert documents.check_upload(b"x" * limit, "text/plain") == "text/plain"
    with pytest.raises(HTTPException) as exc:
        documents.check_upload(b"x" * (limit + 1), "text/plain")
    assert exc.value.status_code == 413


def test_check_upload_mime_allowlist_and_normalization():
    assert documents.check_upload(b"x", "Text/Plain; charset=utf-8") == "text/plain"
    with pytest.raises(HTTPException) as exc:
        documents.check_upload(b"x", "application/octet-stream")
    assert exc.value.status_code == 415
    with pytest.raises(HTTPException) as exc:
        documents.check_upload(b"x", None)
    assert exc.value.status_code == 415


def test_download_filename_sanitized():
    name = documents._download_filename("My Secret: Plan/2026?", "text/plain")
    assert name == "My_Secret__Plan_2026.txt"
    assert documents._download_filename("", "application/pdf") == "document.pdf"
    assert documents._download_filename("a" * 200, "image/png").endswith(".png")


# policy (AC-6 through AC-13)


def test_policy_write_classification_pinned_to_clearance():
    from app.services import policy

    user = _user(clearance=ClassificationLevel.SECRET)
    assert policy.write_classification(user) == ClassificationLevel.SECRET
    assert policy.can_read(user, ClassificationLevel.SECRET)
    assert not policy.can_read(user, ClassificationLevel.TOP_SECRET + 1)
    admin = _user(role=UserRole.ADMIN, clearance=ClassificationLevel.TOP_SECRET)
    assert not policy.can_access_documents(admin)
    assert not policy.can_read(admin, 1)


# read_capped upload streaming (AC-7)


def _upload_file(content: bytes, filename="f.txt", content_type="text/plain"):
    from io import BytesIO

    from starlette.datastructures import Headers
    from starlette.datastructures import UploadFile as StarletteUploadFile

    return StarletteUploadFile(
        file=BytesIO(content),
        size=len(content),
        filename=filename,
        headers=Headers({"content-type": content_type}),
    )


async def test_read_capped_under_limit_returns_content():
    payload = b"a" * (2 * 1024 * 1024 + 7)
    file = _upload_file(payload)
    assert await documents.read_capped(file) == payload


async def test_read_capped_empty_file():
    assert await documents.read_capped(_upload_file(b"")) == b""


async def test_read_capped_rejects_past_limit_early():
    limit = documents.MAX_UPLOAD_BYTES
    # one byte over the cap spread across chunks
    file = _upload_file(b"x" * (limit + 1))
    with pytest.raises(HTTPException) as exc:
        await documents.read_capped(file)
    assert exc.value.status_code == 413


# TOTP secret handling and code verification (spec 0004 AC-2, AC-7)


def _code_at(secret: str, offset_steps: int = 0) -> str:
    counter = int(time.time() // 30) + offset_steps
    return pyotp.TOTP(secret).at(for_time=datetime.fromtimestamp(counter * 30, UTC))


def test_totp_generate_secret_is_base32():
    secret = totp_security.generate_secret()
    assert len(secret) >= 16
    assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_totp_secret_seal_open_roundtrip():
    secret = totp_security.generate_secret()
    blob = totp_security.seal_secret(secret)
    assert secret.encode() not in blob
    assert totp_security.open_secret(blob) == secret


def test_totp_provisioning_uri_encodes_username_and_issuer():
    uri = totp_security.provisioning_uri("user@example.com", "JBSWY3DPEHPK3PXP")
    assert uri.startswith("otpauth://totp/")
    assert "user%40example.com" in uri
    assert get_settings().totp_issuer in uri


def test_totp_verify_accepts_current_step():
    secret = totp_security.generate_secret()
    step = totp_security.verify_code(secret, _code_at(secret), None)
    assert step == int(time.time() // 30)


def test_totp_verify_accepts_previous_step_within_skew():
    secret = totp_security.generate_secret()
    expected = int(time.time() // 30) - 1
    assert totp_security.verify_code(secret, _code_at(secret, -1), None) == expected


def test_totp_verify_rejects_step_beyond_skew():
    secret = totp_security.generate_secret()
    assert totp_security.verify_code(secret, _code_at(secret, -2), None) is None
    assert totp_security.verify_code(secret, _code_at(secret, 2), None) is None


def test_totp_verify_rejects_malformed_codes():
    secret = totp_security.generate_secret()
    for bad in ("", "12345", "1234567", "abcdef", "12 456"):
        assert totp_security.verify_code(secret, bad, None) is None


def test_totp_verify_rejects_replayed_step():
    secret = totp_security.generate_secret()
    now_counter = int(time.time() // 30)
    code = _code_at(secret)
    # a stored counter at or above the matched step rejects the code
    assert totp_security.verify_code(secret, code, now_counter) is None
    assert totp_security.verify_code(secret, code, now_counter + 5) is None


# lockout policy (spec 0004 AC-8)


def test_lockout_not_locked_without_timestamp():
    assert not lockout.is_locked(_user())


def test_lockout_locked_while_locked_until_in_future():
    user = _user(locked_until=datetime.now(UTC) + timedelta(minutes=5))
    assert lockout.is_locked(user)
    assert 290 < lockout.retry_after_seconds(user) <= 300


def test_lockout_expired_timestamp_is_not_locked():
    user = _user(locked_until=datetime.now(UTC) - timedelta(seconds=1))
    assert not lockout.is_locked(user)
    assert lockout.retry_after_seconds(user) == 0


def test_lockout_accepts_naive_datetimes():
    user = _user(locked_until=datetime.now(UTC).replace(tzinfo=None) + timedelta(minutes=1))
    assert lockout.is_locked(user)


def test_record_failure_locks_at_max_attempts():
    settings = get_settings()
    user = _user(failed_login_attempts=0)
    now = datetime.now(UTC)
    for _ in range(settings.login_max_attempts - 1):
        lockout.record_failure(user, now=now)
    assert user.failed_login_attempts == settings.login_max_attempts - 1
    assert user.locked_until is None

    lockout.record_failure(user, now=now)
    assert user.failed_login_attempts == settings.login_max_attempts
    assert user.locked_until == now + timedelta(seconds=settings.login_lockout_seconds)


def test_record_success_resets_counter_and_lock():
    user = _user(
        failed_login_attempts=5,
        locked_until=datetime.now(UTC) + timedelta(minutes=10),
    )
    lockout.record_success(user)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


# MFA configuration defaults (spec 0004)


def test_mfa_settings_defaults():
    settings = get_settings()
    assert settings.totp_issuer == "Sentinel"
    assert settings.mfa_challenge_ttl_seconds == 300
    assert settings.totp_skew_steps == 1
    assert settings.login_max_attempts == 5
    assert settings.login_lockout_seconds == 900
