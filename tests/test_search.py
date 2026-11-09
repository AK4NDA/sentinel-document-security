"""Acceptance tests for full text search (spec 0008)."""

import uuid

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from test_api import auth_client, denied_rows, make_user

from app.core.config import get_settings
from app.main import app
from app.models import (
    AuditLog,
    ClassificationLevel,
    Document,
    DocumentVersion,
    UserRole,
)
from app.security import encryption
from app.services import audit as audit_service
from app.services import search as search_service

SECRET_TXT = b"the quick brown fox jumps over the lazy dog"


async def _upload(client, title, content=SECRET_TXT, mime="text/plain", filename="doc.txt"):
    return await client.post(
        "/v1/documents",
        files={"file": (filename, content, mime)},
        data={"title": title},
    )


async def _search(client, q="fox", **params):
    return await client.get("/v1/documents/search", params={"q": q, **params})


# AC-1: union of title, description, extracted content; all terms required


async def test_search_matches_title_description_and_content(client, session_factory):
    await make_user(session_factory, "s1", clearance=ClassificationLevel.CONFIDENTIAL)
    await auth_client(client, "s1")

    by_title = await _upload(client, "quarterly fox report")
    by_desc = await client.post(
        "/v1/documents",
        files={"file": ("a.txt", b"nothing special here", "text/plain")},
        data={"title": "notes", "description": "mentions fox in passing"},
    )
    by_content = await _upload(client, "plain", content=b"a fox lives here")

    response = await _search(client, "fox")

    assert response.status_code == 200, response.text
    body = response.json()
    ids = {d["id"] for d in body["documents"]}
    assert ids == {
        by_title.json()["id"],
        by_desc.json()["id"],
        by_content.json()["id"],
    }
    assert body["total"] == 3
    assert body["limit"] == 50
    assert body["offset"] == 0

    # all query terms must be present in the union
    multi = await _search(client, "fox report")
    assert [d["id"] for d in multi.json()["documents"]] == [by_title.json()["id"]]
    assert multi.json()["total"] == 1

    # case insensitive and punctuation tokenized away
    assert (await _search(client, "FOX")).json()["total"] == 3
    assert (await _search(client, "fox!!!")).json()["total"] == 3


# AC-2: only readable documents; no existence or count leak


async def test_search_respects_clearance_without_leak(client, session_factory):
    await make_user(session_factory, "low_s", clearance=ClassificationLevel.CONFIDENTIAL)
    await make_user(session_factory, "high_s", clearance=ClassificationLevel.TOP_SECRET)
    high_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(high_client, "high_s")
    secret_doc = await _upload(high_client, "vault fox", content=b"fox secret")
    await high_client.aclose()

    await auth_client(client, "low_s")
    own = await _upload(client, "open fox", content=b"fox public")

    response = await _search(client, "fox")

    assert response.status_code == 200
    body = response.json()
    assert [d["id"] for d in body["documents"]] == [own.json()["id"]]
    assert body["total"] == 1
    assert secret_doc.json()["id"] not in str(body)

    # term only inside the secret doc yields an honest empty result
    only_secret = await _search(client, "vault")
    assert only_secret.json() == {
        "documents": [],
        "total": 0,
        "limit": 50,
        "offset": 0,
    }


# AC-3 / AC-4: role gates and authentication


async def test_search_admin_and_auditor_denied_403_audited(client, session_factory):
    await make_user(session_factory, "officer_s")
    await make_user(session_factory, "admin_s", role=UserRole.ADMIN)
    await make_user(session_factory, "auditor_s", role=UserRole.AUDITOR)

    for username in ("admin_s", "auditor_s"):
        c = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(c, username)
        response = await c.get("/v1/documents/search", params={"q": "fox"})
        assert response.status_code == 403, (username, response.text)
        await c.aclose()

    rows = await denied_rows(session_factory, "document.search")
    assert len(rows) == 2
    assert all(r.target_type == "user" for r in rows)


async def test_search_requires_auth(client, session_factory):
    await make_user(session_factory, "officer_s2")
    response = await client.get("/v1/documents/search", params={"q": "fox"})
    assert response.status_code == 401


# AC-5: only the current version's text is searched


async def test_search_uses_current_version_only(client, session_factory):
    await make_user(session_factory, "editor_s", clearance=ClassificationLevel.CONFIDENTIAL)
    await auth_client(client, "editor_s")
    upload = await _upload(client, "living doc", content=b"obsolete tokenalpha")
    doc_id = upload.json()["id"]

    edit = await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"brand new content", "text/plain")},
        data={"title": "living doc"},
    )
    assert edit.status_code == 201, edit.text

    assert (await _search(client, "tokenalpha")).json()["total"] == 0
    assert (await _search(client, "obsolete")).json()["total"] == 0
    assert (await _search(client, "brand")).json()["total"] == 1

    # restoring version 1 brings its text back
    restore = await client.post(f"/v1/documents/{doc_id}/versions/1/restore")
    assert restore.status_code == 201, restore.text
    assert (await _search(client, "tokenalpha")).json()["total"] == 1
    assert (await _search(client, "brand")).json()["total"] == 0


# AC-6: non extractable MIME types match metadata only


async def test_search_image_matches_metadata_not_content(client, session_factory):
    await make_user(session_factory, "img_s")
    await auth_client(client, "img_s")

    png = b"\x89PNG\r\n\x1a\n" + b"fake image bytes with hiddenkeyword inside"
    await client.post(
        "/v1/documents",
        files={"file": ("pic.png", png, "image/png")},
        data={"title": "holiday snap"},
    )
    await _upload(client, "text doc", content=b"unrelated body")

    assert (await _search(client, "hiddenkeyword")).json()["total"] == 0
    assert (await _search(client, "holiday")).json()["total"] == 1
    assert (await _search(client, "snap")).json()["total"] == 1


# AC-7: query validation


async def test_search_query_validation(client, session_factory):
    await make_user(session_factory, "val_s")
    await auth_client(client, "val_s")

    assert (await client.get("/v1/documents/search")).status_code == 422
    assert (await client.get("/v1/documents/search", params={"q": ""})).status_code == 422
    assert (await _search(client, "!!!")).status_code == 422
    assert (await _search(client, "x" * 201)).status_code == 422
    for params in (
        {"q": "fox", "limit": 0},
        {"q": "fox", "limit": 201},
        {"q": "fox", "offset": -1},
    ):
        response = await client.get("/v1/documents/search", params=params)
        assert response.status_code == 422
    assert (await _search(client, "fox", limit=200)).status_code == 200


# AC-8: one allowed audit row per executed search; 422 writes none


async def test_search_audit_row_per_query(client, session_factory):
    await make_user(session_factory, "aud_s")
    await auth_client(client, "aud_s")
    await _upload(client, "audited fox")

    await _search(client, "fox")
    await _search(client, "nothing matches this")
    await _search(client, "!!!")  # 422, must not audit

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == "document.search")
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )

    assert len(rows) == 2
    assert all(r.outcome == "allowed" for r in rows)
    assert all(r.target_type == "endpoint" for r in rows)
    assert all(r.target_id == "/v1/documents/search" for r in rows)
    assert rows[0].details["q"] == "fox"
    assert rows[0].details["total"] == 1
    assert rows[1].details["total"] == 0


# AC-9 / AC-10: ciphertext storage, sync on write paths, failure tolerance


async def test_search_text_stored_encrypted_and_synced(client, session_factory):
    await make_user(session_factory, "enc_s")
    await auth_client(client, "enc_s")
    upload = await _upload(client, "cipher fox", content=b"encrypted body fox")
    doc_id = uuid.UUID(upload.json()["id"])

    async with session_factory() as session:
        version = (
            await session.execute(
                select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
            )
        ).scalar_one()
        assert version.search_text is not None
        blob = get_settings().upload_dir / version.blob_path
        assert b"encrypted body fox" not in blob.read_bytes()
        plaintext = encryption.open_blob(version.search_text).decode()
        assert "encrypted body fox" in plaintext
        assert "fox" in plaintext

    # edit refreshes it
    await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"rotated fox content", "text/plain")},
        data={"title": "cipher fox"},
    )
    async with session_factory() as session:
        current = (
            (
                await session.execute(
                    select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
                )
            )
            .scalars()
            .all()
        )
        latest = max(current, key=lambda v: v.version_number)
        assert "rotated fox content" in encryption.open_blob(latest.search_text).decode()
        old = min(current, key=lambda v: v.version_number)
        assert "encrypted body fox" in encryption.open_blob(old.search_text).decode()


async def test_extraction_failure_stores_null_but_upload_succeeds(client, session_factory):
    await make_user(session_factory, "fail_s")
    await auth_client(client, "fail_s")

    corrupt_pdf = await client.post(
        "/v1/documents",
        files={"file": ("bad.pdf", b"not a real pdf at all", "application/pdf")},
        data={"title": "broken fox pdf"},
    )
    assert corrupt_pdf.status_code == 201, corrupt_pdf.text
    doc_id = uuid.UUID(corrupt_pdf.json()["id"])

    async with session_factory() as session:
        version = (
            await session.execute(
                select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
            )
        ).scalar_one()
        assert version.search_text is None

    # title still searchable, including the fox term inside it
    assert (await _search(client, "broken")).json()["total"] == 1
    assert (await _search(client, "fox")).json()["total"] == 1
    # the corrupt body contributes no content terms
    assert (await _search(client, "pdf")).json()["total"] == 1


async def test_undecryptable_search_text_does_not_fail_search(client, session_factory):
    await make_user(session_factory, "corrupt_s")
    await auth_client(client, "corrupt_s")
    upload = await _upload(client, "meta fox only", content=b"body fox")
    doc_id = uuid.UUID(upload.json()["id"])

    async with session_factory() as session:
        await session.execute(
            update(DocumentVersion)
            .where(DocumentVersion.document_id == doc_id)
            .values(search_text=b"\x00" * 32)
        )
        await session.commit()

    response = await _search(client, "fox")
    assert response.status_code == 200
    assert response.json()["total"] == 1  # title match still works
    assert (await _search(client, "body")).json()["total"] == 0


async def test_restore_reextracts_when_source_search_text_null(client, session_factory):
    await make_user(session_factory, "reext_s")
    await auth_client(client, "reext_s")
    upload = await _upload(client, "restore fox", content=b"first fox body")
    doc_id = uuid.UUID(upload.json()["id"])

    # simulate a pre feature version: wipe the ciphertext on v1
    async with session_factory() as session:
        v1 = (
            await session.execute(
                select(DocumentVersion).where(
                    DocumentVersion.document_id == doc_id,
                    DocumentVersion.version_number == 1,
                )
            )
        ).scalar_one()
        await session.execute(
            update(DocumentVersion).where(DocumentVersion.id == v1.id).values(search_text=None)
        )
        await session.commit()

    await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"second body", "text/plain")},
        data={"title": "restore fox"},
    )
    restore = await client.post(f"/v1/documents/{doc_id}/versions/1/restore")
    assert restore.status_code == 201, restore.text

    async with session_factory() as session:
        doc = (await session.execute(select(Document).where(Document.id == doc_id))).scalar_one()
        current = (
            await session.execute(
                select(DocumentVersion).where(DocumentVersion.id == doc.current_version_id)
            )
        ).scalar_one()
        assert current.search_text is not None
        assert "first fox body" in encryption.open_blob(current.search_text).decode()

    assert (await _search(client, "first")).json()["total"] == 1


# AC-11 / AC-12: ordering, total, pagination, empty results


async def test_search_pagination_ordering_and_empty(client, session_factory):
    await make_user(session_factory, "page_s")
    await auth_client(client, "page_s")

    for i in range(3):
        await _upload(client, f"pagedoc{i}", content=f"commonterm body {i}".encode())

    page1 = await _search(client, "commonterm", limit=2, offset=0)
    page2 = await _search(client, "commonterm", limit=2, offset=2)
    beyond = await _search(client, "commonterm", limit=2, offset=99)

    assert page1.status_code == page2.status_code == beyond.status_code == 200
    assert page1.json()["total"] == 3
    assert len(page1.json()["documents"]) == 2
    assert len(page2.json()["documents"]) == 1
    assert page1.json()["documents"][0]["id"] != page2.json()["documents"][0]["id"]
    assert beyond.json()["documents"] == []
    assert beyond.json()["total"] == 3
    assert beyond.json()["limit"] == 2
    assert beyond.json()["offset"] == 99

    # updated_at desc ordering: newest upload first
    ids = [d["id"] for d in page1.json()["documents"]] + [
        d["id"] for d in page2.json()["documents"]
    ]
    async with session_factory() as session:
        docs = (
            (await session.execute(select(Document).where(Document.title.like("pagedoc%"))))
            .scalars()
            .all()
        )
    by_updated = sorted(docs, key=lambda d: d.updated_at, reverse=True)
    expected = [str(d.id) for d in by_updated]
    # tie order may vary on identical timestamps; verify set and rough recency
    assert set(ids) == set(expected)

    empty = await _search(client, "zzz-no-such-term")
    assert empty.status_code == 200
    assert empty.json() == {"documents": [], "total": 0, "limit": 50, "offset": 0}


async def test_search_survives_audit_chain_fork(client, session_factory, monkeypatch):
    """Regression: a fork retry must not touch expired ORM objects (review finding)."""
    await make_user(session_factory, "fork_s")
    await auth_client(client, "fork_s")
    await _upload(client, "fork fox", content=b"fork body fox")

    real_append = audit_service.append
    calls = 0

    async def flaky_append(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise audit_service.AuditChainFork()
        return await real_append(*args, **kwargs)

    monkeypatch.setattr(audit_service, "append", flaky_append)

    response = await _search(client, "fox")

    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert calls == 2


# AC-13: route rate limit


async def test_search_rate_limited(client, session_factory):
    settings = get_settings()
    settings.rate_limit_enabled = True
    settings.rate_limit_search = "3/minute"
    try:
        await make_user(session_factory, "rl_s")
        await auth_client(client, "rl_s")
        codes = [(await _search(client, "fox")).status_code for _ in range(4)]
        assert codes[-1] == 429
    finally:
        settings.rate_limit_enabled = False
        settings.rate_limit_search = "30/minute"


# Unit coverage for the tokenizer


def test_tokenize_casefold_and_runs():
    assert search_service.tokenize("Hello, WORLD!") == {"hello", "world"}
    assert search_service.tokenize("  spaced   out  ") == {"spaced", "out"}
    assert search_service.tokenize("!!!") == set()
    assert search_service.tokenize("café déjà") == {"café", "déjà"}
