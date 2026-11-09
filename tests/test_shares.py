"""API acceptance tests for per user document sharing (spec 0009)."""

import uuid
from datetime import UTC, datetime, timedelta

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from test_api import (
    audit_rows,
    auth_client,
    denied_rows,
    edit_doc,
    make_admin,
    make_user,
    upload_doc,
)

from app.main import app
from app.models import ClassificationLevel, Document, DocumentShare, User, UserRole


def new_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def grant_share(owner_client: AsyncClient, doc_id: str, user_id) -> AsyncClient:
    return await owner_client.post(f"/v1/documents/{doc_id}/shares", json={"user_id": str(user_id)})


async def setup_shared_doc(session_factory, owner_name="owner1", grantee_name="grantee1"):
    """Owner at SECRET uploads; returns (owner_user, grantee_user)."""
    owner = await make_user(session_factory, owner_name, clearance=ClassificationLevel.SECRET)
    grantee = await make_user(
        session_factory, grantee_name, clearance=ClassificationLevel.UNCLASSIFIED
    )
    return owner, grantee


# AC-1, AC-2: grant plus share aware reads with via_share audit details


async def test_grant_then_grantee_reads_with_via_share_audit(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory)
    owner_client = new_client()
    await auth_client(owner_client, "owner1")
    upload = await upload_doc(owner_client, content=b"shared secret")
    doc_id = upload.json()["id"]
    assert upload.json()["classification"] == 4

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee1")
    denied = await grantee_client.get(f"/v1/documents/{doc_id}")
    assert denied.status_code == 403

    grant = await grant_share(owner_client, doc_id, grantee.id)
    assert grant.status_code == 201, grant.text
    body = grant.json()
    assert body["user_id"] == str(grantee.id)
    assert body["username"] == "grantee1"
    assert body["access_level"] == "read"
    assert body["granted_by"] == "owner1"
    assert body["revoked_at"] is None and body["revoked_by"] is None
    share_id = body["id"]

    meta = await grantee_client.get(f"/v1/documents/{doc_id}")
    assert meta.status_code == 200, meta.text
    assert meta.json()["title"] == "My Doc"

    content = await grantee_client.get(f"/v1/documents/{doc_id}/content")
    assert content.status_code == 200
    assert content.content == b"shared secret"

    rows = await audit_rows(session_factory)
    grant_rows = [r for r in rows if r.action == "document.share_grant"]
    assert len(grant_rows) == 1
    assert grant_rows[0].outcome == "allowed"
    assert grant_rows[0].target_id == doc_id
    assert grant_rows[0].details["share_id"] == share_id
    assert grant_rows[0].details["grantee_id"] == str(grantee.id)

    for action in ("document.read", "document.download"):
        allowed = [
            r
            for r in rows
            if r.action == action and r.outcome == "allowed" and r.actor_username == "grantee1"
        ]
        assert len(allowed) == 1, action
        assert allowed[0].details["via_share"] is True
        assert allowed[0].details["share_id"] == share_id

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-3: revoke cuts access and is audited


async def test_revoke_blocks_grantee_and_audits(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner2", "grantee2")
    owner_client = new_client()
    await auth_client(owner_client, "owner2")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee2")
    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 200

    revoke = await owner_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")
    assert revoke.status_code == 204, revoke.text

    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 403
    assert (await grantee_client.get(f"/v1/documents/{doc_id}/content")).status_code == 403
    assert (await grantee_client.get(f"/v1/documents/{doc_id}/versions")).status_code == 403

    rows = await audit_rows(session_factory)
    revoke_rows = [r for r in rows if r.action == "document.share_revoke"]
    assert len(revoke_rows) == 1
    assert revoke_rows[0].outcome == "allowed"
    assert revoke_rows[0].details["grantee_id"] == str(grantee.id)
    denied_read = await denied_rows(session_factory, "document.read")
    assert any(r.actor_username == "grantee2" for r in denied_read)

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-4: regrant semantics and idempotent POST


async def test_regrant_preserves_created_at_and_repeat_post_is_noop(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner3", "grantee3")
    owner_client = new_client()
    await auth_client(owner_client, "owner3")
    doc_id = (await upload_doc(owner_client)).json()["id"]

    first = (await grant_share(owner_client, doc_id, grantee.id)).json()
    await owner_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")

    regrant = await grant_share(owner_client, doc_id, grantee.id)
    assert regrant.status_code == 200, regrant.text
    again = regrant.json()
    assert again["id"] == first["id"]
    assert again["created_at"] == first["created_at"]
    assert again["revoked_at"] is None and again["revoked_by"] is None
    assert again["granted_by"] == "owner3"

    repeat = await grant_share(owner_client, doc_id, grantee.id)
    assert repeat.status_code == 200
    assert repeat.json()["id"] == first["id"]

    rows = await audit_rows(session_factory)
    grant_rows = [r for r in rows if r.action == "document.share_grant"]
    assert len(grant_rows) == 2  # create + regrant; the noop POST added none
    revoke_rows = [r for r in rows if r.action == "document.share_revoke"]
    assert len(revoke_rows) == 1

    await owner_client.aclose()


# AC-5, AC-8: owner lists all share rows; non owners get 404


async def test_list_shares_owner_only_with_full_row_shape(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner4", "grantee4")
    await make_user(session_factory, "other4", clearance=ClassificationLevel.TOP_SECRET)
    owner_client = new_client()
    await auth_client(owner_client, "owner4")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    share = (await grant_share(owner_client, doc_id, grantee.id)).json()
    await owner_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")

    listing = await owner_client.get(f"/v1/documents/{doc_id}/shares")
    assert listing.status_code == 200, listing.text
    shares = listing.json()["shares"]
    assert len(shares) == 1
    row = shares[0]
    assert row["id"] == share["id"]
    assert row["username"] == "grantee4"
    assert row["granted_by"] == "owner4"
    assert row["revoked_at"] is not None
    assert row["revoked_by"] == "owner4"

    other_client = new_client()
    await auth_client(other_client, "other4")
    denied = await other_client.get(f"/v1/documents/{doc_id}/shares")
    assert denied.status_code == 404
    share_denied = await denied_rows(session_factory, "document.shares_list")
    assert share_denied[0].details["reason"] == "not_owner_or_missing"

    rows = await audit_rows(session_factory)
    list_rows = [r for r in rows if r.action == "document.shares_list"]
    assert any(r.outcome == "allowed" and r.target_type == "endpoint" for r in list_rows)

    await owner_client.aclose()
    await other_client.aclose()


# AC-6: /v1/shares/mine


async def test_shares_mine_lists_active_shared_documents(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner5", "grantee5")
    owner_client = new_client()
    await auth_client(owner_client, "owner5")
    doc_a = (await upload_doc(owner_client, title="Alpha")).json()["id"]
    doc_b = (await upload_doc(owner_client, title="Beta")).json()["id"]
    await grant_share(owner_client, doc_a, grantee.id)
    await grant_share(owner_client, doc_b, grantee.id)
    await owner_client.delete(f"/v1/documents/{doc_a}/shares/{grantee.id}")

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee5")
    mine = await grantee_client.get("/v1/shares/mine")
    assert mine.status_code == 200, mine.text
    docs = mine.json()["documents"]
    assert [d["id"] for d in docs] == [doc_b]
    row = docs[0]
    assert row["title"] == "Beta"
    assert row["classification"] == 4
    assert row["owner"] == "owner5"
    assert "shared_at" in row

    rows = await audit_rows(session_factory)
    mine_rows = [r for r in rows if r.action == "document.list_shared"]
    assert len(mine_rows) == 1
    assert mine_rows[0].outcome == "allowed"

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-7: grantee reaches every version through the share


async def test_shared_document_versions_fully_readable(client, session_factory):
    await make_user(session_factory, "vowner", clearance=ClassificationLevel.UNCLASSIFIED)
    grantee = await make_user(
        session_factory, "vgrantee", clearance=ClassificationLevel.UNCLASSIFIED
    )
    owner_client = new_client()
    await auth_client(owner_client, "vowner")
    doc_id = (await upload_doc(owner_client, content=b"low version")).json()["id"]

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "vowner"))).scalar_one()
        user.clearance = ClassificationLevel.TOP_SECRET
        await session.commit()
    await edit_doc(owner_client, doc_id, b"high version")

    grantee_client = new_client()
    await auth_client(grantee_client, "vgrantee")
    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 403

    await grant_share(owner_client, doc_id, grantee.id)

    listing = await grantee_client.get(f"/v1/documents/{doc_id}/versions")
    assert listing.status_code == 200, listing.text
    assert [v["version_number"] for v in listing.json()["versions"]] == [2, 1]

    v1 = await grantee_client.get(f"/v1/documents/{doc_id}/versions/1/content")
    assert v1.status_code == 200 and v1.content == b"low version"
    v2 = await grantee_client.get(f"/v1/documents/{doc_id}/versions/2/content")
    assert v2.status_code == 200 and v2.content == b"high version"

    rows = await audit_rows(session_factory)
    for action in ("document.versions_list", "document.version_download"):
        allowed = [
            r
            for r in rows
            if r.action == action and r.outcome == "allowed" and r.actor_username == "vgrantee"
        ]
        assert allowed, action
        assert all(r.details.get("via_share") is True for r in allowed)
        assert all(r.details.get("share_id") for r in allowed)

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-15: a share never permits writes


async def test_share_is_read_only(client, session_factory):
    owner, grantee = await setup_shared_doc(session_factory, "owner7", "grantee7")
    owner_client = new_client()
    await auth_client(owner_client, "owner7")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee7")

    edit = await grantee_client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("evil.txt", b"overwrite", "text/plain")},
    )
    assert edit.status_code == 404
    delete = await grantee_client.delete(f"/v1/documents/{doc_id}")
    assert delete.status_code == 404
    restore = await grantee_client.post(f"/v1/documents/{doc_id}/versions/1/restore")
    assert restore.status_code == 404
    reshare = await grantee_client.post(
        f"/v1/documents/{doc_id}/shares", json={"user_id": str(owner.id)}
    )
    assert reshare.status_code == 404

    for action in ("document.edit", "document.delete", "document.version_restore"):
        denied = await denied_rows(session_factory, action)
        assert any(r.actor_username == "grantee7" for r in denied), action

    # The document is untouched.
    meta = await grantee_client.get(f"/v1/documents/{doc_id}")
    assert meta.status_code == 200
    content = await grantee_client.get(f"/v1/documents/{doc_id}/content")
    assert content.content == b"secret contents"

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-9: grant eligibility denials


async def test_grant_rejects_ineligible_grantees(client, session_factory):
    owner, _ = await setup_shared_doc(session_factory, "owner8", "grantee8")
    disabled = await make_user(session_factory, "disabled8", is_active=False)
    admin = await make_admin(session_factory, "admin8")
    auditor = await make_user(session_factory, "auditor8", role=UserRole.AUDITOR)
    owner_client = new_client()
    await auth_client(owner_client, "owner8")
    doc_id = (await upload_doc(owner_client)).json()["id"]

    cases = [
        (owner.id, 409, "self_share"),
        (disabled.id, 409, "grantee_disabled"),
        (admin.id, 409, "grantee_role"),
        (auditor.id, 409, "grantee_role"),
        (uuid.uuid4(), 404, "user_not_found"),
    ]
    for user_id, code, reason in cases:
        response = await grant_share(owner_client, doc_id, user_id)
        assert response.status_code == code, (reason, response.text)
        denied = await denied_rows(session_factory, "document.share_grant")
        assert denied[-1].details["reason"] == reason

    await owner_client.aclose()


# AC-10: revoking an inactive share is a 404


async def test_revoke_never_shared_or_already_revoked_404(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner9", "grantee9")
    other = await make_user(session_factory, "other9")
    owner_client = new_client()
    await auth_client(owner_client, "owner9")
    doc_id = (await upload_doc(owner_client)).json()["id"]

    missing = await owner_client.delete(f"/v1/documents/{doc_id}/shares/{other.id}")
    assert missing.status_code == 404

    await grant_share(owner_client, doc_id, grantee.id)
    await owner_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")
    again = await owner_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")
    assert again.status_code == 404

    denied = await denied_rows(session_factory, "document.share_revoke")
    assert len(denied) == 2
    assert all(r.details["reason"] == "share_not_active" for r in denied)

    await owner_client.aclose()


# AC-11: shares never leak into search or the owned document list


async def test_shared_doc_stays_out_of_search_and_own_list(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner10", "grantee10")
    owner_client = new_client()
    await auth_client(owner_client, "owner10")
    doc_id = (await upload_doc(owner_client, title="zebra plans", content=b"zebra content")).json()[
        "id"
    ]
    await grant_share(owner_client, doc_id, grantee.id)

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee10")

    search = await grantee_client.get("/v1/documents/search", params={"q": "zebra"})
    assert search.status_code == 200
    assert search.json()["total"] == 0

    listing = await grantee_client.get("/v1/documents")
    assert listing.status_code == 200
    assert listing.json()["documents"] == []

    mine = await grantee_client.get("/v1/shares/mine")
    assert [d["id"] for d in mine.json()["documents"]] == [doc_id]

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-12: role gates on share management; auditor can never hold a share


async def test_share_endpoints_deny_admin_and_auditor(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner11", "grantee11")
    await make_admin(session_factory, "admin11")
    await make_user(session_factory, "auditor11", role=UserRole.AUDITOR)
    owner_client = new_client()
    await auth_client(owner_client, "owner11")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    for name in ("admin11", "auditor11"):
        actor_client = new_client()
        await auth_client(actor_client, name)
        assert (await actor_client.get(f"/v1/documents/{doc_id}/shares")).status_code == 403
        assert (
            await actor_client.post(
                f"/v1/documents/{doc_id}/shares", json={"user_id": str(grantee.id)}
            )
        ).status_code == 403
        assert (
            await actor_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")
        ).status_code == 403
        assert (await actor_client.get("/v1/shares/mine")).status_code == 403
        lookup = await actor_client.get("/v1/users/lookup", params={"username": "ow"})
        assert lookup.status_code == 403
        # Auditors still cannot touch documents at all.
        assert (await actor_client.get(f"/v1/documents/{doc_id}")).status_code == 403
        await actor_client.aclose()

    # Auditor document denial is still audited.
    denied = await denied_rows(session_factory, "document.read")
    assert any(r.actor_username == "auditor11" for r in denied)

    await owner_client.aclose()


# AC-13: user lookup


async def test_user_lookup_prefix_filters_and_audits(client, session_factory):
    await make_user(session_factory, "lookupable1", clearance=ClassificationLevel.SECRET)
    await make_user(session_factory, "lookupable2")
    await make_user(session_factory, "LOOKUPABLE3")
    await make_user(session_factory, "other", clearance=ClassificationLevel.SECRET)
    await make_admin(session_factory, "lookupadmin")
    await make_user(session_factory, "lookupoff", is_active=False)
    await make_user(session_factory, "viewer", role=UserRole.AUDITOR)
    await auth_client(client, "lookupable1")

    response = await client.get("/v1/users/lookup", params={"username": "lookup"})
    assert response.status_code == 200, response.text
    names = [u["username"] for u in response.json()["users"]]
    assert names == ["LOOKUPABLE3", "lookupable1", "lookupable2"]
    assert set(response.json()["users"][0]) == {"id", "username"}

    short = await client.get("/v1/users/lookup", params={"username": "l"})
    assert short.status_code == 422
    missing = await client.get("/v1/users/lookup")
    assert missing.status_code == 422

    rows = await audit_rows(session_factory)
    lookup_rows = [r for r in rows if r.action == "user.lookup"]
    assert len(lookup_rows) == 1
    assert lookup_rows[0].details["username"] == "lookup"
    assert lookup_rows[0].details["limit"] == 20


# AC-14: admin actions never modify shares; account gates still apply


async def test_admin_changes_leave_share_rows_untouched(client, session_factory):
    owner, grantee = await setup_shared_doc(session_factory, "owner12", "grantee12")
    await make_admin(session_factory, "admin12")
    owner_client = new_client()
    await auth_client(owner_client, "owner12")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee12")

    async def share_row_count():
        async with session_factory() as session:
            return len(
                (
                    await session.execute(
                        select(DocumentShare).where(DocumentShare.document_id == uuid.UUID(doc_id))
                    )
                )
                .scalars()
                .all()
            )

    assert await share_row_count() == 1

    admin_client = new_client()
    await auth_client(admin_client, "admin12")

    # Lower the grantee's clearance: the share still admits the read.
    patch = await admin_client.patch(f"/v1/users/{grantee.id}", json={"clearance": 1})
    assert patch.status_code == 200
    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 200

    # Demote the grantee to auditor: the role gate blocks, share row remains.
    patch = await admin_client.patch(f"/v1/users/{grantee.id}", json={"role": "auditor"})
    assert patch.status_code == 200
    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 403
    assert await share_row_count() == 1

    # Restore the role; disable the owner: grantees keep access.
    await admin_client.patch(f"/v1/users/{grantee.id}", json={"role": "user"})
    disable = await admin_client.post(f"/v1/users/{owner.id}/disable")
    assert disable.status_code == 204
    assert (await grantee_client.get(f"/v1/documents/{doc_id}")).status_code == 200

    # A disabled grantee's session stops working entirely.
    await admin_client.post(f"/v1/users/{grantee.id}/disable")
    assert (await grantee_client.get("/v1/auth/me")).status_code == 401

    await owner_client.aclose()
    await grantee_client.aclose()
    await admin_client.aclose()


# AC-1 extra: share grant ignores extra body fields


async def test_grant_ignores_extra_fields(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner13", "grantee13")
    owner_client = new_client()
    await auth_client(owner_client, "owner13")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    response = await owner_client.post(
        f"/v1/documents/{doc_id}/shares",
        json={"user_id": str(grantee.id), "access_level": "admin", "extra": 1},
    )
    assert response.status_code == 201, response.text
    assert response.json()["access_level"] == "read"
    await owner_client.aclose()


# AC-8: non owners get the same non revealing 404 on grant and revoke


async def test_non_owner_cannot_grant_or_revoke(client, session_factory):
    _, grantee = await setup_shared_doc(session_factory, "owner14", "grantee14")
    other = await make_user(session_factory, "other14", clearance=ClassificationLevel.TOP_SECRET)
    owner_client = new_client()
    await auth_client(owner_client, "owner14")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    other_client = new_client()
    await auth_client(other_client, "other14")
    grant = await other_client.post(
        f"/v1/documents/{doc_id}/shares", json={"user_id": str(other.id)}
    )
    assert grant.status_code == 404
    revoke = await other_client.delete(f"/v1/documents/{doc_id}/shares/{grantee.id}")
    assert revoke.status_code == 404

    # The owner gets the same 404 for a document that does not exist.
    missing = await owner_client.post(
        f"/v1/documents/{uuid.uuid4()}/shares", json={"user_id": str(grantee.id)}
    )
    assert missing.status_code == 404

    for action in ("document.share_grant", "document.share_revoke"):
        denied = await denied_rows(session_factory, action)
        assert any(r.actor_username == "other14" for r in denied), action

    await owner_client.aclose()
    await other_client.aclose()


# AC-6: /v1/shares/mine orders newest grant first and skips versionless documents


async def test_shares_mine_orders_newest_first_and_skips_versionless(client, session_factory):
    owner, grantee = await setup_shared_doc(session_factory, "owner15", "grantee15")
    owner_client = new_client()
    await auth_client(owner_client, "owner15")
    doc_a = (await upload_doc(owner_client, title="First")).json()["id"]
    doc_b = (await upload_doc(owner_client, title="Second")).json()["id"]
    await grant_share(owner_client, doc_a, grantee.id)
    await grant_share(owner_client, doc_b, grantee.id)

    async with session_factory() as session:
        shares = (
            (
                await session.execute(
                    select(DocumentShare).where(DocumentShare.user_id == grantee.id)
                )
            )
            .scalars()
            .all()
        )
        by_doc = {s.document_id: s for s in shares}
        base = datetime(2026, 1, 1, tzinfo=UTC)
        by_doc[uuid.UUID(doc_a)].created_at = base
        by_doc[uuid.UUID(doc_b)].created_at = base + timedelta(minutes=1)

        # A versionless document with the newest share must not appear.
        versionless = Document(title="No versions", owner_id=owner.id)
        session.add(versionless)
        await session.flush()
        session.add(
            DocumentShare(
                document_id=versionless.id,
                user_id=grantee.id,
                granted_by=owner.id,
                access_level="read",
                created_at=base + timedelta(minutes=2),
            )
        )
        await session.commit()

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee15")
    mine = await grantee_client.get("/v1/shares/mine")
    assert mine.status_code == 200, mine.text
    docs = mine.json()["documents"]
    assert [d["id"] for d in docs] == [doc_b, doc_a]
    assert all(d["title"] != "No versions" for d in docs)

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-13: lookup honors the limit and treats wildcards literally


async def test_user_lookup_limit_and_wildcard_literals(client, session_factory):
    await make_user(session_factory, "wilduser1")
    await make_user(session_factory, "wild_user2")
    await make_user(session_factory, "wildXuser3")
    await auth_client(client, "wilduser1")

    limited = await client.get("/v1/users/lookup", params={"username": "wild", "limit": 1})
    assert limited.status_code == 200, limited.text
    assert len(limited.json()["users"]) == 1

    over = await client.get("/v1/users/lookup", params={"username": "wild", "limit": 21})
    assert over.status_code == 422

    # Underscore and percent are literal characters, not ILIKE wildcards.
    literal = await client.get("/v1/users/lookup", params={"username": "wild_"})
    assert literal.status_code == 200
    assert [u["username"] for u in literal.json()["users"]] == ["wild_user2"]

    percent = await client.get("/v1/users/lookup", params={"username": "wild%"})
    assert percent.status_code == 200
    assert percent.json()["users"] == []


# AC-2: via_share is flagged only when the share was actually needed


async def test_cleared_grantee_read_has_no_via_share_flag(client, session_factory):
    await make_user(session_factory, "owner16", clearance=ClassificationLevel.SECRET)
    grantee = await make_user(
        session_factory, "grantee16", clearance=ClassificationLevel.TOP_SECRET
    )
    owner_client = new_client()
    await auth_client(owner_client, "owner16")
    doc_id = (await upload_doc(owner_client)).json()["id"]
    await grant_share(owner_client, doc_id, grantee.id)

    grantee_client = new_client()
    await auth_client(grantee_client, "grantee16")
    meta = await grantee_client.get(f"/v1/documents/{doc_id}")
    assert meta.status_code == 200

    rows = await audit_rows(session_factory)
    reads = [
        r
        for r in rows
        if r.action == "document.read"
        and r.outcome == "allowed"
        and r.actor_username == "grantee16"
    ]
    assert reads
    assert all("via_share" not in (r.details or {}) for r in reads)

    await owner_client.aclose()
    await grantee_client.aclose()


# AC-4: a grant that loses the concurrent insert race returns the winner row


async def test_lost_grant_race_returns_winner_row(client, session_factory, monkeypatch):
    owner, grantee = await setup_shared_doc(session_factory, "owner17", "grantee17")
    owner_client = new_client()
    await auth_client(owner_client, "owner17")
    doc_id = (await upload_doc(owner_client)).json()["id"]

    # The winning grant commits first.
    async with session_factory() as session:
        winner = DocumentShare(
            document_id=uuid.UUID(doc_id),
            user_id=grantee.id,
            granted_by=owner.id,
            access_level="read",
        )
        session.add(winner)
        await session.commit()
        winner_id = winner.id

    # Simulate losing the insert race: the pair constraint fires with a
    # SQLite style message that names no constraint.
    async def losing_transact(db, op):
        raise IntegrityError(
            "INSERT INTO document_shares ...",
            {},
            Exception(
                "UNIQUE constraint failed: document_shares.document_id, document_shares.user_id"
            ),
        )

    monkeypatch.setattr("app.services.audit.transact", losing_transact)

    response = await grant_share(owner_client, doc_id, grantee.id)
    assert response.status_code == 200, response.text
    assert response.json()["id"] == str(winner_id)

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(DocumentShare).where(DocumentShare.document_id == uuid.UUID(doc_id))
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1

    await owner_client.aclose()
