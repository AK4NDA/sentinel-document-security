"""Access alerts tests (spec 0010)."""

import uuid
from datetime import UTC, datetime, timedelta

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from test_api import (
    audit_rows,
    auth_client,
    denied_rows,
    login,
    make_admin,
    make_user,
    upload_doc,
)
from test_audit import make_auditor

from app.core.config import get_settings
from app.main import app
from app.models import (
    Alert,
    AuditLog,
    ClassificationLevel,
    User,
)
from app.services import audit as audit_service


async def alert_rows(session_factory) -> list[Alert]:
    async with session_factory() as session:
        result = await session.execute(select(Alert).order_by(Alert.audit_seq))
        return list(result.scalars().all())


# AC-1, AC-5, AC-10: denied read raises denied_access alert tied to its audit row
async def test_denied_read_raises_denied_access_alert(client, session_factory):
    await make_user(session_factory, "owner_al", clearance=ClassificationLevel.SECRET)
    await make_user(session_factory, "reader_al", clearance=ClassificationLevel.UNCLASSIFIED)
    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "owner_al")
    uploaded = await upload_doc(owner, title="secret doc")
    await owner.aclose()
    doc_id = uploaded.json()["id"]

    await auth_client(client, "reader_al")
    response = await client.get(f"/v1/documents/{doc_id}/content")
    assert response.status_code == 403

    rows = await audit_rows(session_factory)
    denied = [r for r in rows if r.action == "document.download" and r.outcome == "denied"]
    assert len(denied) == 1

    alerts = await alert_rows(session_factory)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "denied_access"
    assert alert.state == "open"
    assert alert.audit_seq == denied[0].seq
    assert alert.actor_username == "reader_al"
    assert alert.summary["action"] == "document.download"
    assert alert.summary["outcome"] == "denied"
    assert alert.summary["target_id"] == doc_id
    assert alert.summary["reason"] == "clearance"

    raise_rows = [r for r in rows if r.action == "alert.raise"]
    assert len(raise_rows) == 1
    assert raise_rows[0].outcome == "allowed"
    assert raise_rows[0].details["alert_type"] == "denied_access"
    assert raise_rows[0].details["trigger_seq"] == denied[0].seq
    assert raise_rows[0].target_type == "alert"
    assert raise_rows[0].target_id == str(alert.id)
    # alert.raise itself produced no alert (recursion guard)
    assert len(await alert_rows(session_factory)) == 1


# AC-2: Top Secret content reads raise sensitive_read, including via share
async def test_top_secret_reads_raise_sensitive_read(client, session_factory):
    await make_user(session_factory, "ts_owner", clearance=ClassificationLevel.TOP_SECRET)
    await make_user(session_factory, "ts_reader", clearance=ClassificationLevel.TOP_SECRET)
    await make_user(session_factory, "low_reader", clearance=ClassificationLevel.UNCLASSIFIED)

    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "ts_owner")
    uploaded = await upload_doc(owner, title="ts doc", content=b"top secret")
    doc_id = uploaded.json()["id"]
    # edit once so a non current Top Secret version exists to download
    edited = await owner.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("doc.txt", b"newer secret", "text/plain")},
    )
    assert edited.status_code in (200, 201), edited.text
    await owner.aclose()

    await auth_client(client, "ts_reader")
    assert (await client.get(f"/v1/documents/{doc_id}/content")).status_code == 200
    versions = await client.get(f"/v1/documents/{doc_id}/versions")
    assert versions.status_code == 200, versions.text
    old_version = next(v for v in versions.json()["versions"] if not v["is_current"])
    assert (
        await client.get(f"/v1/documents/{doc_id}/versions/{old_version['version_number']}/content")
    ).status_code == 200

    alerts = await alert_rows(session_factory)
    sensitive = [a for a in alerts if a.alert_type == "sensitive_read"]
    assert len(sensitive) == 2
    assert all(a.actor_username == "ts_reader" for a in sensitive)
    seqs = {a.audit_seq for a in sensitive}
    rows = await audit_rows(session_factory)
    actions = {r.seq: r.action for r in rows}
    assert {actions[s] for s in seqs} == {"document.download", "document.version_download"}


async def test_share_granted_top_secret_read_alerts(client, session_factory):
    await make_user(session_factory, "sh_owner", clearance=ClassificationLevel.TOP_SECRET)
    await make_user(session_factory, "sh_grantee", clearance=ClassificationLevel.UNCLASSIFIED)

    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "sh_owner")
    uploaded = await upload_doc(owner, title="shared ts", content=b"shared secret")
    doc_id = uploaded.json()["id"]
    async with session_factory() as session:
        grantee = (
            await session.execute(select(User).where(User.username == "sh_grantee"))
        ).scalar_one()
    grant = await owner.post(f"/v1/documents/{doc_id}/shares", json={"user_id": str(grantee.id)})
    assert grant.status_code in (200, 201), grant.text
    await owner.aclose()

    await auth_client(client, "sh_grantee")
    assert (await client.get(f"/v1/documents/{doc_id}/content")).status_code == 200

    alerts = await alert_rows(session_factory)
    sensitive = [a for a in alerts if a.alert_type == "sensitive_read"]
    assert len(sensitive) == 1
    assert sensitive[0].actor_username == "sh_grantee"
    rows = await audit_rows(session_factory)
    trigger = next(r for r in rows if r.seq == sensitive[0].audit_seq)
    assert trigger.action == "document.download"
    assert trigger.details.get("via_share") is True


async def test_non_top_secret_download_raises_no_alert(client, session_factory):
    await make_user(session_factory, "plain_owner", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "plain_owner")
    uploaded = await upload_doc(client, title="plain", content=b"not that secret")
    assert uploaded.status_code == 201
    doc_id = uploaded.json()["id"]

    assert (await client.get(f"/v1/documents/{doc_id}/content")).status_code == 200
    assert await alert_rows(session_factory) == []


# AC-3: allowed admin mutations raise privilege_change; denials raise denied_access
async def test_privilege_change_and_denied_admin_mutation(client, session_factory):
    await make_admin(session_factory, "admin_al")
    await make_user(session_factory, "target_al")
    await make_user(session_factory, "nosy_al")

    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin, "admin_al")
    async with session_factory() as session:
        target = (
            await session.execute(select(User).where(User.username == "target_al"))
        ).scalar_one()
    patch = await admin.patch(
        f"/v1/users/{target.id}", json={"clearance": ClassificationLevel.SECRET}
    )
    assert patch.status_code == 200, patch.text
    disable = await admin.post(f"/v1/users/{target.id}/disable")
    assert disable.status_code == 204, disable.text
    await admin.aclose()

    alerts = await alert_rows(session_factory)
    privilege = [a for a in alerts if a.alert_type == "privilege_change"]
    assert len(privilege) == 2
    assert {a.actor_username for a in privilege} == {"admin_al"}

    # a user role attempt at the same admin surface is denied_access only
    await auth_client(client, "nosy_al")
    assert (await client.patch(f"/v1/users/{target.id}", json={"clearance": 1})).status_code == 403
    alerts = await alert_rows(session_factory)
    denied = [a for a in alerts if a.alert_type == "denied_access"]
    assert len(denied) == 1
    assert denied[0].actor_username == "nosy_al"
    assert denied[0].summary["reason"] == "role"
    assert len([a for a in alerts if a.alert_type == "privilege_change"]) == 2


# AC-4: failed chain verification raises chain_tamper attributed to the auditor
async def test_failed_verify_raises_chain_tamper(client, session_factory):
    await make_user(session_factory, "officer_ct")
    await make_auditor(session_factory, "aud_ct")
    await auth_client(client, "aud_ct")
    await login(client, "officer_ct", password="wrong password!!")

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        middle = rows[len(rows) // 2]
        middle.details = {"tampered": True}
        await session.commit()

    response = await client.post("/v1/audit/verify")
    assert response.status_code == 200
    assert response.json()["valid"] is False

    alerts = await alert_rows(session_factory)
    tamper = [a for a in alerts if a.alert_type == "chain_tamper"]
    assert len(tamper) == 1
    assert tamper[0].actor_username == "aud_ct"
    rows = await audit_rows(session_factory)
    trigger = next(r for r in rows if r.seq == tamper[0].audit_seq)
    assert trigger.action == "audit.verify"
    assert trigger.details["valid"] is False


# AC-6: hourly cap per actor per type
async def test_hourly_cap_limits_alert_volume(client, session_factory):
    settings = get_settings()
    settings.alert_hourly_cap = 2
    try:
        await make_user(session_factory, "owner_cap", clearance=ClassificationLevel.SECRET)
        await make_user(session_factory, "reader_cap", clearance=ClassificationLevel.UNCLASSIFIED)
        owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(owner, "owner_cap")
        uploaded = await upload_doc(owner, title="cap doc")
        doc_id = uploaded.json()["id"]
        await owner.aclose()

        await auth_client(client, "reader_cap")
        for _ in range(3):
            assert (await client.get(f"/v1/documents/{doc_id}/content")).status_code == 403

        alerts = await alert_rows(session_factory)
        denied_alerts = [a for a in alerts if a.alert_type == "denied_access"]
        assert len(denied_alerts) == 2
        rows = await audit_rows(session_factory)
        denied_entries = [
            r for r in rows if r.action == "document.download" and r.outcome == "denied"
        ]
        assert len(denied_entries) == 3
        raise_entries = [r for r in rows if r.action == "alert.raise"]
        assert len(raise_entries) == 2
    finally:
        settings.alert_hourly_cap = 20


# AC-7, AC-9 read side: list filters, pagination, roles
async def test_list_alerts_filters_and_pagination(client, session_factory):
    await make_user(session_factory, "owner_lp", clearance=ClassificationLevel.SECRET)
    await make_user(session_factory, "reader_lp", clearance=ClassificationLevel.UNCLASSIFIED)
    await make_admin(session_factory, "admin_lp")
    await make_auditor(session_factory, "aud_lp")

    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "owner_lp")
    uploaded = await upload_doc(owner, title="lp doc")
    doc_id = uploaded.json()["id"]
    await owner.aclose()

    await auth_client(client, "reader_lp")
    for _ in range(3):
        await client.get(f"/v1/documents/{doc_id}/content")

    # admin sees the same unscoped set
    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin, "admin_lp")
    listing = await admin.get("/v1/alerts")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert len(body["items"]) == 3
    assert body["next_cursor"] is None
    first = body["items"][0]
    assert set(first.keys()) == {
        "id",
        "alert_type",
        "state",
        "actor_id",
        "actor_username",
        "summary",
        "audit_seq",
        "acknowledged_by_id",
        "acknowledged_by_username",
        "acknowledged_at",
        "created_at",
    }
    seqs = [i["audit_seq"] for i in body["items"]]
    assert seqs == sorted(seqs, reverse=True)

    # filters
    by_type = await admin.get("/v1/alerts", params={"alert_type": "denied_access"})
    assert len(by_type.json()["items"]) == 3
    by_type_miss = await admin.get("/v1/alerts", params={"alert_type": "sensitive_read"})
    assert by_type_miss.json()["items"] == []
    by_actor = await admin.get("/v1/alerts", params={"actor_username": "reader_lp"})
    assert len(by_actor.json()["items"]) == 3
    by_actor_miss = await admin.get("/v1/alerts", params={"actor_username": "admin_lp"})
    assert by_actor_miss.json()["items"] == []
    now = datetime.now(UTC)
    future = await admin.get(
        "/v1/alerts",
        params={"created_after": (now + timedelta(hours=1)).isoformat()},
    )
    assert future.json()["items"] == []
    past = await admin.get(
        "/v1/alerts",
        params={"created_before": (now - timedelta(hours=1)).isoformat()},
    )
    assert past.json()["items"] == []

    # pagination
    page1 = await admin.get("/v1/alerts", params={"limit": 2})
    assert len(page1.json()["items"]) == 2
    cursor = page1.json()["next_cursor"]
    assert cursor == page1.json()["items"][-1]["audit_seq"]
    page2 = await admin.get("/v1/alerts", params={"limit": 2, "cursor": cursor})
    assert len(page2.json()["items"]) == 1
    assert all(i["audit_seq"] < cursor for i in page2.json()["items"])
    assert page2.json()["next_cursor"] is None

    # auditor sees the identical set
    auditor = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(auditor, "aud_lp")
    aud_listing = await auditor.get("/v1/alerts")
    assert aud_listing.json()["items"] == body["items"]

    # invalid filter values rejected
    for params in (
        {"alert_type": "bogus"},
        {"state": "bogus"},
        {"created_after": "not-a-date"},
        {"limit": 0},
        {"limit": 201},
        {"cursor": 0},
    ):
        response = await admin.get("/v1/alerts", params=params)
        assert response.status_code == 422, (params, response.text)

    await admin.aclose()
    await auditor.aclose()


# AC-8, AC-9: acknowledge flow, self block, roles, 404/409
async def test_acknowledge_flow_and_guards(client, session_factory):
    await make_user(session_factory, "owner_ak", clearance=ClassificationLevel.SECRET)
    await make_user(session_factory, "reader_ak", clearance=ClassificationLevel.UNCLASSIFIED)
    await make_admin(session_factory, "admin_ak")
    await make_user(session_factory, "user_ak")

    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "owner_ak")
    uploaded = await upload_doc(owner, title="ack doc")
    doc_id = uploaded.json()["id"]
    await owner.aclose()

    await auth_client(client, "reader_ak")
    await client.get(f"/v1/documents/{doc_id}/content")

    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin, "admin_ak")
    listing = await admin.get("/v1/alerts")
    alert_id = listing.json()["items"][0]["id"]

    # user role cannot list or acknowledge
    user_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(user_client, "user_ak")
    assert (await user_client.get("/v1/alerts")).status_code == 403
    assert (await user_client.post(f"/v1/alerts/{alert_id}/acknowledge")).status_code == 403
    await user_client.aclose()

    # unauthenticated requests get 401
    anon = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    assert (await anon.get("/v1/alerts")).status_code == 401
    assert (await anon.post(f"/v1/alerts/{alert_id}/acknowledge")).status_code == 401
    await anon.aclose()

    # unknown id -> audited 404
    missing = await admin.post(f"/v1/alerts/{uuid.uuid4()}/acknowledge")
    assert missing.status_code == 404
    denials = await denied_rows(session_factory, "alert.acknowledge")
    assert any(r.details.get("reason") == "not_found" for r in denials)

    # successful acknowledge
    ack = await admin.post(f"/v1/alerts/{alert_id}/acknowledge")
    assert ack.status_code == 200, ack.text
    body = ack.json()
    assert body["state"] == "acknowledged"
    assert body["acknowledged_by_username"] == "admin_ak"
    assert body["acknowledged_at"] is not None
    async with session_factory() as session:
        admin_user = (
            await session.execute(select(User).where(User.username == "admin_ak"))
        ).scalar_one()
    assert body["acknowledged_by_id"] == str(admin_user.id)

    # second acknowledge -> 409
    again = await admin.post(f"/v1/alerts/{alert_id}/acknowledge")
    assert again.status_code == 409

    # alert.acknowledge audit entries exist for allow and the 404 denial
    rows = await audit_rows(session_factory)
    ack_rows = [r for r in rows if r.action == "alert.acknowledge"]
    assert any(r.outcome == "allowed" and r.actor_username == "admin_ak" for r in ack_rows)
    assert any(r.outcome == "denied" for r in ack_rows)
    # acknowledged alert no longer matches the open filter
    open_listing = await admin.get("/v1/alerts", params={"state": "open"})
    assert open_listing.json()["items"] == []
    closed = await admin.get("/v1/alerts", params={"state": "acknowledged"})
    assert len(closed.json()["items"]) == 1

    await admin.aclose()


async def test_self_acknowledge_denied(client, session_factory):
    # an admin who triggers a denied_access alert cannot acknowledge it
    await make_admin(session_factory, "admin_self")
    await make_user(session_factory, "owner_self", clearance=ClassificationLevel.SECRET)
    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "owner_self")
    uploaded = await upload_doc(owner, title="self doc")
    doc_id = uploaded.json()["id"]
    await owner.aclose()

    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin, "admin_self")
    # admin role is denied document surfaces; the denial alerts under admin_self
    assert (await admin.get(f"/v1/documents/{doc_id}/content")).status_code == 403

    listing = await admin.get("/v1/alerts")
    mine = [i for i in listing.json()["items"] if i["actor_username"] == "admin_self"]
    assert len(mine) == 1
    response = await admin.post(f"/v1/alerts/{mine[0]['id']}/acknowledge")
    assert response.status_code == 403

    denials = await denied_rows(session_factory, "alert.acknowledge")
    assert any(r.details.get("reason") == "self_acknowledge" for r in denials)
    alerts = await alert_rows(session_factory)
    assert all(a.state == "open" for a in alerts)
    await admin.aclose()


# AC-9: MFA enrollment gate covers the new routes
async def test_unenrolled_user_gate_denied(client, session_factory):
    await make_user(session_factory, "un_enrolled", enrolled=False)
    await auth_client(client, "un_enrolled")

    assert (await client.get("/v1/alerts")).status_code == 403
    assert (await client.post(f"/v1/alerts/{uuid.uuid4()}/acknowledge")).status_code == 403
    denials = await denied_rows(session_factory)
    gated = {r.action for r in denials if r.details.get("reason") == "mfa_enrollment_required"}
    assert {"alert.list", "alert.acknowledge"} <= gated


# AC-11: alert insert shares the business transaction; rollback leaves nothing
async def test_alert_rolls_back_with_business_transaction(client, session_factory):
    user = await make_user(session_factory, "rb_user")
    async with session_factory() as session:
        await audit_service.append(
            session,
            action="document.read",
            outcome="denied",
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role.value,
            target_type="document",
            target_id=str(uuid.uuid4()),
            details={"reason": "clearance"},
        )
        await session.rollback()

    assert await alert_rows(session_factory) == []
    rows = await audit_rows(session_factory)
    assert not any(r.action == "alert.raise" for r in rows)


# list appends alert.list; acknowledge appends alert.acknowledge (AC-5)
async def test_list_and_acknowledge_are_audited(client, session_factory):
    await make_user(session_factory, "owner_la", clearance=ClassificationLevel.SECRET)
    await make_user(session_factory, "reader_la", clearance=ClassificationLevel.UNCLASSIFIED)
    await make_admin(session_factory, "admin_la")

    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "owner_la")
    uploaded = await upload_doc(owner, title="la doc")
    doc_id = uploaded.json()["id"]
    await owner.aclose()

    await auth_client(client, "reader_la")
    await client.get(f"/v1/documents/{doc_id}/content")

    admin = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin, "admin_la")
    await admin.get("/v1/alerts")
    alert_id = (await admin.get("/v1/alerts")).json()["items"][0]["id"]
    await admin.post(f"/v1/alerts/{alert_id}/acknowledge")
    await admin.aclose()

    rows = await audit_rows(session_factory)
    list_rows = [r for r in rows if r.action == "alert.list" and r.outcome == "allowed"]
    assert len(list_rows) >= 1
    assert all(r.actor_username == "admin_la" for r in list_rows)
    ack_rows = [r for r in rows if r.action == "alert.acknowledge" and r.outcome == "allowed"]
    assert len(ack_rows) == 1
    # alert.* audit entries produced no alerts themselves
    assert len(await alert_rows(session_factory)) == 1


# AC-4 negative: a clean verify raises no chain_tamper alert
async def test_successful_verify_raises_no_chain_tamper(client, session_factory):
    await make_user(session_factory, "officer_cv")
    await make_auditor(session_factory, "aud_cv")
    await auth_client(client, "aud_cv")
    await login(client, "officer_cv")

    response = await client.post("/v1/audit/verify")
    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert await alert_rows(session_factory) == []


# AC-2 gate: a denied download is denied_access only, never sensitive_read
async def test_denied_top_secret_download_raises_denied_access_only(client, session_factory):
    await make_user(session_factory, "tsd_owner", clearance=ClassificationLevel.TOP_SECRET)
    await make_user(session_factory, "tsd_reader", clearance=ClassificationLevel.UNCLASSIFIED)
    owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner, "tsd_owner")
    uploaded = await upload_doc(owner, title="tsd doc", content=b"tsd secret")
    doc_id = uploaded.json()["id"]
    await owner.aclose()

    await auth_client(client, "tsd_reader")
    assert (await client.get(f"/v1/documents/{doc_id}/content")).status_code == 403

    alerts = await alert_rows(session_factory)
    assert [a.alert_type for a in alerts] == ["denied_access"]


# AC-6: the cap counts per actor, so a second actor is not blocked by the first
async def test_hourly_cap_is_per_actor(client, session_factory):
    settings = get_settings()
    settings.alert_hourly_cap = 1
    try:
        await make_user(session_factory, "cap_owner", clearance=ClassificationLevel.SECRET)
        await make_user(session_factory, "cap_reader1", clearance=ClassificationLevel.UNCLASSIFIED)
        await make_user(session_factory, "cap_reader2", clearance=ClassificationLevel.UNCLASSIFIED)
        owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(owner, "cap_owner")
        uploaded = await upload_doc(owner, title="cap doc")
        doc_id = uploaded.json()["id"]
        await owner.aclose()

        for username in ("cap_reader1", "cap_reader2"):
            reader = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
            await auth_client(reader, username)
            assert (await reader.get(f"/v1/documents/{doc_id}/content")).status_code == 403
            await reader.aclose()

        alerts = await alert_rows(session_factory)
        denied_alerts = [a for a in alerts if a.alert_type == "denied_access"]
        assert len(denied_alerts) == 2
        assert {a.actor_username for a in denied_alerts} == {"cap_reader1", "cap_reader2"}
    finally:
        settings.alert_hourly_cap = 20


# AC-6: the cap counts per alert type, so one type cannot starve another
async def test_hourly_cap_is_per_alert_type(client, session_factory):
    settings = get_settings()
    settings.alert_hourly_cap = 1
    try:
        await make_user(session_factory, "captype_owner", clearance=ClassificationLevel.TOP_SECRET)
        await make_user(session_factory, "captype_user", clearance=ClassificationLevel.TOP_SECRET)
        owner = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(owner, "captype_owner")
        uploaded = await upload_doc(owner, title="captype doc", content=b"captype secret")
        doc_id = uploaded.json()["id"]
        await owner.aclose()

        actor = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(actor, "captype_user")
        # denied_access hits the cap of 1 for this actor
        assert (
            await actor.patch(f"/v1/users/{uuid.uuid4()}", json={"clearance": 1})
        ).status_code == 403
        # sensitive_read is a different type and must still alert
        assert (await actor.get(f"/v1/documents/{doc_id}/content")).status_code == 200
        await actor.aclose()

        alerts = await alert_rows(session_factory)
        types = sorted(a.alert_type for a in alerts)
        assert types == ["denied_access", "sensitive_read"]
        assert all(a.actor_username == "captype_user" for a in alerts)
    finally:
        settings.alert_hourly_cap = 20


# classifier negative space: entries that match no trigger raise no alert
async def test_non_qualifying_audit_entries_raise_no_alert(session_factory):
    user = await make_user(session_factory, "nq_user")
    async with session_factory() as session:
        kwargs = {
            "actor_id": user.id,
            "actor_username": user.username,
            "actor_role": user.role.value,
        }
        # version download without a version_number detail cannot resolve a classification
        await audit_service.append(
            session,
            action="document.version_download",
            outcome="allowed",
            target_type="document",
            target_id=str(uuid.uuid4()),
            details={},
            **kwargs,
        )
        # a clean verify result is not tamper
        await audit_service.append(
            session,
            action="audit.verify",
            outcome="allowed",
            details={"valid": True},
            **kwargs,
        )
        # auth surface denials are excluded from denied_access
        await audit_service.append(
            session,
            action="auth.login",
            outcome="denied",
            details={"reason": "bad_password"},
            **kwargs,
        )
        # alert.* actions never recurse
        await audit_service.append(
            session,
            action="alert.list",
            outcome="allowed",
            target_type="alert",
            **kwargs,
        )
        # an allowed non sensitive action is not alertable
        await audit_service.append(
            session,
            action="document.upload",
            outcome="allowed",
            target_type="document",
            target_id=str(uuid.uuid4()),
            **kwargs,
        )
        await session.commit()

    assert await alert_rows(session_factory) == []
    rows = await audit_rows(session_factory)
    assert len(rows) == 5
    assert not any(r.action == "alert.raise" for r in rows)


# AC-10: summary falls back to the full details dict when no reason key exists
async def test_alert_summary_uses_details_when_reason_absent(session_factory):
    user = await make_user(session_factory, "sum_user")
    async with session_factory() as session:
        await audit_service.append(
            session,
            action="document.read",
            outcome="denied",
            actor_id=user.id,
            actor_username=user.username,
            actor_role=user.role.value,
            target_type="document",
            target_id=str(uuid.uuid4()),
            details={"attempts": 3},
        )
        await session.commit()

    alerts = await alert_rows(session_factory)
    assert len(alerts) == 1
    assert alerts[0].summary["details"] == {"attempts": 3}
    assert "reason" not in alerts[0].summary
