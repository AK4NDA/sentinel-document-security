"""Step body coverage for scripts/walkthrough.py (spec 0011 AC-7, AC-8, AC-10).

The existing test_walkthrough.py covers fixtures, guards, login failure modes,
and three step assertions. This file exercises the remaining step bodies and a
full happy path tour through a scripted in memory API so the step ordering and
branching logic (version counts, share then revoke, alert acknowledge) are
pinned without a live stack.
"""

import pytest
from test_walkthrough import FakeClient, _install_clients, _path, _response, _tour

import scripts.walkthrough as wt
from scripts.walkthrough import StepFailed, Walkthrough

CAST = [
    "demo-admin",
    "demo-auditor",
    "demo-officer-low",
    "demo-officer-mid",
    "demo-officer-high",
]

ADMIN, AUDITOR, LOW, MID, HIGH = CAST


def _fresh_state() -> dict:
    return {
        "secret_id": None,
        "top_secret_id": None,
        "disposable_id": None,
        "versions": {},
        "deleted": set(),
        "shared": False,
        "uploads": {},
    }


def _versions_payload(state: dict, doc_id: str) -> dict:
    nums = state["versions"].get(doc_id, [1])
    current = nums[-1]
    return {"versions": [{"version_number": n, "is_current": n == current} for n in nums]}


def _api_handler(name: str, state: dict):
    """One persona's slice of a tiny stateful fake of the /v1 surface."""

    def handler(method: str, url: str, **kwargs):
        path = _path(url)
        parts = [p for p in path.split("/") if p]
        # parts[0] == "v1"

        if path == "/v1/auth/login":
            return _response(200, {"mfa_required": True, "pending_token": "tok"})
        if path == "/v1/auth/mfa/verify":
            return _response(200, {"username": name})
        if path == "/v1/auth/me":
            return _response(200, {"username": name})

        if path == "/v1/users" and method == "GET":
            if name == AUDITOR:
                return _response(403)
            return _response(
                200,
                {"users": [{"username": u} for u in CAST]},
            )
        if path == "/v1/users/lookup":
            return _response(200, {"users": [{"id": "user-low-uuid"}]})
        if path == "/v1/shares/mine":
            return _response(200, {"documents": [{"id": state["secret_id"]}]})

        if path == "/v1/alerts" and method == "GET":
            return _response(
                200,
                {
                    "items": [
                        {
                            "id": "alert-denied",
                            "alert_type": "denied_access",
                            "actor_username": LOW,
                            "state": "open",
                        },
                        {
                            "id": "alert-sensitive",
                            "alert_type": "sensitive_read",
                            "actor_username": HIGH,
                            "state": "open",
                        },
                    ]
                },
            )
        if (
            len(parts) == 4
            and parts[0] == "v1"
            and parts[1] == "alerts"
            and parts[3] == "acknowledge"
        ):
            return _response(200, {"state": "acknowledged"})

        if path == "/v1/audit/entries":
            return _response(
                200,
                {"entries": [{"outcome": "allowed"}, {"outcome": "denied"}]},
            )
        if path == "/v1/audit/verify":
            return _response(200, {"valid": True})

        if path == "/v1/documents" and method == "GET":
            # admin and auditor are hard denied on every document route
            return _response(403)
        if path == "/v1/documents/search":
            if name == LOW:
                return _response(200, {"documents": [], "total": 0})
            if name == MID:
                return _response(
                    200,
                    {"documents": [{"id": state["secret_id"]}], "total": 1},
                )
            return _response(200, {"documents": [], "total": 0})
        if path == "/v1/documents" and method == "POST":
            count = state["uploads"].get(name, 0) + 1
            state["uploads"][name] = count
            doc_id = f"doc-{name}-{count}"
            if name == MID:
                state["secret_id"] = doc_id
                classification = 4  # SECRET
            elif name == HIGH and count == 1:
                state["top_secret_id"] = doc_id
                classification = 5  # TOP_SECRET
            else:
                state["disposable_id"] = doc_id
                classification = 5
            state["versions"][doc_id] = [1]
            return _response(201, {"id": doc_id, "classification": classification})

        # /v1/documents/{id}...
        if len(parts) >= 3 and parts[0] == "v1" and parts[1] == "documents":
            doc_id = parts[2]
            tail = parts[3:]

            if not tail and method == "GET":
                if doc_id in state["deleted"]:
                    return _response(404)
                if name == LOW and doc_id == state["secret_id"] and not state["shared"]:
                    return _response(403)
                return _response(200, {"id": doc_id})
            if tail == ["content"] and method == "GET":
                body = (
                    f"Demo document body run {wt.RUN}. Search token ZTR{wt.RUN} marked eyes only."
                ).encode()
                return _response(200, content=body)
            if tail == ["versions"] and method == "POST":
                nums = state["versions"][doc_id]
                nums.append(nums[-1] + 1)
                return _response(201, {"id": doc_id, "version_number": nums[-1]})
            if tail == ["versions"] and method == "GET":
                return _response(200, _versions_payload(state, doc_id))
            if len(tail) == 3 and tail[0] == "versions" and tail[2] == "content":
                return _response(200, content=b"version one bytes")
            if len(tail) == 3 and tail[0] == "versions" and tail[2] == "restore":
                nums = state["versions"][doc_id]
                nums.append(nums[-1] + 1)
                return _response(201, {"id": doc_id, "version_number": nums[-1]})
            if tail == ["shares"] and method == "POST":
                state["shared"] = True
                return _response(201, {"user_id": kwargs["json"]["user_id"]})
            if len(tail) == 2 and tail[0] == "shares" and method == "DELETE":
                state["shared"] = False
                return _response(204)
            if not tail and method == "DELETE":
                state["deleted"].add(doc_id)
                return _response(204)

        return _response(404, {"detail": f"unhandled {method} {path}"})

    return handler


def _full_tour(monkeypatch) -> Walkthrough:
    """A Walkthrough wired to the scripted fake API for every persona."""
    monkeypatch.setattr(Walkthrough, "wait_ready", lambda self: None)
    state = _fresh_state()
    handlers = {name: _api_handler(name, state) for name in CAST}
    _install_clients(monkeypatch, handlers)
    return Walkthrough("http://localhost:8000")


# --- full happy path tour ---------------------------------------------------


def test_full_tour_passes_end_to_end(monkeypatch, capsys):
    tour = _full_tour(monkeypatch)
    assert tour.run() == 0
    out = capsys.readouterr().out
    assert "walkthrough complete" in out
    # every labeled step ran
    for label in (
        "logins for all seeded personas",
        "admin surfaces",
        "officer-low denied read of Secret doc",
        "version list, download, and restore",
        "share grant, grantee read, revoke, denied again",
        "auditor lists and acknowledges alerts",
        "audit entries cover allow and deny; chain verifies",
    ):
        assert f"== {label}" in out


def test_full_tour_stops_at_first_failure(monkeypatch, capsys):
    state = _fresh_state()

    def broken_mid(name, state):
        inner = _api_handler(name, state)

        def handler(method, url, **kwargs):
            if _path(url) == "/v1/documents" and method == "POST":
                return _response(415, {"detail": "unsupported media type"})
            return inner(method, url, **kwargs)

        return handler

    monkeypatch.setattr(Walkthrough, "wait_ready", lambda self: None)
    handlers = {}
    for name in CAST:
        handlers[name] = broken_mid(name, state) if name == MID else _api_handler(name, state)
    _install_clients(monkeypatch, handlers)
    tour = Walkthrough("http://localhost:8000")

    assert tour.run() == 1
    out = capsys.readouterr().out
    assert "== officer-mid uploads Secret docx" in out
    assert "FAIL" in out
    # nothing after the failed step ran
    assert "auditor lists and acknowledges alerts" not in out


# --- individual step bodies --------------------------------------------------


def test_admin_surfaces_passes():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/auth/me":
            return _response(200, {"username": "demo-admin"})
        if path == "/v1/users":
            return _response(200, {"users": [{"username": "demo-officer-low"}]})
        return _response(404)

    _tour_with_admin = Walkthrough("http://localhost:8000")
    _tour_with_admin.clients["demo-admin"] = FakeClient(handler)
    _tour_with_admin.step_admin_surfaces()


def test_admin_surfaces_fails_when_officer_missing():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/auth/me":
            return _response(200, {"username": "demo-admin"})
        if path == "/v1/users":
            return _response(200, {"users": [{"username": "someone-else"}]})
        return _response(404)

    tour = Walkthrough("http://localhost:8000")
    tour.clients["demo-admin"] = FakeClient(handler)
    with pytest.raises(StepFailed):
        tour.step_admin_surfaces()


def test_officer_denied_by_design_expects_403s():
    state_calls = []

    def handler(method, url, **kwargs):
        state_calls.append((_path(url), method))
        return _response(403)

    tour = Walkthrough("http://localhost:8000")
    tour.clients["demo-admin"] = FakeClient(handler)
    tour.clients["demo-auditor"] = FakeClient(handler)
    tour.step_officer_denied_by_design()
    assert ("/v1/documents", "GET") in state_calls
    assert ("/v1/users", "GET") in state_calls


def test_mid_upload_sets_secret_doc_and_checks_classification():
    state = _fresh_state()
    handler = _api_handler(MID, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    tour.step_mid_uploads_secret_docx()
    assert tour.doc_secret == state["secret_id"]


def test_mid_upload_fails_on_wrong_classification():
    def handler(method, url, **kwargs):
        return _response(201, {"id": "doc-x", "classification": 1})

    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    with pytest.raises(StepFailed):
        tour.step_mid_uploads_secret_docx()


def test_high_upload_sets_both_doc_ids():
    state = _fresh_state()
    handler = _api_handler(HIGH, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[HIGH] = FakeClient(handler)
    tour.step_high_uploads_top_secret_txt()
    assert tour.doc_top_secret == state["top_secret_id"]
    assert tour.doc_disposable == state["disposable_id"]
    assert tour.doc_top_secret != tour.doc_disposable


def test_low_denied_read_expects_403():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1]
    handler = _api_handler(LOW, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[LOW] = FakeClient(handler)
    tour.doc_secret = "doc-secret"
    tour.step_low_denied_read()  # 403 is the expected outcome, no raise


def test_mid_search_finds_secret_doc():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1]
    handler = _api_handler(MID, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    tour.doc_secret = "doc-secret"
    tour.step_mid_search_finds_docx_text()


def test_mid_search_fails_when_doc_missing():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    handler = _api_handler(MID, state)

    def empty_search(method, url, **kwargs):
        if _path(url) == "/v1/documents/search":
            return _response(200, {"documents": [], "total": 0})
        return handler(method, url, **kwargs)

    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(empty_search)
    tour.doc_secret = "doc-secret"
    with pytest.raises(StepFailed):
        tour.step_mid_search_finds_docx_text()


def test_high_download_checks_token_in_content():
    state = _fresh_state()
    state["top_secret_id"] = "doc-ts"
    handler = _api_handler(HIGH, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[HIGH] = FakeClient(handler)
    tour.doc_top_secret = "doc-ts"
    tour.step_high_download_triggers_sensitive_alert()


def test_high_download_fails_when_token_absent():
    def handler(method, url, **kwargs):
        return _response(200, content=b"no token here")

    tour = Walkthrough("http://localhost:8000")
    tour.clients[HIGH] = FakeClient(handler)
    tour.doc_top_secret = "doc-ts"
    with pytest.raises(StepFailed):
        tour.step_high_download_triggers_sensitive_alert()


def test_versions_step_passes_on_expected_counts():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1, 2]
    handler = _api_handler(MID, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    tour.doc_secret = "doc-secret"
    # pre stage: this step itself performs the restore, so drive it fully
    tour.step_versions_list_download_restore()
    # after restore the fake appended v3
    assert state["versions"]["doc-secret"] == [1, 2, 3]


def test_versions_step_fails_on_wrong_initial_count():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1]  # edit step never ran
    handler = _api_handler(MID, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    tour.doc_secret = "doc-secret"
    with pytest.raises(StepFailed):
        tour.step_versions_list_download_restore()


def test_versions_step_fails_when_v2_not_current():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1, 2]

    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/documents/doc-secret/versions" and method == "GET":
            return _response(
                200,
                {
                    "versions": [
                        {"version_number": 1, "is_current": True},
                        {"version_number": 2, "is_current": False},
                    ]
                },
            )
        return _api_handler(MID, state)(method, url, **kwargs)

    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handler)
    tour.doc_secret = "doc-secret"
    with pytest.raises(StepFailed):
        tour.step_versions_list_download_restore()


def test_share_step_grants_reads_then_revokes():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"
    state["versions"]["doc-secret"] = [1]
    handlers = {
        MID: _api_handler(MID, state),
        LOW: _api_handler(LOW, state),
    }
    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(handlers[MID])
    tour.clients[LOW] = FakeClient(handlers[LOW])
    tour.doc_secret = "doc-secret"
    tour.step_share_grant_and_revoke()
    assert state["shared"] is False  # left revoked


def test_share_step_fails_when_lookup_empty():
    state = _fresh_state()
    state["secret_id"] = "doc-secret"

    def mid_handler(method, url, **kwargs):
        if _path(url) == "/v1/users/lookup":
            return _response(200, {"users": []})
        return _api_handler(MID, state)(method, url, **kwargs)

    tour = Walkthrough("http://localhost:8000")
    tour.clients[MID] = FakeClient(mid_handler)
    tour.doc_secret = "doc-secret"
    with pytest.raises(StepFailed):
        tour.step_share_grant_and_revoke()


def test_delete_step_then_get_404():
    state = _fresh_state()
    state["disposable_id"] = "doc-disp"
    handler = _api_handler(HIGH, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[HIGH] = FakeClient(handler)
    tour.doc_disposable = "doc-disp"
    tour.step_high_deletes_disposable_doc()
    assert "doc-disp" in state["deleted"]


def test_alert_step_passes_and_acknowledges():
    state = _fresh_state()
    handler = _api_handler(AUDITOR, state)
    tour = Walkthrough("http://localhost:8000")
    tour.clients[AUDITOR] = FakeClient(handler)
    tour.step_auditor_lists_and_acks_alert()


def test_alert_step_fails_without_sensitive_read():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/alerts":
            return _response(
                200,
                {
                    "items": [
                        {
                            "id": "alert-denied",
                            "alert_type": "denied_access",
                            "actor_username": LOW,
                            "state": "open",
                        }
                    ]
                },
            )
        return _api_handler(AUDITOR, _fresh_state())(method, url, **kwargs)

    tour = Walkthrough("http://localhost:8000")
    tour.clients[AUDITOR] = FakeClient(handler)
    with pytest.raises(StepFailed):
        tour.step_auditor_lists_and_acks_alert()


def test_alert_step_fails_when_ack_not_acknowledged():
    state = _fresh_state()

    def handler(method, url, **kwargs):
        path = _path(url)
        if path.endswith("/acknowledge"):
            return _response(200, {"state": "open"})
        return _api_handler(AUDITOR, state)(method, url, **kwargs)

    tour = Walkthrough("http://localhost:8000")
    tour.clients[AUDITOR] = FakeClient(handler)
    with pytest.raises(StepFailed):
        tour.step_auditor_lists_and_acks_alert()


# --- orchestration edge: readiness failure ------------------------------------


def test_run_reports_readiness_failure_as_clean_step_failure(monkeypatch, capsys):
    """AC-8/AC-9: a readiness timeout should fail like any other step."""
    tour = _tour(monkeypatch, {})
    monkeypatch.setattr(
        Walkthrough,
        "wait_ready",
        lambda self: (_ for _ in ()).throw(StepFailed("api not ready within 60s")),
    )
    assert tour.run() == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
