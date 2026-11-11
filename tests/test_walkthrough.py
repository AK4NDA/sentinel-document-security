"""Tests for scripts/walkthrough.py demo tour logic (spec 0011 AC-7 to AC-11)."""

from urllib.parse import urlparse

import httpx
import pytest
from docx import Document as DocxDocument

import scripts.walkthrough as wt
from scripts.walkthrough import Fixtures, StepFailed, Walkthrough, _is_local, main


def _response(status: int, payload=None, content: bytes = b"") -> httpx.Response:
    if payload is not None:
        return httpx.Response(status, json=payload)
    return httpx.Response(status, content=content)


class FakeClient:
    """Stands in for httpx.Client; routes requests through a handler."""

    def __init__(self, handler):
        self.handler = handler
        self.closed = False

    def request(self, method, url, **kwargs):
        return self.handler(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def close(self):
        self.closed = True


def _install_clients(monkeypatch, handlers: dict[str, object]):
    """Patch httpx.Client so each login() gets the FakeClient for its persona."""
    clients = {name: FakeClient(handler) for name, handler in handlers.items()}
    queue = iter(clients.values())
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: next(queue))
    return clients


def _path(url: str) -> str:
    return urlparse(url).path


# --- fixtures ------------------------------------------------------------


def test_fixtures_docx_contains_search_token():
    fixtures = Fixtures()
    try:
        raw = fixtures.docx_bytes(fixtures.secret_token)
        doc = DocxDocument(__import__("io").BytesIO(raw))
        text = "\n".join(p.text for p in doc.paragraphs)
        assert fixtures.secret_token in text
    finally:
        fixtures.cleanup()


def test_fixtures_txt_contains_token_and_cleanup_removes_dir():
    fixtures = Fixtures()
    root = fixtures.root
    assert root.exists()
    assert fixtures.top_secret_token.encode() in fixtures.txt_bytes(fixtures.top_secret_token)
    fixtures.cleanup()
    assert not root.exists()


# --- remote guard and base url resolution ---------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://[::1]:8000", True),
        ("http://example.com", False),
        ("http://192.168.1.10:8000", False),
    ],
)
def test_is_local(url, expected):
    assert _is_local(url) is expected


def test_main_refuses_remote_without_flag(capsys):
    assert main(["--base-url", "http://example.com"]) == 2
    assert "--allow-remote" in capsys.readouterr().err


def test_main_allow_remote_reaches_walkthrough(monkeypatch):
    seen = {}

    class FakeWalkthrough:
        def __init__(self, base_url):
            seen["base_url"] = base_url

        def run(self):
            return 0

    monkeypatch.setattr(wt, "Walkthrough", FakeWalkthrough)
    assert main(["--base-url", "http://example.com", "--allow-remote"]) == 0
    assert seen["base_url"] == "http://example.com"


def test_main_base_url_env_fallback(monkeypatch):
    seen = {}

    class FakeWalkthrough:
        def __init__(self, base_url):
            seen["base_url"] = base_url

        def run(self):
            return 0

    monkeypatch.setattr(wt, "Walkthrough", FakeWalkthrough)
    monkeypatch.setenv("WALKTHROUGH_BASE_URL", "http://localhost:9000")
    assert main([]) == 0
    assert seen["base_url"] == "http://localhost:9000"


# --- login and failure handling --------------------------------------------


def _login_handler(username: str, login_status: int = 200):
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/auth/login":
            if login_status != 200:
                return _response(login_status)
            return _response(200, {"mfa_required": True, "pending_token": "tok"})
        if path == "/v1/auth/mfa/verify":
            return _response(200, {"username": username})
        if path == "/v1/auth/me":
            return _response(200, {"username": username})
        return _response(404)

    return handler


def _tour(monkeypatch, handlers):
    """A Walkthrough whose wait_ready is skipped and logins use fake clients."""
    monkeypatch.setattr(Walkthrough, "wait_ready", lambda self: None)
    _install_clients(monkeypatch, handlers)
    return Walkthrough("http://localhost:8000")


def test_run_fails_fast_naming_the_step(monkeypatch, capsys):
    cast = [
        "demo-admin",
        "demo-auditor",
        "demo-officer-low",
        "demo-officer-mid",
        "demo-officer-high",
    ]

    def admin_handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/users":
            return _response(500, {"detail": "boom"})
        return _login_handler("demo-admin")(method, url, **kwargs)

    handlers = {name: _login_handler(name) for name in cast}
    handlers["demo-admin"] = admin_handler
    tour = _tour(monkeypatch, handlers)

    assert tour.run() == 1
    out = capsys.readouterr().out
    assert "== admin surfaces" in out
    assert "FAIL" in out
    assert "GET /users" in out


def test_run_prints_rate_limit_hint_on_429(monkeypatch, capsys):
    handlers = {
        name: _login_handler(name, login_status=429)
        for name in (
            "demo-admin",
            "demo-auditor",
            "demo-officer-low",
            "demo-officer-mid",
            "demo-officer-high",
        )
    }
    tour = _tour(monkeypatch, handlers)

    assert tour.run() == 1
    out = capsys.readouterr().out
    assert "RATE_LIMIT_ENABLED=false" in out


def test_login_rejects_missing_mfa_challenge(monkeypatch):
    tour = Walkthrough("http://localhost:8000")
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kwargs: FakeClient(
            lambda method, url, **kw: _response(200, {"username": "demo-admin"})
        ),
    )
    from app.demo_constants import DEMO_ADMIN

    with pytest.raises(StepFailed):
        tour.login(DEMO_ADMIN)


# --- step assertions --------------------------------------------------------


def _tour_with(who: str, handler) -> Walkthrough:
    tour = Walkthrough("http://localhost:8000")
    tour.clients[who] = FakeClient(handler)
    return tour


def test_audit_step_passes_when_chain_valid():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/audit/entries":
            return _response(200, {"entries": [{"outcome": "allowed"}, {"outcome": "denied"}]})
        if path == "/v1/audit/verify":
            return _response(200, {"valid": True})
        return _response(404)

    _tour_with("demo-auditor", handler).step_audit_entries_and_verify()


def test_audit_step_fails_when_chain_invalid():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/audit/entries":
            return _response(200, {"entries": [{"outcome": "allowed"}, {"outcome": "denied"}]})
        if path == "/v1/audit/verify":
            return _response(200, {"valid": False})
        return _response(404)

    with pytest.raises(StepFailed):
        _tour_with("demo-auditor", handler).step_audit_entries_and_verify()


def test_search_step_fails_when_secret_doc_leaks():
    def handler(method, url, **kwargs):
        return _response(
            200,
            {
                "documents": [{"id": "doc-secret", "title": "leak"}],
                "total": 1,
            },
        )

    tour = _tour_with("demo-officer-low", handler)
    tour.doc_secret = "doc-secret"
    with pytest.raises(StepFailed):
        tour.step_low_search_does_not_leak()


def test_search_step_passes_when_nothing_leaks():
    def handler(method, url, **kwargs):
        return _response(200, {"documents": [], "total": 0})

    tour = _tour_with("demo-officer-low", handler)
    tour.doc_secret = "doc-secret"
    tour.step_low_search_does_not_leak()


def test_alert_step_fails_without_denied_access_alert():
    def handler(method, url, **kwargs):
        path = _path(url)
        if path == "/v1/alerts":
            return _response(200, {"items": []})
        return _response(404)

    with pytest.raises(StepFailed):
        _tour_with("demo-auditor", handler).step_auditor_lists_and_acks_alert()


def test_call_maps_429_to_rate_limited():
    tour = _tour_with("demo-admin", lambda *a, **kw: _response(429))
    with pytest.raises(wt.RateLimited):
        tour.call("demo-admin", "GET", "/documents")
