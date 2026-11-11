"""Guided demo tour against a live API (spec 0011 AC-7 to AC-11).

Run from the repo root:

    uv run python -m scripts.walkthrough [--base-url URL] [--allow-remote]

Logs in as every seeded demo user (password plus TOTP), drives the document
lifecycle across classifications including deny paths, shares, alerts, and
ends with audit chain verification. Stops at the first failed step.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pyotp
from docx import Document as DocxDocument

from app.demo_constants import (
    DEMO_ADMIN,
    DEMO_AUDITOR,
    DEMO_OFFICER_HIGH,
    DEMO_OFFICER_LOW,
    DEMO_OFFICER_MID,
    DemoUser,
)
from app.models.enums import ClassificationLevel

API = "/v1"
DEFAULT_BASE_URL = "http://localhost:8000"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
READY_TIMEOUT_SECONDS = 60
RUN = uuid.uuid4().hex[:8].upper()


class StepFailed(Exception):
    """A walkthrough step saw something other than what it expected."""


class RateLimited(StepFailed):
    """The API answered 429; the auth bucket is per client IP."""


@dataclass
class Fixtures:
    """Runtime generated upload files; removed when the tour ends."""

    directory: tempfile.TemporaryDirectory = field(
        default_factory=lambda: tempfile.TemporaryDirectory(prefix="demo-walkthrough-")
    )
    secret_token: str = f"ZXQ{RUN}"
    top_secret_token: str = f"ZTR{RUN}"

    @property
    def root(self) -> Path:
        return Path(self.directory.name)

    def docx_bytes(self, token: str) -> bytes:
        doc = DocxDocument()
        doc.add_paragraph(f"Demo document body. Search token {token} marked eyes only.")
        buffer = BytesIO()
        doc.save(buffer)
        return buffer.getvalue()

    def txt_bytes(self, token: str) -> bytes:
        return (
            f"Demo walkthrough file for run {RUN}.\n"
            f"Search token {token} appears here for the tour.\n"
        ).encode()

    def cleanup(self) -> None:
        self.directory.cleanup()


class Walkthrough:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.clients: dict[str, httpx.Client] = {}
        self.profiles: dict[str, dict] = {}
        self.doc_secret = ""
        self.doc_top_secret = ""
        self.doc_disposable = ""
        self.fixtures = Fixtures()

    # --- transport -----------------------------------------------------

    def call(
        self,
        who: str,
        method: str,
        path: str,
        *,
        expect: tuple[int, ...] = (200,),
        **kwargs,
    ) -> httpx.Response:
        resp = self.clients[who].request(method, f"{API}{path}", **kwargs)
        if resp.status_code == 429:
            raise RateLimited(
                f"{method} {path} returned 429; the demo shares one auth rate "
                "limit bucket per client IP, rerun with RATE_LIMIT_ENABLED=false"
            )
        if resp.status_code not in expect:
            raise StepFailed(
                f"{method} {path}: expected {expect}, got {resp.status_code}: {resp.text[:300]}"
            )
        return resp

    @staticmethod
    def _check(cond: bool, expected: str, actual: str) -> None:
        if not cond:
            raise StepFailed(f"expected {expected}, got {actual}")

    # --- steps ---------------------------------------------------------

    def login(self, demo: DemoUser) -> None:
        client = httpx.Client(base_url=self.base, timeout=30)
        self.clients[demo.username] = client
        resp = client.post(
            f"{API}/auth/login",
            json={"username": demo.username, "password": demo.password},
        )
        if resp.status_code == 429:
            raise RateLimited(
                f"login for {demo.username} returned 429; the demo shares one "
                "auth rate limit bucket per client IP, rerun with "
                "RATE_LIMIT_ENABLED=false"
            )
        self._check(resp.status_code == 200, "200", f"{resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        self._check(
            body.get("mfa_required") is True,
            "mfa_required true",
            str(body)[:200],
        )
        code = pyotp.TOTP(demo.totp_secret).now()
        resp = client.post(
            f"{API}/auth/mfa/verify",
            json={"pending_token": body["pending_token"], "code": code},
        )
        if resp.status_code == 429:
            raise RateLimited(
                f"mfa verify for {demo.username} returned 429; rerun with RATE_LIMIT_ENABLED=false"
            )
        self._check(resp.status_code == 200, "200", f"{resp.status_code}: {resp.text[:200]}")
        me = client.get(f"{API}/auth/me")
        self._check(me.status_code == 200, "200", f"{me.status_code}")
        self.profiles[demo.username] = me.json()
        role = demo.role.value
        clearance = demo.clearance.name
        print(f"   session for {demo.username} ({role}, clearance {clearance})")

    def _upload(self, who: str, filename: str, content: bytes, mime: str, title: str) -> dict:
        resp = self.call(
            who,
            "POST",
            "/documents",
            expect=(201,),
            files={"file": (filename, content, mime)},
            data={"title": title, "description": f"demo walkthrough run {RUN}"},
        )
        return resp.json()

    def step_admin_surfaces(self) -> None:
        me = self.call("demo-admin", "GET", "/auth/me").json()
        self._check(me["username"] == "demo-admin", "demo-admin", me["username"])
        users = self.call("demo-admin", "GET", "/users").json()["users"]
        names = {u["username"] for u in users}
        self._check("demo-officer-low" in names, "officer in user list", str(sorted(names)))

    def step_officer_denied_by_design(self) -> None:
        # admin and auditor roles are hard denied on every document route
        self.call("demo-admin", "GET", "/documents", expect=(403,))
        self.call("demo-auditor", "GET", "/documents", expect=(403,))
        # user administration is admin only
        self.call("demo-auditor", "GET", "/users", expect=(403,))

    def step_mid_uploads_secret_docx(self) -> None:
        meta = self._upload(
            "demo-officer-mid",
            f"secret-{RUN}.docx",
            self.fixtures.docx_bytes(self.fixtures.secret_token),
            DOCX_MIME,
            f"Demo Secret Report {RUN}",
        )
        self.doc_secret = meta["id"]
        self._check(
            meta["classification"] == ClassificationLevel.SECRET.value,
            "Secret classification",
            str(meta["classification"]),
        )

    def step_high_uploads_top_secret_txt(self) -> None:
        meta = self._upload(
            "demo-officer-high",
            f"topsecret-{RUN}.txt",
            self.fixtures.txt_bytes(self.fixtures.top_secret_token),
            "text/plain",
            f"Demo Top Secret Memo {RUN}",
        )
        self.doc_top_secret = meta["id"]
        self._check(
            meta["classification"] == ClassificationLevel.TOP_SECRET.value,
            "Top Secret classification",
            str(meta["classification"]),
        )
        disposable = self._upload(
            "demo-officer-high",
            f"disposable-{RUN}.txt",
            self.fixtures.txt_bytes(f"ZXQDISP{RUN}"),
            "text/plain",
            f"Demo Disposable {RUN}",
        )
        self.doc_disposable = disposable["id"]

    def step_low_denied_read(self) -> None:
        self.call(
            "demo-officer-low",
            "GET",
            f"/documents/{self.doc_secret}",
            expect=(403,),
        )

    def step_low_search_does_not_leak(self) -> None:
        resp = self.call(
            "demo-officer-low", "GET", "/documents/search", params={"q": self.fixtures.secret_token}
        ).json()
        ids = {d["id"] for d in resp["documents"]}
        self._check(self.doc_secret not in ids, "secret doc absent", "secret doc present")
        self._check(resp["total"] == 0, "total 0", f"total {resp['total']}")

    def step_mid_search_finds_docx_text(self) -> None:
        resp = self.call(
            "demo-officer-mid", "GET", "/documents/search", params={"q": self.fixtures.secret_token}
        ).json()
        ids = {d["id"] for d in resp["documents"]}
        self._check(self.doc_secret in ids, "secret doc found via docx text", str(ids))

    def step_high_download_triggers_sensitive_alert(self) -> None:
        resp = self.call("demo-officer-high", "GET", f"/documents/{self.doc_top_secret}/content")
        self._check(
            self.fixtures.top_secret_token.encode() in resp.content,
            "top secret token in content",
            resp.content[:120].decode("utf-8", "replace"),
        )

    def step_mid_edits_new_version(self) -> None:
        self.call(
            "demo-officer-mid",
            "POST",
            f"/documents/{self.doc_secret}/versions",
            expect=(201,),
            files={
                "file": (
                    f"secret-v2-{RUN}.txt",
                    self.fixtures.txt_bytes(self.fixtures.secret_token),
                    "text/plain",
                )
            },
            data={"description": f"version two for run {RUN}"},
        )

    def step_versions_list_download_restore(self) -> None:
        versions = self.call(
            "demo-officer-mid", "GET", f"/documents/{self.doc_secret}/versions"
        ).json()["versions"]
        self._check(len(versions) == 2, "2 versions", str(len(versions)))
        by_num = {v["version_number"]: v for v in versions}
        self._check(by_num[2]["is_current"] is True, "v2 current", str(by_num))
        content = self.call(
            "demo-officer-mid",
            "GET",
            f"/documents/{self.doc_secret}/versions/1/content",
        )
        self._check(len(content.content) > 0, "v1 content bytes", "empty")
        self.call(
            "demo-officer-mid",
            "POST",
            f"/documents/{self.doc_secret}/versions/1/restore",
            expect=(201,),
        )
        # restore appends a new version copying v1 content, so v3 is current
        versions = self.call(
            "demo-officer-mid", "GET", f"/documents/{self.doc_secret}/versions"
        ).json()["versions"]
        self._check(len(versions) == 3, "3 versions after restore", str(len(versions)))
        by_num = {v["version_number"]: v for v in versions}
        self._check(by_num[3]["is_current"] is True, "v3 current after restore", str(by_num))

    def step_share_grant_and_revoke(self) -> None:
        lookup = self.call(
            "demo-officer-mid",
            "GET",
            "/users/lookup",
            params={"username": "demo-officer-low", "limit": 5},
        ).json()["users"]
        self._check(len(lookup) >= 1, "officer-low found", str(lookup))
        low_id = lookup[0]["id"]

        resp = self.call(
            "demo-officer-mid",
            "POST",
            f"/documents/{self.doc_secret}/shares",
            expect=(200, 201),
            json={"user_id": low_id},
        )
        self._check(resp.json()["user_id"] == low_id, "share user id", resp.text[:200])

        mine = self.call("demo-officer-low", "GET", "/shares/mine").json()["documents"]
        self._check(
            any(d["id"] == self.doc_secret for d in mine),
            "shared doc in shares/mine",
            str([d["id"] for d in mine]),
        )
        self.call("demo-officer-low", "GET", f"/documents/{self.doc_secret}", expect=(200,))

        self.call(
            "demo-officer-mid",
            "DELETE",
            f"/documents/{self.doc_secret}/shares/{low_id}",
            expect=(204,),
        )
        self.call(
            "demo-officer-low",
            "GET",
            f"/documents/{self.doc_secret}",
            expect=(403,),
        )

    def step_high_deletes_disposable_doc(self) -> None:
        self.call(
            "demo-officer-high",
            "DELETE",
            f"/documents/{self.doc_disposable}",
            expect=(204,),
        )
        self.call(
            "demo-officer-high",
            "GET",
            f"/documents/{self.doc_disposable}",
            expect=(404,),
        )

    def step_auditor_lists_and_acks_alert(self) -> None:
        alerts = self.call(
            "demo-auditor", "GET", "/alerts", params={"state": "open", "limit": 50}
        ).json()["items"]
        denied = [
            a
            for a in alerts
            if a["alert_type"] == "denied_access" and a["actor_username"] == "demo-officer-low"
        ]
        self._check(len(denied) >= 1, "open denied_access alert", str(alerts)[:300])
        sensitive = [a for a in alerts if a["alert_type"] == "sensitive_read"]
        self._check(len(sensitive) >= 1, "open sensitive_read alert", str(alerts)[:300])
        acked = self.call("demo-auditor", "POST", f"/alerts/{denied[0]['id']}/acknowledge").json()
        self._check(acked["state"] == "acknowledged", "acknowledged", acked["state"])

    def step_audit_entries_and_verify(self) -> None:
        entries = self.call("demo-auditor", "GET", "/audit/entries", params={"limit": 200}).json()[
            "entries"
        ]
        outcomes = {e["outcome"] for e in entries}
        self._check("allowed" in outcomes, "allowed entries", str(outcomes))
        self._check("denied" in outcomes, "denied entries", str(outcomes))
        result = self.call("demo-auditor", "POST", "/audit/verify").json()
        self._check(result["valid"] is True, "chain valid", str(result))

    def steps(self) -> list[tuple[str, object]]:
        return [
            ("logins for all seeded personas", self._login_all),
            ("admin surfaces", self.step_admin_surfaces),
            ("admin and auditor cannot reach documents", self.step_officer_denied_by_design),
            ("officer-mid uploads Secret docx", self.step_mid_uploads_secret_docx),
            (
                "officer-high uploads Top Secret txt plus disposable doc",
                self.step_high_uploads_top_secret_txt,
            ),
            ("officer-low denied read of Secret doc", self.step_low_denied_read),
            ("officer-low search does not leak Secret doc", self.step_low_search_does_not_leak),
            ("officer-mid search finds docx text", self.step_mid_search_finds_docx_text),
            (
                "officer-high downloads Top Secret content",
                self.step_high_download_triggers_sensitive_alert,
            ),
            ("officer-mid edits doc into version two", self.step_mid_edits_new_version),
            ("version list, download, and restore", self.step_versions_list_download_restore),
            ("share grant, grantee read, revoke, denied again", self.step_share_grant_and_revoke),
            ("officer-high deletes disposable doc", self.step_high_deletes_disposable_doc),
            ("auditor lists and acknowledges alerts", self.step_auditor_lists_and_acks_alert),
            (
                "audit entries cover allow and deny; chain verifies",
                self.step_audit_entries_and_verify,
            ),
        ]

    def _login_all(self) -> None:
        cast = (DEMO_ADMIN, DEMO_AUDITOR, DEMO_OFFICER_LOW, DEMO_OFFICER_MID, DEMO_OFFICER_HIGH)
        for demo in cast:
            self.login(demo)

    # --- orchestration -------------------------------------------------

    def wait_ready(self) -> None:
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        last = "no response"
        with httpx.Client(base_url=self.base, timeout=5) as probe:
            while time.monotonic() < deadline:
                try:
                    resp = probe.get("/readyz")
                    if resp.status_code == 200:
                        print(f"api ready at {self.base}")
                        return
                    last = f"{resp.status_code}: {resp.text[:120]}"
                except httpx.HTTPError as exc:
                    last = str(exc)
                time.sleep(1)
        raise StepFailed(f"api not ready within {READY_TIMEOUT_SECONDS}s: {last}")

    def run(self) -> int:
        self.wait_ready()
        try:
            for label, step in self.steps():
                print(f"== {label}")
                try:
                    step()  # type: ignore[operator]
                except RateLimited as exc:
                    print(f"   FAIL: {exc}")
                    print("   hint: set RATE_LIMIT_ENABLED=false for repeated demos")
                    return 1
                except Exception as exc:
                    print(f"   FAIL: {exc}")
                    return 1
                print("   ok")
        finally:
            for client in self.clients.values():
                client.close()
            self.fixtures.cleanup()
        print("walkthrough complete: every step passed")
        return 0


def _is_local(base_url: str) -> bool:
    host = urlparse(base_url).hostname
    return host is not None and host.lower() in LOCAL_HOSTS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts.walkthrough")
    parser.add_argument("--base-url", default=None, help="API base URL")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a non localhost base URL (sends demo passwords over the wire)",
    )
    args = parser.parse_args(argv)

    base_url = args.base_url or os.environ.get("WALKTHROUGH_BASE_URL") or DEFAULT_BASE_URL
    if not _is_local(base_url) and not args.allow_remote:
        print(
            f"refusing to send demo credentials to non localhost host "
            f"{urlparse(base_url).hostname}; pass --allow-remote to override",
            file=sys.stderr,
        )
        return 2

    return Walkthrough(base_url).run()


if __name__ == "__main__":
    sys.exit(main())
