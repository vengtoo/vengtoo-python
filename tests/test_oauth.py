"""OAuth2 Client Credentials tests for the Vengtoo Python SDK."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from authzx import (
    Vengtoo,
    VengtooError,
    VengtooOAuthError,
    Resource,
    Subject,
)


class _State:
    """Mutable state shared between the test and the mock server handler."""

    token_calls: int = 0
    api_calls: int = 0
    # Token endpoint behavior
    token_status: int = 200
    token_body: dict | str = {"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}
    # Per-call token generation (overrides token_body when set)
    token_sequence: list[dict] | None = None
    # API behavior — either a dict (fixed response), or a callable
    # (auth_header: str) -> tuple[int, dict].
    api_responder = None
    # Record the Authorization header seen on the last API call.
    last_api_auth: str = ""
    # Record the last token form body
    last_token_form: dict[str, list[str]] | None = None


def _reset_state() -> None:
    _State.token_calls = 0
    _State.api_calls = 0
    _State.token_status = 200
    _State.token_body = {"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}
    _State.token_sequence = None
    _State.api_responder = None
    _State.last_api_auth = ""
    _State.last_token_form = None


class _OAuthHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: D401
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        if self.path == "/oauth/token":
            _State.token_calls += 1
            _State.last_token_form = parse_qs(raw.decode())
            if _State.token_sequence:
                body = _State.token_sequence[min(_State.token_calls - 1, len(_State.token_sequence) - 1)]
                status = 200
            else:
                body = _State.token_body
                status = _State.token_status
            payload = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # API path
        _State.api_calls += 1
        auth_header = self.headers.get("Authorization", "")
        _State.last_api_auth = auth_header
        responder = _State.api_responder
        if responder is not None:
            status, body = responder(auth_header)
        else:
            status, body = 200, {"decision": True, "context": {"reason": "ok"}}
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def oauth_server():
    _reset_state()
    server = HTTPServer(("127.0.0.1", 0), _OAuthHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    yield {"base_url": base, "token_url": f"{base}/oauth/token"}
    server.shutdown()


def test_oauth_token_exchange_happy_path(oauth_server):
    client = Vengtoo(
        client_id="cid",
        client_secret="azx_cs_secret",
        base_url=oauth_server["base_url"],
        token_url=oauth_server["token_url"],
    )
    allowed = client.check(
        subject=Subject(id="u-1"),
        action="read",
        resource=Resource(id="d-1"),
    )
    assert allowed is True
    assert _State.token_calls == 1
    assert _State.api_calls == 1
    assert _State.last_api_auth == "Bearer tok-1"
    assert _State.last_token_form is not None
    assert _State.last_token_form.get("grant_type") == ["client_credentials"]
    assert _State.last_token_form.get("client_id") == ["cid"]
    assert _State.last_token_form.get("client_secret") == ["azx_cs_secret"]


def test_oauth_invalid_client_clear_error(oauth_server):
    _State.token_status = 401
    _State.token_body = {"error": "invalid_client"}

    client = Vengtoo(
        client_id="cid",
        client_secret="azx_cs_wrong",
        base_url=oauth_server["base_url"],
        token_url=oauth_server["token_url"],
    )
    with pytest.raises(VengtooOAuthError) as exc_info:
        client.check(
            subject=Subject(id="u-1"),
            action="read",
            resource=Resource(id="d-1"),
        )
    assert "check client_id/client_secret" in str(exc_info.value)
    assert exc_info.value.code == "invalid_client"
    assert _State.api_calls == 0, "API should not be called on token exchange failure"


def test_oauth_cached_token_reused(oauth_server):
    client = Vengtoo(
        client_id="cid",
        client_secret="azx_cs_secret",
        base_url=oauth_server["base_url"],
        token_url=oauth_server["token_url"],
    )
    for _ in range(3):
        client.check(
            subject=Subject(id="u-1"),
            action="read",
            resource=Resource(id="d-1"),
        )
    assert _State.token_calls == 1
    assert _State.api_calls == 3


def test_oauth_401_triggers_refresh_and_retry(oauth_server):
    _State.token_sequence = [
        {"access_token": "tok-stale", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": "tok-fresh", "token_type": "Bearer", "expires_in": 3600},
    ]

    def responder(auth_header: str):
        if auth_header == "Bearer tok-stale":
            return 401, {"error": "stale"}
        return 200, {"decision": True, "context": {"reason": "ok"}}

    _State.api_responder = responder

    client = Vengtoo(
        client_id="cid",
        client_secret="azx_cs_secret",
        base_url=oauth_server["base_url"],
        token_url=oauth_server["token_url"],
    )
    allowed = client.check(
        subject=Subject(id="u-1"),
        action="read",
        resource=Resource(id="d-1"),
    )
    assert allowed is True
    assert _State.token_calls == 2, "expected initial + refresh"
    assert _State.api_calls == 2, "expected 401 + retry"


def test_oauth_401_retry_only_once(oauth_server):
    def responder(auth_header: str):
        return 401, {"error": "bad token"}

    _State.api_responder = responder

    client = Vengtoo(
        client_id="cid",
        client_secret="azx_cs_secret",
        base_url=oauth_server["base_url"],
        token_url=oauth_server["token_url"],
    )
    with pytest.raises(VengtooError) as exc_info:
        client.check(
            subject=Subject(id="u-1"),
            action="read",
            resource=Resource(id="d-1"),
        )
    assert exc_info.value.status_code == 401
    # One retry allowed — so 2 API calls total, no infinite loop.
    assert _State.api_calls == 2


def test_oauth_apikey_plus_oauth_is_construction_error():
    with pytest.raises(ValueError) as exc_info:
        Vengtoo(
            api_key="azx_key",
            client_id="cid",
            client_secret="azx_cs_secret",
        )
    assert "either api_key or OAuth" in str(exc_info.value)


def test_oauth_partial_credentials_is_construction_error():
    with pytest.raises(ValueError):
        Vengtoo(client_id="cid")  # missing client_secret
    with pytest.raises(ValueError):
        Vengtoo(client_secret="azx_cs_secret")  # missing client_id
