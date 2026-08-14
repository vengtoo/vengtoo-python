import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from vengtoo import (
    Action,
    BatchEvalItem,
    BatchEvaluationRequest,
    BatchOptions,
    CreateDelegationRequest,
    EvaluationRequest,
    Resource,
    Subject,
    Vengtoo,
    VengtooError,
    verify_policy_decision_point,
)

ALICE = Subject(id="user-1", type="user")
DOC = Resource(id="doc-1", type="document")


class MockHandler(BaseHTTPRequestHandler):
    response_data: dict = {"decision": True, "context": {"reason": "ok"}}
    status_code = 200
    extra_headers: dict = {}
    call_count = 0
    last_body: dict = {}
    #: optional per-call responder: (call_number, body) -> (status, data, headers)
    responder = None

    def do_POST(self):
        MockHandler.call_count += 1
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        MockHandler.last_body = json.loads(raw) if raw else {}

        status, data, headers = MockHandler.status_code, MockHandler.response_data, MockHandler.extra_headers
        if MockHandler.responder is not None:
            status, data, headers = MockHandler.responder(MockHandler.call_count, MockHandler.last_body)

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_DELETE(self):
        MockHandler.call_count += 1
        status = MockHandler.status_code
        if MockHandler.responder is not None:
            status, _, _ = MockHandler.responder(MockHandler.call_count, {})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    discovery_data: dict = {"policy_decision_point": "http://placeholder"}
    discovery_status = 200

    def do_GET(self):
        MockHandler.call_count += 1
        self.send_response(MockHandler.discovery_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(MockHandler.discovery_data).encode())

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_server():
    MockHandler.call_count = 0
    MockHandler.status_code = 200
    MockHandler.response_data = {"decision": True, "context": {"reason": "ok"}}
    MockHandler.extra_headers = {}
    MockHandler.last_body = {}
    MockHandler.responder = None
    MockHandler.discovery_data = {"policy_decision_point": "http://placeholder"}
    MockHandler.discovery_status = 200

    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# --- core decision flow ---


def test_check_allowed(mock_server):
    client = Vengtoo(api_key="test-key", base_url=mock_server)
    assert client.check(ALICE, "read", DOC) is True


def test_check_denied(mock_server):
    MockHandler.response_data = {"decision": False, "context": {"reason": "no policy"}}
    client = Vengtoo(api_key="test-key", base_url=mock_server)
    assert client.check(ALICE, "delete", DOC) is False


def test_evaluate_full_response(mock_server):
    MockHandler.response_data = {
        "decision": True,
        "context": {"reason": "direct", "policy_id": "pol-1", "access_path": "direct"},
    }
    client = Vengtoo(api_key="test-key", base_url=mock_server)
    resp = client.evaluate(EvaluationRequest(subject=ALICE, resource=DOC, action=Action(name="read")))
    assert resp.decision is True
    assert resp.context.policy_id == "pol-1"
    assert resp.context.access_path == "direct"


def test_sends_headers_and_body(mock_server):
    client = Vengtoo(api_key="my-key", base_url=mock_server)
    client.check(ALICE, "read", DOC)
    body = MockHandler.last_body
    assert body["subject"] == {"id": "user-1", "type": "user"}
    assert body["action"]["name"] == "read"


# --- validation mirrors the API contract (AuthZEN 1.0) ---


def test_validation_required_fields():
    client = Vengtoo(api_key="k", base_url="http://127.0.0.1:1")
    with pytest.raises(ValueError, match="subject.id or subject.external_id"):
        client.evaluate(EvaluationRequest(subject=Subject(type="user"), resource=DOC, action=Action(name="read")))
    with pytest.raises(ValueError, match="subject.type"):
        client.evaluate(EvaluationRequest(subject=Subject(type="", id="u"), resource=DOC, action=Action(name="read")))
    with pytest.raises(ValueError, match="resource.type"):
        client.evaluate(EvaluationRequest(subject=ALICE, resource=Resource(type="", id="d"), action=Action(name="read")))
    with pytest.raises(ValueError, match="action.name"):
        client.evaluate(EvaluationRequest(subject=ALICE, resource=DOC, action=Action(name="")))


def test_type_level_resource_defaults_to_star(mock_server):
    client = Vengtoo(api_key="k", base_url=mock_server)
    client.check(ALICE, "read", Resource(type="document"))
    assert MockHandler.last_body["resource"]["id"] == "*"


# --- errors and retries ---


def test_401_raises(mock_server):
    MockHandler.status_code = 401
    MockHandler.response_data = {"error": "invalid key"}
    client = Vengtoo(api_key="bad", base_url=mock_server)
    with pytest.raises(VengtooError) as ei:
        client.check(ALICE, "read", DOC)
    assert ei.value.status_code == 401
    assert ei.value.is_auth_error


def test_retries_on_500_then_succeeds(mock_server):
    def responder(n, body):
        if n < 3:
            return 500, {"error": "boom"}, {}
        return 200, {"decision": True}, {}

    MockHandler.responder = responder
    client = Vengtoo(api_key="test", base_url=mock_server, max_retries=2)
    assert client.check(ALICE, "read", DOC) is True
    assert MockHandler.call_count == 3


def test_no_retry_on_400(mock_server):
    MockHandler.status_code = 400
    MockHandler.response_data = {"error": "bad request"}
    client = Vengtoo(api_key="test", base_url=mock_server)
    with pytest.raises(VengtooError):
        client.check(ALICE, "read", DOC)
    assert MockHandler.call_count == 1


def test_429_honors_retry_after(mock_server):
    def responder(n, body):
        if n == 1:
            return 429, {"error": "slow down"}, {"Retry-After": "1"}
        return 200, {"decision": True}, {}

    MockHandler.responder = responder
    client = Vengtoo(api_key="test", base_url=mock_server, max_retries=1)
    start = time.monotonic()
    assert client.check(ALICE, "read", DOC) is True
    assert time.monotonic() - start >= 0.9, "Retry-After: 1 not honored"


# --- batch ---


def test_batch_preserves_top_level_defaults_and_normalizes(mock_server):
    MockHandler.response_data = {"evaluations": [{"decision": True}]}
    client = Vengtoo(api_key="k", base_url=mock_server)
    resp = client.evaluate_batch(
        BatchEvaluationRequest(
            subject=ALICE,
            action=Action(name="read"),
            context={"env": "prod"},
            options=BatchOptions(evaluations_semantic="execute_all"),
            evaluations=[BatchEvalItem(resource=Resource(type="document"))],
        )
    )
    assert resp.evaluations[0].decision is True
    body = MockHandler.last_body
    assert body["subject"]["id"] == "user-1", "top-level subject lost"
    assert body["action"]["name"] == "read", "top-level action lost"
    assert body["context"]["env"] == "prod", "top-level context lost"
    assert body["options"]["evaluations_semantic"] == "execute_all", "options lost"
    assert body["evaluations"][0]["resource"]["id"] == "*", "item resource not normalized"


def test_batch_rejects_empty_and_oversized():
    client = Vengtoo(api_key="k", base_url="http://127.0.0.1:1")
    with pytest.raises(ValueError, match="at least one"):
        client.evaluate_batch(BatchEvaluationRequest(evaluations=[]))
    with pytest.raises(ValueError, match="maximum of 50"):
        client.evaluate_batch(
            BatchEvaluationRequest(evaluations=[BatchEvalItem(resource=DOC)] * 51)
        )


# --- HITL approval polling ---


def pending(interval=0):
    return {
        "decision": False,
        "context": {
            "reason_code": "authorization_pending",
            "auth_req_id": "ar_1",
            "interval": interval,
            "expires_in": 60,
        },
    }


def test_approval_approved_after_pending(mock_server):
    def responder(n, body):
        if n == 1:
            return 200, pending(), {}
        return 200, {"decision": True, "context": {"reason_code": "approved_by_human"}}, {}

    MockHandler.responder = responder
    client = Vengtoo(api_key="k", base_url=mock_server)
    seen = {}
    resp = client.evaluate_with_approval(
        EvaluationRequest(subject=ALICE, resource=DOC, action=Action(name="deploy")),
        timeout=10,
        on_pending=lambda rid, exp: seen.update(rid=rid),
    )
    assert resp.decision is True
    assert seen["rid"] == "ar_1"


def test_approval_network_errors_yield_polling_error(mock_server):
    def responder(n, body):
        if n == 1:
            return 200, pending(), {}
        return 500, {"error": "boom"}, {}

    MockHandler.responder = responder
    client = Vengtoo(api_key="k", base_url=mock_server, max_retries=0)
    resp = client.evaluate_with_approval(
        EvaluationRequest(subject=ALICE, resource=DOC, action=Action(name="deploy")),
        timeout=30,
        max_network_errors=1,
    )
    assert resp.decision is False
    assert resp.context.reason_code == "polling_error"


# --- delegations ---


def delegation_responder(revoke_status):
    def responder(n, body):
        if body:  # POST create
            return (
                201,
                {
                    "id": "del-1",
                    "delegate_id": "a",
                    "delegator_id": "b",
                    "description": "task",
                    "scope": ["invoices:read"],
                    "created_at": "2026-01-01T00:00:00Z",
                },
                {},
            )
        return revoke_status, {}, {}  # DELETE revoke

    return responder


def test_delegation_scope_description_roundtrip(mock_server):
    MockHandler.responder = delegation_responder(200)
    client = Vengtoo(api_key="k", base_url=mock_server)
    d = client.create_delegation(
        CreateDelegationRequest(
            delegate_id="a", delegator_id="b", description="task", scope=["invoices:read"]
        )
    )
    assert MockHandler.last_body["scope"] == ["invoices:read"]
    assert MockHandler.last_body["description"] == "task"
    assert d.scope == ["invoices:read"]
    assert d.description == "task"


def test_with_delegation_revoke_failure_surfaces(mock_server):
    MockHandler.responder = delegation_responder(500)
    client = Vengtoo(api_key="k", base_url=mock_server)
    with pytest.raises(VengtooError) as ei:
        with client.with_delegation(CreateDelegationRequest(delegate_id="a", delegator_id="b")):
            pass  # body succeeds — revoke failure must still surface
    assert ei.value.status_code == 500


def test_with_delegation_body_error_chains_revoke_error(mock_server):
    MockHandler.responder = delegation_responder(500)
    client = Vengtoo(api_key="k", base_url=mock_server)
    with pytest.raises(VengtooError) as ei:
        with client.with_delegation(CreateDelegationRequest(delegate_id="a", delegator_id="b")):
            raise RuntimeError("task exploded")
    # Python chains the in-flight body exception onto the revoke error.
    assert isinstance(ei.value.__context__, RuntimeError)
    assert str(ei.value.__context__) == "task exploded"


def test_with_delegation_revokes_on_body_error(mock_server):
    MockHandler.responder = delegation_responder(200)
    client = Vengtoo(api_key="k", base_url=mock_server)
    with pytest.raises(RuntimeError, match="boom"):
        with client.with_delegation(CreateDelegationRequest(delegate_id="a", delegator_id="b")):
            raise RuntimeError("boom")
    assert MockHandler.call_count == 2, "revoke must run despite body error"


# --- FastAPI dependency ---


class FakeURL:
    path = "/documents/abc"


class FakeRequest:
    """Duck-typed starlette Request — the dependency only reads these."""

    path_params = {"id": "doc-abc"}
    url = FakeURL()

    def __init__(self, user=None):
        self.user = user


@pytest.mark.asyncio
async def test_require_allows_and_uses_extractor_subject(mock_server):
    from starlette.exceptions import HTTPException

    client = Vengtoo(api_key="k", base_url=mock_server)
    dep = client.require(
        "document", "read", lambda req: Subject(id=req.user, type="user") if req.user else Subject(type="user")
    )
    # allowed
    await dep(FakeRequest(user="user-9"))
    assert MockHandler.last_body["subject"]["id"] == "user-9"
    # empty identity -> 401
    with pytest.raises(HTTPException) as ei:
        await dep(FakeRequest(user=None))
    assert ei.value.status_code == 401
    await client.async_close()


@pytest.mark.asyncio
async def test_require_deny_403_and_infra_500(mock_server):
    from starlette.exceptions import HTTPException

    MockHandler.response_data = {"decision": False}
    client = Vengtoo(api_key="k", base_url=mock_server)
    dep = client.require("document", "read", lambda req: Subject(id="u", type="user"))
    with pytest.raises(HTTPException) as ei:
        await dep(FakeRequest())
    assert ei.value.status_code == 403
    await client.async_close()

    dead = Vengtoo(api_key="k", base_url="http://127.0.0.1:1", max_retries=0)
    dep500 = dead.require("document", "read", lambda req: Subject(id="u", type="user"))
    with pytest.raises(HTTPException) as ei:
        await dep500(FakeRequest())
    assert ei.value.status_code == 500
    await dead.async_close()


# --- mix-up protection (verify_policy_decision_point) ---


def test_verify_pdp_match(mock_server):
    MockHandler.discovery_data = {"policy_decision_point": mock_server}
    client = Vengtoo(api_key="k", base_url=mock_server)
    assert client.verify_policy_decision_point(mock_server) is True


def test_verify_pdp_mismatch(mock_server):
    MockHandler.discovery_data = {"policy_decision_point": "https://evil.example.com"}
    client = Vengtoo(api_key="k", base_url=mock_server)
    assert client.verify_policy_decision_point(mock_server) is False


def test_verify_pdp_missing_field(mock_server):
    MockHandler.discovery_data = {}
    client = Vengtoo(api_key="k", base_url=mock_server)
    assert client.verify_policy_decision_point(mock_server) is False


def test_verify_pdp_http_error_raises(mock_server):
    MockHandler.discovery_status = 500
    MockHandler.discovery_data = {"error": "boom"}
    client = Vengtoo(api_key="k", base_url=mock_server)
    with pytest.raises(VengtooError) as ei:
        client.verify_policy_decision_point(mock_server)
    assert ei.value.status_code == 500


def test_verify_pdp_connection_error_propagates():
    # Distinct from a clean mismatch: a request failure must not silently
    # look like "the PDP identity didn't match."
    dead = Vengtoo(api_key="k", base_url="http://127.0.0.1:1", max_retries=0)
    with pytest.raises(Exception):
        dead.verify_policy_decision_point("http://127.0.0.1:1")


def test_verify_pdp_standalone_function(mock_server):
    # Standalone module-level function — no Vengtoo client instance needed.
    MockHandler.discovery_data = {"policy_decision_point": mock_server}
    assert verify_policy_decision_point(mock_server, mock_server) is True


@pytest.mark.asyncio
async def test_async_verify_pdp_match(mock_server):
    MockHandler.discovery_data = {"policy_decision_point": mock_server}
    client = Vengtoo(api_key="k", base_url=mock_server)
    assert await client.async_verify_policy_decision_point(mock_server) is True
    await client.async_close()


@pytest.mark.asyncio
async def test_async_verify_pdp_http_error_raises(mock_server):
    MockHandler.discovery_status = 503
    MockHandler.discovery_data = {"error": "unavailable"}
    client = Vengtoo(api_key="k", base_url=mock_server)
    with pytest.raises(VengtooError) as ei:
        await client.async_verify_policy_decision_point(mock_server)
    assert ei.value.status_code == 503
    await client.async_close()
