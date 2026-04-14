import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

import pytest

from authzx import AuthzX, Subject, Resource, AuthorizeRequest, AuthzXError


class MockHandler(BaseHTTPRequestHandler):
    response_data = {"allowed": True, "reason": "ok"}
    status_code = 200
    call_count = 0

    def do_POST(self):
        MockHandler.call_count += 1
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)

        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.response_data).encode())

    def log_message(self, format, *args):
        pass  # suppress logs


@pytest.fixture
def mock_server():
    MockHandler.call_count = 0
    MockHandler.status_code = 200
    MockHandler.response_data = {"allowed": True, "reason": "ok"}

    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_check_allowed(mock_server):
    MockHandler.response_data = {"allowed": True, "reason": "role_match"}
    client = AuthzX(api_key="test-key", base_url=mock_server)
    allowed = client.check(
        subject=Subject(id="user-1"),
        action="read",
        resource=Resource(id="doc-1"),
    )
    assert allowed is True


def test_check_denied(mock_server):
    MockHandler.response_data = {"allowed": False, "reason": "no policy"}
    client = AuthzX(api_key="test-key", base_url=mock_server)
    allowed = client.check(
        subject=Subject(id="user-1"),
        action="delete",
        resource=Resource(id="doc-1"),
    )
    assert allowed is False


def test_authorize_full_response(mock_server):
    MockHandler.response_data = {
        "allowed": True,
        "reason": "direct_access",
        "policy_id": "pol-123",
        "access_path": "direct",
    }
    client = AuthzX(api_key="test-key", base_url=mock_server)
    resp = client.authorize(AuthorizeRequest(
        subject=Subject(id="user-1"),
        resource=Resource(id="doc-1"),
        action="read",
    ))
    assert resp.allowed is True
    assert resp.policy_id == "pol-123"
    assert resp.access_path == "direct"


def test_auth_error(mock_server):
    MockHandler.status_code = 401
    MockHandler.response_data = "invalid key"
    client = AuthzX(api_key="bad-key", base_url=mock_server)
    with pytest.raises(AuthzXError) as exc_info:
        client.check(subject=Subject(id="user-1"), action="read", resource=Resource(id="doc-1"))
    assert exc_info.value.status_code == 401
    assert exc_info.value.is_auth_error


def test_retry_on_500(mock_server):
    call_sequence = [0]

    original_handler = MockHandler.do_POST

    def custom_handler(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        call_sequence[0] += 1
        if call_sequence[0] < 3:
            body = json.dumps({"error": "internal"}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"allowed": True, "reason": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    MockHandler.do_POST = custom_handler
    try:
        client = AuthzX(api_key="test-key", base_url=mock_server, max_retries=2)
        allowed = client.check(subject=Subject(id="user-1"), action="read", resource=Resource(id="doc-1"))
        assert allowed is True
        assert call_sequence[0] == 3
    finally:
        MockHandler.do_POST = original_handler


def test_no_retry_on_400(mock_server):
    MockHandler.status_code = 400
    MockHandler.call_count = 0
    client = AuthzX(api_key="test-key", base_url=mock_server)
    with pytest.raises(AuthzXError) as exc_info:
        client.check(subject=Subject(id="user-1"), action="read", resource=Resource(id="doc-1"))
    assert exc_info.value.status_code == 400
    assert MockHandler.call_count == 1


def test_subject_type_optional():
    s = Subject(id="user-1")
    d = s.to_dict()
    assert "type" not in d


def test_resource_type_optional():
    r = Resource(id="doc-1")
    d = r.to_dict()
    assert "type" not in d
