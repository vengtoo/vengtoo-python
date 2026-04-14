# AuthzX Python SDK

Python client for [AuthzX](https://authzx.com) — works with both AuthzX Cloud and the local AuthzX Agent.

Supports sync and async. Requires Python 3.9+.

## Install

```bash
pip install authzx
```

## Usage

### Cloud Mode

```python
from authzx import AuthzX, Subject, Resource

client = AuthzX(api_key="azx_...")

allowed = client.check(
    subject=Subject(id="user:123", type="user", roles=["editor"]),
    action="read",
    resource=Resource(type="document", id="doc:456"),
)
```

### Agent Mode (local)

```python
client = AuthzX(base_url="http://localhost:8181")
```

### Full Evaluate Response

```python
from authzx import AuthorizeRequest

resp = client.authorize(AuthorizeRequest(
    subject=Subject(id="user:123", type="user"),
    resource=Resource(type="document", id="doc:456"),
    action="read",
    context={"ip": "10.0.0.1"},
))
# resp.allowed, resp.reason, resp.policy_id, resp.access_path
```

### Async

```python
allowed = await client.async_check(
    subject=Subject(id="user:123", type="user"),
    action="read",
    resource=Resource(type="document", id="doc:456"),
)

resp = await client.async_authorize(request)
```

### FastAPI Dependency

```python
from fastapi import FastAPI, Depends

app = FastAPI()
authzx = AuthzX(api_key="azx_...")

@app.get("/documents/{id}")
async def get_doc(id: str, _=Depends(authzx.require("document", "read"))):
    return {"id": id}
```

The `require()` dependency extracts subject ID from the `X-User-ID` header by default. Customize with:

```python
authzx.require("document", "read", subject_header="authorization-user-id")
```

### Options

```python
AuthzX(
    api_key="azx_...",                    # API key for cloud mode
    base_url="http://localhost:8181",          # Custom URL (agent mode)
    timeout=5.0,                               # Request timeout in seconds (default: 10)
)
```

## Types

| Type | Fields |
|------|--------|
| `Subject` | `id`, `type`, `attributes`, `roles` |
| `Resource` | `type`, `id`, `attributes` |
| `AuthorizeRequest` | `subject`, `resource`, `action`, `context` |
| `AuthorizeResponse` | `allowed`, `reason`, `policy_id`, `access_path` |
