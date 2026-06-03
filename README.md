# Vengtoo Python SDK

Python client for [Vengtoo](https://vengtoo.com) — works with both Vengtoo Cloud and the Vengtoo Agent.

Supports sync and async. Requires Python 3.9+.

## Install

```bash
pip install vengtoo
```

## Usage

### Cloud Mode

```python
from vengtoo import Vengtoo, Subject, Resource

client = Vengtoo(api_key="azx_...")

allowed = client.check(
    subject=Subject(id="user:123", type="user", roles=["editor"]),
    action="read",
    resource=Resource(type="document", id="doc:456"),
)
```

### OAuth2 Client Credentials

For service-to-service auth, pass `client_id` and `client_secret` (secret is prefixed `azx_cs_`). The SDK exchanges credentials at the token endpoint, caches the JWT in memory, and refreshes ~60s before expiry. Both sync and async calls share the same cache.

```python
client = Vengtoo(
    client_id="my-client-id",
    client_secret="azx_cs_...",
)
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.vengtoo.com/identity-srv/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both `api_key` and OAuth credentials is rejected at construction. A bad `client_id` / `client_secret` surfaces as `VengtooOAuthError` (distinct from `VengtooError`) with a message pointing you at the OAuth exchange.

### Agent Mode (local)

```python
client = Vengtoo(base_url="http://localhost:8181")
```

### Full Evaluate Response

```python
from vengtoo import AuthorizeRequest, Action

resp = client.authorize(AuthorizeRequest(
    subject=Subject(id="user:123", type="user"),
    resource=Resource(type="document", id="doc:456"),
    action=Action(name="read"),
    context={"ip": "10.0.0.1"},
))
# resp.decision, resp.context.reason, resp.context.policy_id, resp.context.access_path
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
vengtoo = Vengtoo(api_key="azx_...")

@app.get("/documents/{id}")
async def get_doc(id: str, _=Depends(vengtoo.require("document", "read"))):
    return {"id": id}
```

The `require()` dependency extracts subject ID from the `X-User-ID` header by default. Customize with:

```python
vengtoo.require("document", "read", subject_header="authorization-user-id")
```

### Options

```python
Vengtoo(
    api_key="azx_...",                    # API key for cloud mode
    base_url="http://localhost:8181",          # Custom URL (agent mode)
    timeout=5.0,                               # Request timeout in seconds (default: 10)
)
```

## Types

| Type                | Fields                                              |
| ------------------- | --------------------------------------------------- |
| `Subject`           | `id`, `type`, `attributes`, `properties`, `roles`   |
| `Resource`          | `id`, `type`, `attributes`, `properties`            |
| `Action`            | `name`, `properties`                                |
| `AuthorizeRequest`  | `subject`, `resource`, `action`, `context`          |
| `AuthorizeContext`  | `reason`, `reason_code`, `policy_id`, `access_path` |
| `AuthorizeResponse` | `decision`, `context`                               |
