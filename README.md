# Vengtoo Python SDK

Python client for [Vengtoo](https://vengtoo.com) — works with both Vengtoo Cloud and the Vengtoo Agent.

Supports sync and async. Requires Python 3.10+. One dependency (`httpx`).

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
    subject=Subject(id="user:123", type="user"),
    action="read",
    resource=Resource(type="document", id="doc:456"),
)
```

### OAuth2 Client Credentials

For service-to-service auth, pass `client_id` and `client_secret` (secret is prefixed `azx_cs_`). The SDK exchanges credentials at the token endpoint, caches the JWT in memory, refreshes ~60s before expiry, and retries once automatically on a 401. Sync and async calls share the same cache.

```python
client = Vengtoo(
    client_id="my-client-id",
    client_secret="azx_cs_...",
)
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.vengtoo.com/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both `api_key` and OAuth credentials is rejected at construction. A bad `client_id` / `client_secret` surfaces as `VengtooOAuthError` (distinct from `VengtooError`) with a message pointing you at the OAuth exchange.

### Agent Mode (local)

```python
client = Vengtoo(base_url="http://127.0.0.1:8181")
```

### Full Evaluation Response

```python
from vengtoo import EvaluationRequest, Action

resp = client.evaluate(EvaluationRequest(
    subject=Subject(id="user:123", type="user"),
    resource=Resource(type="document", id="doc:456"),
    action=Action(name="read"),
    context={"ip": "10.0.0.1"},
))
# resp.decision, resp.context.reason, resp.context.policy_id, resp.context.access_path
```

### Batch Evaluation

Evaluate up to 50 checks in one round-trip (AuthZEN 1.0). Top-level fields act
as defaults that individual items inherit:

```python
from vengtoo import BatchEvaluationRequest, BatchEvalItem

resp = client.evaluate_batch(BatchEvaluationRequest(
    subject=Subject(id="user:123", type="user"),  # default for all items
    action=Action(name="read"),
    evaluations=[
        BatchEvalItem(resource=Resource(type="document", id="doc:1")),
        BatchEvalItem(resource=Resource(type="document", id="doc:2")),
    ],
))
# resp.evaluations[i].decision, positional
```

### Human-in-the-Loop Approvals

When a policy requires human approval, `evaluate()` returns
`reason_code == "authorization_pending"`. `evaluate_with_approval()` handles
the wait — polling at the server-recommended interval until a human approves
or denies in the Vengtoo dashboard:

```python
resp = client.evaluate_with_approval(
    req,
    timeout=300,
    on_pending=lambda auth_req_id, expires_in:
        print(f"waiting for approval {auth_req_id} (expires in {expires_in}s)"),
)
# Terminal reason_codes: "approved_by_human", "access_denied",
# "approval_timeout" (no human answered), "polling_error" (network).
# Never raises for these — always fails closed.
```

The async variant (`async_evaluate_with_approval`) follows normal asyncio
cancellation semantics — cancel the task to stop waiting.

### Delegations

Grant an agent the delegator's permission scope for exactly the duration of a
task — created on enter, revoked on exit, even when the body raises. A failed
revocation is never swallowed: it raises (chained onto the body's exception if
both failed):

```python
from vengtoo import CreateDelegationRequest

with client.with_delegation(CreateDelegationRequest(
    delegator_id=user_entity_id,
    delegate_id=agent_entity_id,
    scope=["invoices:read", "invoices:submit"],  # optional: attenuate further
    description="Q3 invoice processing run",     # optional: shows in audit/dashboard
)) as delegation:
    run_workflow()

# async: `async with client.async_with_delegation(...) as delegation:`
```

The delegate's effective permissions are always the _intersection_ of its own
policies and the delegator's — `scope` narrows that further, it can never
escalate.

### Async

```python
allowed = await client.async_check(
    subject=Subject(id="user:123", type="user"),
    action="read",
    resource=Resource(type="document", id="doc:456"),
)

resp = await client.async_evaluate(request)
```

### FastAPI Dependency

Two layers, two jobs: `require()` is the **route-level perimeter** ("may this
caller touch this API area at all?"). For **per-object decisions**, call
`check()`/`evaluate()` inside the handler where the resource is known.

`require()` takes a subject extractor — you tell it where your authentication
layer put the caller's identity:

```python
from fastapi import FastAPI, Depends, HTTPException, Request

app = FastAPI()
vengtoo = Vengtoo(api_key="azx_...")

def current_subject(request: Request) -> Subject:
    user = getattr(request.state, "user", None)  # set by your authn middleware
    if user is None:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return Subject(id=user.id, type="user")

@app.get("/documents/{id}")
async def get_doc(id: str, _=Depends(vengtoo.require("document", "read", current_subject))):
    return {"id": id}
```

An extractor exception (or a subject with no `id`/`external_id`) → 401. Policy
deny → 403. Authorization infrastructure failure → 500, fail closed.

### Options

```python
Vengtoo(
    api_key="azx_...",                  # API key for cloud mode
    base_url="http://127.0.0.1:8181",   # Custom URL (agent mode)
    timeout=5.0,                        # Per-request timeout in seconds (default: 10)
    max_retries=3,                      # Max retries on 5xx/429 (default: 2)
)
```

## Error Handling

```python
from vengtoo import VengtooError, VengtooOAuthError

try:
    client.evaluate(req)
except VengtooOAuthError:
    ...  # bad client_id/client_secret
except VengtooError as e:
    e.is_auth_error    # 401 — bad API key or expired token
    e.is_forbidden     # 403
    e.is_not_found     # 404
    e.is_server_error  # 5xx — retries exhausted
```

The SDK automatically retries on 5xx and 429 responses (default: 2 retries,
honoring the server's `Retry-After` hint). Other 4xx errors are never retried.
With OAuth, a 401 triggers one token refresh before failing.

## Types

| Type                      | Fields                                                                     |
| ------------------------- | -------------------------------------------------------------------------- |
| `Subject`                 | `type`, `id`, `external_id`, `properties`                                  |
| `Resource`                | `type`, `id`, `external_id`, `properties`                                  |
| `Action`                  | `name`, `properties`                                                       |
| `EvaluationRequest`       | `subject`, `resource`, `action`, `context`                                 |
| `EvaluationResponse`      | `decision`, `context` (reason, reason_code, policy_id, access_path + HITL) |
| `CreateDelegationRequest` | `delegate_id`, `delegator_id`, `description`, `scope`, `expires_at`        |

Required on every check (matching the API and AuthZEN 1.0): `subject.type`,
`subject.id` (or `external_id`), `resource.type`, and `action.name`. The SDK
validates these locally so you get an immediate, clear error instead of a
server 400.

## License

Apache-2.0 — see [LICENSE](LICENSE).
