from __future__ import annotations

import asyncio
import contextlib
import inspect
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx

from vengtoo.errors import VengtooError, VengtooOAuthError
from vengtoo.types import (
    Action,
    BatchEvaluationRequest,
    BatchEvaluationResponse,
    CreateDelegationRequest,
    Delegation,
    EvaluationContext,
    EvaluationRequest,
    EvaluationResponse,
    Resource,
    Subject,
)

DEFAULT_TOKEN_URL = "https://api.vengtoo.com/v1/oauth/token"
REFRESH_SKEW_SECONDS = 60.0
MAX_RETRY_AFTER_SECONDS = 5.0


def _validate_evaluation(req: EvaluationRequest) -> None:
    """Validates the fields the API requires (AuthZEN 1.0): subject.type,
    subject.id or external_id, resource.type, action.name. Catching these
    locally turns a guaranteed server 400 into an immediate, clearer error."""
    if not req.subject or not req.subject.type:
        raise ValueError("vengtoo: subject.type is required")
    if not req.subject.id and not req.subject.external_id:
        raise ValueError("vengtoo: subject.id or subject.external_id is required")
    if not req.resource or not req.resource.type:
        raise ValueError("vengtoo: resource.type is required")
    if not req.action or not req.action.name:
        raise ValueError("vengtoo: action.name is required")


def _parse_retry_after(value: str | None) -> float:
    """Parses a Retry-After header in delta-seconds form; garbage yields 0."""
    if not value:
        return 0.0
    try:
        secs = float(value)
    except ValueError:
        return 0.0
    return secs if secs > 0 else 0.0


def _parse_delegation(data: dict[str, Any]) -> Delegation:
    return Delegation(
        id=data["id"],
        delegate_id=data["delegate_id"],
        delegator_id=data["delegator_id"],
        created_at=data["created_at"],
        description=data.get("description"),
        scope=data.get("scope"),
        expires_at=data.get("expires_at"),
        revoked_at=data.get("revoked_at"),
    )


class Vengtoo:
    """Vengtoo authorization client.

    For cloud with API key:
        Vengtoo(api_key="azx_...")

    For cloud with OAuth2 Client Credentials:
        Vengtoo(client_id="...", client_secret="azx_cs_...")

    For local agent:
        Vengtoo(base_url="http://127.0.0.1:8181")
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.vengtoo.com",
        timeout: float = 10.0,
        max_retries: int = 2,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str = DEFAULT_TOKEN_URL,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._client = httpx.Client(timeout=timeout)
        self._async_client: httpx.AsyncClient | None = None

        # OAuth configuration + token cache.
        oauth_provided = bool(client_id or client_secret)
        if oauth_provided:
            if not client_id or not client_secret:
                raise ValueError(
                    "Vengtoo: both client_id and client_secret are required for OAuth"
                )
            self._oauth = {
                "client_id": client_id,
                "client_secret": client_secret,
                "token_url": token_url,
            }
        else:
            self._oauth = None

        if self.api_key and self._oauth is not None:
            raise ValueError(
                "Vengtoo: configure either api_key or OAuth client credentials, not both"
            )

        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0
        # Separate locks for sync and async paths — they protect the same
        # cache but are never held across sync/async boundaries.
        self._token_lock = threading.Lock()
        self._async_token_lock: asyncio.Lock | None = None

    def close(self) -> None:
        self._client.close()
        if self._async_client:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                loop.create_task(self._async_client.aclose())
            else:
                asyncio.run(self._async_client.aclose())
            self._async_client = None

    async def async_close(self) -> None:
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    def __enter__(self) -> Vengtoo:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aenter__(self) -> Vengtoo:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.async_close()

    def _url(self) -> str:
        return f"{self.base_url}/access/v1/evaluation"

    def _batch_url(self) -> str:
        return f"{self.base_url}/access/v1/evaluations"

    # --- Auth header resolution ---

    def _static_auth_header(self) -> dict[str, str]:
        """Headers for API-key mode (or empty dict for local-agent mode)."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def _token_is_fresh(self) -> bool:
        return (
            self._cached_token is not None
            and time.time() < self._token_expires_at - REFRESH_SKEW_SECONDS
        )

    def _invalidate_token(self) -> None:
        self._cached_token = None
        self._token_expires_at = 0.0

    def _parse_token_response(self, resp: httpx.Response) -> str:
        text = resp.text
        if resp.status_code == 200:
            try:
                payload = resp.json()
            except Exception as e:  # noqa: BLE001
                raise VengtooOAuthError(
                    resp.status_code,
                    "invalid_response",
                    f"token endpoint returned non-JSON body: {e}",
                )
            access_token = payload.get("access_token")
            if not access_token:
                raise VengtooOAuthError(
                    resp.status_code,
                    "invalid_response",
                    "token endpoint returned empty access_token",
                )
            ttl = float(payload.get("expires_in") or 3600)
            self._cached_token = access_token
            self._token_expires_at = time.time() + ttl
            return access_token

        # Error path — try to decode RFC 6749 body.
        code = "token_endpoint_error"
        description = text
        try:
            parsed = resp.json()
            if isinstance(parsed, dict):
                code = str(parsed.get("error") or code)
                if parsed.get("error_description"):
                    description = str(parsed["error_description"])
        except Exception:  # noqa: BLE001
            pass
        if resp.status_code == 401 and code == "token_endpoint_error":
            code = "invalid_client"
        raise VengtooOAuthError(resp.status_code, code, description)

    def _fetch_token_sync(self) -> str:
        assert self._oauth is not None
        data = {
            "grant_type": "client_credentials",
            "client_id": self._oauth["client_id"],
            "client_secret": self._oauth["client_secret"],
        }
        try:
            resp = self._client.post(
                self._oauth["token_url"],
                data=data,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as e:
            raise VengtooOAuthError(
                0, "network_error", f"OAuth token request failed: {e}"
            )
        return self._parse_token_response(resp)

    def _get_access_token_sync(self) -> str:
        with self._token_lock:
            if self._token_is_fresh():
                return self._cached_token  # type: ignore[return-value]
            return self._fetch_token_sync()

    def _headers_sync(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self._oauth is not None:
            h["Authorization"] = f"Bearer {self._get_access_token_sync()}"
        else:
            h.update(self._static_auth_header())
        return h

    async def _fetch_token_async(self) -> str:
        assert self._oauth is not None
        client = self._get_async_client()
        data = {
            "grant_type": "client_credentials",
            "client_id": self._oauth["client_id"],
            "client_secret": self._oauth["client_secret"],
        }
        try:
            resp = await client.post(
                self._oauth["token_url"],
                data=data,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as e:
            raise VengtooOAuthError(
                0, "network_error", f"OAuth token request failed: {e}"
            )
        return self._parse_token_response(resp)

    async def _get_access_token_async(self) -> str:
        if self._async_token_lock is None:
            self._async_token_lock = asyncio.Lock()
        async with self._async_token_lock:
            if self._token_is_fresh():
                return self._cached_token  # type: ignore[return-value]
            return await self._fetch_token_async()

    async def _headers_async(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self._oauth is not None:
            h["Authorization"] = f"Bearer {await self._get_access_token_async()}"
        else:
            h.update(self._static_auth_header())
        return h

    def _parse_response(self, data: dict[str, Any]) -> EvaluationResponse:
        ctx_data = data.get("context")
        ctx = None
        if ctx_data and isinstance(ctx_data, dict):
            ctx = EvaluationContext(
                reason=ctx_data.get("reason"),
                reason_code=ctx_data.get("reason_code"),
                policy_id=ctx_data.get("policy_id"),
                access_path=ctx_data.get("access_path"),
                auth_req_id=ctx_data.get("auth_req_id"),
                approval_id=ctx_data.get("approval_id"),
                expires_in=ctx_data.get("expires_in"),
                interval=ctx_data.get("interval"),
            )
        return EvaluationResponse(decision=data["decision"], context=ctx)

    # --- Shared retry engine ---
    #
    # One POST with per-attempt timeout, 5xx/429 retry (honoring Retry-After,
    # capped), and exactly one OAuth refresh+retry on 401.

    def _post_sync(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        oauth_retried = False
        last_err: Exception | None = None
        retry_after = 0.0
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                time.sleep(min(max(attempt * 0.1, retry_after), MAX_RETRY_AFTER_SECONDS))
                retry_after = 0.0
            try:
                resp = self._client.post(url, headers=self._headers_sync(), json=payload)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 401 and self._oauth is not None and not oauth_retried:
                    self._invalidate_token()
                    oauth_retried = True
                    continue  # does not count against max_retries
                err = VengtooError(resp.status_code, resp.text)
                if resp.status_code >= 500 or resp.status_code == 429:
                    last_err = err
                    retry_after = _parse_retry_after(resp.headers.get("retry-after"))
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:  # noqa: BLE001 — network/transport errors are retryable
                last_err = e
                attempt += 1
        assert last_err is not None
        raise last_err

    async def _post_async(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._get_async_client()
        oauth_retried = False
        last_err: Exception | None = None
        retry_after = 0.0
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                await asyncio.sleep(min(max(attempt * 0.1, retry_after), MAX_RETRY_AFTER_SECONDS))
                retry_after = 0.0
            try:
                resp = await client.post(url, headers=await self._headers_async(), json=payload)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 401 and self._oauth is not None and not oauth_retried:
                    self._invalidate_token()
                    oauth_retried = True
                    continue
                err = VengtooError(resp.status_code, resp.text)
                if resp.status_code >= 500 or resp.status_code == 429:
                    last_err = err
                    retry_after = _parse_retry_after(resp.headers.get("retry-after"))
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:  # noqa: BLE001
                last_err = e
                attempt += 1
        assert last_err is not None
        raise last_err

    @staticmethod
    def _validate_batch(req: BatchEvaluationRequest) -> None:
        if not req.evaluations:
            raise ValueError("vengtoo: batch request requires at least one evaluation")
        if len(req.evaluations) > 50:
            raise ValueError("vengtoo: batch request exceeds maximum of 50 evaluations")

    # --- Sync ---

    def evaluate(self, req: EvaluationRequest) -> EvaluationResponse:
        """Evaluates a single authorization request (AuthZEN 1.0 Access Evaluation)."""
        _validate_evaluation(req)
        return self._parse_response(self._post_sync(self._url(), req.to_dict()))

    def check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Convenience: evaluate and return just the boolean decision."""
        resp = self.evaluate(
            EvaluationRequest(
                subject=subject, resource=resource, action=Action(name=action), context=context
            )
        )
        return resp.decision

    def evaluate_batch(self, req: BatchEvaluationRequest) -> BatchEvaluationResponse:
        """Evaluates up to 50 checks in one round-trip (AuthZEN 1.0 batch).
        Top-level subject/action/resource/context act as defaults items inherit."""
        self._validate_batch(req)
        data = self._post_sync(self._batch_url(), req.to_dict())
        return BatchEvaluationResponse(
            evaluations=[self._parse_response(e) for e in data["evaluations"]],
        )

    def evaluate_with_approval(
        self,
        req: EvaluationRequest,
        timeout: float = 300.0,
        max_network_errors: int = 3,
        on_pending: Callable[[str | None, int | None], None] | None = None,
    ) -> EvaluationResponse:
        """Blocking HITL-aware evaluate that polls until approved, denied, or timed out.

        Returns an EvaluationResponse in all cases — never raises for pending/timeout/
        network errors. Distinct reason_codes:
          "approval_timeout" — no human responded within timeout seconds
          "polling_error"    — network errors persisted beyond max_network_errors retries
        """
        result = self.evaluate(req)
        if result.decision:
            return result

        reason_code = result.context.reason_code if result.context else ""
        if reason_code != "authorization_pending":
            return result

        if on_pending is not None:
            on_pending(
                result.context.auth_req_id if result.context else None,
                result.context.expires_in if result.context else None,
            )

        deadline = time.monotonic() + timeout
        network_errors = 0
        # Tracked outside the loop, updated only after successful polls.
        interval = (result.context.interval if result.context and result.context.interval else 5) + 1

        while time.monotonic() < deadline:
            time.sleep(interval)
            if time.monotonic() >= deadline:
                break

            try:
                result = self.evaluate(req)
                network_errors = 0
            except Exception as e:  # noqa: BLE001
                network_errors += 1
                if network_errors >= max_network_errors:
                    return EvaluationResponse(
                        decision=False,
                        context=EvaluationContext(reason_code="polling_error", reason=str(e)),
                    )
                time.sleep(min(network_errors * 2, 10))
                continue

            if result.decision:
                return result

            poll_code = result.context.reason_code if result.context else ""
            if result.context and result.context.interval:
                interval = result.context.interval + 1
            if poll_code == "slow_down":
                continue
            if poll_code != "authorization_pending":
                return result

        return EvaluationResponse(
            decision=False,
            context=EvaluationContext(reason_code="approval_timeout"),
        )

    # --- Async ---

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self.timeout)
        return self._async_client

    async def async_evaluate(self, req: EvaluationRequest) -> EvaluationResponse:
        """Async variant of evaluate()."""
        _validate_evaluation(req)
        return self._parse_response(await self._post_async(self._url(), req.to_dict()))

    async def async_check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Async variant of check()."""
        resp = await self.async_evaluate(
            EvaluationRequest(
                subject=subject, resource=resource, action=Action(name=action), context=context
            )
        )
        return resp.decision

    async def async_evaluate_batch(self, req: BatchEvaluationRequest) -> BatchEvaluationResponse:
        """Async variant of evaluate_batch()."""
        self._validate_batch(req)
        data = await self._post_async(self._batch_url(), req.to_dict())
        return BatchEvaluationResponse(
            evaluations=[self._parse_response(e) for e in data["evaluations"]],
        )

    async def async_evaluate_with_approval(
        self,
        req: EvaluationRequest,
        timeout: float = 300.0,
        max_network_errors: int = 3,
        on_pending: Callable[[str | None, int | None], None] | None = None,
    ) -> EvaluationResponse:
        """Async HITL-aware evaluate that polls until approved, denied, or timed out.

        Cancellation follows asyncio semantics: cancelling the task raises
        CancelledError out of the sleep, as any async caller expects.
        """
        result = await self.async_evaluate(req)
        if result.decision:
            return result

        reason_code = result.context.reason_code if result.context else ""
        if reason_code != "authorization_pending":
            return result

        if on_pending is not None:
            on_pending(
                result.context.auth_req_id if result.context else None,
                result.context.expires_in if result.context else None,
            )

        deadline = time.monotonic() + timeout
        network_errors = 0
        interval = (result.context.interval if result.context and result.context.interval else 5) + 1

        while time.monotonic() < deadline:
            await asyncio.sleep(interval)
            if time.monotonic() >= deadline:
                break

            try:
                result = await self.async_evaluate(req)
                network_errors = 0
            except Exception as e:  # noqa: BLE001
                network_errors += 1
                if network_errors >= max_network_errors:
                    return EvaluationResponse(
                        decision=False,
                        context=EvaluationContext(reason_code="polling_error", reason=str(e)),
                    )
                await asyncio.sleep(min(network_errors * 2, 10))
                continue

            if result.decision:
                return result

            poll_code = result.context.reason_code if result.context else ""
            if result.context and result.context.interval:
                interval = result.context.interval + 1
            if poll_code == "slow_down":
                continue
            if poll_code != "authorization_pending":
                return result

        return EvaluationResponse(
            decision=False,
            context=EvaluationContext(reason_code="approval_timeout"),
        )

    # --- FastAPI ---

    def require(
        self,
        resource_type: str,
        action: str,
        subject: Callable[[Any], Subject | Any],
    ):
        """FastAPI dependency that enforces authorization — the coarse,
        route-level layer. For per-object decisions, call check()/evaluate()
        inside the handler where the resource is known.

        ``subject`` resolves the authenticated caller from the request — the
        hand-off point between your authentication layer and this dependency.
        It may be sync or async, and may itself raise HTTPException. Returning
        a Subject with neither id nor external_id (or raising) rejects with 401.

        Usage::

            def current_subject(request: Request) -> Subject:
                user = getattr(request.state, "user", None)  # set by authn middleware
                if user is None:
                    raise HTTPException(status_code=401, detail="unauthenticated")
                return Subject(id=user.id, type="user")

            @app.get("/documents/{id}")
            async def get_doc(id: str, _=Depends(vengtoo.require("document", "read", current_subject))):
                ...
        """
        from starlette.exceptions import HTTPException
        from starlette.requests import Request

        async def dependency(request: Request) -> None:
            try:
                sub = subject(request)
                if inspect.isawaitable(sub):
                    sub = await sub
            except HTTPException:
                raise
            except Exception:  # noqa: BLE001 — extractor failure = unauthenticated
                raise HTTPException(status_code=401, detail="unauthenticated")
            if not isinstance(sub, Subject) or (not sub.id and not sub.external_id):
                raise HTTPException(status_code=401, detail="unauthenticated")

            resource_id = request.path_params.get("id", request.url.path)
            try:
                allowed = await self.async_check(
                    sub, action, Resource(id=resource_id, type=resource_type)
                )
            except Exception:  # noqa: BLE001 — fail closed on infrastructure errors
                raise HTTPException(status_code=500, detail="authorization check failed")
            if not allowed:
                raise HTTPException(status_code=403, detail="forbidden")

        return dependency

    # --- Delegation ---

    def create_delegation(self, req: CreateDelegationRequest) -> Delegation:
        """Creates a delegation so that delegate can act on behalf of delegator."""
        resp = self._client.post(
            f"{self.base_url}/v1/delegations",
            json=req.to_dict(),
            headers=self._headers_sync(),
        )
        if resp.status_code != 201:
            raise VengtooError(resp.status_code, resp.text)
        return _parse_delegation(resp.json())

    def revoke_delegation(self, delegation_id: str) -> None:
        """Revokes an active delegation. The delegate immediately loses access."""
        resp = self._client.delete(
            f"{self.base_url}/v1/delegations/{delegation_id}",
            headers=self._headers_sync(),
        )
        if resp.status_code != 200:
            raise VengtooError(resp.status_code, resp.text)

    @contextlib.contextmanager
    def with_delegation(self, req: CreateDelegationRequest) -> Iterator[Delegation]:
        """Context manager that creates a delegation on enter and revokes it on exit.

        Guarantees the delegate never retains access beyond the task boundary,
        even if the body raises. A revocation failure is never swallowed — it
        raises (chained onto the body's exception if both failed), because a
        silently-unrevoked delegation means the delegate retains access and
        the caller must know.

        Example::

            with vengtoo.with_delegation(
                CreateDelegationRequest(
                    delegator_id=john_id, delegate_id=agent_id, scope=["invoices:read"]
                )
            ) as delegation:
                run_workflow()
        """
        delegation = self.create_delegation(req)
        try:
            yield delegation
        finally:
            # Deliberately NOT wrapped in try/except: if this raises during an
            # in-flight body exception, Python chains them (__context__), so
            # neither failure is lost.
            self.revoke_delegation(delegation.id)

    async def async_create_delegation(self, req: CreateDelegationRequest) -> Delegation:
        """Async variant of create_delegation."""
        resp = await self._get_async_client().post(
            f"{self.base_url}/v1/delegations",
            json=req.to_dict(),
            headers=await self._headers_async(),
        )
        if resp.status_code != 201:
            raise VengtooError(resp.status_code, resp.text)
        return _parse_delegation(resp.json())

    async def async_revoke_delegation(self, delegation_id: str) -> None:
        """Async variant of revoke_delegation."""
        resp = await self._get_async_client().delete(
            f"{self.base_url}/v1/delegations/{delegation_id}",
            headers=await self._headers_async(),
        )
        if resp.status_code != 200:
            raise VengtooError(resp.status_code, resp.text)

    @contextlib.asynccontextmanager
    async def async_with_delegation(
        self, req: CreateDelegationRequest
    ) -> AsyncIterator[Delegation]:
        """Async context manager variant of with_delegation.

        Example::

            async with vengtoo.async_with_delegation(
                CreateDelegationRequest(delegator_id=john_id, delegate_id=agent_id)
            ) as delegation:
                await run_workflow()
        """
        delegation = await self.async_create_delegation(req)
        try:
            yield delegation
        finally:
            # See with_delegation: revocation failures must surface.
            await self.async_revoke_delegation(delegation.id)
