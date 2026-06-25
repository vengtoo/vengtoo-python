from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx

from vengtoo.errors import VengtooError, VengtooOAuthError
from vengtoo.types import (
    Action, AuthorizeContext, AuthorizeRequest, AuthorizeResponse,
    BatchEvalItem, BatchEvaluationRequest, BatchEvaluationResponse,
    CreateDelegationRequest, Delegation,
    Resource, Subject,
)


DEFAULT_TOKEN_URL = "https://api.vengtoo.com/v1/oauth/token"
REFRESH_SKEW_SECONDS = 60.0


class Vengtoo:
    """Vengtoo authorization client.

    For cloud with API key:
        Vengtoo(api_key="azx_...")

    For cloud with OAuth2 Client Credentials:
        Vengtoo(client_id="...", client_secret="azx_cs_...")

    For local agent:
        Vengtoo(base_url="http://localhost:8181")
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

    def _parse_response(self, data: dict[str, Any]) -> AuthorizeResponse:
        ctx_data = data.get("context")
        ctx = None
        if ctx_data and isinstance(ctx_data, dict):
            ctx = AuthorizeContext(
                reason=ctx_data.get("reason"),
                reason_code=ctx_data.get("reason_code"),
                policy_id=ctx_data.get("policy_id"),
                access_path=ctx_data.get("access_path"),
                auth_req_id=ctx_data.get("auth_req_id"),
                approval_id=ctx_data.get("approval_id"),
                expires_in=ctx_data.get("expires_in"),
                interval=ctx_data.get("interval"),
            )
        return AuthorizeResponse(
            decision=data["decision"],
            context=ctx,
        )

    def _is_retryable(self, status_code: int) -> bool:
        return status_code >= 500 or status_code == 429

    # --- Sync ---

    def authorize(self, req: AuthorizeRequest) -> AuthorizeResponse:
        # OAuth flow gets exactly one 401-triggered refresh+retry across the
        # whole authorize() call, independent of max_retries.
        oauth_retried = False
        last_err: Exception | None = None
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                time.sleep(attempt * 0.1)
            try:
                resp = self._client.post(
                    self._url(), headers=self._headers_sync(), json=req.to_dict()
                )
                if resp.status_code == 200:
                    return self._parse_response(resp.json())
                if (
                    resp.status_code == 401
                    and self._oauth is not None
                    and not oauth_retried
                ):
                    self._invalidate_token()
                    oauth_retried = True
                    # do not count this against max_retries
                    continue
                err = VengtooError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:
                last_err = e
                attempt += 1
                continue
            attempt += 1
        assert last_err is not None
        raise last_err

    def check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        resp = self.authorize(AuthorizeRequest(subject=subject, resource=resource, action=Action(name=action), context=context))
        return resp.decision

    def authorize_batch(self, req: BatchEvaluationRequest) -> BatchEvaluationResponse:
        if not req.evaluations:
            raise ValueError("batch request requires at least one evaluation")
        if len(req.evaluations) > 50:
            raise ValueError("batch request exceeds maximum of 50 evaluations")
        oauth_retried = False
        last_err: Exception | None = None
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                time.sleep(attempt * 0.1)
            try:
                resp = self._client.post(
                    self._batch_url(), headers=self._headers_sync(), json=req.to_dict()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return BatchEvaluationResponse(
                        evaluations=[self._parse_response(e) for e in data["evaluations"]],
                    )
                if (
                    resp.status_code == 401
                    and self._oauth is not None
                    and not oauth_retried
                ):
                    self._invalidate_token()
                    oauth_retried = True
                    continue
                err = VengtooError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:
                last_err = e
                attempt += 1
                continue
            attempt += 1
        assert last_err is not None
        raise last_err

    def check_batch(self, req: BatchEvaluationRequest) -> list[bool]:
        resp = self.authorize_batch(req)
        return [e.decision for e in resp.evaluations]

    def authorize_with_polling(
        self,
        req: AuthorizeRequest,
        timeout: float = 300.0,
        max_network_errors: int = 3,
        on_pending: Callable[[str | None, int | None], None] | None = None,
    ) -> AuthorizeResponse:
        """Blocking HITL-aware authorize that polls until approved, denied, or timed out.

        Returns an AuthorizeResponse in all cases — never raises for pending/timeout/
        network errors. Distinct reason_codes:
          "approval_timeout" — no human responded within timeout seconds
          "polling_error"    — network errors persisted beyond max_network_errors retries
        """
        result = self.authorize(req)
        if result.decision:
            return result

        reason_code = result.context.reason_code if result.context else ""
        if reason_code != "authorization_pending":
            return result

        if on_pending is not None:
            auth_req_id = result.context.auth_req_id if result.context else None
            expires_in = result.context.expires_in if result.context else None
            on_pending(auth_req_id, expires_in)

        deadline = time.monotonic() + timeout
        network_errors = 0

        while time.monotonic() < deadline:
            interval = (result.context.interval if result.context and result.context.interval else 5) + 1
            time.sleep(interval)

            if time.monotonic() >= deadline:
                break

            try:
                result = self.authorize(req)
                network_errors = 0
            except Exception:
                network_errors += 1
                if network_errors >= max_network_errors:
                    return AuthorizeResponse(
                        decision=False,
                        context=AuthorizeContext(reason_code="polling_error"),
                    )
                time.sleep(min(network_errors * 2, 10))
                continue

            if result.decision:
                return result

            poll_code = result.context.reason_code if result.context else ""
            if poll_code == "slow_down":
                continue
            if poll_code != "authorization_pending":
                return result

        return AuthorizeResponse(
            decision=False,
            context=AuthorizeContext(reason_code="approval_timeout"),
        )

    # --- Async ---

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self.timeout)
        return self._async_client

    async def async_authorize(self, req: AuthorizeRequest) -> AuthorizeResponse:
        client = self._get_async_client()
        oauth_retried = False
        last_err: Exception | None = None
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                await asyncio.sleep(attempt * 0.1)
            try:
                resp = await client.post(
                    self._url(), headers=await self._headers_async(), json=req.to_dict()
                )
                if resp.status_code == 200:
                    return self._parse_response(resp.json())
                if (
                    resp.status_code == 401
                    and self._oauth is not None
                    and not oauth_retried
                ):
                    self._invalidate_token()
                    oauth_retried = True
                    continue
                err = VengtooError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:
                last_err = e
                attempt += 1
                continue
            attempt += 1
        assert last_err is not None
        raise last_err

    async def async_check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        resp = await self.async_authorize(AuthorizeRequest(subject=subject, resource=resource, action=Action(name=action), context=context))
        return resp.decision

    async def async_authorize_batch(self, req: BatchEvaluationRequest) -> BatchEvaluationResponse:
        if not req.evaluations:
            raise ValueError("batch request requires at least one evaluation")
        if len(req.evaluations) > 50:
            raise ValueError("batch request exceeds maximum of 50 evaluations")
        client = self._get_async_client()
        oauth_retried = False
        last_err: Exception | None = None
        attempt = 0
        while attempt <= self.max_retries:
            if attempt > 0:
                await asyncio.sleep(attempt * 0.1)
            try:
                resp = await client.post(
                    self._batch_url(), headers=await self._headers_async(), json=req.to_dict()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return BatchEvaluationResponse(
                        evaluations=[self._parse_response(e) for e in data["evaluations"]],
                    )
                if (
                    resp.status_code == 401
                    and self._oauth is not None
                    and not oauth_retried
                ):
                    self._invalidate_token()
                    oauth_retried = True
                    continue
                err = VengtooError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    attempt += 1
                    continue
                raise err
            except (VengtooError, VengtooOAuthError):
                raise
            except Exception as e:
                last_err = e
                attempt += 1
                continue
            attempt += 1
        assert last_err is not None
        raise last_err

    async def async_check_batch(self, req: BatchEvaluationRequest) -> list[bool]:
        resp = await self.async_authorize_batch(req)
        return [e.decision for e in resp.evaluations]

    async def async_authorize_with_polling(
        self,
        req: AuthorizeRequest,
        timeout: float = 300.0,
        max_network_errors: int = 3,
        on_pending: Callable[[str | None, int | None], None] | None = None,
    ) -> AuthorizeResponse:
        """Async HITL-aware authorize that polls until approved, denied, or timed out.

        Returns an AuthorizeResponse in all cases — never raises for pending/timeout/
        network errors. Distinct reason_codes:
          "approval_timeout" — no human responded within timeout seconds
          "polling_error"    — network errors persisted beyond max_network_errors retries
        """
        result = await self.async_authorize(req)
        if result.decision:
            return result

        reason_code = result.context.reason_code if result.context else ""
        if reason_code != "authorization_pending":
            return result

        if on_pending is not None:
            auth_req_id = result.context.auth_req_id if result.context else None
            expires_in = result.context.expires_in if result.context else None
            on_pending(auth_req_id, expires_in)

        deadline = time.monotonic() + timeout
        network_errors = 0

        while time.monotonic() < deadline:
            interval = (result.context.interval if result.context and result.context.interval else 5) + 1
            await asyncio.sleep(interval)

            if time.monotonic() >= deadline:
                break

            try:
                result = await self.async_authorize(req)
                network_errors = 0
            except Exception:
                network_errors += 1
                if network_errors >= max_network_errors:
                    return AuthorizeResponse(
                        decision=False,
                        context=AuthorizeContext(reason_code="polling_error"),
                    )
                await asyncio.sleep(min(network_errors * 2, 10))
                continue

            if result.decision:
                return result

            poll_code = result.context.reason_code if result.context else ""
            if poll_code == "slow_down":
                continue
            if poll_code != "authorization_pending":
                return result

        return AuthorizeResponse(
            decision=False,
            context=AuthorizeContext(reason_code="approval_timeout"),
        )

    # --- FastAPI ---

    def require(
        self,
        resource_type: str,
        action: str,
        subject_header: str = "x-user-id",
    ):
        """FastAPI dependency that enforces authorization.

        Usage:
            @app.get("/documents/{id}")
            async def get_doc(id: str, _=Depends(vengtoo.require("document", "read"))):
                ...
        """
        from starlette.requests import Request

        async def dependency(request: Request) -> None:
            subject_id = request.headers.get(subject_header, "")
            if not subject_id:
                from starlette.exceptions import HTTPException
                raise HTTPException(status_code=401, detail="missing subject ID")

            resource_id = request.path_params.get("id", request.url.path)
            allowed = await self.async_check(
                Subject(id=subject_id, type="user"),
                action,
                Resource(id=resource_id, type=resource_type),
            )
            if not allowed:
                from starlette.exceptions import HTTPException
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
        data = resp.json()
        return Delegation(
            id=data["id"],
            delegate_id=data["delegate_id"],
            delegator_id=data["delegator_id"],
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            revoked_at=data.get("revoked_at"),
        )

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
        even if the body raises an exception.

        Example::

            with vengtoo.with_delegation(
                CreateDelegationRequest(delegator_id=john_id, delegate_id=agent_id)
            ) as delegation:
                run_workflow()
        """
        delegation = self.create_delegation(req)
        try:
            yield delegation
        finally:
            try:
                self.revoke_delegation(delegation.id)
            except Exception:
                pass

    async def async_create_delegation(self, req: CreateDelegationRequest) -> Delegation:
        """Async variant of create_delegation."""
        resp = await self._get_async_client().post(
            f"{self.base_url}/v1/delegations",
            json=req.to_dict(),
            headers=await self._headers_async(),
        )
        if resp.status_code != 201:
            raise VengtooError(resp.status_code, resp.text)
        data = resp.json()
        return Delegation(
            id=data["id"],
            delegate_id=data["delegate_id"],
            delegator_id=data["delegator_id"],
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            revoked_at=data.get("revoked_at"),
        )

    async def async_revoke_delegation(self, delegation_id: str) -> None:
        """Async variant of revoke_delegation."""
        resp = await self._get_async_client().delete(
            f"{self.base_url}/v1/delegations/{delegation_id}",
            headers=await self._headers_async(),
        )
        if resp.status_code != 200:
            raise VengtooError(resp.status_code, resp.text)

    @contextlib.asynccontextmanager
    async def async_with_delegation(self, req: CreateDelegationRequest) -> AsyncIterator[Delegation]:
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
            try:
                await self.async_revoke_delegation(delegation.id)
            except Exception:
                pass
