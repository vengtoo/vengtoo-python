from __future__ import annotations

import time
from typing import Any

import httpx

from authzx.errors import AuthzXError
from authzx.types import AuthorizeRequest, AuthorizeResponse, Resource, Subject


class AuthzX:
    """AuthzX authorization client.

    For cloud:  AuthzX(api_key="azx_...")
    For agent:  AuthzX(base_url="http://localhost:8181")
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.authzx.com/v1",
        timeout: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._client = httpx.Client(timeout=timeout)
        self._async_client: httpx.AsyncClient | None = None

    def close(self) -> None:
        self._client.close()
        if self._async_client:
            # async client should be closed with async_close()
            pass

    async def async_close(self) -> None:
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None

    def _url(self) -> str:
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/authorize"
        return f"{self.base_url}/v1/authorize"

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _parse_response(self, data: dict[str, Any]) -> AuthorizeResponse:
        return AuthorizeResponse(
            allowed=data["allowed"],
            reason=data.get("reason", ""),
            policy_id=data.get("policy_id"),
            access_path=data.get("access_path"),
        )

    def _handle_response(self, resp: httpx.Response) -> AuthorizeResponse:
        if resp.status_code == 200:
            return self._parse_response(resp.json())
        raise AuthzXError(resp.status_code, resp.text)

    def _is_retryable(self, status_code: int) -> bool:
        return status_code >= 500 or status_code == 429

    # --- Sync ---

    def authorize(self, req: AuthorizeRequest) -> AuthorizeResponse:
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                time.sleep(attempt * 0.1)
            try:
                resp = self._client.post(self._url(), headers=self._headers(), json=req.to_dict())
                if resp.status_code == 200:
                    return self._parse_response(resp.json())
                err = AuthzXError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    continue
                raise err
            except AuthzXError:
                raise
            except Exception as e:
                last_err = e
                continue
        raise last_err  # type: ignore[misc]

    def check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        resp = self.authorize(AuthorizeRequest(subject=subject, resource=resource, action=action, context=context))
        return resp.allowed

    # --- Async ---

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self.timeout)
        return self._async_client

    async def async_authorize(self, req: AuthorizeRequest) -> AuthorizeResponse:
        client = self._get_async_client()
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                import asyncio
                await asyncio.sleep(attempt * 0.1)
            try:
                resp = await client.post(self._url(), headers=self._headers(), json=req.to_dict())
                if resp.status_code == 200:
                    return self._parse_response(resp.json())
                err = AuthzXError(resp.status_code, resp.text)
                if self._is_retryable(resp.status_code):
                    last_err = err
                    continue
                raise err
            except AuthzXError:
                raise
            except Exception as e:
                last_err = e
                continue
        raise last_err  # type: ignore[misc]

    async def async_check(
        self,
        subject: Subject,
        action: str,
        resource: Resource,
        context: dict[str, Any] | None = None,
    ) -> bool:
        resp = await self.async_authorize(AuthorizeRequest(subject=subject, resource=resource, action=action, context=context))
        return resp.allowed

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
            async def get_doc(id: str, _=Depends(authzx.require("document", "read"))):
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
