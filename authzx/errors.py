class VengtooError(Exception):
    """Vengtoo API error with status code."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"Vengtoo API error (status {status_code}): {message}")

    @property
    def is_auth_error(self) -> bool:
        return self.status_code == 401

    @property
    def is_forbidden(self) -> bool:
        return self.status_code == 403

    @property
    def is_not_found(self) -> bool:
        return self.status_code == 404

    @property
    def is_server_error(self) -> bool:
        return self.status_code >= 500


class VengtooOAuthError(Exception):
    """Raised when the OAuth2 Client Credentials token exchange fails.

    Distinct from ``VengtooError`` (which wraps API-call failures) so
    customers debugging setup know the failure was the OAuth exchange, not
    their ``authorize()`` call.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        description: str = "",
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.description = description
        if code == "invalid_client":
            msg = "OAuth authentication failed: check client_id/client_secret"
        elif description:
            msg = f"OAuth token exchange failed ({code}): {description}"
        else:
            msg = f"OAuth token exchange failed ({code})"
        super().__init__(msg)
