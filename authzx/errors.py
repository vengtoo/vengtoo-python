class AuthzXError(Exception):
    """AuthzX API error with status code."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"AuthzX API error (status {status_code}): {message}")

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
