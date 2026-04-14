from dataclasses import dataclass, field
from typing import Any


@dataclass
class Subject:
    id: str
    type: str | None = None
    attributes: dict[str, Any] | None = None
    roles: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.type:
            d["type"] = self.type
        if self.attributes:
            d["attributes"] = self.attributes
        if self.roles:
            d["roles"] = self.roles
        return d


@dataclass
class Resource:
    id: str
    type: str | None = None
    attributes: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.type:
            d["type"] = self.type
        if self.attributes:
            d["attributes"] = self.attributes
        return d


@dataclass
class AuthorizeRequest:
    subject: Subject
    resource: Resource
    action: str
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "subject": self.subject.to_dict(),
            "resource": self.resource.to_dict(),
            "action": self.action,
        }
        if self.context:
            d["context"] = self.context
        return d


@dataclass
class AuthorizeResponse:
    allowed: bool
    reason: str
    policy_id: str | None = None
    access_path: str | None = None
