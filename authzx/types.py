from dataclasses import dataclass, field
from typing import Any


@dataclass
class Subject:
    id: str
    type: str | None = None
    attributes: dict[str, Any] | None = None
    properties: dict[str, Any] | None = None
    roles: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.type:
            d["type"] = self.type
        if self.attributes:
            d["attributes"] = self.attributes
        if self.properties:
            d["properties"] = self.properties
        if self.roles:
            d["roles"] = self.roles
        return d


@dataclass
class Resource:
    id: str
    type: str | None = None
    attributes: dict[str, Any] | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.type:
            d["type"] = self.type
        if self.attributes:
            d["attributes"] = self.attributes
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class Action:
    name: str
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name}
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class AuthorizeRequest:
    subject: Subject
    resource: Resource
    action: Action
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "subject": self.subject.to_dict(),
            "resource": self.resource.to_dict(),
            "action": self.action.to_dict(),
        }
        if self.context:
            d["context"] = self.context
        return d


@dataclass
class AuthorizeContext:
    reason: str | None = None
    reason_code: str | None = None
    policy_id: str | None = None
    access_path: str | None = None


@dataclass
class AuthorizeResponse:
    decision: bool
    context: AuthorizeContext | None = None


@dataclass
class BatchEvalItem:
    subject: Subject | None = None
    action: Action | None = None
    resource: Resource | None = None
    context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.subject:
            d["subject"] = self.subject.to_dict()
        if self.action:
            d["action"] = self.action.to_dict()
        if self.resource:
            d["resource"] = self.resource.to_dict()
        if self.context:
            d["context"] = self.context
        return d


@dataclass
class BatchOptions:
    evaluations_semantic: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.evaluations_semantic:
            d["evaluations_semantic"] = self.evaluations_semantic
        return d


@dataclass
class BatchEvaluationRequest:
    evaluations: list[BatchEvalItem]
    subject: Subject | None = None
    action: Action | None = None
    resource: Resource | None = None
    context: dict[str, Any] | None = None
    options: BatchOptions | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "evaluations": [e.to_dict() for e in self.evaluations],
        }
        if self.subject:
            d["subject"] = self.subject.to_dict()
        if self.action:
            d["action"] = self.action.to_dict()
        if self.resource:
            d["resource"] = self.resource.to_dict()
        if self.context:
            d["context"] = self.context
        if self.options:
            d["options"] = self.options.to_dict()
        return d


@dataclass
class BatchEvaluationResponse:
    evaluations: list[AuthorizeResponse]
