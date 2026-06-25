from dataclasses import dataclass, field
from typing import Any


@dataclass
class Subject:
    type: str
    id: str | None = None
    external_id: str | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.id:
            d["id"] = self.id
        if self.external_id:
            d["external_id"] = self.external_id
        if self.type:
            d["type"] = self.type
        if self.properties:
            d["properties"] = self.properties
        return d


@dataclass
class Resource:
    type: str
    id: str | None = None
    external_id: str | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.id:
            d["id"] = self.id
        elif not self.external_id:
            d["id"] = "*"
        if self.external_id:
            d["external_id"] = self.external_id
        if self.type:
            d["type"] = self.type
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
    # HITL fields — present when reason_code is "authorization_pending".
    auth_req_id: str | None = None
    approval_id: str | None = None
    expires_in: int | None = None
    interval: int | None = None


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


@dataclass
class CreateDelegationRequest:
    delegate_id: str
    delegator_id: str
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "delegate_id": self.delegate_id,
            "delegator_id": self.delegator_id,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d


@dataclass
class Delegation:
    id: str
    delegate_id: str
    delegator_id: str
    created_at: str
    expires_at: str | None = None
    revoked_at: str | None = None
