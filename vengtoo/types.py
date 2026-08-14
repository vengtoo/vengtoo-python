from __future__ import annotations

from dataclasses import dataclass
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
            # Type-level check: default id to "*" so type-wide policies evaluate.
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
class EvaluationRequest:
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
class EvaluationContext:
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
class EvaluationResponse:
    decision: bool
    context: EvaluationContext | None = None


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
    evaluations: list[EvaluationResponse]


def _resource_template_dict(r: Resource) -> dict[str, Any]:
    """Serializes a Resource without the type-level ``id="*"`` defaulting that
    ``Resource.to_dict`` applies. AuthZEN Search passes a bare type template
    (e.g. ``Resource(type="document")``) to search the whole type, so injecting
    a wildcard id would misrepresent the query."""
    d: dict[str, Any] = {}
    if r.id:
        d["id"] = r.id
    if r.external_id:
        d["external_id"] = r.external_id
    if r.type:
        d["type"] = r.type
    if r.properties:
        d["properties"] = r.properties
    return d


@dataclass
class SearchOptions:
    #: What the response should include: "filter" (default), "results", or "both".
    return_: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.return_:
            d["return"] = self.return_
        return d


@dataclass
class SearchRequest:
    """Input for an AuthZEN Search (list-filtering) query. Which fields are the
    query constraints and which is the searched dimension depends on the variant
    called (search_resource / search_subject / search_action). The searched
    dimension may be omitted or given only a type template."""

    subject: Subject | None = None
    action: Action | None = None
    resource: Resource | None = None
    context: dict[str, Any] | None = None
    options: SearchOptions | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.subject:
            d["subject"] = self.subject.to_dict()
        if self.action:
            d["action"] = self.action.to_dict()
        if self.resource:
            d["resource"] = _resource_template_dict(self.resource)
        if self.context:
            d["context"] = self.context
        if self.options:
            d["options"] = self.options.to_dict()
        return d


@dataclass
class SearchResponse:
    #: UCAST-style filter object (Vengtoo's own condition tree) describing the
    #: matching set as a predicate. Returned as received; the ``ucast_to_sql``
    #: helper can translate it to a parameterized SQL WHERE clause.
    filter: dict[str, Any] | None = None
    #: Concrete matching items, present when the request asked for "results" or "both".
    results: list[Any] | None = None
    context: EvaluationContext | None = None


@dataclass
class CreateDelegationRequest:
    delegate_id: str
    delegator_id: str
    #: Free-text label shown in audit and the dashboard.
    description: str | None = None
    #: Narrows the delegation to specific permissions of the delegator. Omit
    #: for the delegator's full scope. The delegate's effective permissions
    #: are always the intersection of its own policies and the delegator's —
    #: attenuation, never escalation.
    scope: list[str] | None = None
    #: ISO 8601 timestamp at which the delegation automatically expires.
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "delegate_id": self.delegate_id,
            "delegator_id": self.delegator_id,
        }
        if self.description:
            d["description"] = self.description
        if self.scope:
            d["scope"] = self.scope
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d


@dataclass
class Delegation:
    id: str
    delegate_id: str
    delegator_id: str
    created_at: str
    description: str | None = None
    scope: list[str] | None = None
    expires_at: str | None = None
    revoked_at: str | None = None
