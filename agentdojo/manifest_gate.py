"""AAL-style action-manifest gate for AgentDojo v0.1.35.

The bridge deliberately evaluates only the execution-boundary part of AAL:
independent authority, exact action binding, single-use budgets, and fail-closed
tool execution. AgentDojo does not provide physical target sensing, so the
embodied identity/spatial claims remain supported by the robot experiments.
"""
from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

MUTATING_PREFIXES = (
    "add_", "book_", "buy_", "cancel_", "create_", "delete_", "edit_",
    "invite_", "make_", "move_", "pay_", "post_", "purchase_", "remove_",
    "reserve_", "schedule_", "send_", "set_", "share_", "transfer_", "update_",
    "upload_", "write_",
)


def _plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    if isinstance(value, Mapping):
        return {str(k): _plain(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, float):
        return float(f"{value:.12g}")
    return value


# Fields whose value is free-text content rather than a determinant of the
# action's effect. Authorization binds who/what an action affects and by how
# much; it does not bind the wording. This mirrors the robot-side certificate,
# which binds capability, target, tool, room, and envelope but not phrasing.
#
# Consequence, stated explicitly: when an injection reaches its goal purely by
# changing content inside an action the user already authorized (for example a
# link placed in a direct message to a recipient the user chose), the gate has
# no authority-level basis to refuse it. Those pairs are reported as
# `authority_overlap` and excluded from the in-scope denominator; content
# safety belongs to the planner's refusal layer, not to this one.
EFFECT_UNBOUND_FIELDS = frozenset({
    "body", "subject", "description", "content", "title", "text", "message",
    "note", "comment", "query", "date",
})
# Note the distinction this set encodes: a field is unbound when it carries
# narrative text the agent composes, not when it carries a value the action
# sets. `password` therefore stays bound -- the value written IS the effect,
# and AgentDojo's own user tasks specify it verbatim in the prompt, so binding
# it costs no benign utility while separating the attacker's chosen value.


def effect_fields(args: Mapping[str, Any]) -> dict:
    return {k: v for k, v in args.items() if k not in EFFECT_UNBOUND_FIELDS}


def call_signature(function: str, args: Mapping[str, Any]) -> str:
    payload = {"function": function, "args": _plain(effect_fields(args))}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def function_call_signature(call: Any) -> str:
    return call_signature(call.function, call.args)


def derive_sensitive_tools(suite: Any, environment: Any) -> set[str]:
    """Derive side-effect/security-sensitive tools without benchmark patching.

    Injection-task ground truths are authoritative examples of attacker side
    effects. Prefix matching additionally covers legitimate mutators that do
    not happen to appear in an injection-task ground truth.
    """
    sensitive = {
        tool.name
        for tool in suite.tools
        if tool.name.lower().startswith(MUTATING_PREFIXES)
    }
    for task in suite.injection_tasks.values():
        try:
            calls = task.ground_truth(environment.model_copy(deep=True))
        except Exception:
            continue
        sensitive.update(call.function for call in calls)
    return sensitive


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    sensitive: bool
    reason: str
    signature: str


@dataclass
class ManifestAudit:
    allowed_sensitive: int = 0
    allowed_read_only: int = 0
    denied_sensitive: int = 0
    released_after_error: int = 0
    records: list[dict[str, Any]] = field(default_factory=list)

    def add(self, *, function: str, decision: GateDecision, args: Mapping[str, Any]) -> None:
        if decision.sensitive and decision.allowed:
            self.allowed_sensitive += 1
        elif decision.sensitive:
            self.denied_sensitive += 1
        else:
            self.allowed_read_only += 1
        self.records.append({
            "function": function,
            "args": _plain(dict(args)),
            "allowed": decision.allowed,
            "sensitive": decision.sensitive,
            "reason": decision.reason,
            "signature": decision.signature,
        })


class TaskActionManifest:
    """Single-use authorization budget derived from a trusted user-task plan."""

    def __init__(
        self,
        authorized_calls: Iterable[Any],
        sensitive_tools: set[str],
        *,
        authority_id: str,
    ) -> None:
        self.authority_id = authority_id
        self.sensitive_tools = frozenset(sensitive_tools)
        self._template = Counter(
            function_call_signature(call)
            for call in authorized_calls
            if call.function in self.sensitive_tools
        )
        self.audit = ManifestAudit()
        self.reset()

    @classmethod
    def from_user_task(cls, suite: Any, user_task: Any, clean_environment: Any) -> "TaskActionManifest":
        environment = clean_environment.model_copy(deep=True)
        if hasattr(user_task, "init_environment"):
            environment = user_task.init_environment(environment)
        authorized_calls = user_task.ground_truth(environment.model_copy(deep=True))
        sensitive = derive_sensitive_tools(suite, environment)
        return cls(authorized_calls, sensitive, authority_id=f"{suite.name}:{user_task.ID}")

    @property
    def authorized_sensitive_count(self) -> int:
        return sum(self._template.values())

    @property
    def authorized_signatures(self) -> Counter[str]:
        return self._template.copy()

    def reset(self) -> None:
        self._remaining = self._template.copy()

    def authorize(self, function: str, args: Mapping[str, Any]) -> GateDecision:
        signature = call_signature(function, args)
        if function not in self.sensitive_tools:
            decision = GateDecision(True, False, "read_only_or_non_mutating", signature)
        elif self._remaining[signature] > 0:
            self._remaining[signature] -= 1
            decision = GateDecision(True, True, "authorized_manifest_match", signature)
        else:
            decision = GateDecision(False, True, "not_authorized_by_task_manifest", signature)
        self.audit.add(function=function, decision=decision, args=args)
        return decision

    def release(self, decision: GateDecision) -> None:
        if decision.allowed and decision.sensitive:
            self._remaining[decision.signature] += 1
            self.audit.released_after_error += 1

    def replay(self, calls: Iterable[Any]) -> list[GateDecision]:
        self.reset()
        return [self.authorize(call.function, copy.deepcopy(call.args)) for call in calls]

    def classify_injection_calls(self, calls: Iterable[Any]) -> dict[str, Any]:
        """Classify an injection ground-truth sequence against this authority.

        Three disjoint outcomes:

        - ``no_sensitive_effect``: the attack needs no security-sensitive call.
        - ``authority_overlap``: every sensitive effect it needs is already
          authorized by the user task, so no authorization layer can refuse it.
        - ``in_scope``: it needs at least one sensitive effect outside the
          user's authority.

        ``in_scope`` is a property of the attack relative to the authority, and
        is what a containment claim may be measured over. It is deliberately
        NOT reported alongside a same-expression "contained" flag: in a
        ground-truth replay the gate's decision is manifest membership, so such
        a rate would be true by construction. Containment under a live agent is
        measured by the benchmark's own security predicate, not here.
        """
        calls = list(calls)
        decisions = self.replay(calls)
        sensitive = [d for d in decisions if d.sensitive]
        denied = [d for d in sensitive if not d.allowed]
        return {
            "requires_sensitive": bool(sensitive),
            "in_scope": bool(denied),
            "sensitive_call_count": len(sensitive),
            "denied_sensitive_call_count": len(denied),
            "authority_overlap": bool(sensitive) and not denied,
            "no_sensitive_effect": not sensitive,
            "decisions": [d.__dict__ for d in decisions],
        }
