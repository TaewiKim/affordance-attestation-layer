"""Trusted order source and protocol engine (removes the ground-truth oracle).

Reviewer point: the certifier must NOT consult a magic ``correct_target_id``. In a real system the
authorized target comes from a signed task order (pharmacy/EHR/scheduler) and a protocol state
machine, and target binding is decided by whether *authenticated sensor readings of the physically
present entity* agree with that signed order. This module supplies exactly that, so the verifier
never sees ground truth --- only a signed order plus sensor readings that may be wrong or spoofed.

Trust assumptions (stated in the paper as A1-A6):
  A1 order-authority signing key is uncompromised
  A3 sensor evidence is authenticated at the reader (see limitation: physical tag spoofing)
  A5 protocol-state source is trusted
The scenario's ground truth is kept OUT of this module and used only by the scorer.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field

from .types import Capability

_DEVELOPMENT_ORDER_SECRET = "order_authority_hmac_key"


def order_signing_secret() -> str:
    """Return the authority key; the source fallback is simulation-only."""
    return os.environ.get("AAL_ORDER_AUTHORITY_SECRET", _DEVELOPMENT_ORDER_SECRET)


def has_external_order_secret() -> bool:
    value = os.environ.get("AAL_ORDER_AUTHORITY_SECRET", "")
    return len(value) >= 32 and value != _DEVELOPMENT_ORDER_SECRET


@dataclass
class TaskOrder:
    """A signed authorization issued by a trusted order source, independent of the planner."""
    order_id: str
    capability: Capability
    authorized_target_id: str          # who/what the order authorizes action on
    authorized_recipient_id: str = ""  # for handoff: authorized recipient
    protocol_sequence: tuple = ()      # ordered protocol steps this order must follow
    room: str = ""
    tool_id: str = ""
    signature: str = ""
    issued_at_unix_s: float = 0.0
    valid_until_unix_s: float = 0.0

    def _payload(self) -> str:
        return "|".join([
            self.order_id, self.capability.value, self.authorized_target_id,
            self.authorized_recipient_id, ",".join(self.protocol_sequence),
            self.room, self.tool_id,
            f"{self.issued_at_unix_s:.6f}", f"{self.valid_until_unix_s:.6f}",
        ])

    def sign(self) -> "TaskOrder":
        self.signature = hmac.new(order_signing_secret().encode(), self._payload().encode(),
                                  hashlib.sha256).hexdigest()[:24]
        return self

    def verify(self, now_unix_s: float | None = None) -> bool:
        """MAC check plus, when a clock is supplied, the order's validity interval.

        An authenticated but expired (or not-yet-valid) order must not anchor a new
        issuance: otherwise a stale order for a completed task remains a usable
        authority anchor indefinitely. ``valid_until_unix_s == 0`` means the order
        carries no expiry (used by fixtures that predate the field)."""
        expected = hmac.new(order_signing_secret().encode(), self._payload().encode(),
                            hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(expected, self.signature):
            return False
        if now_unix_s is None or self.valid_until_unix_s <= 0.0:
            return True
        return self.issued_at_unix_s <= now_unix_s <= self.valid_until_unix_s


class ProtocolEngine:
    """Tracks the authorized protocol step per order; the certifier queries it (never the world)."""

    def __init__(self):
        self._completed: dict[str, set[str]] = {}
        self._current: dict[str, str] = {}

    def set_state(self, order: TaskOrder, current_step: str, completed_steps=None):
        self._current[order.order_id] = current_step
        self._completed[order.order_id] = set(completed_steps or [])

    def current_step(self, order: TaskOrder) -> str:
        return self._current.get(order.order_id, "")

    def step_satisfied(self, order: TaskOrder, required_step: str) -> bool:
        """A capability is protocol-authorized iff its required step is the current step AND all
        earlier steps in the order sequence are completed (enforces ordering, not just presence)."""
        if not required_step:
            return True
        if self._current.get(order.order_id) != required_step:
            return False
        seq = list(order.protocol_sequence)
        if required_step in seq:
            idx = seq.index(required_step)
            done = self._completed.get(order.order_id, set())
            return all(s in done for s in seq[:idx])
        return True


def make_order(order_id, capability, target, recipient="", protocol_sequence=(),
               room="", tool_id="") -> TaskOrder:
    return TaskOrder(order_id, capability, target, recipient,
                     tuple(protocol_sequence), room, tool_id).sign()
