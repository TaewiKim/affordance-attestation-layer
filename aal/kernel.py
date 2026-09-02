"""Certified Action Kernel + Runtime Monitor.

The kernel is the ONLY path to the controller (research plan sec 4.1, 11.1). It refuses any
action lacking a valid, signature-checked certificate whose binding matches the action. The
runtime monitor re-checks the certificate against the *live* world state on every control tick
and aborts on staleness / envelope breach (research plan sec 4.4 properties P1-P3).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import math

from .types import (
    ActionRequest, Certificate, WorldState, Clock, Capability, SafetyEnvelope,
)
from .verifier import endpoint_agrees, signing_secret


@dataclass
class ExecutionResult:
    executed: bool
    aborted: bool = False
    reject_reason: str = ""
    abort_reason: str = ""
    time_to_abort_ms: float | None = None
    audit: list[str] = field(default_factory=list)
    exec_params: dict = field(default_factory=dict)   # action params that reached the controller


class RuntimeMonitor:
    """Re-attests a live certificate against the current world (research plan sec 5 H3)."""

    def __init__(self, clock: Clock, enable: bool = True):
        self.clock = clock
        self.enable = enable

    def check(self, cert: Certificate, req: ActionRequest, world: WorldState) -> tuple[bool, str]:
        """Return (still_ok, reason). Called each control tick during execution.

        Staleness is judged against the live sensor reading (``present_target_id``): if the entity
        the robot now perceives at the acted-on location no longer matches the certificate's bound
        target, the cert is stale and execution aborts. No oracle is consulted.
        """
        if not self.enable:
            return True, "monitor_disabled"
        now = self.clock.now()
        if not cert.valid_at(now):
            return False, "certificate_expired"
        if "workspace_intrusion" in cert.envelope.abort_if and world.human_in_workspace \
                and req.capability in {Capability.HANDOFF, Capability.TOUCH, Capability.SCAN, Capability.GRASP}:
            return False, "workspace_intrusion"
        if "identity_confidence_below_0.90" in cert.envelope.abort_if and world.identity_confidence < 0.90:
            return False, "identity_confidence_dropped"
        if "target_moved" in cert.envelope.abort_if and world.present_target_id != cert.target_id:
            return False, "target_changed"
        return True, "ok"


class CertifiedActionKernel:
    """Gate between planner output and the robot controller."""

    def __init__(self, clock: Clock, monitor: RuntimeMonitor, ledger=None):
        self.clock = clock
        self.monitor = monitor
        self.controller_calls: list[ActionRequest] = []   # spy: what actually reached the controller
        self._used_cert_ids: set[str] = set()             # token replay prevention (single-use certs)
        # consumption ledger shared with the certifier: a COMPLETED execution
        # consumes the authorization instance; an ABORT releases it (retry allowed).
        self.ledger = ledger

    def _binding_matches(self, cert: Certificate, req: ActionRequest) -> bool:
        return cert.capability == req.capability and cert.target_id == req.target_id

    def _params_within_envelope(self, req: ActionRequest, env: SafetyEnvelope) -> bool:
        speed = req.params.get("speed_mps", 0.0)
        force = req.params.get("force_n", 0.0)
        return speed <= env.max_speed_mps and force <= env.max_force_n

    @staticmethod
    def _endpoint_matches_certificate(req: ActionRequest, cert: Certificate) -> bool:
        """Defense in depth for the spatial binding, using the same agreement rule
        the certifier applies at issuance and runtime re-attestation applies per
        tick (aal.verifier.endpoint_agrees), so the three cannot drift apart."""
        return endpoint_agrees(req, cert)

    def execute(self, req: ActionRequest, cert: Certificate | None,
                world: WorldState, monitor_ticks: int = 3,
                tick_ms: float = 150.0,
                world_events: list | None = None) -> ExecutionResult:
        """Attempt to run `req`. Enforces the full invariant from research plan sec 4.3.

        world_events: optional list of (tick_index, mutation_fn) applied before each tick to
        simulate dynamic-state changes (person enters, target moves) for H3 scenarios.
        """
        audit: list[str] = []
        t_start = self.clock.now()

        # --- P1: no certificate => never reaches controller ---
        if cert is None:
            return ExecutionResult(False, reject_reason="no_certificate", audit=["reject:no_certificate"])
        if not cert.verify_signature(signing_secret()):
            return ExecutionResult(False, reject_reason="bad_signature", audit=["reject:bad_signature"])
        if not self._binding_matches(cert, req):
            return ExecutionResult(False, reject_reason="binding_mismatch",
                                   audit=["reject:binding_mismatch"])
        if not cert.valid_at(self.clock.now()):
            return ExecutionResult(False, reject_reason="certificate_expired",
                                   audit=["reject:certificate_expired"])
        if not self._params_within_envelope(req, cert.envelope):
            return ExecutionResult(False, reject_reason="envelope_violation",
                                   audit=["reject:envelope_violation"])
        if not self._endpoint_matches_certificate(req, cert):
            return ExecutionResult(False, reject_reason="endpoint_outside_binding",
                                   audit=["reject:endpoint_outside_binding"])
        if cert.certificate_id and cert.certificate_id in self._used_cert_ids:
            return ExecutionResult(False, reject_reason="replayed_certificate",
                                   audit=["reject:replayed_certificate"])
        if cert.certificate_id:
            self._used_cert_ids.add(cert.certificate_id)

        # --- action admitted; simulate execution under runtime monitoring ---
        audit.append(f"admit:{req.capability.value}->{req.target_id}")
        self.controller_calls.append(req)
        exec_params = dict(req.params)
        events = dict(world_events or [])
        for i in range(monitor_ticks):
            if i in events:
                events[i](world)                     # apply dynamic-state mutation
            ok, reason = self.monitor.check(cert, req, world)
            if not ok:
                t_abort = self.clock.now() - t_start
                audit.append(f"abort:{reason}@tick{i}")
                if self.ledger is not None and cert.authorization_instance:
                    self.ledger.release(cert.authorization_instance)
                return ExecutionResult(True, aborted=True, abort_reason=reason,
                                       time_to_abort_ms=t_abort, audit=audit,
                                       exec_params=exec_params)
            self.clock.advance(tick_ms)
        audit.append("complete")
        if self.ledger is not None and cert.authorization_instance:
            self.ledger.consume(cert.authorization_instance)
        return ExecutionResult(True, aborted=False, audit=audit, exec_params=exec_params)
