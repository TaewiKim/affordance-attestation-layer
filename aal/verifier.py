"""Certificate verifier / issuer --- the deterministic root-of-trust.

Refactored to remove the ground-truth oracle. The certifier's target decision is now:
  (request target == signed order's authorized target)  AND
  (authenticated sensor readings of the present entity agree with that same order, with
   sufficient fused confidence and no unresolved sensor conflict).
It never reads ``correct_target_id``; the only trusted anchors are a signed TaskOrder
(from a pharmacy/EHR authority) and the sensor readings themselves.
"""
from __future__ import annotations

import hashlib
import math
import os

from .types import (
    ActionRequest, Certificate, Denial, Decision, Evidence, WorldState,
    SafetyEnvelope, Capability, Clock,
    CONTACT_CAPABILITIES, LOW_RISK_CAPABILITIES,
)
from .authority import TaskOrder, ProtocolEngine

CONFIDENCE_THRESHOLD = {
    Capability.HANDOFF: 0.90, Capability.TOUCH: 0.90, Capability.SCAN: 0.90,
    Capability.GRASP: 0.85, Capability.APPROACH: 0.80, Capability.NAVIGATE: 0.70,
    Capability.OBSERVE: 0.50, Capability.SPEAK: 0.50,
}
TTL_MS = {
    Capability.HANDOFF: 500, Capability.TOUCH: 500, Capability.SCAN: 500,
    Capability.GRASP: 800, Capability.APPROACH: 1000, Capability.NAVIGATE: 2000,
    Capability.OBSERVE: 3000, Capability.SPEAK: 3000,
}
# Evidence older than this (per capability) is stale and cannot support a certificate.
MAX_EVIDENCE_AGE_MS = {
    Capability.HANDOFF: 500, Capability.TOUCH: 500, Capability.SCAN: 500,
    Capability.GRASP: 800, Capability.APPROACH: 1000, Capability.NAVIGATE: 2000,
    Capability.OBSERVE: 3000, Capability.SPEAK: 3000,
}
# visual_id: object identity from a calibrated camera's visual signature (the
# bench rig's D435/C270 pair) -- an identity modality alongside tag readers
IDENTITY_EVIDENCE_TYPES = {"barcode", "rfid", "wristband", "face_staff", "visual_id"}
LOCATION_EVIDENCE_TYPES = {"rgbd_pose"}
LOCATION_BOUND_CAPABILITIES = {Capability.NAVIGATE}

_DEVELOPMENT_SIGNING_SECRET = "aal_root_of_trust_secret"

from . import ledger as ledger_mod                     # noqa: E402
from .ledger import AuthorizationLedger                # noqa: E402


def endpoint_agrees(req, cert) -> bool:
    """Does the request's spatial endpoint still match the certificate's binding?

    Three ways it can disagree, all refused: the two disagree on whether an
    endpoint exists at all (adding one after an endpoint-free issuance, or
    stripping one from a pose-bound certificate), the frames differ (identical
    coordinates in different frames are different places, and this prototype
    carries no trusted transform), or the endpoint has moved outside the
    certified tolerance of the bound target pose.

    Shared by the kernel's admission check and runtime re-attestation so the two
    cannot drift apart.
    """
    endpoint = req.params.get("target_position_m")
    if endpoint is None and cert.target_pose_m is None:
        return True
    if (endpoint is None) != (cert.target_pose_m is None):
        return False
    frame = req.params.get("target_position_frame", "")
    if not frame or frame != cert.pose_frame:
        return False
    return math.dist([float(v) for v in endpoint],
                     [float(v) for v in cert.target_pose_m]) <= float(
                         cert.position_tolerance_m)


class AALVerifier:
    def __init__(self, clock: Clock, config: dict | None = None,
                 ledger: "AuthorizationLedger | None" = None):
        self.clock = clock
        cfg = config or {}
        # consumption ledger: per-authorization-instance execution state
        # (execution budget 1), shared with the kernel. Durable by default, so a
        # certifier restart cannot resurrect a consumed instance; an evaluation harness
        # that must not inherit state across runs asks for the in-memory form
        # explicitly via {"ephemeral_ledger": True} (see AuthorizationLedger).
        if ledger is not None:
            self.ledger = ledger
        elif cfg.get("ephemeral_ledger", False):
            self.ledger = AuthorizationLedger.ephemeral()
        else:
            self.ledger = AuthorizationLedger.durable()
        self.enable_target = cfg.get("enable_target", True)
        self.enable_expiry = cfg.get("enable_expiry", True)
        self.enable_protocol = cfg.get("enable_protocol", True)
        self.enable_envelope = cfg.get("enable_envelope", True)
        self.require_two_factor = cfg.get("require_two_factor", True)
        self.trust_order = cfg.get("trust_order", True)   # False => no signed-order anchor (ablation)
        # optional global confidence-threshold override for sensitivity/ROC analysis
        self.conf_override = cfg.get("confidence_threshold_override", None)
        # spatial binding: a named endpoint must sit within this distance of where an
        # authenticated reader observed the authorized target (Sec. III)
        self.position_tolerance_m = float(cfg.get("position_tolerance_m", 0.15))
        self._nonce = 0

    @classmethod
    def for_deployment(cls, clock: Clock, config: dict | None = None,
                       ledger_path: str | None = None) -> "AALVerifier":
        """Constructor for a deployed certifier (the hardware stack uses this one).

        The authorization ledger is durable: it is opened on disk, so an instance
        consumed before a restart stays consumed afterwards. `ledger_path` defaults to
        AAL_LEDGER_PATH, else the package-local state file. Passing
        {"ephemeral_ledger": True} here is a contradiction and is refused.
        """
        cfg = dict(config or {})
        if cfg.pop("ephemeral_ledger", False):
            raise ValueError("a deployed certifier cannot use an in-memory ledger")
        return cls(clock, cfg, ledger=AuthorizationLedger.durable(ledger_path))

    def _thr(self, capability):
        return self.conf_override if self.conf_override is not None else CONFIDENCE_THRESHOLD[capability]

    # --- fusion of sensor readings against the ORDER's authorized target ---
    def _fused_confidence_vs_order(self, authorized_target: str, evidence: list[Evidence],
                                   accept_types: set) -> tuple[float, int, bool]:
        """Confidence that the present entity == the order's authorized target.
        Returns (fused_confidence, n_agreeing_factors, conflict_present)."""
        matching = [e for e in evidence
                    if e.type in accept_types and e.value == authorized_target]
        conflicting = [e for e in evidence
                       if e.type in accept_types and e.value != authorized_target]
        if not matching:
            return 0.0, 0, bool(conflicting)
        agree = 1.0
        for e in matching:
            agree *= (1.0 - e.confidence)
        fused = 1.0 - agree
        if conflicting:
            fused *= 0.5
        n_factors = len({e.type for e in matching})
        return fused, n_factors, bool(conflicting)

    def _fresh(self, evidence, capability):
        """Drop evidence older than the per-capability max age (freshness enforcement)."""
        max_age = MAX_EVIDENCE_AGE_MS[capability]
        now = self.clock.now()
        return [e for e in evidence if 0.0 <= (now - e.timestamp_ms) <= max_age]

    def _verify_target(self, req, order, evidence):
        if not self.enable_target:
            return True, 1.0, "target_check_disabled"
        # The request must be for the target the order authorizes.
        if req.target_id != order.authorized_target_id:
            return False, 0.0, "target_not_authorized_by_order"
        accept = (LOCATION_EVIDENCE_TYPES if req.capability in LOCATION_BOUND_CAPABILITIES
                  else IDENTITY_EVIDENCE_TYPES)
        relevant = [e for e in evidence if e.type in accept]
        fresh = self._fresh(evidence, req.capability)
        if relevant and not [e for e in fresh if e.type in accept]:
            return False, 0.0, "evidence_stale"       # had relevant evidence, but all too old
        conf, n_factors, conflict = self._fused_confidence_vs_order(
            order.authorized_target_id, fresh, accept)
        thr = self._thr(req.capability)
        if conflict and conf < thr:
            return False, conf, "sensor_conflict"
        if conf < thr:
            return False, conf, f"confidence_{conf:.2f}_below_{thr:.2f}"
        if self.require_two_factor and req.capability in CONTACT_CAPABILITIES and n_factors < 2:
            return False, conf, "insufficient_binding_factors"
        return True, conf, "ok"

    def _verify_geometry(self, req, order, world):
        room = order.room or req.room
        if room and world.room and room != world.room:
            return False, "wrong_room"
        if req.capability in CONTACT_CAPABILITIES and not world.workspace_clear:
            return False, "workspace_not_clear"
        return True, "ok"

    def _verify_endpoint(self, req, evidence):
        """Bind WHERE the action goes, not just what it names.

        An identity match alone leaves a gap: a planner could certify "grasp
        box_teal" while streaming the controller toward some other in-workspace
        location. When the request names a spatial endpoint
        (``params["target_position_m"]``), at least one authenticated reader must
        have observed the AUTHORIZED target within ``position_tolerance_m`` of that
        endpoint; with no such observation the request fails closed. Requests
        without a spatial endpoint (planner-space benchmarks, streamed sweeps
        certified per tick) are outside this check's scope by construction.

        Returns (ok, reason, sensed_pose, frame)."""
        endpoint = req.params.get("target_position_m")
        if endpoint is None:
            return True, "no_spatial_endpoint", None, ""
        if req.capability not in CONTACT_CAPABILITIES:
            return True, "non_contact", None, ""
        # frames are part of the binding: identical coordinates in different frames
        # are different places, and this prototype carries no trusted transform, so
        # anything but an exact frame match fails closed
        req_frame = req.params.get("target_position_frame", "")
        if not req_frame:
            return False, "endpoint_frame_unspecified", None, ""
        tol = self.position_tolerance_m
        # freshness applies to the posed observation too: an old reading must not
        # ground a fresh spatial binding any more than it may ground identity
        fresh = self._fresh(evidence, req.capability) if self.enable_expiry else evidence
        posed = [e for e in fresh
                 if e.value == req.target_id and getattr(e, "pose_m", None) is not None]
        sensed = [e for e in posed if e.frame == req_frame]
        if not sensed:
            if posed:
                return False, "endpoint_frame_mismatch", None, ""
            return False, "no_sensed_pose_for_authorized_target", None, ""
        endpoint = [float(v) for v in endpoint]
        best = min(sensed, key=lambda e: math.dist(endpoint, [float(v) for v in e.pose_m]))
        distance = math.dist(endpoint, [float(v) for v in best.pose_m])
        if distance > tol:
            return False, "endpoint_not_at_sensed_target", None, ""
        return True, "ok", [float(v) for v in best.pose_m], best.frame

    def _verify_tool(self, req, order, world):
        if req.capability == Capability.SCAN:
            if not world.tool_state.get("calibrated", False):
                return False, "tool_uncalibrated"
            want = order.tool_id or req.tool
            have = world.tool_state.get("tool_id")
            if want and have and want != have:
                return False, "wrong_tool"
        return True, "ok"

    def _verify_protocol(self, req, order, protocol: ProtocolEngine):
        if not self.enable_protocol:
            return True, "protocol_check_disabled"
        if req.capability in LOW_RISK_CAPABILITIES:
            return True, "ok"
        if not protocol.step_satisfied(order, req.protocol_step):
            return False, f"protocol_step_not_satisfied_{req.protocol_step}"
        return True, "ok"

    def _build_envelope(self, req, world) -> SafetyEnvelope:
        return SafetyEnvelope(
            max_speed_mps=0.15 if req.capability in CONTACT_CAPABILITIES else 0.5,
            max_force_n=2.0 if req.capability in CONTACT_CAPABILITIES else 10.0,
            allowed_region=world.room,
            abort_if=["workspace_intrusion", "identity_confidence_below_0.90", "target_moved"],
        )

    def certify(self, req: ActionRequest, world: WorldState, evidence: list[Evidence],
                order: TaskOrder | None, protocol: ProtocolEngine,
                _renew_instance: str | None = None):
        """Issue a certificate. ``_renew_instance`` is set only by ``renew`` for an
        instance whose reservation the caller already holds, so the ledger's
        one-execution meter is not tripped by a legitimate mid-execution renewal."""
        # A valid signed order authorizing this capability is the entry anchor.
        if self.trust_order:
            if order is None or not order.verify():
                return Denial("order:missing_or_invalid_mac", Decision.BLOCK)
            # an authenticated but expired order is not a usable authority anchor.
            # Order timestamps are Unix wall time issued by an external authority, so
            # they are checked on the wall clock, never the monotonic execution clock
            # (whose epoch is arbitrary and would reject every dated order).
            if not order.verify(now_unix_s=self.clock.wall_now_unix_s()):
                return Denial("order:outside_validity_interval", Decision.BLOCK)
            if order.capability != req.capability:
                return Denial("order:capability_not_ordered", Decision.BLOCK)

        if req.capability in LOW_RISK_CAPABILITIES:
            return self._issue(req, world, evidence, order, _renew_instance)

        # --- consumption check: one execution per authorization instance ---
        # Checked immediately after the order anchor (the instance is an order-level
        # notion). Single-use certificate ids stop token replay; this stops a fresh
        # token being minted for an already-consumed authorization instance.
        # (Real signed orders only; the trust_order-disabled ablation has no durable
        # authorization instance to meter.)
        if self.trust_order and order is not None and _renew_instance is None:
            state = self.ledger.status(
                ledger_mod.instance_key(order.order_id, req.protocol_step,
                                        req.capability.value, req.target_id),
                self.clock.now())
            if state == ledger_mod.CONSUMED:
                return Denial("replay:authorization_instance_consumed", Decision.BLOCK)
            if state == ledger_mod.RESERVED:
                return Denial("replay:authorization_instance_reserved", Decision.BLOCK)

        # Fabricate a permissive pseudo-order only for the trust_order-disabled ablation.
        eff_order = order if order is not None else _pseudo_order(req)

        ok, conf, reason = self._verify_target(req, eff_order, evidence)
        if not ok:
            dec = Decision.BLOCK if reason == "target_not_authorized_by_order" else Decision.DEFER
            return Denial(f"target:{reason}", dec)

        ok, reason = self._verify_geometry(req, eff_order, world)
        if not ok:
            return Denial(f"geometry:{reason}", Decision.BLOCK)

        ok, reason, sensed_pose, pose_frame = self._verify_endpoint(req, evidence)
        if not ok:
            return Denial(f"geometry:{reason}", Decision.BLOCK)

        ok, reason = self._verify_tool(req, eff_order, world)
        if not ok:
            return Denial(f"tool:{reason}", Decision.DEFER)

        ok, reason = self._verify_protocol(req, eff_order, protocol)
        if not ok:
            return Denial(f"protocol:{reason}", Decision.BLOCK)

        return self._issue(req, world, evidence, eff_order, _renew_instance,
                           sensed_pose=sensed_pose, pose_frame=pose_frame)

    def revalidate(self, cert: Certificate, req: ActionRequest, world: WorldState,
                   evidence: list[Evidence]):
        """Re-attest an ALREADY ISSUED certificate against the live world.

        This is the runtime path, and it is deliberately NOT ``certify``: it mints
        no token and never touches the authorization ledger, so per-tick
        revalidation cannot be mistaken for a second issuance of the same
        authorization instance (which the ledger refuses by design). It answers one
        question---is this certificate still true right now---by re-checking the MAC,
        the validity window, the action binding, evidence freshness, and agreement
        between the bound target and what the readers currently see.

        Returns the certificate when it still holds, else a ``Denial``.
        """
        if not cert.verify_signature(signing_secret()):
            return Denial("revalidate:bad_mac", Decision.BLOCK)
        if self.enable_expiry and not cert.valid_at(self.clock.now()):
            return Denial("revalidate:certificate_expired", Decision.BLOCK)
        if cert.capability != req.capability or cert.target_id != req.target_id:
            return Denial("revalidate:binding_mismatch", Decision.BLOCK)
        if req.capability in LOW_RISK_CAPABILITIES:
            return cert

        accept = (LOCATION_EVIDENCE_TYPES if req.capability in LOCATION_BOUND_CAPABILITIES
                  else IDENTITY_EVIDENCE_TYPES)
        fresh = self._fresh(evidence, req.capability)
        if not [e for e in fresh if e.type in accept]:
            return Denial("revalidate:evidence_stale", Decision.BLOCK)
        conf, _factors, conflict = self._fused_confidence_vs_order(
            cert.target_id, fresh, accept)
        thr = self._thr(req.capability)
        if conflict and conf < thr:
            return Denial("revalidate:sensor_conflict", Decision.BLOCK)
        if conf < thr:
            return Denial(f"revalidate:confidence_{conf:.2f}_below_{thr:.2f}",
                          Decision.BLOCK)
        if not endpoint_agrees(req, cert):
            # the commanded endpoint no longer matches what was certified: the
            # request was mutated after issuance (redirected, added, stripped, or
            # re-expressed in another frame)
            return Denial("revalidate:endpoint_outside_binding", Decision.BLOCK)
        if world.present_target_id and world.present_target_id != cert.target_id:
            return Denial("revalidate:target_changed", Decision.BLOCK)
        if not world.workspace_clear and req.capability in CONTACT_CAPABILITIES:
            return Denial("revalidate:workspace_not_clear", Decision.BLOCK)
        return cert

    def renew(self, cert: Certificate, req: ActionRequest, world: WorldState,
              evidence: list[Evidence], order, protocol):
        """Re-attest an in-flight execution whose certificate TTL has lapsed.

        A long certified motion outlives a short-lived token by design, so the
        holder of the outstanding certificate may mint a successor for the SAME
        authorization instance provided every issuance check passes again against
        current evidence (fail-safe-then-resume). This is not a second execution:
        the caller must present the outstanding token, the instance must still be
        RESERVED to that token, and a CONSUMED instance can never be renewed.
        """
        if not cert.verify_signature(signing_secret()):
            return Denial("renew:bad_mac", Decision.BLOCK)
        if cert.capability != req.capability or cert.target_id != req.target_id:
            return Denial("renew:binding_mismatch", Decision.BLOCK)
        key = cert.authorization_instance
        if self.trust_order and key:
            entry = self.ledger._state.get(key)          # holder check
            if entry is None or entry.get("state") != ledger_mod.RESERVED:
                return Denial("renew:instance_not_reserved", Decision.BLOCK)
            if entry.get("certificate_id") != cert.certificate_id:
                return Denial("renew:not_the_outstanding_holder", Decision.BLOCK)
        fresh = self.certify(req, world, evidence, order, protocol,
                             _renew_instance=key)
        return fresh

    def attest_tick(self, cert: Certificate, req: ActionRequest, world: WorldState,
                    evidence: list[Evidence], order, protocol,
                    renew_within_ms: float = 150.0):
        """One runtime control-tick attestation: re-check the live certificate and,
        when its TTL is about to lapse, renew it from current evidence.

        Returns the certificate to keep using (possibly a fresh one) or a Denial,
        which the caller must treat as an abort. This is the only entry point the
        runtime needs; it never opens a second execution of the instance."""
        out = self.revalidate(cert, req, world, evidence)
        if hasattr(out, "is_denial"):
            if out.reason == "revalidate:certificate_expired":
                return self.renew(cert, req, world, evidence, order, protocol)
            return out
        if self.enable_expiry and cert.valid_until_ms - self.clock.now() <= renew_within_ms:
            renewed = self.renew(cert, req, world, evidence, order, protocol)
            if not hasattr(renewed, "is_denial"):
                return renewed
        return cert

    def _issue(self, req, world, evidence, order, renew_instance=None,
               sensed_pose=None, pose_frame="") -> Certificate:
        now = self.clock.now()
        ttl = TTL_MS[req.capability] if self.enable_expiry else 10_000_000
        envelope = self._build_envelope(req, world) if self.enable_envelope else SafetyEnvelope(
            max_speed_mps=1e9, max_force_n=1e9, allowed_region="", abort_if=[])
        self._nonce += 1
        cert_id = hashlib.sha256(
            f"{req.target_id}|{now}|{self._nonce}|{signing_secret()}".encode()).hexdigest()[:32]
        instance = ("" if order is None else ledger_mod.instance_key(
            order.order_id, req.protocol_step, req.capability.value, req.target_id))
        cert = Certificate(
            capability=req.capability, target_id=req.target_id,
            evidence_hashes=[e.hash() for e in evidence], envelope=envelope,
            valid_from_ms=now, valid_until_ms=now + ttl,
            protocol_step=req.protocol_step, tool_id=req.tool, room=world.room,
            certificate_id=cert_id, authorization_instance=instance,
            target_pose_m=sensed_pose, pose_frame=pose_frame,
            position_tolerance_m=(self.position_tolerance_m if sensed_pose is not None
                                  else 0.0),
        ).sign(signing_secret())
        if self.trust_order and instance:
            if renew_instance == instance:
                # mid-execution renewal by the outstanding holder: keep the same
                # reservation, point it at the successor token
                self.ledger.reserve(instance, cert_id, cert.valid_until_ms)
            elif not self.ledger.reserve_if_unused(instance, cert_id,
                                                   cert.valid_until_ms, now):
                # atomic claim: the pre-check above is advisory (it produces the
                # precise denial reason); this is where exactly one of N concurrent
                # requests wins the instance.
                return Denial("replay:authorization_instance_reserved", Decision.BLOCK)
        return cert


def _pseudo_order(req):
    """For the trust_order-disabled ablation only: an order that rubber-stamps the request."""
    from .authority import make_order
    return make_order("PSEUDO", req.capability, req.target_id, room=req.room, tool_id=req.tool)


def signing_secret() -> str:
    """Return the runtime certificate key; the source fallback is simulation-only."""
    return os.environ.get("AAL_CERT_SIGNING_SECRET", _DEVELOPMENT_SIGNING_SECRET)


def has_external_signing_secret() -> bool:
    value = os.environ.get("AAL_CERT_SIGNING_SECRET", "")
    return len(value) >= 32 and value != _DEVELOPMENT_SIGNING_SECRET
