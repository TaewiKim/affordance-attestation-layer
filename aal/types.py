"""AAL core data types.

Defines the certificate schema and the action model the kernel admits against.
Pure-Python, no ML dependencies, so this layer is testable independently of any VLA.
"""
from __future__ import annotations

import time
import hmac
import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# Deterministic clock so scenarios are reproducible. Real deployment would use time.monotonic().
class Clock:
    """Monotonic virtual clock (milliseconds). Advanced explicitly by the scenario harness.

    Two clock domains, deliberately separate: ``now()`` is the EXECUTION clock
    (certificate TTLs, evidence freshness, runtime monitoring) and may be monotonic
    with an arbitrary epoch; ``wall_now_unix_s()`` is the WALL clock used only to
    check externally issued TaskOrder validity windows, whose timestamps are Unix
    seconds. A deployment clock built on time.monotonic() MUST override
    wall_now_unix_s() with real wall time, or every order carrying an expiry would
    be rejected (the monotonic epoch is decades before any order's issue time)."""

    def __init__(self, start_ms: float = 0.0):
        self._now = float(start_ms)

    def now(self) -> float:
        return self._now

    def wall_now_unix_s(self) -> float:
        # virtual clocks run scenarios in a self-consistent time base, so the wall
        # domain coincides with the execution domain
        return self.now() / 1000.0

    def advance(self, ms: float) -> float:
        self._now += ms
        return self._now


class Decision(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_MONITOR = "allow_with_monitor"
    DEFER = "defer"
    BLOCK = "block"


class Capability(str, Enum):
    HANDOFF = "handoff"
    TOUCH = "touch"
    APPROACH = "approach"
    SCAN = "scan"
    GRASP = "grasp"
    NAVIGATE = "navigate"
    OBSERVE = "observe"
    SPEAK = "speak"


# Which capabilities physically actuate near/at a person. These require strict certificates.
CONTACT_CAPABILITIES = {Capability.HANDOFF, Capability.TOUCH, Capability.SCAN, Capability.GRASP}
# Non-physical or low-risk capabilities may receive auto-certificates.
LOW_RISK_CAPABILITIES = {Capability.OBSERVE, Capability.SPEAK}


@dataclass
class Evidence:
    """A single authenticated sensor observation feeding target/tool/geometry verification."""
    type: str                      # barcode | rfid | rgbd_pose | wristband | force | face_staff
    value: str                     # observed id / reading (what the sensor actually saw)
    confidence: float              # [0,1]
    timestamp_ms: float            # when the observation was captured (for freshness checks)
    reader_id: str = ""            # which authenticated reader produced it (A3)
    pose_m: Optional[list] = None  # observed position of the entity, metres in `frame`
    frame: str = ""                # reference frame of pose_m (e.g. "robot_base")

    def hash(self) -> str:
        # bind value, confidence, timestamp, reader, and observed pose so none can be
        # altered post hoc (full SHA-256; truncation would invite collision arguments)
        pose = "" if self.pose_m is None else ",".join(f"{v:.6f}" for v in self.pose_m)
        raw = (f"{self.type}:{self.value}:{self.confidence}:{self.timestamp_ms}:"
               f"{self.reader_id}:{pose}:{self.frame}")
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class SafetyEnvelope:
    max_speed_mps: float = 0.15
    max_force_n: float = 2.0
    allowed_region: str = ""
    abort_if: list[str] = field(default_factory=list)


@dataclass
class ActionRequest:
    """A capability the (untrusted) VLA planner proposes. This is what AAL evaluates."""
    capability: Capability
    target_id: str                 # object/recipient/body-part the action is bound to
    room: str = ""
    tool: str = ""
    protocol_step: str = ""
    params: dict = field(default_factory=dict)   # e.g. {"speed_mps":.., "force_n":..}
    origin: str = "vla_planner"    # provenance tag (planner vs injected)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capability"] = self.capability.value
        return d


@dataclass
class Certificate:
    capability: Capability
    target_id: str
    evidence_hashes: list[str]
    envelope: SafetyEnvelope
    valid_from_ms: float
    valid_until_ms: float
    protocol_step: str
    tool_id: str = ""
    room: str = ""
    certificate_id: str = ""        # nonce for token replay prevention
    authorization_instance: str = ""  # (order,step,cap,target) key for the consumption ledger
    target_pose_m: Optional[list] = None   # sensed position of the authorized target
    pose_frame: str = ""                   # frame of target_pose_m
    position_tolerance_m: float = 0.0      # admissible endpoint distance from that pose
    issuer: str = "AAL_certifier_node"
    signature: str = ""

    def valid_at(self, now_ms: float) -> bool:
        return self.valid_from_ms <= now_ms <= self.valid_until_ms

    def _payload(self) -> str:
        # EVERYTHING the kernel relies on is bound, including the full safety envelope, so a
        # post-issuance tamper (widened force/speed, removed abort condition, changed region,
        # extended TTL) invalidates the signature.
        return json.dumps({
            "id": self.certificate_id, "ai": self.authorization_instance,
            "cap": self.capability.value, "tgt": self.target_id,
            "tool": self.tool_id, "room": self.room, "ps": self.protocol_step,
            "ev": self.evidence_hashes, "vf": self.valid_from_ms, "vu": self.valid_until_ms,
            "pose": None if self.target_pose_m is None else [round(float(v), 6)
                                                             for v in self.target_pose_m],
            "pframe": self.pose_frame, "ptol": round(float(self.position_tolerance_m), 6),
            "env": {"v": self.envelope.max_speed_mps, "f": self.envelope.max_force_n,
                    "reg": self.envelope.allowed_region, "abort": sorted(self.envelope.abort_if)},
            "iss": self.issuer,
        }, sort_keys=True)

    def sign(self, secret: str) -> "Certificate":
        self.signature = hmac.new(secret.encode(), self._payload().encode(),
                                  hashlib.sha256).hexdigest()
        return self

    def verify_signature(self, secret: str) -> bool:
        expected = hmac.new(secret.encode(), self._payload().encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


@dataclass
class Denial:
    reason: str
    decision: Decision   # DEFER or BLOCK

    def is_denial(self) -> bool:
        return True


@dataclass
class WorldState:
    """The physical environment as the ROBOT perceives it via sensors.

    Contains NO ground-truth oracle. ``present_target_id`` is what authenticated sensors actually
    read at the location the robot is acting on --- it may be the wrong entity (misbinding) or a
    spoofed reading. The certifier compares this against the signed TaskOrder, never against gold.
    Scenario ground truth lives in the Scenario object and is used only by the scorer.
    """
    room: str
    present_target_id: str                     # what sensors read at the acted-on location
    candidate_targets: list[str] = field(default_factory=list)
    workspace_clear: bool = True
    tool_state: dict = field(default_factory=dict)   # e.g. {"calibrated": True, "tool_id": ...}
    human_in_workspace: bool = False
    identity_confidence: float = 0.95          # current fused identity confidence
