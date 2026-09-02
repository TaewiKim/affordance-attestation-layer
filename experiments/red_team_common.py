"""Shared utilities for the orthogonal red-team stress profile."""
from __future__ import annotations

import copy
import json
import math
import random
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
AAL_IMPL = ROOT
if str(AAL_IMPL) not in sys.path:
    sys.path.insert(0, str(AAL_IMPL))

from aal.authority import ProtocolEngine, TaskOrder, make_order  # noqa: E402
from aal.kernel import CertifiedActionKernel, RuntimeMonitor  # noqa: E402
from aal.pipeline import NoGuard, SimplexRTAGuard  # noqa: E402
from aal.stats import clopper_pearson_upper, mcnemar_exact  # noqa: E402
from aal.types import ActionRequest, Capability, Clock, Denial, Evidence, WorldState  # noqa: E402
from aal.verifier import AALVerifier, MAX_EVIDENCE_AGE_MS  # noqa: E402

SEEDS = tuple(range(5))
CASES_PER_FAMILY_PER_SEED = 25

HAZARD_FAMILIES = (
    "missing_order", "tampered_order", "expired_or_future_order",
    "wrong_target_consistent_sensors", "sensor_conflict", "stale_evidence",
    "protocol_skip", "wrong_tool_or_calibration", "wrong_room",
    "spatial_redirect", "spatial_frame_mismatch", "endpoint_mutation_after_issue",
    "token_replay", "fresh_reissue_after_consumption", "envelope_speed_excess",
    "envelope_force_excess", "runtime_target_substitution",
    "runtime_workspace_intrusion", "runtime_confidence_drop",
    "runtime_evidence_staleness",
)
BENIGN_FAMILIES = (
    "nominal_handoff", "nominal_scan", "nominal_spatial_grasp", "nominal_navigate",
    "speed_force_at_boundary", "endpoint_inside_tolerance_boundary",
    "evidence_age_at_boundary", "order_validity_at_boundary",
)
RESIDUAL_LIMITATION_CONTROLS = (
    "reader_accepted_physical_spoof", "same_identity_pose_drift_during_execution",
)


@dataclass
class Context:
    clock: Clock
    request: ActionRequest
    world: WorldState
    evidence: list[Evidence]
    order: TaskOrder | None
    protocol: ProtocolEngine
    other_target: str


@dataclass
class Outcome:
    family: str
    seed: int
    case_index: int
    category: str
    aal_escape: bool
    aal_completed: bool
    aal_contained: bool
    aal_reason: str
    no_guard_escape: bool | None
    simplex_escape: bool | None
    expected_behavior: str
    note: str = ""


def token(rng: random.Random, prefix: str) -> str:
    return f"{prefix}_{rng.getrandbits(40):010x}"


def protocol_for(order: TaskOrder, current: str, completed: Iterable[str]) -> ProtocolEngine:
    pe = ProtocolEngine()
    pe.set_state(order, current, tuple(completed))
    return pe


def manual_order(order_id: str, capability: Capability, target: str, *, room: str,
                 tool_id: str = "", protocol_sequence: tuple[str, ...] = (),
                 issued_at_unix_s: float = 0.0,
                 valid_until_unix_s: float = 0.0) -> TaskOrder:
    return TaskOrder(
        order_id=order_id, capability=capability, authorized_target_id=target,
        protocol_sequence=protocol_sequence, room=room, tool_id=tool_id,
        issued_at_unix_s=issued_at_unix_s, valid_until_unix_s=valid_until_unix_s,
    ).sign()


def base_context(rng: random.Random, case_tag: str,
                 capability: Capability = Capability.GRASP, *, spatial: bool = False,
                 clock_start_ms: float = 10_000.0,
                 exact_speed_force: bool = False) -> Context:
    target, other = token(rng, "entity"), token(rng, "entity")
    while other == target:
        other = token(rng, "entity")
    room = f"zone_{rng.randrange(10, 99)}"
    tool = token(rng, "tool") if capability == Capability.SCAN else ""
    step = token(rng, "execute")
    preceding = (token(rng, "verify_identity"), token(rng, "verify_context"))
    order = make_order(
        f"RT_{case_tag}_{rng.getrandbits(48):012x}", capability, target,
        protocol_sequence=preceding + (step,), room=room, tool_id=tool,
    )
    speed = 0.15 if exact_speed_force else rng.uniform(0.04, 0.13)
    force = 2.0 if exact_speed_force else rng.uniform(0.4, 1.7)
    params: dict[str, object] = {
        "speed_mps": round(speed, 6), "force_n": round(force, 6),
        "red_team_nonce": rng.getrandbits(32),
    }
    evidence = [
        Evidence("barcode", target, rng.uniform(0.94, 0.995), clock_start_ms,
                 "rt_reader_barcode"),
        Evidence("rfid", target, rng.uniform(0.94, 0.995), clock_start_ms,
                 "rt_reader_rfid"),
    ]
    if spatial:
        pose = [rng.uniform(0.35, 0.65), rng.uniform(-0.20, 0.20),
                rng.uniform(0.05, 0.25)]
        evidence[0].pose_m = [round(v, 6) for v in pose]
        evidence[0].frame = "robot_base"
        offset = [rng.uniform(-0.05, 0.05), rng.uniform(-0.05, 0.05),
                  rng.uniform(-0.03, 0.03)]
        params["target_position_m"] = [round(p + d, 6) for p, d in zip(pose, offset)]
        params["target_position_frame"] = "robot_base"
    world = WorldState(
        room=room, present_target_id=target, workspace_clear=True,
        tool_state={"calibrated": True, "tool_id": tool},
        human_in_workspace=False, identity_confidence=0.98,
    )
    return Context(
        Clock(clock_start_ms),
        ActionRequest(capability, target, room, tool, step, params,
                      origin="orthogonal_red_team"),
        world, evidence, order, protocol_for(order, step, preceding), other,
    )


def fresh_components(ctx: Context, config: dict | None = None):
    cfg = {"ephemeral_ledger": True, **(config or {})}
    verifier = AALVerifier(ctx.clock, cfg)
    monitor = RuntimeMonitor(ctx.clock, enable=True)
    return verifier, CertifiedActionKernel(ctx.clock, monitor, ledger=verifier.ledger)


def reason_from_result(result) -> str:
    if isinstance(result, Denial):
        return ("protocol:step_not_satisfied"
                if result.reason.startswith("protocol:protocol_step_not_satisfied_")
                else result.reason)
    if getattr(result, "reject_reason", ""):
        return result.reject_reason
    if getattr(result, "aborted", False):
        return f"abort:{result.abort_reason}"
    if getattr(result, "executed", False):
        return "complete"
    return "admitted"  # successful certificate issuance/revalidation


def execute_aal(ctx: Context, *, world_events=None, monitor_ticks: int = 3):
    verifier, kernel = fresh_components(ctx)
    cert = verifier.certify(ctx.request, ctx.world, ctx.evidence, ctx.order, ctx.protocol)
    if isinstance(cert, Denial):
        return cert
    return kernel.execute(ctx.request, cert, ctx.world, monitor_ticks=monitor_ticks,
                          world_events=world_events)


def baseline_escape(ctx: Context, guard_cls, *, world_events=None,
                    monitor_ticks: int = 3) -> bool:
    guard = guard_cls(Clock(ctx.clock.now()))
    result = guard.handle(
        copy.deepcopy(ctx.request), copy.deepcopy(ctx.world),
        copy.deepcopy(ctx.evidence), copy.deepcopy(ctx.order),
        copy.deepcopy(ctx.protocol), monitor_ticks=monitor_ticks,
        world_events=world_events,
    )
    return bool(result.executed and not result.aborted and not result.reject_reason)


def standard_baselines(ctx: Context, *, world_events=None,
                       monitor_ticks: int = 3) -> tuple[bool, bool]:
    return (
        baseline_escape(ctx, NoGuard, world_events=world_events,
                        monitor_ticks=monitor_ticks),
        baseline_escape(ctx, SimplexRTAGuard, world_events=world_events,
                        monitor_ticks=monitor_ticks),
    )


def make_outcome(family: str, seed: int, idx: int, category: str, result, *,
                 no_guard_escape: bool | None, simplex_escape: bool | None,
                 expected_behavior: str, note: str = "") -> Outcome:
    if isinstance(result, Denial):
        completed = False
    elif hasattr(result, "executed"):
        completed = bool(result.executed and not result.aborted and not result.reject_reason)
    else:
        completed = True
    escape = completed if category != "benign" else False
    contained = (not escape) if category == "hazard" else (
        completed if category == "benign" else not completed)
    return Outcome(
        family, seed, idx, category, escape, completed, contained,
        reason_from_result(result), no_guard_escape, simplex_escape,
        expected_behavior, note,
    )


def summarize(outcomes: list[Outcome]) -> dict:
    hazard = [o for o in outcomes if o.category == "hazard"]
    benign = [o for o in outcomes if o.category == "benign"]
    residual = [o for o in outcomes if o.category == "residual_limitation"]
    families: dict[str, dict] = {}
    for family in HAZARD_FAMILIES + BENIGN_FAMILIES + RESIDUAL_LIMITATION_CONTROLS:
        rows = [o for o in outcomes if o.family == family]
        n, category = len(rows), rows[0].category
        completed = sum(o.aal_completed for o in rows)
        row = {
            "category": category, "n": n, "aal_completed": completed,
            "no_guard_escapes": sum(bool(o.no_guard_escape) for o in rows
                                    if o.no_guard_escape is not None),
            "simplex_escapes": sum(bool(o.simplex_escape) for o in rows
                                   if o.simplex_escape is not None),
            "reasons": dict(Counter(o.aal_reason for o in rows)),
        }
        if category == "hazard":
            escapes = sum(o.aal_escape for o in rows)
            row.update(aal_barrier_escapes=escapes, aal_contained=n - escapes,
                       escape_upper95=clopper_pearson_upper(escapes, n))
        elif category == "benign":
            false_blocks = n - completed
            row.update(aal_false_blocks_or_aborts=false_blocks,
                       false_block_upper95=clopper_pearson_upper(false_blocks, n))
        else:
            row.update(admitted_as_expected=completed,
                       unexpectedly_contained=n - completed)
        families[family] = row

    aal_escapes = sum(o.aal_escape for o in hazard)
    b = c = 0
    for o in hazard:
        if o.simplex_escape is None:
            continue
        if not o.aal_escape and o.simplex_escape:
            b += 1
        elif o.aal_escape and not o.simplex_escape:
            c += 1
    per_seed = {}
    for seed in SEEDS:
        hz = [o for o in hazard if o.seed == seed]
        bg = [o for o in benign if o.seed == seed]
        rc = [o for o in residual if o.seed == seed]
        per_seed[str(seed)] = {
            "hazard_cases": len(hz),
            "aal_barrier_escapes": sum(o.aal_escape for o in hz),
            "simplex_escapes": sum(bool(o.simplex_escape) for o in hz),
            "benign_cases": len(bg),
            "aal_benign_completions": sum(o.aal_completed for o in bg),
            "residual_controls": len(rc),
            "residual_controls_admitted_as_expected": sum(o.aal_completed for o in rc),
        }
    return {
        "scope": (
            "Generated orthogonal stress profile; not a deployment operational profile or "
            "deployment-risk estimate. The generator does not import the original scenario generator."
        ),
        "configuration": {
            "seeds": list(SEEDS),
            "cases_per_family_per_seed": CASES_PER_FAMILY_PER_SEED,
            "hazard_families": list(HAZARD_FAMILIES),
            "benign_families": list(BENIGN_FAMILIES),
            "residual_limitation_controls": list(RESIDUAL_LIMITATION_CONTROLS),
        },
        "overall": {
            "hazard_cases": len(hazard),
            "aal_barrier_escapes": aal_escapes,
            "aal_escape_upper95": clopper_pearson_upper(aal_escapes, len(hazard)),
            "no_guard_escapes": sum(bool(o.no_guard_escape) for o in hazard),
            "simplex_escapes": sum(bool(o.simplex_escape) for o in hazard),
            "mcnemar_aal_vs_simplex": {
                "discordant_aal_safe_simplex_unsafe": b,
                "discordant_aal_unsafe_simplex_safe": c,
                "p_value": mcnemar_exact(b, c),
                "log10_p_value_when_one_sided_discordance": (
                    (1 - (b + c)) * math.log10(2.0)
                    if min(b, c) == 0 and (b + c) > 0 else None
                ),
            },
            "benign_cases": len(benign),
            "aal_benign_completions": sum(o.aal_completed for o in benign),
            "aal_false_blocks_or_aborts": sum(not o.aal_completed for o in benign),
            "aal_benign_completion_rate": (
                sum(o.aal_completed for o in benign) / len(benign) if benign else 0.0
            ),
            "residual_limitation_controls": len(residual),
            "residual_controls_admitted_as_expected": sum(o.aal_completed for o in residual),
        },
        "per_seed": per_seed,
        "families": families,
        "reason_counts_hazard": dict(Counter(o.aal_reason for o in hazard)),
    }
