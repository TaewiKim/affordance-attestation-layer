#!/usr/bin/env python3
"""Compound-fault interaction campaign for this safety-barrier study."""
from __future__ import annotations

import json
import random
from collections import Counter

from red_team_common import (
    ROOT, base_context, baseline_escape, execute_aal, fresh_components,
    manual_order, protocol_for, Capability, Denial, MAX_EVIDENCE_AGE_MS,
    NoGuard, SimplexRTAGuard,
)

SEEDS = tuple(range(5))
CASES_PER_REGIME_PER_SEED = 100
REGIMES = ("pre_issue_pair", "pre_issue_triple", "runtime_pair", "post_issue_plus_runtime")
PRE_CHANNELS = ("authority", "evidence", "context", "spatial", "envelope")
RUNTIME_FAULTS = ("target_substitution", "workspace_intrusion", "confidence_drop")


def cp0(n: int, alpha: float = 0.05) -> float:
    return 1.0 - alpha ** (1.0 / n)


def rebind_expired_order(ctx, tag: str) -> None:
    now = ctx.clock.wall_now_unix_s()
    old = ctx.order
    assert old
    ctx.order = manual_order(
        f"CMP_EXP_{tag}", ctx.request.capability, old.authorized_target_id,
        room=ctx.request.room, tool_id=ctx.request.tool,
        protocol_sequence=tuple(old.protocol_sequence),
        issued_at_unix_s=now - 100, valid_until_unix_s=now - .1,
    )
    ctx.protocol = protocol_for(ctx.order, ctx.request.protocol_step,
                                tuple(old.protocol_sequence[:-1]))


def apply_pre_channel(ctx, channel: str, rng: random.Random, tag: str) -> str:
    if channel == "authority":
        variant = rng.choice(("tampered_order", "expired_order"))
        if variant == "tampered_order":
            assert ctx.order
            ctx.order.room = f"tampered_{rng.randrange(1000)}"
        else:
            rebind_expired_order(ctx, tag)
        return variant
    if channel == "evidence":
        variant = rng.choice(("wrong_target", "sensor_conflict", "stale_evidence"))
        if variant == "wrong_target":
            ctx.request.target_id = ctx.other_target
            ctx.world.present_target_id = ctx.other_target
            for ev in ctx.evidence:
                ev.value = ctx.other_target
        elif variant == "sensor_conflict":
            ctx.evidence[0].confidence = .99
            ctx.evidence[1].value = ctx.other_target
            ctx.evidence[1].confidence = .99
        else:
            age = MAX_EVIDENCE_AGE_MS[ctx.request.capability]
            for ev in ctx.evidence:
                ev.timestamp_ms = ctx.clock.now() - age - rng.uniform(1, 300)
        return variant
    if channel == "context":
        variant = rng.choice(("protocol_skip", "tool_uncalibrated", "wrong_room"))
        if variant == "protocol_skip":
            assert ctx.order
            ctx.protocol = protocol_for(ctx.order, ctx.request.protocol_step, ())
        elif variant == "tool_uncalibrated":
            ctx.world.tool_state["calibrated"] = False
        else:
            ctx.world.room = f"wrong_zone_{rng.randrange(1000)}"
        return variant
    if channel == "spatial":
        variant = rng.choice(("spatial_redirect", "frame_mismatch", "posed_evidence_removed"))
        pose = ctx.evidence[0].pose_m
        assert pose is not None
        if variant == "spatial_redirect":
            ctx.request.params["target_position_m"] = [
                pose[0] + rng.uniform(.18, .35), pose[1], pose[2]
            ]
        elif variant == "frame_mismatch":
            ctx.request.params["target_position_frame"] = "camera_optical"
        else:
            ctx.evidence[0].pose_m = None
            ctx.evidence[0].frame = ""
        return variant
    if channel == "envelope":
        variant = rng.choice(("speed_excess", "force_excess"))
        if variant == "speed_excess":
            ctx.request.params["speed_mps"] = rng.uniform(.16, .24)
        else:
            ctx.request.params["force_n"] = rng.uniform(2.1, 4.8)
        return variant
    raise ValueError(channel)


def runtime_mutator(names: tuple[str, ...], other_target: str):
    def mutate(world):
        for name in names:
            if name == "target_substitution":
                world.present_target_id = other_target
            elif name == "workspace_intrusion":
                world.human_in_workspace = True
            elif name == "confidence_drop":
                world.identity_confidence = .2
            else:
                raise ValueError(name)
    return mutate


def aal_escaped(result) -> bool:
    if isinstance(result, Denial):
        return False
    return bool(result.executed and not result.aborted and not result.reject_reason)


def result_reason(result) -> str:
    if isinstance(result, Denial):
        if result.reason.startswith("protocol:protocol_step_not_satisfied_"):
            return "protocol:step_not_satisfied"
        return result.reason
    if result.reject_reason:
        return result.reject_reason
    if result.aborted:
        return f"abort:{result.abort_reason}"
    return "complete"


def run_hazard_case(regime: str, rng: random.Random, seed: int, idx: int) -> dict:
    tag = f"{seed}_{idx}_{regime}"
    ctx = base_context(rng, tag, Capability.SCAN, spatial=True)
    applied: list[str] = []
    events = None

    if regime in {"pre_issue_pair", "pre_issue_triple"}:
        n = 2 if regime == "pre_issue_pair" else 3
        selected = set(rng.sample(PRE_CHANNELS, n))
        for channel in PRE_CHANNELS:
            if channel in selected:
                applied.append(apply_pre_channel(ctx, channel, rng, tag))
        result = execute_aal(ctx)
    elif regime == "runtime_pair":
        faults = tuple(rng.sample(RUNTIME_FAULTS, 2))
        applied.extend(faults)
        events = [(1, runtime_mutator(faults, ctx.other_target))]
        result = execute_aal(ctx, world_events=events, monitor_ticks=4)
    elif regime == "post_issue_plus_runtime":
        verifier, kernel = fresh_components(ctx)
        cert = verifier.certify(ctx.request, ctx.world, ctx.evidence, ctx.order, ctx.protocol)
        if isinstance(cert, Denial):
            result = cert
        else:
            mutation = rng.choice(("redirect_endpoint", "strip_endpoint", "change_frame"))
            applied.append(mutation)
            if mutation == "redirect_endpoint":
                pose = ctx.evidence[0].pose_m
                assert pose is not None
                ctx.request.params["target_position_m"] = [pose[0] + .3, pose[1], pose[2]]
            elif mutation == "strip_endpoint":
                ctx.request.params.pop("target_position_m", None)
                ctx.request.params.pop("target_position_frame", None)
            else:
                ctx.request.params["target_position_frame"] = "camera_optical"
            runtime = rng.choice(RUNTIME_FAULTS)
            applied.append(runtime)
            events = [(0, runtime_mutator((runtime,), ctx.other_target))]
            result = kernel.execute(
                ctx.request, cert, ctx.world, world_events=events, monitor_ticks=4
            )
    else:
        raise ValueError(regime)

    no_guard = baseline_escape(ctx, NoGuard, world_events=events, monitor_ticks=4)
    simplex = baseline_escape(ctx, SimplexRTAGuard, world_events=events, monitor_ticks=4)
    return {
        "seed": seed,
        "case_index": idx,
        "regime": regime,
        "faults": applied,
        "aal_escape": aal_escaped(result),
        "aal_reason": result_reason(result),
        "no_guard_escape": no_guard,
        "simplex_escape": simplex,
    }


def run_benign_case(rng: random.Random, seed: int, idx: int) -> dict:
    tag = f"{seed}_{idx}_compound_benign"
    ctx = base_context(rng, tag, Capability.SCAN, spatial=True)
    ctx.request.params["speed_mps"] = rng.uniform(.13, .15)
    ctx.request.params["force_n"] = rng.uniform(1.7, 2.0)
    pose = ctx.evidence[0].pose_m
    assert pose is not None
    direction = rng.choice((-1.0, 1.0))
    ctx.request.params["target_position_m"] = [
        pose[0] + direction * rng.uniform(.13, .1499), pose[1], pose[2]
    ]
    age = rng.uniform(.95, .999) * MAX_EVIDENCE_AGE_MS[Capability.SCAN]
    for ev in ctx.evidence:
        ev.timestamp_ms = ctx.clock.now() - age
    ctx.world.identity_confidence = rng.uniform(.90, .93)
    old = ctx.order
    assert old
    now = ctx.clock.wall_now_unix_s()
    ctx.order = manual_order(
        f"CMP_OK_{tag}", ctx.request.capability, ctx.request.target_id,
        room=ctx.request.room, tool_id=ctx.request.tool,
        protocol_sequence=tuple(old.protocol_sequence),
        issued_at_unix_s=now - 10, valid_until_unix_s=now + rng.uniform(.1, 2.0),
    )
    ctx.protocol = protocol_for(
        ctx.order, ctx.request.protocol_step, tuple(old.protocol_sequence[:-1])
    )
    result = execute_aal(ctx)
    complete = (
        not isinstance(result, Denial)
        and result.executed
        and not result.aborted
        and not result.reject_reason
    )
    return {
        "seed": seed,
        "case_index": idx,
        "aal_completed": complete,
        "aal_reason": result_reason(result),
    }


def main() -> None:
    hazards = []
    benign = []
    for seed in SEEDS:
        rng = random.Random(0xC0FFEE + seed)
        for regime in REGIMES:
            for idx in range(CASES_PER_REGIME_PER_SEED):
                hazards.append(run_hazard_case(regime, rng, seed, idx))
        for idx in range(CASES_PER_REGIME_PER_SEED):
            benign.append(run_benign_case(rng, seed, idx))

    n = len(hazards)
    escapes = sum(row["aal_escape"] for row in hazards)
    simplex = sum(row["simplex_escape"] for row in hazards)
    no_guard = sum(row["no_guard_escape"] for row in hazards)
    completed = sum(row["aal_completed"] for row in benign)
    by_regime = {}
    for regime in REGIMES:
        rows = [row for row in hazards if row["regime"] == regime]
        by_regime[regime] = {
            "n": len(rows),
            "aal_escapes": sum(row["aal_escape"] for row in rows),
            "no_guard_escapes": sum(row["no_guard_escape"] for row in rows),
            "simplex_escapes": sum(row["simplex_escape"] for row in rows),
            "aal_reasons": dict(Counter(row["aal_reason"] for row in rows)),
        }

    summary = {
        "scope": "Generated compound-fault interaction campaign; not deployment risk.",
        "configuration": {
            "seeds": list(SEEDS),
            "cases_per_regime_per_seed": CASES_PER_REGIME_PER_SEED,
            "regimes": list(REGIMES),
        },
        "overall": {
            "hazard_cases": n,
            "aal_barrier_escapes": escapes,
            "aal_escape_upper95": cp0(n) if escapes == 0 else None,
            "no_guard_escapes": no_guard,
            "simplex_escapes": simplex,
            "benign_cases": len(benign),
            "aal_benign_completions": completed,
            "aal_false_blocks_or_aborts": len(benign) - completed,
        },
        "regimes": by_regime,
        "benign_reasons": dict(Counter(row["aal_reason"] for row in benign)),
    }
    out = ROOT / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "compound_fault_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["overall"], indent=2))
    print(json.dumps(by_regime, indent=2))
    if escapes:
        raise SystemExit("FAIL: compound hazard escaped")
    if completed != len(benign):
        raise SystemExit("FAIL: benign compound control failed")


if __name__ == "__main__":
    main()
