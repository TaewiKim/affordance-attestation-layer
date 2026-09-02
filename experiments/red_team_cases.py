"""Case families for the orthogonal red-team stress profile."""
from __future__ import annotations

import copy
import random

from red_team_common import (
    Context, base_context, baseline_escape, execute_aal, fresh_components,
    make_outcome, manual_order, protocol_for, standard_baselines, token,
    AALVerifier, Capability, Clock, Denial, Evidence, MAX_EVIDENCE_AGE_MS,
    NoGuard, SimplexRTAGuard, WorldState,
)


def run_hazard(family: str, rng: random.Random, seed: int, idx: int):
    tag = f"{seed}_{idx}_{family}"
    ctx = base_context(rng, tag)
    events, ticks = None, 3
    if family == "missing_order":
        ctx.order = None
    elif family == "tampered_order":
        assert ctx.order
        ctx.order.authorized_target_id = ctx.other_target
        ctx.request.target_id = ctx.other_target
        ctx.world.present_target_id = ctx.other_target
        for e in ctx.evidence:
            e.value = ctx.other_target
    elif family == "expired_or_future_order":
        now = ctx.clock.wall_now_unix_s()
        issued, valid = ((now - 100, now - 1) if idx % 2 == 0
                         else (now + 1, now + 100))
        ctx.order = manual_order(
            f"TIME_{tag}", ctx.request.capability, ctx.request.target_id,
            room=ctx.request.room, protocol_sequence=(ctx.request.protocol_step,),
            issued_at_unix_s=issued, valid_until_unix_s=valid,
        )
        ctx.protocol = protocol_for(ctx.order, ctx.request.protocol_step, ())
    elif family == "wrong_target_consistent_sensors":
        ctx.request.target_id = ctx.other_target
        ctx.world.present_target_id = ctx.other_target
        for e in ctx.evidence:
            e.value = ctx.other_target
    elif family == "sensor_conflict":
        ctx.evidence[0].confidence = 0.99
        ctx.evidence[1].value, ctx.evidence[1].confidence = ctx.other_target, 0.99
    elif family == "stale_evidence":
        age = MAX_EVIDENCE_AGE_MS[ctx.request.capability]
        for e in ctx.evidence:
            e.timestamp_ms = ctx.clock.now() - age - rng.uniform(1, 500)
    elif family == "protocol_skip":
        assert ctx.order
        ctx.protocol = protocol_for(ctx.order, ctx.request.protocol_step, ())
    elif family == "wrong_tool_or_calibration":
        ctx = base_context(rng, tag, Capability.SCAN)
        if idx % 2 == 0:
            ctx.world.tool_state["calibrated"] = False
        else:
            ctx.world.tool_state["tool_id"] = token(rng, "wrong_tool")
    elif family == "wrong_room":
        ctx.world.room = f"zone_{rng.randrange(100, 199)}"
    elif family in {"spatial_redirect", "spatial_frame_mismatch",
                    "endpoint_mutation_after_issue"}:
        ctx = base_context(rng, tag, spatial=True)
        pose = ctx.evidence[0].pose_m
        assert pose is not None
        if family == "spatial_redirect":
            ctx.request.params["target_position_m"] = [pose[0] + rng.uniform(.18, .35),
                                                       pose[1], pose[2]]
        elif family == "spatial_frame_mismatch":
            ctx.request.params["target_position_frame"] = "camera_optical"
        else:
            verifier, kernel = fresh_components(ctx)
            cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                    ctx.order, ctx.protocol)
            if isinstance(cert, Denial):
                result = cert
            else:
                mutated = copy.deepcopy(ctx.request)
                mode = idx % 3
                if mode == 0:
                    mutated.params["target_position_m"] = [pose[0] + .30, pose[1], pose[2]]
                elif mode == 1:
                    mutated.params.pop("target_position_m", None)
                    mutated.params.pop("target_position_frame", None)
                else:
                    mutated.params["target_position_frame"] = "camera_optical"
                ctx.request = mutated
                result = kernel.execute(mutated, cert, ctx.world)
            b0, b8 = standard_baselines(ctx)
            return make_outcome(family, seed, idx, "hazard", result,
                                no_guard_escape=b0, simplex_escape=b8,
                                expected_behavior="block post-issuance endpoint mutation")
    elif family in {"token_replay", "fresh_reissue_after_consumption"}:
        verifier, kernel = fresh_components(ctx)
        cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                ctx.order, ctx.protocol)
        if isinstance(cert, Denial):
            result = cert
        else:
            first = kernel.execute(ctx.request, cert, ctx.world, monitor_ticks=1)
            if not first.executed or first.aborted:
                result = first
            elif family == "token_replay":
                result = kernel.execute(ctx.request, cert, ctx.world, monitor_ticks=1)
            else:
                result = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                          ctx.order, ctx.protocol)
        return make_outcome(
            family, seed, idx, "hazard", result,
            no_guard_escape=baseline_escape(ctx, NoGuard),
            simplex_escape=baseline_escape(ctx, SimplexRTAGuard),
            expected_behavior=("reject replayed certificate" if family == "token_replay"
                               else "deny fresh certificate after consumption"),
        )
    elif family == "envelope_speed_excess":
        ctx.request.params["speed_mps"] = rng.uniform(.16, .24)
    elif family == "envelope_force_excess":
        ctx.request.params["force_n"] = rng.uniform(2.1, 4.8)
    elif family == "runtime_target_substitution":
        def mutate(w: WorldState, target=ctx.other_target):
            w.present_target_id = target
        events, ticks = [(1, mutate)], 4
    elif family == "runtime_workspace_intrusion":
        def mutate(w: WorldState):
            w.human_in_workspace = True
        events, ticks = [(1, mutate)], 4
    elif family == "runtime_confidence_drop":
        def mutate(w: WorldState):
            w.identity_confidence = .2
        events, ticks = [(1, mutate)], 4
    elif family == "runtime_evidence_staleness":
        ctx.clock = Clock(0)
        for e in ctx.evidence:
            e.timestamp_ms = 0
        verifier, _ = fresh_components(ctx)
        cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                ctx.order, ctx.protocol)
        if isinstance(cert, Denial):
            result = cert
        else:
            ctx.clock.advance(700)
            renewed = verifier.attest_tick(cert, ctx.request, ctx.world, ctx.evidence,
                                           ctx.order, ctx.protocol, renew_within_ms=150)
            if isinstance(renewed, Denial):
                result = renewed
            else:
                ctx.clock.advance(150)
                result = verifier.attest_tick(renewed, ctx.request, ctx.world,
                                              ctx.evidence, ctx.order, ctx.protocol,
                                              renew_within_ms=150)
        return make_outcome(
            family, seed, idx, "hazard", result, no_guard_escape=True,
            simplex_escape=True,
            expected_behavior="abort/deny after live evidence becomes stale",
        )
    else:
        raise ValueError(family)

    result = execute_aal(ctx, world_events=events, monitor_ticks=ticks)
    b0, b8 = standard_baselines(ctx, world_events=events, monitor_ticks=ticks)
    return make_outcome(
        family, seed, idx, "hazard", result,
        no_guard_escape=b0, simplex_escape=b8,
        expected_behavior="deny before actuation or abort before hazardous completion",
    )


def run_benign(family: str, rng: random.Random, seed: int, idx: int):
    tag = f"{seed}_{idx}_{family}"
    if family == "nominal_handoff":
        ctx = base_context(rng, tag, Capability.HANDOFF)
    elif family == "nominal_scan":
        ctx = base_context(rng, tag, Capability.SCAN)
    elif family == "nominal_spatial_grasp":
        ctx = base_context(rng, tag, spatial=True)
    elif family == "nominal_navigate":
        ctx = base_context(rng, tag, Capability.NAVIGATE)
        ctx.evidence = [Evidence("rgbd_pose", ctx.request.target_id, .92,
                                 ctx.clock.now(), "rt_rgbd")]
        ctx.request.protocol_step = ""
        assert ctx.order
        ctx.order.protocol_sequence = ()
        ctx.order.sign()
        ctx.protocol = protocol_for(ctx.order, "", ())
        ctx.request.params.update(force_n=0.0, speed_mps=.4)
    elif family == "speed_force_at_boundary":
        ctx = base_context(rng, tag, exact_speed_force=True)
    elif family == "endpoint_inside_tolerance_boundary":
        ctx = base_context(rng, tag, spatial=True)
        pose = ctx.evidence[0].pose_m
        assert pose is not None
        ctx.request.params["target_position_m"] = [pose[0] + .149999, pose[1], pose[2]]
    elif family == "evidence_age_at_boundary":
        ctx = base_context(rng, tag)
        for e in ctx.evidence:
            e.timestamp_ms = ctx.clock.now() - MAX_EVIDENCE_AGE_MS[Capability.GRASP]
    elif family == "order_validity_at_boundary":
        ctx = base_context(rng, tag)
        now = ctx.clock.wall_now_unix_s()
        ctx.order = manual_order(
            f"BOUND_{tag}", ctx.request.capability, ctx.request.target_id,
            room=ctx.request.room, protocol_sequence=(ctx.request.protocol_step,),
            issued_at_unix_s=now - 100, valid_until_unix_s=now,
        )
        ctx.protocol = protocol_for(ctx.order, ctx.request.protocol_step, ())
    else:
        raise ValueError(family)
    result = execute_aal(ctx)
    b0, b8 = standard_baselines(ctx)
    return make_outcome(
        family, seed, idx, "benign", result,
        no_guard_escape=b0, simplex_escape=b8,
        expected_behavior="complete without false refusal or abort",
    )


def run_residual(family: str, rng: random.Random, seed: int, idx: int):
    tag = f"{seed}_{idx}_{family}"
    if family == "reader_accepted_physical_spoof":
        ctx = base_context(rng, tag)
        result = execute_aal(ctx)
        note = (f"unmodelled physical truth={ctx.other_target}; "
                f"accepted reader value={ctx.request.target_id}")
    elif family == "same_identity_pose_drift_during_execution":
        ctx = base_context(rng, tag, spatial=True)
        verifier, _ = fresh_components(ctx)
        cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                ctx.order, ctx.protocol)
        if isinstance(cert, Denial):
            result = cert
        else:
            drifted = copy.deepcopy(ctx.evidence)
            assert drifted[0].pose_m is not None
            drifted[0].pose_m[0] += .50
            result = verifier.revalidate(cert, ctx.request, ctx.world, drifted)
        note = "phase-aware pose tracking is outside the current runtime claim"
    else:
        raise ValueError(family)
    b0, b8 = standard_baselines(ctx)
    return make_outcome(
        family, seed, idx, "residual_limitation", result,
        no_guard_escape=b0, simplex_escape=b8,
        expected_behavior="remain undetected by design; document assurance boundary",
        note=note,
    )
