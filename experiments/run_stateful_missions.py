#!/usr/bin/env python3
"""Long-horizon stateful mission campaign for this study."""
from __future__ import annotations

import json
import random
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from red_team_common import ROOT, base_context, Capability, Clock, Denial
from aal.kernel import CertifiedActionKernel, RuntimeMonitor
from aal.verifier import AALVerifier, TTL_MS

SEEDS = tuple(range(5))
CASES_PER_CATEGORY_PER_SEED = 25
CATEGORIES = (
    "benign_completion",
    "wrong_target_denial",
    "replay_after_completion",
    "abort_then_retry",
    "expired_reservation_recovery",
    "restart_persistence",
    "concurrent_duplicate_race",
    "multi_renewal_completion",
)
RACE_CONTENDERS = 8
RENEWALS_PER_CASE = 4
PERIODIC_RESTART_EVERY = 20


@dataclass
class Stack:
    clock: Clock
    ledger_path: str
    verifier: AALVerifier
    kernel: CertifiedActionKernel

    @classmethod
    def create(cls, clock: Clock, ledger_path: str) -> "Stack":
        verifier = AALVerifier.for_deployment(
            clock, {"require_two_factor": True}, ledger_path=ledger_path
        )
        kernel = CertifiedActionKernel(
            clock, RuntimeMonitor(clock), ledger=verifier.ledger
        )
        return cls(clock, ledger_path, verifier, kernel)

    def restart(self) -> None:
        self.verifier = AALVerifier.for_deployment(
            self.clock, {"require_two_factor": True}, ledger_path=self.ledger_path
        )
        self.kernel = CertifiedActionKernel(
            self.clock, RuntimeMonitor(self.clock), ledger=self.verifier.ledger
        )


def is_denial(value) -> bool:
    return isinstance(value, Denial)


def certify(stack: Stack, ctx):
    return stack.verifier.certify(
        ctx.request, ctx.world, ctx.evidence, ctx.order, ctx.protocol
    )


def complete(stack: Stack, ctx, cert, monitor_ticks: int = 1):
    return stack.kernel.execute(
        ctx.request, cert, ctx.world, monitor_ticks=monitor_ticks
    )


def refresh(ctx, clock: Clock) -> None:
    ctx.clock = clock
    for ev in ctx.evidence:
        ev.timestamp_ms = clock.now()


def new_context(rng: random.Random, seed: int, index: int, category: str,
                clock: Clock):
    ctx = base_context(
        rng, f"mission_{seed}_{index}_{category}", Capability.GRASP,
        spatial=True, clock_start_ms=clock.now(),
    )
    refresh(ctx, clock)
    return ctx


def denial_reason(value) -> str:
    return value.reason if isinstance(value, Denial) else "not_denied"


def run_case(stack: Stack, rng: random.Random, seed: int, index: int,
             category: str) -> dict:
    ctx = new_context(rng, seed, index, category, stack.clock)
    record = {"seed": seed, "index": index, "category": category,
              "passed": False, "reason": ""}

    if category == "benign_completion":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_cert_denial:{denial_reason(cert)}"
            return record
        result = complete(stack, ctx, cert)
        record["passed"] = bool(result.executed and not result.aborted)
        record["reason"] = "complete" if record["passed"] else "unexpected_execution_failure"
        return record

    if category == "wrong_target_denial":
        ctx.request.target_id = ctx.other_target
        ctx.world.present_target_id = ctx.other_target
        for ev in ctx.evidence:
            ev.value = ctx.other_target
        out = certify(stack, ctx)
        record["passed"] = (
            is_denial(out) and out.reason == "target:target_not_authorized_by_order"
        )
        record["reason"] = denial_reason(out)
        return record

    if category == "replay_after_completion":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_initial_denial:{denial_reason(cert)}"
            return record
        first = complete(stack, ctx, cert)
        if not first.executed or first.aborted:
            record["reason"] = "initial_execution_failed"
            return record
        if rng.random() < .5:
            stack.restart()
        refresh(ctx, stack.clock)
        replay = certify(stack, ctx)
        record["passed"] = (
            is_denial(replay)
            and replay.reason == "replay:authorization_instance_consumed"
        )
        record["reason"] = denial_reason(replay)
        return record

    if category == "abort_then_retry":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_initial_denial:{denial_reason(cert)}"
            return record

        def intrude(world):
            world.human_in_workspace = True

        first = stack.kernel.execute(
            ctx.request, cert, ctx.world, monitor_ticks=3,
            world_events=[(1, intrude)],
        )
        if (not first.executed or not first.aborted
                or first.abort_reason != "workspace_intrusion"):
            record["reason"] = "expected_abort_missing"
            return record
        ctx.world.human_in_workspace = False
        stack.clock.advance(1)
        refresh(ctx, stack.clock)
        retry = certify(stack, ctx)
        if is_denial(retry):
            record["reason"] = f"retry_denied:{denial_reason(retry)}"
            return record
        done = complete(stack, ctx, retry)
        record["passed"] = bool(done.executed and not done.aborted)
        record["reason"] = (
            "abort_release_retry_complete" if record["passed"] else "retry_failed"
        )
        return record

    if category == "expired_reservation_recovery":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_initial_denial:{denial_reason(cert)}"
            return record
        stack.clock.advance(TTL_MS[ctx.request.capability] + 1)
        refresh(ctx, stack.clock)
        if rng.random() < .5:
            stack.restart()
        replacement = certify(stack, ctx)
        if is_denial(replacement):
            record["reason"] = (
                f"expired_reservation_not_released:{denial_reason(replacement)}"
            )
            return record
        done = complete(stack, ctx, replacement)
        record["passed"] = bool(done.executed and not done.aborted)
        record["reason"] = (
            "expired_reservation_recovered" if record["passed"]
            else "replacement_failed"
        )
        return record

    if category == "restart_persistence":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_initial_denial:{denial_reason(cert)}"
            return record
        done = complete(stack, ctx, cert)
        if not done.executed or done.aborted:
            record["reason"] = "initial_execution_failed"
            return record
        stack.restart()
        refresh(ctx, stack.clock)
        after = certify(stack, ctx)
        record["passed"] = (
            is_denial(after)
            and after.reason == "replay:authorization_instance_consumed"
        )
        record["reason"] = denial_reason(after)
        return record

    if category == "concurrent_duplicate_race":
        def contender(_):
            verifier = AALVerifier.for_deployment(
                stack.clock, {"require_two_factor": True},
                ledger_path=stack.ledger_path,
            )
            return verifier.certify(
                ctx.request, ctx.world, ctx.evidence, ctx.order, ctx.protocol
            )

        with ThreadPoolExecutor(max_workers=RACE_CONTENDERS) as pool:
            outputs = list(pool.map(contender, range(RACE_CONTENDERS)))
        winners = [out for out in outputs if not is_denial(out)]
        denials = [out for out in outputs if is_denial(out)]
        if len(winners) != 1 or len(denials) != RACE_CONTENDERS - 1:
            record["reason"] = (
                f"race_winners_{len(winners)}_denials_{len(denials)}"
            )
            return record
        stack.restart()
        done = complete(stack, ctx, winners[0])
        record["passed"] = bool(done.executed and not done.aborted)
        record["reason"] = (
            "exactly_one_winner" if record["passed"]
            else "winner_execution_failed"
        )
        return record

    if category == "multi_renewal_completion":
        cert = certify(stack, ctx)
        if is_denial(cert):
            record["reason"] = f"unexpected_initial_denial:{denial_reason(cert)}"
            return record
        for _ in range(RENEWALS_PER_CASE):
            stack.clock.advance(TTL_MS[ctx.request.capability] - 100)
            refresh(ctx, stack.clock)
            renewed = stack.verifier.attest_tick(
                cert, ctx.request, ctx.world, ctx.evidence,
                ctx.order, ctx.protocol, renew_within_ms=150,
            )
            if is_denial(renewed):
                record["reason"] = f"renew_denied:{denial_reason(renewed)}"
                return record
            if renewed.certificate_id == cert.certificate_id:
                record["reason"] = "renewal_did_not_replace_certificate"
                return record
            cert = renewed
            if rng.random() < .25:
                stack.restart()
        refresh(ctx, stack.clock)
        done = complete(stack, ctx, cert)
        record["passed"] = bool(done.executed and not done.aborted)
        record["reason"] = (
            "four_renewals_complete" if record["passed"]
            else "renewed_execution_failed"
        )
        return record

    raise ValueError(category)


def main() -> None:
    records = []
    with tempfile.TemporaryDirectory(prefix="aal_stateful_mission_") as temp:
        for seed in SEEDS:
            clock = Clock(10_000.0)
            path = str(Path(temp) / f"ledger_seed_{seed}.json")
            stack = Stack.create(clock, path)
            rng = random.Random(0x57A7EF00 + seed)
            schedule = [
                category
                for category in CATEGORIES
                for _ in range(CASES_PER_CATEGORY_PER_SEED)
            ]
            rng.shuffle(schedule)
            for index, category in enumerate(schedule):
                if index and index % PERIODIC_RESTART_EVERY == 0:
                    stack.restart()
                records.append(run_case(stack, rng, seed, index, category))
                stack.clock.advance(1)

    failures = [row for row in records if not row["passed"]]
    by_category = {}
    for category in CATEGORIES:
        rows = [row for row in records if row["category"] == category]
        by_category[category] = {
            "n": len(rows),
            "passed": sum(row["passed"] for row in rows),
            "failed": sum(not row["passed"] for row in rows),
            "reasons": dict(Counter(row["reason"] for row in rows)),
        }
    summary = {
        "scope": "Generated stateful mission workload; not deployment reliability.",
        "configuration": {
            "seeds": list(SEEDS),
            "categories": list(CATEGORIES),
            "cases_per_category_per_seed": CASES_PER_CATEGORY_PER_SEED,
            "race_contenders": RACE_CONTENDERS,
            "renewals_per_case": RENEWALS_PER_CASE,
            "periodic_restart_every": PERIODIC_RESTART_EVERY,
        },
        "overall": {
            "mission_units": len(records),
            "passed": len(records) - len(failures),
            "failed": len(failures),
            "planned_restarts": len(SEEDS) * (
                (len(CATEGORIES) * CASES_PER_CATEGORY_PER_SEED - 1)
                // PERIODIC_RESTART_EVERY
            ),
        },
        "categories": by_category,
        "failure_records": failures[:100],
    }
    out = ROOT / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "stateful_mission_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["overall"], indent=2))
    print(json.dumps(by_category, indent=2))
    if failures:
        raise SystemExit(
            f"FAIL: {len(failures)} stateful mission units violated expectations"
        )


if __name__ == "__main__":
    main()
