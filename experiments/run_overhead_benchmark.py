#!/usr/bin/env python3
"""CPU-side overhead and availability microbenchmark for this study.

This benchmark measures the deterministic authorization path only. It excludes
camera inference, robot communication, trajectory generation, and controller
settling. Timings are host-specific engineering measurements, not universal
latency guarantees.
"""
from __future__ import annotations

import json
import os
import platform
import random
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AAL_IMPL = ROOT
if str(AAL_IMPL) not in sys.path:
    sys.path.insert(0, str(AAL_IMPL))

from aal.kernel import CertifiedActionKernel, RuntimeMonitor
from aal.ledger import AuthorizationLedger
from aal.types import Clock, Denial
from aal.verifier import AALVerifier

from red_team_common import base_context

EPHEMERAL_N = 5_000
REVALIDATE_N = 100_000
DURABLE_N = 500
RACE_ROUNDS = 100
RACE_CONTENDERS = 8
RESTART_N = 100
WARMUP_N = 100
REPETITIONS = 3


@dataclass
class Metric:
    name: str
    samples_ns: list[int]
    successes: int
    failures: int
    note: str

    def summary(self) -> dict:
        values_us = [x / 1_000.0 for x in self.samples_ns]
        total_s = sum(self.samples_ns) / 1e9
        return {
            "name": self.name,
            "n": len(values_us),
            "successes": self.successes,
            "failures": self.failures,
            "p50_us": percentile(values_us, 50),
            "p95_us": percentile(values_us, 95),
            "p99_us": percentile(values_us, 99),
            "max_us": max(values_us) if values_us else None,
            "mean_us": statistics.fmean(values_us) if values_us else None,
            "throughput_ops_s_from_measured_call_time": (
                len(values_us) / total_s if total_s > 0 else None
            ),
            "note": self.note,
        }


def percentile(sorted_or_unsorted: list[float], q: float) -> float:
    if not sorted_or_unsorted:
        raise ValueError("empty sample")
    values = sorted(sorted_or_unsorted)
    if len(values) == 1:
        return values[0]
    pos = (len(values) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(values) - 1)
    weight = pos - lo
    return values[lo] * (1.0 - weight) + values[hi] * weight


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def prepare_contexts(n: int, seed: int, clock: Clock):
    rng = random.Random(seed)
    contexts = []
    for i in range(n):
        ctx = base_context(rng, f"overhead_{seed}_{i}", spatial=True,
                           clock_start_ms=clock.now())
        ctx.clock = clock
        for evidence in ctx.evidence:
            evidence.timestamp_ms = clock.now()
        contexts.append(ctx)
    return contexts


def benchmark_ephemeral_certify(rep: int) -> tuple[Metric, list, AALVerifier, Clock]:
    clock = Clock(10_000.0)
    verifier = AALVerifier(clock, {"ephemeral_ledger": True})
    contexts = prepare_contexts(EPHEMERAL_N + WARMUP_N, 0xE001 + rep, clock)
    for ctx in contexts[:WARMUP_N]:
        out = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                               ctx.order, ctx.protocol)
        if isinstance(out, Denial):
            raise RuntimeError(f"warmup certification denied: {out.reason}")
    samples, failures = [], 0
    certs = []
    for ctx in contexts[WARMUP_N:]:
        start = time.perf_counter_ns()
        out = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                               ctx.order, ctx.protocol)
        samples.append(time.perf_counter_ns() - start)
        if isinstance(out, Denial):
            failures += 1
        else:
            certs.append((ctx, out))
    return Metric(
        "ephemeral_certificate_issuance", samples, len(certs), failures,
        "Includes all deterministic checks, HMAC, and in-memory reservation; excludes input construction.",
    ), certs, verifier, clock


def benchmark_revalidate(ctx, cert, verifier, clock) -> Metric:
    for _ in range(WARMUP_N):
        out = verifier.revalidate(cert, ctx.request, ctx.world, ctx.evidence)
        if isinstance(out, Denial):
            raise RuntimeError(f"warmup revalidation denied: {out.reason}")
    samples, failures = [], 0
    for _ in range(REVALIDATE_N):
        start = time.perf_counter_ns()
        out = verifier.revalidate(cert, ctx.request, ctx.world, ctx.evidence)
        samples.append(time.perf_counter_ns() - start)
        failures += isinstance(out, Denial)
    return Metric(
        "runtime_revalidation", samples, REVALIDATE_N - failures, failures,
        "Checks MAC, TTL, binding, fresh evidence, confidence, live target, and workspace; no renewal.",
    )


def benchmark_ephemeral_end_to_end(rep: int) -> Metric:
    clock = Clock(20_000.0)
    verifier = AALVerifier(clock, {"ephemeral_ledger": True})
    kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock), ledger=verifier.ledger)
    contexts = prepare_contexts(EPHEMERAL_N, 0xE002 + rep, clock)
    samples, failures = [], 0
    for ctx in contexts:
        start = time.perf_counter_ns()
        cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                ctx.order, ctx.protocol)
        if isinstance(cert, Denial):
            failures += 1
        else:
            result = kernel.execute(ctx.request, cert, ctx.world,
                                    monitor_ticks=1, tick_ms=0.0)
            if not result.executed or result.aborted or result.reject_reason:
                failures += 1
        samples.append(time.perf_counter_ns() - start)
    return Metric(
        "ephemeral_certify_plus_kernel_entry", samples,
        EPHEMERAL_N - failures, failures,
        "Certificate issuance plus controller-entry checks, one runtime-monitor tick, and in-memory consumption.",
    )


def benchmark_durable_end_to_end(rep: int) -> Metric:
    samples, failures = [], 0
    with tempfile.TemporaryDirectory(prefix="aal_overhead_durable_") as temp:
        path = str(Path(temp) / "ledger.json")
        clock = Clock(30_000.0)
        verifier = AALVerifier.for_deployment(
            clock, {"require_two_factor": True}, ledger_path=path
        )
        kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock), ledger=verifier.ledger)
        contexts = prepare_contexts(DURABLE_N, 0xD001 + rep, clock)
        for ctx in contexts:
            start = time.perf_counter_ns()
            cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                    ctx.order, ctx.protocol)
            if isinstance(cert, Denial):
                failures += 1
            else:
                result = kernel.execute(ctx.request, cert, ctx.world,
                                        monitor_ticks=1, tick_ms=0.0)
                if not result.executed or result.aborted or result.reject_reason:
                    failures += 1
            samples.append(time.perf_counter_ns() - start)
    return Metric(
        "durable_certify_plus_kernel_entry", samples,
        DURABLE_N - failures, failures,
        "Includes two write-through JSON ledger transitions (reserve and consume); ledger grows across the run.",
    )


def benchmark_duplicate_race(rep: int) -> Metric:
    samples, failures = [], 0
    with tempfile.TemporaryDirectory(prefix="aal_overhead_race_") as temp:
        path = str(Path(temp) / "ledger.json")
        clock = Clock(40_000.0)
        contexts = prepare_contexts(RACE_ROUNDS, 0xD002 + rep, clock)
        for ctx in contexts:
            def contender(_):
                verifier = AALVerifier.for_deployment(
                    clock, {"require_two_factor": True}, ledger_path=path
                )
                return verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                        ctx.order, ctx.protocol)

            start = time.perf_counter_ns()
            with ThreadPoolExecutor(max_workers=RACE_CONTENDERS) as pool:
                outputs = list(pool.map(contender, range(RACE_CONTENDERS)))
            samples.append(time.perf_counter_ns() - start)
            winners = [x for x in outputs if not isinstance(x, Denial)]
            reserved = [x for x in outputs if isinstance(x, Denial)
                        and x.reason == "replay:authorization_instance_reserved"]
            if len(winners) != 1 or len(reserved) != RACE_CONTENDERS - 1:
                failures += 1
            else:
                AuthorizationLedger.durable(path).consume(
                    winners[0].authorization_instance
                )
    return Metric(
        "eight_contender_duplicate_race", samples,
        RACE_ROUNDS - failures, failures,
        "Wall-clock duration to resolve eight simultaneous durable certifiers; exactly one winner required.",
    )


def benchmark_restart_replay_denial(rep: int) -> Metric:
    samples, failures = [], 0
    with tempfile.TemporaryDirectory(prefix="aal_overhead_restart_") as temp:
        path = str(Path(temp) / "ledger.json")
        clock = Clock(50_000.0)
        contexts = prepare_contexts(RESTART_N, 0xD003 + rep, clock)
        verifier = AALVerifier.for_deployment(
            clock, {"require_two_factor": True}, ledger_path=path
        )
        kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock), ledger=verifier.ledger)
        for ctx in contexts:
            cert = verifier.certify(ctx.request, ctx.world, ctx.evidence,
                                    ctx.order, ctx.protocol)
            if isinstance(cert, Denial):
                failures += 1
                samples.append(0)
                continue
            result = kernel.execute(ctx.request, cert, ctx.world,
                                    monitor_ticks=1, tick_ms=0.0)
            if not result.executed or result.aborted:
                failures += 1
                samples.append(0)
                continue
            start = time.perf_counter_ns()
            restarted = AALVerifier.for_deployment(
                clock, {"require_two_factor": True}, ledger_path=path
            )
            replay = restarted.certify(ctx.request, ctx.world, ctx.evidence,
                                       ctx.order, ctx.protocol)
            samples.append(time.perf_counter_ns() - start)
            if not isinstance(replay, Denial) or replay.reason != "replay:authorization_instance_consumed":
                failures += 1
            verifier = restarted
            kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock), ledger=verifier.ledger)
    return Metric(
        "restart_and_consumed_replay_denial", samples,
        RESTART_N - failures, failures,
        "Constructs a new durable verifier from disk and attempts fresh issuance for a consumed instance.",
    )


def aggregate_runs(per_run: list[dict[str, dict]]) -> dict[str, dict]:
    names = list(per_run[0])
    out: dict[str, dict] = {}
    for name in names:
        rows = [run[name] for run in per_run]

        def med(field: str) -> float:
            return statistics.median(float(row[field]) for row in rows)

        def span(field: str) -> list[float]:
            values = [float(row[field]) for row in rows]
            return [min(values), max(values)]

        out[name] = {
            "repetitions": len(rows),
            "samples_per_repetition": rows[0]["n"],
            "total_samples": sum(row["n"] for row in rows),
            "successes": sum(row["successes"] for row in rows),
            "failures": sum(row["failures"] for row in rows),
            "median_run_p50_us": med("p50_us"),
            "run_p50_range_us": span("p50_us"),
            "median_run_p95_us": med("p95_us"),
            "run_p95_range_us": span("p95_us"),
            "median_run_p99_us": med("p99_us"),
            "run_p99_range_us": span("p99_us"),
            "median_run_mean_us": med("mean_us"),
            "median_run_throughput_ops_s": med("throughput_ops_s_from_measured_call_time"),
            "note": rows[0]["note"],
            "per_run": rows,
        }
    return out


def main() -> None:
    per_run: list[dict[str, dict]] = []
    all_metrics: list[Metric] = []
    for rep in range(REPETITIONS):
        metric_issue, certs, verifier, clock = benchmark_ephemeral_certify(rep)
        metric_revalidate = benchmark_revalidate(certs[0][0], certs[0][1], verifier, clock)
        metrics = [
            metric_issue,
            metric_revalidate,
            benchmark_ephemeral_end_to_end(rep),
            benchmark_durable_end_to_end(rep),
            benchmark_duplicate_race(rep),
            benchmark_restart_replay_denial(rep),
        ]
        all_metrics.extend(metrics)
        per_run.append({metric.name: metric.summary() for metric in metrics})

    summary = {
        "scope": (
            "CPU-side deterministic-path microbenchmark. Excludes sensing, model inference, "
            "network/robot transport, trajectory generation, and controller settling. "
            "Host-specific; not a universal latency guarantee."
        ),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": cpu_model(),
            "cpu_count": os.cpu_count(),
        },
        "configuration": {
            "repetitions": REPETITIONS,
            "ephemeral_n_per_repetition": EPHEMERAL_N,
            "revalidate_n_per_repetition": REVALIDATE_N,
            "durable_n_per_repetition": DURABLE_N,
            "race_rounds_per_repetition": RACE_ROUNDS,
            "race_contenders": RACE_CONTENDERS,
            "restart_n_per_repetition": RESTART_N,
        },
        "metrics": aggregate_runs(per_run),
    }
    out = ROOT / "results"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "overhead_benchmark.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if any(metric.failures for metric in all_metrics):
        raise SystemExit("FAIL: an overhead benchmark correctness assertion failed")


if __name__ == "__main__":
    main()
