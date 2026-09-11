#!/usr/bin/env python3
"""Generate and validate the deterministic-path overhead table."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "overhead_benchmark.json"
OUTPUT = ROOT / "generated" / "overhead_table.tex"

ROWS = (
    ("runtime_revalidation", "Runtime revalidation"),
    ("ephemeral_certificate_issuance", "Certificate issuance (memory ledger)"),
    ("ephemeral_certify_plus_kernel_entry", "Issuance + kernel entry (memory ledger)"),
    ("durable_certify_plus_kernel_entry", "Issuance + kernel entry (durable ledger)"),
    ("restart_and_consumed_replay_denial", "Restart + consumed-instance denial"),
    ("eight_contender_duplicate_race", "Eight-contender duplicate race"),
)


def fmt_us(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.3f} ms"
    return f"{value:.1f} $\\mu$s"


def main() -> None:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    metrics = data["metrics"]
    expected_samples = {
        "runtime_revalidation": 300000,
        "ephemeral_certificate_issuance": 15000,
        "ephemeral_certify_plus_kernel_entry": 15000,
        "durable_certify_plus_kernel_entry": 1500,
        "restart_and_consumed_replay_denial": 300,
        "eight_contender_duplicate_race": 300,
    }
    for key, _ in ROWS:
        row = metrics[key]
        assert row["failures"] == 0
        assert row["successes"] == expected_samples[key]
        assert row["total_samples"] == expected_samples[key]

    lines = [
        r"\begin{table*}[t]",
        r"\centering\small",
        r"\caption{CPU-side deterministic-path microbenchmark. Values are the median across three repetitions of each repetition's percentile. Sensing, model inference, robot/network transport, trajectory generation, and controller settling are excluded.}",
        r"\label{tab:overhead}",
        r"\begin{tabular}{>{\raggedright\arraybackslash}p{7.2cm}rrr}",
        r"\toprule",
        r"Operation & Calls & Median p50 & Median p95\\",
        r"\midrule",
    ]
    for key, label in ROWS:
        row = metrics[key]
        lines.append(
            f"{label} & {row['total_samples']} & "
            f"{fmt_us(row['median_run_p50_us'])} & "
            f"{fmt_us(row['median_run_p95_us'])}\\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\textwidth}\footnotesize",
        rf"Reference host: {data['environment']['cpu_count']} vCPUs on {data['environment']['processor']}, Python {data['environment']['python']}. All calls satisfied their correctness assertions. The durable path includes write-through reserve and consume operations on a growing JSON ledger; the race row reports wall-clock resolution of eight simultaneous certifiers and required exactly one winner.",
        r"\end{minipage}",
        r"\end{table*}",
        "",
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
