#!/usr/bin/env python3
"""Generate and validate the stateful-mission results table."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "stateful_mission_summary.json"
OUTPUT = ROOT / "generated" / "stateful_mission_table.tex"

ROWS = (
    ("benign_completion", "Benign certified completion"),
    ("wrong_target_denial", "Wrong-target denial"),
    ("replay_after_completion", "Replay after completed consumption"),
    ("abort_then_retry", "Abort, release, and re-attested retry"),
    ("expired_reservation_recovery", "Expired reservation recovery"),
    ("restart_persistence", "Consumption persistence after restart"),
    ("concurrent_duplicate_race", "Eight-contender duplicate race"),
    ("multi_renewal_completion", "Four-renewal completion"),
)


def main() -> None:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    overall = data["overall"]
    categories = data["categories"]

    assert overall["mission_units"] == 1000
    assert overall["passed"] == 1000
    assert overall["failed"] == 0
    assert sum(categories[key]["n"] for key, _ in ROWS) == 1000
    assert sum(categories[key]["passed"] for key, _ in ROWS) == 1000
    assert sum(categories[key]["failed"] for key, _ in ROWS) == 0

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Stateful mission and recovery campaign using durable ledgers, periodic certifier restarts, retries, expiration, renewal, and contention. Counts are generated lifecycle tests, not field transaction frequencies.}",
        r"\label{tab:stateful}",
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Lifecycle category & Units & Passed & Failed\\",
        r"\midrule",
    ]
    for key, label in ROWS:
        row = categories[key]
        lines.append(
            f"{label} & {row['n']} & {row['passed']} & {row['failed']}\\\\"
        )
    lines += [
        r"\midrule",
        rf"\textbf{{Total mission units}} & \textbf{{{overall['mission_units']}}} & \textbf{{{overall['passed']}}} & \textbf{{{overall['failed']}}}\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\textwidth}\footnotesize",
        rf"The workload includes {overall['planned_restarts']} scheduled periodic restarts, 125 eight-contender races, 125 abort--retry cycles, 125 expired-reservation recoveries, and 500 in-flight certificate renewals. Category-specific restarts occur in addition to the scheduled restarts.",
        r"\end{minipage}",
        r"\end{table*}",
        "",
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
