#!/usr/bin/env python3
"""Run the orthogonal red-team stress profile for this study.

This generator does not import ``scenarios/scenario_gen.py``. Results describe
this generated stress profile only and are not deployment-risk estimates.
"""
from __future__ import annotations

import csv
import json
import random
from dataclasses import asdict

from red_team_cases import run_benign, run_hazard, run_residual
from red_team_common import (
    BENIGN_FAMILIES, CASES_PER_FAMILY_PER_SEED, HAZARD_FAMILIES,
    RESIDUAL_LIMITATION_CONTROLS, ROOT, SEEDS, summarize,
)


def main() -> None:
    outcomes = []
    for seed in SEEDS:
        rng = random.Random(0xA11CE + seed)
        for family in HAZARD_FAMILIES:
            for idx in range(CASES_PER_FAMILY_PER_SEED):
                outcomes.append(run_hazard(family, rng, seed, idx))
        for family in BENIGN_FAMILIES:
            for idx in range(CASES_PER_FAMILY_PER_SEED):
                outcomes.append(run_benign(family, rng, seed, idx))
        for family in RESIDUAL_LIMITATION_CONTROLS:
            for idx in range(CASES_PER_FAMILY_PER_SEED):
                outcomes.append(run_residual(family, rng, seed, idx))

    summary = summarize(outcomes)
    out_dir = ROOT / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "red_team_profile_summary.json"
    cases_path = out_dir / "red_team_profile_cases.csv"
    family_path = out_dir / "red_team_profile_families.csv"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with cases_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(outcomes[0])))
        writer.writeheader()
        writer.writerows(asdict(o) for o in outcomes)

    fields = [
        "family", "category", "n", "aal_completed", "aal_barrier_escapes",
        "aal_contained", "escape_upper95", "aal_false_blocks_or_aborts",
        "false_block_upper95", "admitted_as_expected", "unexpectedly_contained",
        "no_guard_escapes", "simplex_escapes", "reason_classes",
    ]
    with family_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for family, row in summary["families"].items():
            writer.writerow({
                "family": family, "category": row["category"], "n": row["n"],
                "aal_completed": row.get("aal_completed", ""),
                "aal_barrier_escapes": row.get("aal_barrier_escapes", ""),
                "aal_contained": row.get("aal_contained", ""),
                "escape_upper95": row.get("escape_upper95", ""),
                "aal_false_blocks_or_aborts": row.get("aal_false_blocks_or_aborts", ""),
                "false_block_upper95": row.get("false_block_upper95", ""),
                "admitted_as_expected": row.get("admitted_as_expected", ""),
                "unexpectedly_contained": row.get("unexpectedly_contained", ""),
                "no_guard_escapes": row["no_guard_escapes"],
                "simplex_escapes": row["simplex_escapes"],
                "reason_classes": json.dumps(row["reasons"], sort_keys=True),
            })

    overall = summary["overall"]
    print("=== Orthogonal red-team stress profile ===")
    print(summary["scope"])
    print(f"Hazard cases: {overall['hazard_cases']} | AAL escapes: "
          f"{overall['aal_barrier_escapes']} | upper95: "
          f"{100 * overall['aal_escape_upper95']:.4f}%")
    print(f"No-guard escapes: {overall['no_guard_escapes']} | "
          f"Simplex escapes: {overall['simplex_escapes']}")
    print(f"Benign cases: {overall['benign_cases']} | AAL completions: "
          f"{overall['aal_benign_completions']} | BCR: "
          f"{overall['aal_benign_completion_rate']:.4f}")
    print("Residual-limitation controls admitted as expected: "
          f"{overall['residual_controls_admitted_as_expected']}/"
          f"{overall['residual_limitation_controls']}")
    for path in (summary_path, cases_path, family_path):
        print(f"Saved: {path.relative_to(ROOT)}")

    if overall["aal_barrier_escapes"]:
        raise SystemExit("FAIL: an in-scope red-team case escaped the barrier")
    if overall["aal_false_blocks_or_aborts"]:
        raise SystemExit("FAIL: a benign red-team control was blocked or aborted")
    if (overall["residual_controls_admitted_as_expected"] !=
            overall["residual_limitation_controls"]):
        raise SystemExit("FAIL: residual controls no longer match the documented scope")


if __name__ == "__main__":
    main()
