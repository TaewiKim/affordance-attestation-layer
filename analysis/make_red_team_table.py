#!/usr/bin/env python3
"""Generate the orthogonal red-team LaTeX table from committed JSON.

The script validates all aggregate totals before emitting the table so the
table cannot silently drift from the experiment results.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "red_team_profile_summary.json"
OUTPUT = ROOT / "from_results" / "red_team_table.tex"

GROUPS = OrderedDict([
    ("Authority and order validity", [
        "missing_order", "tampered_order", "expired_or_future_order",
    ]),
    ("Target and evidence consistency", [
        "wrong_target_consistent_sensors", "sensor_conflict", "stale_evidence",
    ]),
    ("Protocol, tool, and context", [
        "protocol_skip", "wrong_tool_or_calibration", "wrong_room",
    ]),
    ("Spatial endpoint binding", [
        "spatial_redirect", "spatial_frame_mismatch", "endpoint_mutation_after_issue",
    ]),
    ("Replay and consumption state", [
        "token_replay", "fresh_reissue_after_consumption",
    ]),
    ("Force and speed envelope", [
        "envelope_speed_excess", "envelope_force_excess",
    ]),
    ("Runtime re-attestation", [
        "runtime_target_substitution", "runtime_workspace_intrusion",
        "runtime_confidence_drop", "runtime_evidence_staleness",
    ]),
])


def main() -> None:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    families = data["families"]
    rows: list[tuple[str, int, int, int]] = []
    for label, names in GROUPS.items():
        n = sum(families[name]["n"] for name in names)
        aal = sum(families[name]["aal_barrier_escapes"] for name in names)
        simplex = sum(families[name]["simplex_escapes"] for name in names)
        rows.append((label, n, aal, simplex))

    overall = data["overall"]
    assert sum(row[1] for row in rows) == overall["hazard_cases"] == 2500
    assert sum(row[2] for row in rows) == overall["aal_barrier_escapes"] == 0
    assert sum(row[3] for row in rows) == overall["simplex_escapes"] == 2375
    assert overall["aal_benign_completions"] == overall["benign_cases"] == 1000
    assert overall["residual_controls_admitted_as_expected"] == 250

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Orthogonal red-team stress profile. The generator is implemented independently of the original hospital scenario generator and attacks public AAL interfaces. Counts characterize this generated profile only, not deployment frequencies.}",
        r"\label{tab:redteam}",
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Hazard group & Cases & AAL escapes & Simplex/RTA escapes\\",
        r"\midrule",
    ]
    for label, n, aal, simplex in rows:
        lines.append(f"{label} & {n} & {aal} & {simplex}\\\\")
    lines += [
        r"\midrule",
        rf"\textbf{{Total in-scope hazardous demands}} & \textbf{{{overall['hazard_cases']}}} & \textbf{{{overall['aal_barrier_escapes']}}} & \textbf{{{overall['simplex_escapes']}}}\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\textwidth}\footnotesize",
        rf"AAL's one-sided exact 95\% upper bound is {100 * overall['aal_escape_upper95']:.4f}\% for this generated stress profile. It completed {overall['aal_benign_completions']}/{overall['benign_cases']} benign controls. Two declared assurance-boundary controls---trusted-reader acceptance of a physical spoof and same-identity runtime pose drift---were admitted in {overall['residual_controls_admitted_as_expected']}/{overall['residual_limitation_controls']} cases as expected and are excluded from the in-scope hazard total.",
        r"\end{minipage}",
        r"\end{table*}",
        "",
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
