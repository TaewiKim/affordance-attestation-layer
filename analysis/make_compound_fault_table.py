#!/usr/bin/env python3
"""Generate and validate the compound-fault results table."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "compound_fault_summary.json"
OUTPUT = ROOT / "generated" / "compound_fault_table.tex"

ROWS = (
    ("pre_issue_pair", "Pre-issuance pair"),
    ("pre_issue_triple", "Pre-issuance triple"),
    ("runtime_pair", "Runtime pair"),
    ("post_issue_plus_runtime", "Post-issuance mutation + runtime fault"),
)


def main() -> None:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    overall = data["overall"]
    regimes = data["regimes"]

    assert overall["hazard_cases"] == 2000
    assert overall["aal_barrier_escapes"] == 0
    assert overall["no_guard_escapes"] == 2000
    assert overall["simplex_escapes"] == 1530
    assert overall["benign_cases"] == 500
    assert overall["aal_benign_completions"] == 500
    assert overall["aal_false_blocks_or_aborts"] == 0
    assert sum(regimes[key]["n"] for key, _ in ROWS) == overall["hazard_cases"]
    assert sum(regimes[key]["aal_escapes"] for key, _ in ROWS) == 0
    assert sum(regimes[key]["simplex_escapes"] for key, _ in ROWS) == 1530

    lines = [
        r"\begin{table*}[t]",
        r"\centering\small",
        r"\caption{Compound-fault interaction campaign. Numeric columns report barrier escapes. Fault pairs/triples are sampled for assurance-channel coverage rather than deployment frequency.}",
        r"\label{tab:compound}",
        r"\begin{tabular}{>{\raggedright\arraybackslash}p{6.4cm}rrrr}",
        r"\toprule",
        r"Regime & Cases & AAL & No guard & Simplex/RTA\\",
        r"\midrule",
    ]
    for key, label in ROWS:
        row = regimes[key]
        lines.append(
            f"{label} & {row['n']} & {row['aal_escapes']} & "
            f"{row['no_guard_escapes']} & {row['simplex_escapes']}\\\\"
        )
    lines += [
        r"\midrule",
        rf"\textbf{{Total hazardous demands}} & \textbf{{{overall['hazard_cases']}}} & \textbf{{{overall['aal_barrier_escapes']}}} & \textbf{{{overall['no_guard_escapes']}}} & \textbf{{{overall['simplex_escapes']}}}\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\textwidth}\footnotesize",
        rf"AAL's one-sided exact 95\% upper bound is {100 * overall['aal_escape_upper95']:.4f}\% for this generated campaign. It completed {overall['aal_benign_completions']}/{overall['benign_cases']} compound benign near-boundary controls.",
        r"\end{minipage}",
        r"\end{table*}",
        "",
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
