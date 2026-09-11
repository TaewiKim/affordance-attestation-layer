#!/usr/bin/env python3
"""Validate sensing-sensitivity results and generate the LaTeX table."""
from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "results" / "sensing_reliability_summary.json"
TABLE = ROOT / "generated" / "sensing_reliability_table.tex"

EXPECTED_TRUTH = {
    "single_factor": {"A": True, "B": False},
    "two_distinct_factors": {
        "AA": True,
        "AB": False,
        "BA": False,
        "BB": False,
    },
}
EXPECTED = {
    "independent_false_accept_1pct_no_common_cause": {
        "single_factor": 0.01,
        "two_distinct_factors": 0.0001,
    },
    "independent_false_accept_1pct_common_cause_1pct": {
        "single_factor": 0.0199,
        "two_distinct_factors": 0.010099,
    },
    "independent_miss_10pct_no_common_cause": {
        "single_factor": 0.9,
        "two_distinct_factors": 0.81,
    },
    "independent_miss_10pct_common_cause_5pct": {
        "single_factor": 0.855,
        "two_distinct_factors": 0.7695,
    },
}


def close(a: float, b: float) -> bool:
    return math.isclose(a, b, rel_tol=0.0, abs_tol=1e-12)


def main() -> None:
    data = json.loads(SUMMARY.read_text(encoding="utf-8"))
    if data["decision_truth_table"] != EXPECTED_TRUTH:
        raise ValueError("AAL sensing decision truth table changed")
    selected = data["selected_exact_probabilities"]
    for label, values in EXPECTED.items():
        for mode, value in values.items():
            if not close(selected[label][mode], value):
                raise ValueError(f"unexpected {label}/{mode}: {selected[label][mode]}")
    mc = data["monte_carlo"]
    if mc["n_per_selected_point"] != 50_000 or len(mc["rows"]) != 8:
        raise ValueError("unexpected Monte Carlo design")
    if mc["max_absolute_error"] > mc["max_allowed_absolute_error"]:
        raise ValueError("Monte Carlo implementation check exceeds tolerance")

    a = selected["independent_false_accept_1pct_no_common_cause"]
    b = selected["independent_false_accept_1pct_common_cause_1pct"]
    c = selected["independent_miss_10pct_no_common_cause"]
    d = selected["independent_miss_10pct_common_cause_5pct"]
    table = f"""\\begin{{table}}[t]
\\centering
\\caption{{Synthetic sensing-trust-base sensitivity. Rates are injected design parameters, not sensor measurements or deployment-risk estimates.}}
\\label{{tab:sensing_reliability}}
\\begin{{tabular}}{{lcc}}
\\toprule
Sensitivity point & Single factor & Two distinct factors\\\\
\\midrule
Escape: $q_i=1\\%$, $q_c=0$ & {100*a['single_factor']:.4f}\\% & \\textbf{{{100*a['two_distinct_factors']:.4f}\\%}}\\\\
Escape: $q_i=1\\%$, $q_c=1\\%$ & {100*b['single_factor']:.4f}\\% & \\textbf{{{100*b['two_distinct_factors']:.4f}\\%}}\\\\
Completion: $m_i=10\\%$, $m_c=0$ & {100*c['single_factor']:.2f}\\% & {100*c['two_distinct_factors']:.2f}\\%\\\\
Completion: $m_i=10\\%$, $m_c=5\\%$ & {100*d['single_factor']:.2f}\\% & {100*d['two_distinct_factors']:.2f}\\%\\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
    TABLE.parent.mkdir(parents=True, exist_ok=True)
    TABLE.write_text(table, encoding="utf-8")
    print(f"Wrote {TABLE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
