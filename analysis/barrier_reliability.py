#!/usr/bin/env python3
"""Distribution-scoped barrier-reliability calculations for this study.

This script does not estimate deployment risk. It reports exact one-sided
Clopper--Pearson bounds for the two evaluated generated profiles and performs
profile-weight sensitivity using stratum-specific bounds from the orthogonal
red-team experiment.

No external dependencies are required.
"""
from __future__ import annotations

import csv
import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

ALPHA = 0.05
ROOT = Path(__file__).resolve().parents[1]
RED_TEAM_SUMMARY = ROOT / "results" / "red_team_profile_summary.json"
CSV_OUT = ROOT / "results" / "profile_sensitivity.csv"
TEX_OUT = ROOT / "from_results" / "profile_sensitivity_table.tex"


@dataclass(frozen=True)
class Stratum:
    name: str
    zero_failure_trials: int

    @property
    def upper95(self) -> float:
        return zero_failure_upper_bound(self.zero_failure_trials)


def zero_failure_upper_bound(n: int, alpha: float = ALPHA) -> float:
    """One-sided exact Clopper--Pearson upper bound for 0 failures in n trials."""
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0,1)")
    return 1.0 - alpha ** (1.0 / n)


def mixture_upper_bound(strata: dict[str, Stratum], weights: dict[str, float]) -> float:
    """Weighted sensitivity bound from stratum-specific exact upper bounds."""
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"weights must sum to 1, got {total}")
    unknown = set(weights) - set(strata)
    if unknown:
        raise ValueError(f"unknown strata: {sorted(unknown)}")
    return sum(weights[name] * strata[name].upper95 for name in weights)


def red_team_strata() -> dict[str, Stratum]:
    data = json.loads(RED_TEAM_SUMMARY.read_text(encoding="utf-8"))
    families = data["families"]
    groups = OrderedDict([
        ("authority", ["missing_order", "tampered_order", "expired_or_future_order"]),
        ("target_evidence", [
            "wrong_target_consistent_sensors", "sensor_conflict", "stale_evidence",
        ]),
        ("protocol_tool_context", [
            "protocol_skip", "wrong_tool_or_calibration", "wrong_room",
        ]),
        ("spatial", [
            "spatial_redirect", "spatial_frame_mismatch", "endpoint_mutation_after_issue",
        ]),
        ("replay", ["token_replay", "fresh_reissue_after_consumption"]),
        ("envelope", ["envelope_speed_excess", "envelope_force_excess"]),
        ("runtime", [
            "runtime_target_substitution", "runtime_workspace_intrusion",
            "runtime_confidence_drop", "runtime_evidence_staleness",
        ]),
    ])
    strata: dict[str, Stratum] = {}
    for label, names in groups.items():
        n = sum(families[name]["n"] for name in names)
        failures = sum(families[name]["aal_barrier_escapes"] for name in names)
        if failures != 0:
            raise ValueError(f"{label} is no longer a zero-failure stratum")
        strata[label] = Stratum(label, n)
    if sum(s.zero_failure_trials for s in strata.values()) != data["overall"]["hazard_cases"]:
        raise ValueError("red-team strata do not sum to the committed hazardous total")
    return strata


def profiles() -> OrderedDict[str, dict[str, float]]:
    return OrderedDict([
        ("Balanced", {
            "authority": 1 / 7, "target_evidence": 1 / 7,
            "protocol_tool_context": 1 / 7, "spatial": 1 / 7,
            "replay": 1 / 7, "envelope": 1 / 7, "runtime": 1 / 7,
        }),
        ("Authority-heavy", {
            "authority": .35, "target_evidence": .20,
            "protocol_tool_context": .15, "spatial": .10,
            "replay": .05, "envelope": .05, "runtime": .10,
        }),
        ("Runtime-heavy", {
            "authority": .10, "target_evidence": .10,
            "protocol_tool_context": .10, "spatial": .10,
            "replay": .05, "envelope": .15, "runtime": .40,
        }),
        ("Semantic-heavy", {
            "authority": .20, "target_evidence": .25,
            "protocol_tool_context": .20, "spatial": .20,
            "replay": .10, "envelope": .02, "runtime": .03,
        }),
    ])


def dominant_weight(weights: dict[str, float]) -> str:
    name, weight = max(weights.items(), key=lambda item: item[1])
    return f"{name.replace('_', ' ')} ({100 * weight:.1f}\\%)"


def write_outputs(strata: dict[str, Stratum]) -> list[dict[str, object]]:
    rows = []
    for label, weights in profiles().items():
        rows.append({
            "profile": label,
            "dominant_weight": dominant_weight(weights),
            "weighted_upper95": mixture_upper_bound(strata, weights),
            "weights": weights,
        })

    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["profile", "dominant_weight", "weighted_upper95"])
        for row in rows:
            writer.writerow([
                row["profile"], row["dominant_weight"],
                f"{row['weighted_upper95']:.12f}",
            ])

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Hypothetical operational-profile sensitivity using hazard-group-specific exact upper bounds from the orthogonal stress profile. These are sensitivity calculations, not deployment-risk estimates.}",
        r"\label{tab:profilesensitivity}",
        r"\begin{tabular}{lcc}",
        r"\toprule",
        r"Hypothetical profile & Largest class weight & Weighted upper 95\% bound\\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(
            f"{row['profile']} & {row['dominant_weight']} & "
            f"{100 * row['weighted_upper95']:.3f}\\%\\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ]
    TEX_OUT.parent.mkdir(parents=True, exist_ok=True)
    TEX_OUT.write_text("\n".join(lines), encoding="utf-8")
    return rows


def main() -> None:
    original = Stratum("original_profile", 931)
    orthogonal = Stratum("orthogonal_profile", 2500)
    semantic = Stratum("original_semantic", 881)
    physical = Stratum("original_physical", 50)

    print("=== Distribution-scoped exact zero-failure bounds ===")
    for s in (original, orthogonal, semantic, physical):
        print(f"{s.name:24s}: 0/{s.zero_failure_trials:<4d} upper95={100*s.upper95:.4f}%")

    strata = red_team_strata()
    print("\n=== Orthogonal-profile strata ===")
    for s in strata.values():
        print(f"{s.name:24s}: 0/{s.zero_failure_trials:<4d} upper95={100*s.upper95:.4f}%")

    print("\n=== Hypothetical profile sensitivity (NOT deployment risk) ===")
    for row in write_outputs(strata):
        print(f"{row['profile']:18s}: weighted upper95={100*row['weighted_upper95']:.4f}%")

    print(f"\nSaved: {CSV_OUT.relative_to(ROOT)}")
    print(f"Saved: {TEX_OUT.relative_to(ROOT)}")
    print("CAUTION: All quantities are scoped to generated profiles; none estimates deployment risk.")


if __name__ == "__main__":
    main()
