#!/usr/bin/env python3
"""Implementation-checked sensing reliability and common-cause sensitivity.

Assumption A3 is relaxed in a synthetic design-sensitivity model. Injected
rates are not measurements of the prototype readers or deployment risk.
"""
from __future__ import annotations

import csv
import json
import random
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AAL_IMPL = ROOT
if str(AAL_IMPL) not in sys.path:
    sys.path.insert(0, str(AAL_IMPL))

from aal.authority import ProtocolEngine, make_order  # noqa: E402
from aal.types import ActionRequest, Capability, Clock, Denial, Evidence, WorldState  # noqa: E402
from aal.verifier import AALVerifier  # noqa: E402

SEED = 20260830
N_MC = 50_000
MAX_MC_ABSOLUTE_ERROR = 0.005
Q_INDEPENDENT = (0.001, 0.005, 0.01, 0.05)
Q_COMMON = (0.0, 0.0001, 0.001, 0.01, 0.05)
M_INDEPENDENT = (0.01, 0.05, 0.10, 0.20)
M_COMMON = (0.0, 0.01, 0.05)
MODES = ("single_factor", "two_distinct_factors")


@dataclass(frozen=True)
class GridRow:
    outcome: str
    mode: str
    independent_rate: float
    common_cause_rate: float
    probability: float


@dataclass(frozen=True)
class MonteCarloRow:
    outcome: str
    mode: str
    independent_rate: float
    common_cause_rate: float
    n: int
    events: int
    observed_probability: float
    analytical_probability: float
    absolute_error: float


def evidence_for(pattern: str, now: float = 10_000.0) -> list[Evidence]:
    if len(pattern) not in (1, 2) or any(char not in "AB" for char in pattern):
        raise ValueError(pattern)
    types = ("barcode", "rfid")[:len(pattern)]
    return [
        Evidence(
            evidence_type,
            "authorized_entity" if report == "A" else "unauthorized_entity",
            0.98,
            now,
            f"sens_{evidence_type}",
        )
        for evidence_type, report in zip(types, pattern)
    ]


def aal_admits(pattern: str, mode: str, case_id: int) -> bool:
    clock = Clock(10_000.0)
    room = "sensing_reliability_cell"
    order = make_order(
        f"SENS_{case_id}", Capability.GRASP, "authorized_entity", room=room
    )
    request = ActionRequest(
        Capability.GRASP,
        "authorized_entity",
        room=room,
        params={"speed_mps": 0.10, "force_n": 1.0},
        origin="sensing_reliability_sensitivity",
    )
    # Once A3 is violated, AAL sees the trusted stack's report rather than the
    # unobserved physical truth.
    world = WorldState(
        room=room,
        present_target_id="authorized_entity",
        workspace_clear=True,
        tool_state={"calibrated": True, "tool_id": ""},
        human_in_workspace=False,
        identity_confidence=0.98,
    )
    verifier = AALVerifier(
        clock,
        {
            "ephemeral_ledger": True,
            "require_two_factor": mode == "two_distinct_factors",
        },
    )
    result = verifier.certify(
        request, world, evidence_for(pattern), order, ProtocolEngine()
    )
    return not isinstance(result, Denial)


def decision_truth_table() -> dict[str, dict[str, bool]]:
    table: dict[str, dict[str, bool]] = {}
    case_id = 0
    for mode, patterns in {
        "single_factor": ("A", "B"),
        "two_distinct_factors": ("AA", "AB", "BA", "BB"),
    }.items():
        table[mode] = {}
        for pattern in patterns:
            table[mode][pattern] = aal_admits(pattern, mode, case_id)
            case_id += 1
    expected = {
        "single_factor": {"A": True, "B": False},
        "two_distinct_factors": {
            "AA": True,
            "AB": False,
            "BA": False,
            "BB": False,
        },
    }
    if table != expected:
        raise RuntimeError(f"unexpected verifier decision map: {table}")
    return table


def hazard_escape_probability(mode: str, q_ind: float, q_common: float) -> float:
    factors = 1 if mode == "single_factor" else 2
    return q_common + (1.0 - q_common) * q_ind**factors


def benign_completion_probability(mode: str, m_ind: float, m_common: float) -> float:
    factors = 1 if mode == "single_factor" else 2
    return (1.0 - m_common) * (1.0 - m_ind) ** factors


def exact_grid() -> list[GridRow]:
    rows: list[GridRow] = []
    for mode in MODES:
        for q_ind in Q_INDEPENDENT:
            for q_common in Q_COMMON:
                rows.append(GridRow(
                    "hazard_escape", mode, q_ind, q_common,
                    hazard_escape_probability(mode, q_ind, q_common),
                ))
        for m_ind in M_INDEPENDENT:
            for m_common in M_COMMON:
                rows.append(GridRow(
                    "benign_completion", mode, m_ind, m_common,
                    benign_completion_probability(mode, m_ind, m_common),
                ))
    return rows


def draw_pattern(rng: random.Random, mode: str, independent_rate: float,
                 common_rate: float, *, hazard: bool) -> str:
    factors = 1 if mode == "single_factor" else 2
    if rng.random() < common_rate:
        return ("A" if hazard else "B") * factors
    if hazard:
        return "".join(
            "A" if rng.random() < independent_rate else "B"
            for _ in range(factors)
        )
    return "".join(
        "B" if rng.random() < independent_rate else "A"
        for _ in range(factors)
    )


def run_mc_point(rng: random.Random, outcome: str, mode: str,
                 independent_rate: float, common_rate: float,
                 case_start: int) -> MonteCarloRow:
    hazard = outcome == "hazard_escape"
    analytical = (
        hazard_escape_probability(mode, independent_rate, common_rate)
        if hazard else
        benign_completion_probability(mode, independent_rate, common_rate)
    )
    events = 0
    for index in range(N_MC):
        pattern = draw_pattern(
            rng, mode, independent_rate, common_rate, hazard=hazard
        )
        events += aal_admits(pattern, mode, case_start + index)
    observed = events / N_MC
    return MonteCarloRow(
        outcome, mode, independent_rate, common_rate, N_MC, events,
        observed, analytical, abs(observed - analytical),
    )


def monte_carlo_checks() -> list[MonteCarloRow]:
    rng = random.Random(SEED)
    points = [
        ("hazard_escape", "single_factor", 0.01, 0.0),
        ("hazard_escape", "two_distinct_factors", 0.01, 0.0),
        ("hazard_escape", "single_factor", 0.01, 0.01),
        ("hazard_escape", "two_distinct_factors", 0.01, 0.01),
        ("benign_completion", "single_factor", 0.10, 0.0),
        ("benign_completion", "two_distinct_factors", 0.10, 0.0),
        ("benign_completion", "single_factor", 0.10, 0.05),
        ("benign_completion", "two_distinct_factors", 0.10, 0.05),
    ]
    rows: list[MonteCarloRow] = []
    case_id = 1_000_000
    for point in points:
        rows.append(run_mc_point(rng, *point, case_start=case_id))
        case_id += N_MC
    max_error = max(row.absolute_error for row in rows)
    if max_error > MAX_MC_ABSOLUTE_ERROR:
        raise RuntimeError(
            f"Monte Carlo implementation check drifted: {max_error:.6f} > "
            f"{MAX_MC_ABSOLUTE_ERROR:.6f}"
        )
    return rows


def write_csv(rows, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(asdict(rows[0])))
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)


def selected_probabilities() -> dict[str, dict[str, float]]:
    return {
        "independent_false_accept_1pct_no_common_cause": {
            mode: hazard_escape_probability(mode, 0.01, 0.0) for mode in MODES
        },
        "independent_false_accept_1pct_common_cause_1pct": {
            mode: hazard_escape_probability(mode, 0.01, 0.01) for mode in MODES
        },
        "independent_miss_10pct_no_common_cause": {
            mode: benign_completion_probability(mode, 0.10, 0.0) for mode in MODES
        },
        "independent_miss_10pct_common_cause_5pct": {
            mode: benign_completion_probability(mode, 0.10, 0.05) for mode in MODES
        },
    }


def main() -> None:
    truth_table = decision_truth_table()
    grid = exact_grid()
    mc = monte_carlo_checks()
    selected = selected_probabilities()

    result_dir = ROOT / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    grid_path = result_dir / "sensing_reliability_grid.csv"
    mc_path = result_dir / "sensing_reliability_mc.csv"
    summary_path = result_dir / "sensing_reliability_summary.json"
    write_csv(grid, grid_path)
    write_csv(mc, mc_path)

    payload = {
        "scope": (
            "Synthetic sensitivity under injected reader faults. Rates are design "
            "parameters, not estimates of sensor reliability or deployment risk."
        ),
        "decision_truth_table": truth_table,
        "fault_model": {
            "hazard": (
                "with probability q_common all readers falsely accept the authorized "
                "identity; otherwise each falsely accepts independently with q_ind"
            ),
            "benign": (
                "with probability m_common all readers miss the authorized identity; "
                "otherwise each misses independently with m_ind"
            ),
        },
        "selected_exact_probabilities": selected,
        "monte_carlo": {
            "seed": SEED,
            "n_per_selected_point": N_MC,
            "max_allowed_absolute_error": MAX_MC_ABSOLUTE_ERROR,
            "max_absolute_error": max(row.absolute_error for row in mc),
            "rows": [asdict(row) for row in mc],
        },
    }
    summary_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    print("=== Sensing trust-base/common-cause sensitivity ===")
    print(payload["scope"])
    for label, values in selected.items():
        print(f"\n{label}")
        for mode, value in values.items():
            print(f"  {mode:22s}: {value:.6f}")
    print(
        f"\nMC max |observed-exact|: "
        f"{payload['monte_carlo']['max_absolute_error']:.6f}"
    )
    for path in (grid_path, mc_path, summary_path):
        print(f"Saved: {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
