# AAL — reproduction code and result data

The Affordance Attestation Layer (AAL) is a runtime barrier between an untrusted
planner and a robot controller. It admits an action only when an independent task
authority, live sensed evidence of the physically present target, the protocol and
tool state, and the commanded endpoint resolve to one physical entity, and it
re-establishes that condition while the action executes.

This repository contains the implementation, the deterministic workload
generators, the analysis scripts, and every result file the reported figures are
computed from. It contains no write-up.

## Layout

| Path | What it is |
| --- | --- |
| `aal/` | The implementation: types, order authority, certifier, kernel, durable ledger, runtime monitor, bounded verifier, exact statistics |
| `experiments/` | Deterministic workload generators |
| `agentdojo/` | Bridge that runs the external AgentDojo prompt-injection benchmark through the AAL action-manifest gate |
| `analysis/` | Exact finite-sample bounds, profile sensitivity, and scope separation |
| `results/` | Committed result files (below) |

## Data

Every file in `results/` is produced by a script in this repository. Nothing is
hand-entered.

| File | Contents | Produced by |
| --- | --- | --- |
| `red_team_profile_summary.json` | Single-fault stress profile: 2,500 hazardous demands, 1,000 benign controls, 250 assurance-boundary controls, over five seeds; per-family and per-seed breakdowns | `experiments/run_internal_stress_profile.py` |
| `red_team_profile_families.csv` | Per-family aggregates for the same run | same |
| `red_team_profile_cases.csv` | Per-case log (regenerated locally, not committed) | same |
| `compound_fault_summary.json` | Compound-fault campaign: 2,000 interacting-fault demands and 500 near-boundary benign controls, by regime | `experiments/run_compound_faults.py` |
| `stateful_mission_summary.json` | Durable-lifecycle campaign: 1,000 mission units across completion, abort/retry, expiry, renewal, restart, and eight-contender races | `experiments/run_stateful_missions.py` |
| `sensing_reliability_summary.json` | Exact independent/common-cause reader model with a Monte Carlo cross-check of the actual verifier | `experiments/run_sensing_reliability_model.py` |
| `sensing_reliability_grid.csv` | Exact escape and completion surface over the modelled rates | same |
| `sensing_reliability_mc.csv` | Monte Carlo points and their deviation from the exact model | same |
| `overhead_benchmark.json` | CPU-side timing of the deterministic path, with host details. Host-specific | `experiments/run_overhead_benchmark.py` |
| `profile_sensitivity.csv` | Group-specific exact bounds combined under hypothetical hazard weights | `analysis/barrier_reliability.py` |
| `agentdojo_manifest_oracle.json` | API-free replay of AgentDojo's own ground-truth action sequences through the gate | `agentdojo/run_manifest_oracle.py` |
| `agentdojo_aal_live.json` | Dynamic AgentDojo run: 97 user tasks and 949 attack pairs | `agentdojo/run_live_benchmark.py` |
| `agentdojo_scope_analysis.json` | The dynamic run separated by what an authorization layer can govern | `analysis/agentdojo_scope_analysis.py` |
| `formal_check.json` | Bounded verification of properties P1–P9 over the enumerated domain | `python -m aal.formal` |

Two result sets in the study are not reproducible from this repository, and are
not included: the physical robot trials, which need the arm and its sensing
hardware, and the full-robot simulation, which needs a licensed simulator.

## Reproducing

Python 3.12 or later. The deterministic parts need no third-party packages.

```bash
export PYTHONPATH=.:experiments        # on Windows: set PYTHONPATH=.;experiments
python -m aal.formal                   # bounded verification, P1-P9
python experiments/run_internal_stress_profile.py
python experiments/run_compound_faults.py
python experiments/run_stateful_missions.py
python analysis/barrier_reliability.py
python analysis/agentdojo_scope_analysis.py
```

Each runner exits non-zero if an in-scope hazardous demand escapes the barrier, a
benign control fails, or a lifecycle outcome is violated. These runs are
deterministic: re-running must reproduce the committed files byte for byte. A
changed number is a bug, not a new result.

Two runs are separated because they are slower or need more than the standard
library:

```bash
python experiments/run_sensing_reliability_model.py      # 400,000 verifier calls
python experiments/run_overhead_benchmark.py             # host-specific timing
```

### External benchmark

The AgentDojo bridge needs the benchmark package, and the dynamic run needs a
model-provider credential supplied through the environment. Never commit one.

```bash
python -m pip install -r agentdojo/requirements.txt
python agentdojo/run_manifest_oracle.py                  # API-free, ground-truth replay
export OPENAI_API_KEY=...
python agentdojo/run_live_benchmark.py --model gpt-4o-mini-2024-07-18 --attack important_instructions
```

`agentdojo/published_reference.json` holds the benchmark's published unguarded
figures. They are a comparison target, not measurements of this system.

## Scope of the evidence

The generated profiles define evaluated distributions, not deployment
distributions. The exact zero-failure bounds computed here are finite-sample
statements about those distributions and are not estimates of deployment risk;
inferring one would need observed field frequencies, which this repository does
not contain. The overhead numbers are host-specific and travel poorly: on a
second, deliberately unlike host the durable-ledger paths differ by an order of
magnitude.

Two assurance boundaries are deliberately exercised and deliberately not
defended: a physical spoof already accepted by a trusted reader, and same-identity
pose drift during execution. Their controls are expected to be admitted, and they
are excluded from the in-scope denominator rather than counted as successes.

## Licence

MIT, see `LICENSE`. Third-party packages retain their own terms; the AgentDojo
benchmark is installed from its own distribution and is not vendored here.
