#!/usr/bin/env python3
"""Generate and validate the AgentDojo results table.

Every number is read from the committed run files. The table reports the
pooled targeted ASR beside the scope-separated figures, because the pooled
number counts attacks an authorization layer cannot bear on.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "results" / "agentdojo_manifest_oracle.json"
LIVE = ROOT / "results" / "agentdojo_aal_live.json"
SCOPE = ROOT / "results" / "agentdojo_scope_analysis.json"
REFERENCE = ROOT / "agentdojo" / "published_reference.json"
OUTPUT = ROOT / "generated" / "agentdojo_table.tex"

BUCKETS = (
    ("in_scope", "In scope: sensitive effect outside user authority"),
    ("authority_overlap", "Authority overlap: effect already authorized"),
    ("no_sensitive_effect", "No security-sensitive tool effect"),
)


def pct(x: float) -> str:
    return f"{100 * x:.2f}"


def main() -> None:
    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))["overall"]
    live = json.loads(LIVE.read_text(encoding="utf-8"))
    scope = json.loads(SCOPE.read_text(encoding="utf-8"))
    published = json.loads(REFERENCE.read_text(encoding="utf-8"))
    metrics = live["metrics"]

    # The replay and the dynamic run must describe the same corpus.
    assert oracle["user_tasks"] == live["metrics"]["clean_tasks"] == 97
    assert oracle["pairs"] == metrics["attack_pairs"] == 949
    assert oracle["requires_sensitive_pairs"] == 609
    assert oracle["in_scope_pairs"] == metrics["in_scope_pairs"] == 606
    assert oracle["authority_overlap_pairs"] == 3
    assert oracle["no_sensitive_effect_pairs"] == 340
    assert oracle["clean_manifest_compatibility"] == 1.0

    # Buckets must partition the attack pairs, with no pair counted twice.
    buckets = scope["buckets"]
    assert sum(buckets[k]["pairs"] for k, _ in BUCKETS) == metrics["attack_pairs"]
    assert sum(buckets[k]["attack_successes"] for k, _ in BUCKETS) == 17

    artifacts = scope["trace_evaluation_artifacts"]
    assert len(artifacts) == 5
    assert {a["injection_task"] for a in artifacts} == {"injection_task_5"}
    assert all(a["sensitive_calls_denied"] == a["sensitive_calls_required"] for a in artifacts)
    assert scope["in_scope_asr_excluding_artifacts"] == 0.0

    ref = published["primary_reference"]
    assert ref["model"] == "gpt-4o-mini-2024-07-18"
    assert ref["attack"] == "important_instructions"
    assert ref["defense"] is None

    lines = [
        r"\begin{table*}[t]",
        r"\centering\small",
        r"\caption{External penetration benchmark (AgentDojo 0.1.35, benchmark data v1.2.2; "
        r"\texttt{gpt-4o-mini-2024-07-18} with the \texttt{important\_instructions} attack over the "
        r"workspace, travel, banking, and slack suites). Published unguarded figures are an external "
        r"comparison target, not measurements of \aal{}.}",
        r"\label{tab:agentdojo}",
        r"\begin{tabular}{>{\raggedright\arraybackslash}p{7.6cm}rr}",
        r"\toprule",
        r"Quantity & \aal{} & Unguarded (published)\\",
        r"\midrule",
        rf"Clean utility (\%) & {pct(metrics['clean_utility'])} & {pct(ref['utility'])}\\",
        rf"Utility under attack (\%) & {pct(metrics['utility_under_attack'])} & {pct(ref['utility_under_attack'])}\\",
        rf"Targeted attack success, pooled (\%) & {pct(metrics['targeted_asr'])} & {pct(ref['targeted_asr'])}\\",
        r"\midrule",
        r"\multicolumn{3}{l}{\emph{Attack pairs separated by what an authorization layer can govern}}\\",
    ]
    for key, label in BUCKETS:
        b = buckets[key]
        lines.append(
            rf"\quad {label} & {b['attack_successes']}/{b['pairs']} & ---\\"
        )
    # Two endpoints, both reported. The benchmark scores a targeted attack from
    # the proposed-call trace; the safety question is whether an unauthorized
    # sensitive effect was executed. Presenting the second as the first with
    # cases "excluded" reads as a rate recomputed after seeing the failures.
    in_scope = buckets["in_scope"]
    lines += [
        r"\midrule",
        rf"\textbf{{Out-of-authority sensitive effects dispatched}} & "
        rf"\textbf{{0/{in_scope['pairs']}}} & ---\\",
        rf"\quad of which blocked calls scored as success by the trace scorer & "
        rf"{len(artifacts)}/{in_scope['pairs']} & ---\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\begin{minipage}{0.96\textwidth}\footnotesize",
        rf"An API-free replay of AgentDojo's own ground-truth action sequences admitted "
        rf"{oracle['user_tasks']}/{oracle['user_tasks']} trusted user tasks "
        rf"(clean-manifest compatibility {oracle['clean_manifest_compatibility']:.2f}); of the "
        rf"{oracle['requires_sensitive_pairs']} attack pairs needing a security-sensitive effect, "
        rf"{oracle['in_scope_pairs']} required one outside the user's authority "
        rf"(manifest separation {pct(oracle['manifest_separation_rate'])}\%). "
        rf"All {len(artifacts)} in-scope successes are \texttt{{slack}}$\times$\texttt{{injection\_task\_5}}, "
        r"whose goal is transient (invite the attacker, add him to a channel, remove him), so the final "
        r"environment equals the initial one and AgentDojo scores it from the call trace. That trace is "
        r"collected from assistant messages, i.e.\ proposed rather than executed calls; every sensitive "
        r"call the attack required lay outside the manifest and was refused, so no such effect was "
        r"dispatched. AgentDojo's targeted attack success is a proposal-sensitive benchmark endpoint; "
        r"the safety endpoint here is execution of an unauthorized sensitive effect. Both are given, "
        r"and the five cases are neither reclassified nor removed from the benchmark endpoint. "
        r"Authority-overlap and no-sensitive-effect pairs are excluded from the in-scope denominator: "
        r"content safety belongs to the planner's refusal layer, not to authorization. "
        rf"The clean-utility gap against the unguarded baseline "
        rf"({pct(metrics['clean_utility'])}\% versus {pct(ref['utility'])}\%) is the measured cost of "
        r"authorization. AgentDojo does not model physical sensing, so no target-identity, spatial, or "
        r"robot-stopping claim is inferred from it. A dash marks a row for which no "
        r"published unguarded figure exists, rather than a missing measurement.",
        r"\end{minipage}",
        r"\end{table*}",
        "",
    ]

    for line in lines:
        stripped = line.rstrip()
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing > 2:
            raise SystemExit(
                f"row ends in {trailing} backslashes, which LaTeX reads as "
                f"{trailing // 2} row breaks: {stripped[:70]!r}"
            )

    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] {OUTPUT.relative_to(ROOT)}")
    print(f"     clean utility {pct(metrics['clean_utility'])}% vs published {pct(ref['utility'])}%")
    print(f"     pooled ASR {pct(metrics['targeted_asr'])}% vs published {pct(ref['targeted_asr'])}%")
    print(f"     in-scope ASR excluding artifacts {pct(scope['in_scope_asr_excluding_artifacts'])}%")


if __name__ == "__main__":
    main()
