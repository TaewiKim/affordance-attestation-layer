#!/usr/bin/env python3
"""Replay AgentDojo's external task/injection manifests through the AAL gate.

This is API-free and model-free. It is an execution-boundary corpus test, not a
full dynamic prompt-injection run: trusted user-task ground-truth calls form the
authority manifest, and each AgentDojo injection-task ground-truth sequence is
replayed against that manifest.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from manifest_gate import TaskActionManifest

try:
    from agentdojo.task_suite.load_suites import get_suites
except ImportError as exc:
    raise SystemExit(
        "AgentDojo is not installed. Run: pip install -r agentdojo/requirements.txt"
    ) from exc

DEFAULT_SUITES = ("workspace", "travel", "banking", "slack")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--suite", action="append", dest="suites")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/agentdojo_manifest_oracle.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    requested = tuple(args.suites or DEFAULT_SUITES)
    available = get_suites(args.benchmark_version)
    missing = sorted(set(requested) - set(available))
    if missing:
        raise SystemExit(f"Unknown AgentDojo suites: {missing}")

    records: list[dict] = []
    clean_failures: list[dict] = []
    suite_summaries: dict[str, dict] = {}

    for suite_name in requested:
        suite = available[suite_name]
        base_environment = suite.load_and_inject_default_environment({})
        counts = Counter()
        denial_reasons = Counter()

        for user_task in suite.user_tasks.values():
            manifest = TaskActionManifest.from_user_task(
                suite, user_task, base_environment
            )
            user_environment = user_task.init_environment(
                base_environment.model_copy(deep=True)
            )
            trusted_calls = user_task.ground_truth(
                user_environment.model_copy(deep=True)
            )
            clean_decisions = manifest.replay(trusted_calls)
            clean_ok = all(decision.allowed for decision in clean_decisions)
            counts["user_tasks"] += 1
            counts["authorized_sensitive_calls"] += manifest.authorized_sensitive_count
            if not clean_ok:
                clean_failures.append({
                    "suite": suite_name,
                    "user_task": user_task.ID,
                    "decisions": [decision.__dict__ for decision in clean_decisions],
                })

            for injection_task in suite.injection_tasks.values():
                injection_calls = injection_task.ground_truth(
                    user_environment.model_copy(deep=True)
                )
                classification = manifest.classify_injection_calls(injection_calls)
                counts["pairs"] += 1
                counts["in_scope_pairs"] += int(classification["in_scope"])
                counts["requires_sensitive_pairs"] += int(
                    classification["requires_sensitive"]
                )
                counts["authority_overlap_pairs"] += int(
                    classification["authority_overlap"]
                )
                counts["no_sensitive_effect_pairs"] += int(
                    classification["no_sensitive_effect"]
                )
                counts["sensitive_injection_calls"] += classification[
                    "sensitive_call_count"
                ]
                counts["denied_sensitive_calls"] += classification[
                    "denied_sensitive_call_count"
                ]
                for decision in classification["decisions"]:
                    if decision["sensitive"] and not decision["allowed"]:
                        denial_reasons[decision["reason"]] += 1
                records.append({
                    "suite": suite_name,
                    "user_task": user_task.ID,
                    "injection_task": injection_task.ID,
                    **classification,
                })

        needs = counts["requires_sensitive_pairs"]
        suite_summaries[suite_name] = {
            **dict(counts),
            "manifest_separation_rate": (
                counts["in_scope_pairs"] / needs if needs else None
            ),
            "denial_reasons": dict(denial_reasons),
        }

    overall = Counter()
    for summary in suite_summaries.values():
        for key in (
            "user_tasks", "authorized_sensitive_calls", "pairs",
            "in_scope_pairs", "requires_sensitive_pairs", "authority_overlap_pairs",
            "no_sensitive_effect_pairs", "sensitive_injection_calls",
            "denied_sensitive_calls",
        ):
            overall[key] += summary.get(key, 0)

    payload = {
        "benchmark": {
            "name": "AgentDojo",
            "package_version": "0.1.35",
            "benchmark_version": args.benchmark_version,
            "suites": list(requested),
        },
        "scope": (
            "API-free replay of AgentDojo user/injection ground-truth tool-call "
            "manifests through an AAL-style single-use action-manifest gate. "
            "This is not a dynamic LLM attack run and does not test physical sensing."
        ),
        "overall": {
            **dict(overall),
            "manifest_separation_rate": (
                overall["in_scope_pairs"] / overall["requires_sensitive_pairs"]
                if overall["requires_sensitive_pairs"] else None
            ),
            "clean_manifest_compatibility": (
                (overall["user_tasks"] - len(clean_failures)) / overall["user_tasks"]
                if overall["user_tasks"] else None
            ),
        },
        "suites": suite_summaries,
        "clean_failures": clean_failures,
        "records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    print("=== AgentDojo action-manifest oracle replay ===")
    print(payload["scope"])
    print(json.dumps(payload["overall"], indent=2, sort_keys=True))
    print(f"Saved: {args.output}")

    if clean_failures:
        raise SystemExit("FAIL: trusted user-task ground truth was denied")
    # Every attack needing a sensitive effect must either fall outside the
    # user's authority (in scope) or be an explicitly reported overlap. A
    # silent third category would mean the classification lost a pair.
    accounted = overall["in_scope_pairs"] + overall["authority_overlap_pairs"]
    if accounted != overall["requires_sensitive_pairs"]:
        raise SystemExit("FAIL: injection pair accounting does not balance")


if __name__ == "__main__":
    main()
