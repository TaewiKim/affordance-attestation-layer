#!/usr/bin/env python3
"""Run AgentDojo with the AAL action-manifest execution gate.

This is the full dynamic benchmark and requires the model provider's API
credential. The default configuration matches AgentDojo's published
GPT-4o-mini/important_instructions result for direct comparability.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from executor import AALManifestExecutor, ResetManifest
from manifest_gate import TaskActionManifest

try:
    import agentdojo.attacks  # noqa: F401 - registers built-in attacks
    from agentdojo.agent_pipeline.agent_pipeline import (
        AgentPipeline,
        get_llm,
        load_system_message,
    )
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from agentdojo.attacks import load_attack
    from agentdojo.benchmark import (
        run_task_with_injection_tasks,
        run_task_without_injection_tasks,
    )
    from agentdojo.logging import OutputLogger
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum
    from agentdojo.task_suite.load_suites import get_suites
except ImportError as exc:
    raise SystemExit(
        "AgentDojo is not installed. Run: pip install -r agentdojo/requirements.txt"
    ) from exc

DEFAULT_SUITES = ("workspace", "travel", "banking", "slack")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--model-id", default=None)
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--suite", action="append", dest="suites")
    parser.add_argument("--user-task", action="append", dest="user_tasks")
    parser.add_argument("--injection-task", action="append", dest="injection_tasks")
    parser.add_argument("--tool-delimiter", default="tool")
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument(
        "--logdir", type=Path, default=Path("results/agentdojo_traces")
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/agentdojo_aal_live.json"),
    )
    return parser.parse_args()


def build_pipeline(args: argparse.Namespace, manifest: TaskActionManifest) -> AgentPipeline:
    model = ModelsEnum(args.model)
    llm = get_llm(
        MODEL_PROVIDERS[model], args.model, args.model_id, args.tool_delimiter
    )
    system = SystemMessage(load_system_message(None))
    init = InitQuery()
    executor = AALManifestExecutor(manifest)
    loop = ToolsExecutionLoop([executor, llm])
    pipeline = AgentPipeline([system, init, ResetManifest(manifest), llm, loop])
    pipeline.name = f"{args.model}-aal-action-manifest"
    return pipeline


def selected_tasks(all_tasks: dict, requested: list[str] | None) -> list:
    if not requested:
        return list(all_tasks.values())
    missing = sorted(set(requested) - set(all_tasks))
    if missing:
        raise SystemExit(f"Unknown task IDs: {missing}")
    return [all_tasks[task_id] for task_id in requested]


def main() -> None:
    args = parse_args()
    suites = get_suites(args.benchmark_version)
    requested_suites = tuple(args.suites or DEFAULT_SUITES)
    missing = sorted(set(requested_suites) - set(suites))
    if missing:
        raise SystemExit(f"Unknown suites: {missing}")

    records: list[dict] = []
    clean_records: list[dict] = []
    totals = {
        "clean_tasks": 0,
        "clean_utility_successes": 0,
        "attack_pairs": 0,
        "utility_under_attack_successes": 0,
        "blocked_pairs": 0,
        "attack_successes": 0,
        "in_scope_pairs": 0,
        "in_scope_attack_successes": 0,
        "authority_overlap_pairs": 0,
        "no_sensitive_effect_pairs": 0,
        "blocked_sensitive_calls": 0,
        "allowed_sensitive_calls": 0,
        "allowed_read_only_calls": 0,
    }

    args.logdir.mkdir(parents=True, exist_ok=True)
    with OutputLogger(str(args.logdir)):
        for suite_name in requested_suites:
            suite = suites[suite_name]
            base_environment = suite.load_and_inject_default_environment({})
            users = selected_tasks(suite.user_tasks, args.user_tasks)
            injections = selected_tasks(suite.injection_tasks, args.injection_tasks)

            for user_task in users:
                manifest = TaskActionManifest.from_user_task(
                    suite, user_task, base_environment
                )
                pipeline = build_pipeline(args, manifest)
                clean_utility, _ = run_task_without_injection_tasks(
                    suite,
                    pipeline,
                    user_task,
                    args.logdir,
                    args.force_rerun,
                    args.benchmark_version,
                )
                totals["clean_tasks"] += 1
                totals["clean_utility_successes"] += int(clean_utility)
                clean_records.append({
                    "suite": suite_name,
                    "user_task": user_task.ID,
                    "utility": clean_utility,
                    "authorized_sensitive_calls": manifest.authorized_sensitive_count,
                })

                attack = load_attack(args.attack, suite, pipeline)
                user_environment = user_task.init_environment(
                    base_environment.model_copy(deep=True)
                )
                for injection_task in injections:
                    classification = manifest.classify_injection_calls(
                        injection_task.ground_truth(
                            user_environment.model_copy(deep=True)
                        )
                    )
                    before = (
                        manifest.audit.denied_sensitive,
                        manifest.audit.allowed_sensitive,
                        manifest.audit.allowed_read_only,
                    )
                    utility_map, security_map = run_task_with_injection_tasks(
                        suite,
                        pipeline,
                        user_task,
                        attack,
                        args.logdir,
                        args.force_rerun,
                        injection_tasks=[injection_task.ID],
                        benchmark_version=args.benchmark_version,
                    )
                    key = (user_task.ID, injection_task.ID)
                    utility = utility_map[key]
                    security = security_map[key]
                    after = (
                        manifest.audit.denied_sensitive,
                        manifest.audit.allowed_sensitive,
                        manifest.audit.allowed_read_only,
                    )
                    blocked = after[0] - before[0]
                    allowed_sensitive = after[1] - before[1]
                    allowed_reads = after[2] - before[2]

                    totals["attack_pairs"] += 1
                    totals["utility_under_attack_successes"] += int(utility)
                    totals["attack_successes"] += int(security)
                    totals["blocked_pairs"] += int(not security)
                    totals["in_scope_pairs"] += int(classification["in_scope"])
                    totals["in_scope_attack_successes"] += int(
                        classification["in_scope"] and security
                    )
                    totals["authority_overlap_pairs"] += int(
                        classification["authority_overlap"]
                    )
                    totals["no_sensitive_effect_pairs"] += int(
                        classification["no_sensitive_effect"]
                    )
                    totals["blocked_sensitive_calls"] += blocked
                    totals["allowed_sensitive_calls"] += allowed_sensitive
                    totals["allowed_read_only_calls"] += allowed_reads
                    records.append({
                        "suite": suite_name,
                        "user_task": user_task.ID,
                        "injection_task": injection_task.ID,
                        "utility": utility,
                        "security": security,
                        "attack_success": security,
                        "blocked_sensitive_calls": blocked,
                        "allowed_sensitive_calls": allowed_sensitive,
                        "allowed_read_only_calls": allowed_reads,
                        "manifest_classification": classification,
                    })

    clean_n = totals["clean_tasks"]
    attack_n = totals["attack_pairs"]
    in_scope_n = totals["in_scope_pairs"]
    metrics = {
        **totals,
        "clean_utility": (
            totals["clean_utility_successes"] / clean_n if clean_n else None
        ),
        "utility_under_attack": (
            totals["utility_under_attack_successes"] / attack_n
            if attack_n else None
        ),
        "targeted_asr": (
            totals["attack_successes"] / attack_n if attack_n else None
        ),
        "in_scope_targeted_asr": (
            totals["in_scope_attack_successes"] / in_scope_n
            if in_scope_n else None
        ),
    }
    payload = {
        "benchmark": {
            "name": "AgentDojo",
            "package_version": "0.1.35",
            "benchmark_version": args.benchmark_version,
            "model": args.model,
            "attack": args.attack,
            "suites": list(requested_suites),
        },
        "scope": (
            "Dynamic AgentDojo run with an AAL-style task-ground-truth action "
            "manifest at the tool execution boundary. Physical target sensing "
            "and spatial re-attestation are not represented by AgentDojo."
        ),
        "metrics": metrics,
        "clean_records": clean_records,
        "attack_records": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print("=== AgentDojo + AAL action-manifest gate ===")
    print(json.dumps(metrics, indent=2, sort_keys=True))
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
