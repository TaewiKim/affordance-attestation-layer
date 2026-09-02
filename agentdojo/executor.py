"""AgentDojo tool executor that enforces a task-scoped action manifest."""
from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Mapping, Sequence
from typing import Any

try:
    from .manifest_gate import GateDecision, TaskActionManifest
except ImportError:  # direct script execution
    from manifest_gate import GateDecision, TaskActionManifest

try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
    from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
    from agentdojo.types import (
        ChatMessage,
        ChatToolResultMessage,
        text_content_block_from_string,
    )
except ImportError as exc:  # pragma: no cover - exercised only without optional dependency
    raise RuntimeError(
        "AgentDojo is required. Install agentdojo/requirements.txt first."
    ) from exc


class ResetManifest(BasePipelineElement):
    """Reset single-use budgets at the beginning of each AgentDojo task run."""

    def __init__(self, manifest: TaskActionManifest) -> None:
        self.manifest = manifest

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ):
        self.manifest.reset()
        return query, runtime, env, messages, extra_args


class AALManifestExecutor(BasePipelineElement):
    """Fail-closed replacement for AgentDojo's ``ToolsExecutor``.

    Read-only/non-mutating calls pass. Every sensitive top-level or nested tool
    call must match an unused call in the trusted user-task manifest. A denied
    call is returned to the model as an execution error and is never dispatched
    to the environment.
    """

    def __init__(
        self,
        manifest: TaskActionManifest,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.manifest = manifest
        self.output_formatter = tool_output_formatter

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = (),
        extra_args: dict = {},
    ):
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1]["tool_calls"]
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        results = []
        valid_tool_names = set(runtime.functions)
        for tool_call in tool_calls:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                results.append(self._error_result(tool_call, "Empty function name."))
                continue
            if tool_call.function not in valid_tool_names:
                results.append(
                    self._error_result(tool_call, f"Invalid tool {tool_call.function}.")
                )
                continue

            for key, value in list(tool_call.args.items()):
                if isinstance(value, str) and is_string_list(value):
                    tool_call.args[key] = literal_eval(value)

            decisions: list[GateDecision] = []
            denial = self._authorize_call_tree(tool_call, valid_tool_names, decisions)
            if denial is not None:
                self._release(decisions)
                results.append(
                    self._error_result(
                        tool_call,
                        "AALAuthorizationDenied: "
                        f"{denial}; authority={self.manifest.authority_id}",
                    )
                )
                continue

            tool_result, error = runtime.run_function(
                env, tool_call.function, tool_call.args
            )
            if error is not None:
                self._release(decisions)
            results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(self.output_formatter(tool_result))],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )

        return query, runtime, env, [*messages, *results], extra_args

    def _authorize_call_tree(
        self,
        call: Any,
        valid_tool_names: set[str],
        decisions: list[GateDecision],
    ) -> str | None:
        """Authorize nested calls in the same order AgentDojo executes them."""
        for value in call.args.values():
            denial = self._authorize_nested_value(value, valid_tool_names, decisions)
            if denial is not None:
                return denial
        if call.function not in valid_tool_names:
            return f"invalid nested tool {call.function}"
        decision = self.manifest.authorize(call.function, call.args)
        decisions.append(decision)
        if not decision.allowed:
            return f"{call.function} is not authorized by the task manifest"
        return None

    def _authorize_nested_value(
        self,
        value: Any,
        valid_tool_names: set[str],
        decisions: list[GateDecision],
    ) -> str | None:
        if hasattr(value, "function") and hasattr(value, "args"):
            return self._authorize_call_tree(value, valid_tool_names, decisions)
        if isinstance(value, Mapping):
            for nested in value.values():
                denial = self._authorize_nested_value(nested, valid_tool_names, decisions)
                if denial is not None:
                    return denial
        elif isinstance(value, (list, tuple)):
            for nested in value:
                denial = self._authorize_nested_value(nested, valid_tool_names, decisions)
                if denial is not None:
                    return denial
        return None

    def _release(self, decisions: Sequence[GateDecision]) -> None:
        for decision in reversed(decisions):
            self.manifest.release(decision)

    @staticmethod
    def _error_result(tool_call: Any, error: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string("")],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=error,
        )
