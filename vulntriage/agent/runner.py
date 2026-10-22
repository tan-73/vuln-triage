"""The agent loop: let the model call read-only tools, then parse its JSON report draft."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from vulntriage.agent.prompts import SYSTEM_PROMPT, TASK_PROMPT
from vulntriage.agent.tools import TOOL_SPECS, Toolbox
from vulntriage.llm.base import LLMError, LLMProvider, Message

log = logging.getLogger(__name__)


class ActionDraft(BaseModel):
    """The model's explanation of one remediation group."""

    group_key: str
    why: str = ""
    evidence: list[str] = Field(default_factory=list)
    fix: str = ""


class DeferDraft(BaseModel):
    """The model's reason a group can wait."""

    group_key: str
    reason: str = ""


class ReportDraft(BaseModel):
    """Structured output requested from the model."""

    executive_summary: str = ""
    actions: list[ActionDraft] = Field(default_factory=list)
    defer: list[DeferDraft] = Field(default_factory=list)


@dataclass
class AgentResult:
    """Outcome of one agent run."""

    draft: ReportDraft | None
    turns: int = 0
    tool_calls: int = 0
    error: str | None = None
    raw_text: str = ""
    usage: dict[str, int] = field(default_factory=dict)


_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def parse_draft(text: str) -> ReportDraft:
    """Extract the JSON object from model output (fenced or bare) and validate it."""
    match = _JSON_FENCE.search(text)
    candidate = match.group(1) if match else text[text.find("{") : text.rfind("}") + 1]
    if not candidate:
        raise ValueError("no JSON object in model output")
    data: Any = json.loads(candidate)
    return ReportDraft.model_validate(data)


class TriageAgent:
    """Runs the tool-calling loop for one report."""

    def __init__(
        self, provider: LLMProvider, toolbox: Toolbox, top_n: int = 5, max_turns: int = 12
    ) -> None:
        self.provider = provider
        self.toolbox = toolbox
        self.top_n = top_n
        self.max_turns = max_turns

    def run(self) -> AgentResult:
        """Drive the conversation until the model returns a valid draft or gives up."""
        task = TASK_PROMPT.format(top_n=self.top_n, limit=self.top_n + 5)
        messages: list[Message] = [Message(role="user", content=task)]
        result = AgentResult(draft=None)
        repaired = False
        for turn in range(1, self.max_turns + 1):
            result.turns = turn
            try:
                response = self.provider.complete(SYSTEM_PROMPT, messages, TOOL_SPECS)
            except LLMError as exc:
                result.error = str(exc)
                log.error("LLM call failed: %s", exc)
                return result
            for key, value in response.usage.items():
                result.usage[key] = result.usage.get(key, 0) + value
            messages.append(self.provider.assistant_message(response))
            if response.tool_calls:
                for call in response.tool_calls:
                    output = self.toolbox.execute(call.name, call.arguments)
                    result.tool_calls += 1
                    messages.append(
                        Message(role="tool", content=output, tool_call_id=call.id, name=call.name)
                    )
                continue
            result.raw_text = response.text
            try:
                result.draft = parse_draft(response.text)
                return result
            except (ValueError, ValidationError) as exc:
                if repaired:
                    result.error = f"model did not return valid JSON: {exc}"
                    return result
                repaired = True
                messages.append(
                    Message(
                        role="user",
                        content=f"That was not valid JSON for the requested shape ({exc}). "
                        "Reply with only the JSON object.",
                    )
                )
        result.error = f"no final answer after {self.max_turns} turns"
        return result
