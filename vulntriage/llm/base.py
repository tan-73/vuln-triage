"""Provider-agnostic LLM interface with native tool/function calling.

The agent speaks only in these neutral types; each provider module converts them to its
SDK's wire format. Conversation state is a list of :class:`Message` objects:

* ``user``: plain text from us;
* ``assistant``: model text and/or :class:`ToolCall` requests;
* ``tool``: the JSON result of one tool call (``tool_call_id`` links it back).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class ToolSpec:
    """A tool the model may call. ``parameters`` is a JSON Schema object."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    """A model's request to run one tool."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    """One turn of the conversation in provider-neutral form."""

    role: Literal["user", "assistant", "tool"]
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    #: Provider-native object to replay verbatim (e.g. Gemini thought signatures).
    provider_state: Any = None


@dataclass
class LLMResponse:
    """What a provider returned for one completion request."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str | None = None
    provider_state: Any = None
    usage: dict[str, int] = field(default_factory=dict)


class LLMError(RuntimeError):
    """A provider call failed or the provider is misconfigured."""


class LLMProvider(ABC):
    """Interface every LLM backend implements."""

    name: str = "base"

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Run one completion. Must not execute tools itself."""

    def assistant_message(self, response: LLMResponse) -> Message:
        """Convert a response into the assistant turn to append to the history."""
        return Message(
            role="assistant",
            content=response.text,
            tool_calls=list(response.tool_calls),
            provider_state=response.provider_state,
        )


def group_tool_results(messages: list[Message]) -> list[list[Message] | Message]:
    """Collapse runs of consecutive ``tool`` messages into lists (for APIs that need it)."""
    out: list[list[Message] | Message] = []
    for msg in messages:
        if msg.role == "tool" and out and isinstance(out[-1], list):
            out[-1].append(msg)
        elif msg.role == "tool":
            out.append([msg])
        else:
            out.append(msg)
    return out
