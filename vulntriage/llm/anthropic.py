"""Anthropic Messages API provider (native ``tool_use`` / ``tool_result`` blocks)."""

from __future__ import annotations

from typing import Any

from vulntriage.llm.base import (
    LLMError,
    LLMProvider,
    LLMResponse,
    Message,
    ToolCall,
    ToolSpec,
    group_tool_results,
)


def to_anthropic_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Neutral messages -> Anthropic ``messages`` (tool results batched in one user turn)."""
    out: list[dict[str, Any]] = []
    for item in group_tool_results(messages):
        if isinstance(item, list):
            out.append(
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content}
                        for m in item
                    ],
                }
            )
        elif item.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if item.content:
                blocks.append({"type": "text", "text": item.content})
            blocks += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                for c in item.tool_calls
            ]
            out.append({"role": "assistant", "content": blocks or item.content})
        else:
            out.append({"role": "user", "content": item.content})
    return out


class AnthropicProvider(LLMProvider):
    """Claude via the official ``anthropic`` SDK."""

    name = "anthropic"

    def __init__(
        self, model: str, api_key: str | None, max_tokens: int = 4096, client: Any = None
    ) -> None:
        super().__init__(model)
        self.max_tokens = max_tokens
        if client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise LLMError(
                    "pip install 'vulntriage[anthropic]' to use LLM_PROVIDER=anthropic"
                ) from exc
            if not api_key:
                raise LLMError("ANTHROPIC_API_KEY is not set")
            client = anthropic.Anthropic(api_key=api_key, max_retries=3, timeout=120.0)
        self.client = client

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Send one Messages API request."""
        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=to_anthropic_messages(messages),
                tools=[
                    {"name": t.name, "description": t.description, "input_schema": t.parameters}
                    for t in tools
                ],
            )
        except Exception as exc:
            raise LLMError(f"anthropic request failed: {exc}") from exc
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        calls = [
            ToolCall(id=b.id, name=b.name, arguments=dict(b.input or {}))
            for b in resp.content
            if getattr(b, "type", "") == "tool_use"
        ]
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=text,
            tool_calls=calls,
            stop_reason=getattr(resp, "stop_reason", None),
            usage={
                "input_tokens": getattr(usage, "input_tokens", 0) or 0,
                "output_tokens": getattr(usage, "output_tokens", 0) or 0,
            },
        )
