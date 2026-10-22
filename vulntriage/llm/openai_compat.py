"""OpenAI-compatible Chat Completions provider (OpenAI, Ollama, vLLM, LM Studio, ...)."""

from __future__ import annotations

import json
from typing import Any

from vulntriage.llm.base import LLMError, LLMProvider, LLMResponse, Message, ToolCall, ToolSpec


def to_openai_messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
    """Neutral messages -> Chat Completions ``messages``."""
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        if m.role == "tool":
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
        elif m.role == "assistant":
            msg: dict[str, Any] = {"role": "assistant", "content": m.content or None}
            if m.tool_calls:
                msg["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                    }
                    for c in m.tool_calls
                ]
            out.append(msg)
        else:
            out.append({"role": "user", "content": m.content})
    return out


class OpenAICompatProvider(LLMProvider):
    """Any server implementing ``POST /v1/chat/completions`` with ``tools``."""

    name = "openai"

    def __init__(
        self,
        model: str,
        api_key: str | None,
        base_url: str | None = None,
        max_tokens: int = 4096,
        client: Any = None,
    ) -> None:
        super().__init__(model)
        self.max_tokens = max_tokens
        if client is None:
            try:
                import openai
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise LLMError(
                    "pip install 'vulntriage[openai]' to use LLM_PROVIDER=openai"
                ) from exc
            if not api_key and not base_url:
                raise LLMError("OPENAI_API_KEY is not set (or set LLM_BASE_URL for a local server)")
            client = openai.OpenAI(
                api_key=api_key or "not-needed", base_url=base_url, max_retries=3, timeout=120.0
            )
        self.client = client

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Send one Chat Completions request."""
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=to_openai_messages(system, messages),
                tools=[
                    {
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                        },
                    }
                    for t in tools
                ],
            )
        except Exception as exc:
            raise LLMError(f"openai-compatible request failed: {exc}") from exc
        choice = resp.choices[0]
        calls = []
        for c in choice.message.tool_calls or []:
            try:
                args = json.loads(c.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"_unparsable_arguments": c.function.arguments}
            calls.append(ToolCall(id=c.id, name=c.function.name, arguments=args))
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=choice.message.content or "",
            tool_calls=calls,
            stop_reason=choice.finish_reason,
            usage={
                "input_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                "output_tokens": getattr(usage, "completion_tokens", 0) or 0,
            },
        )
