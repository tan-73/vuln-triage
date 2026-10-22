"""Google Gemini provider via the ``google-genai`` SDK (manual function calling)."""

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


def to_gemini_contents(messages: list[Message], types: Any) -> list[Any]:
    """Neutral messages -> ``types.Content`` list.

    Assistant turns are replayed from ``provider_state`` when available so that Gemini's
    thought signatures survive multi-turn function calling.
    """
    contents: list[Any] = []
    for item in group_tool_results(messages):
        if isinstance(item, list):
            contents.append(
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_function_response(
                            name=m.name or "tool", response={"result": m.content}
                        )
                        for m in item
                    ],
                )
            )
        elif item.role == "assistant":
            if item.provider_state is not None:
                contents.append(item.provider_state)
                continue
            parts = [types.Part(text=item.content)] if item.content else []
            parts += [
                types.Part(function_call=types.FunctionCall(name=c.name, args=c.arguments))
                for c in item.tool_calls
            ]
            contents.append(types.Content(role="model", parts=parts))
        else:
            contents.append(types.Content(role="user", parts=[types.Part(text=item.content)]))
    return contents


class GeminiProvider(LLMProvider):
    """Gemini models through ``google.genai.Client``."""

    name = "gemini"

    def __init__(
        self,
        model: str,
        api_key: str | None,
        max_tokens: int = 4096,
        client: Any = None,
        types_module: Any = None,
    ) -> None:
        super().__init__(model)
        self.max_tokens = max_tokens
        if types_module is None:
            try:
                from google.genai import types as types_module
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise LLMError(
                    "pip install 'vulntriage[gemini]' to use LLM_PROVIDER=gemini"
                ) from exc
        self.types = types_module
        if client is None:
            from google import genai

            if not api_key:
                raise LLMError("GEMINI_API_KEY is not set")
            client = genai.Client(api_key=api_key)
        self.client = client

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        """Send one ``generate_content`` request with automatic function calling disabled."""
        t = self.types
        config = t.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=self.max_tokens,
            tools=[
                t.Tool(
                    function_declarations=[
                        t.FunctionDeclaration(
                            name=s.name,
                            description=s.description,
                            parameters_json_schema=s.parameters,
                        )
                        for s in tools
                    ]
                )
            ],
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
        )
        try:
            resp = self.client.models.generate_content(
                model=self.model, contents=to_gemini_contents(messages, t), config=config
            )
        except Exception as exc:
            raise LLMError(f"gemini request failed: {exc}") from exc
        if not resp.candidates:
            raise LLMError("gemini returned no candidates (blocked or empty response)")
        content = resp.candidates[0].content
        parts = list(getattr(content, "parts", None) or [])
        calls = [
            ToolCall(
                id=p.function_call.id or f"call_{i}",
                name=p.function_call.name,
                arguments=dict(p.function_call.args or {}),
            )
            for i, p in enumerate(parts)
            if getattr(p, "function_call", None)
        ]
        text = "".join(
            p.text for p in parts if getattr(p, "text", None) and not getattr(p, "thought", False)
        )
        usage = getattr(resp, "usage_metadata", None)
        return LLMResponse(
            text=text,
            tool_calls=calls,
            stop_reason=str(getattr(resp.candidates[0], "finish_reason", "") or ""),
            provider_state=content,
            usage={
                "input_tokens": getattr(usage, "prompt_token_count", 0) or 0,
                "output_tokens": getattr(usage, "candidates_token_count", 0) or 0,
            },
        )
