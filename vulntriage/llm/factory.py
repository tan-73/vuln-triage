"""Build the configured :class:`~vulntriage.llm.base.LLMProvider` from settings."""

from __future__ import annotations

from vulntriage.config import Settings
from vulntriage.llm.base import LLMError, LLMProvider
from vulntriage.llm.mock import MockProvider

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5"}


def _secret(value: object) -> str | None:
    getter = getattr(value, "get_secret_value", None)
    return getter() if getter else None


def get_provider(settings: Settings, provider: str | None = None) -> LLMProvider:
    """Instantiate ``LLM_PROVIDER`` (or ``provider``) with ``LLM_MODEL``.

    Raises:
        LLMError: if the provider needs a model name or API key that is not configured.
    """
    name = provider or settings.llm_provider
    if name == "mock":
        return MockProvider(top_n=settings.report_top_n)
    if name not in ("anthropic", "gemini", "openai"):
        raise LLMError(f"unknown LLM_PROVIDER {name!r}")
    model = settings.llm_model or DEFAULT_MODELS.get(name)
    if not model:
        raise LLMError(f"set LLM_MODEL for LLM_PROVIDER={name}")
    if name == "anthropic":
        from vulntriage.llm.anthropic import AnthropicProvider

        return AnthropicProvider(
            model, _secret(settings.anthropic_api_key), settings.llm_max_tokens
        )
    if name == "gemini":
        from vulntriage.llm.gemini import GeminiProvider

        return GeminiProvider(model, _secret(settings.gemini_api_key), settings.llm_max_tokens)
    if name == "openai":
        from vulntriage.llm.openai_compat import OpenAICompatProvider

        return OpenAICompatProvider(
            model, _secret(settings.openai_api_key), settings.llm_base_url, settings.llm_max_tokens
        )
    raise LLMError(f"unknown LLM_PROVIDER {name!r}")
