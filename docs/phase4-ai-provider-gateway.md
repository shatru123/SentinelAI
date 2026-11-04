# Phase 4.1 — AI Provider Gateway

## Goal

Activate the existing OpenAI, Anthropic Claude and Ollama adapter projects behind a common, advisory-only interface. This increment establishes dependable transport and provenance; it does not give model output authority to add targets, authorize assessments, change policy or dispatch workers.

## Providers

- OpenAI: non-streaming Responses API (POST /v1/responses) and authenticated model-list readiness check (GET /v1/models).
- Anthropic Claude: non-streaming Messages API (POST /v1/messages) and model-list readiness check (GET /v1/models?limit=1).
- Ollama: non-streaming Chat API (POST /api/chat) and local model-tag readiness check (GET /api/tags).

The adapters use native provider request/response shapes. They do not assume that the providers expose interchangeable APIs.

## Safety and reliability boundaries

- Provider API keys are read from runtime configuration and are never stored in source-controlled settings.
- Cloud providers require HTTPS. Ollama permits plain HTTP only when its endpoint is a loopback address; non-loopback endpoints must use HTTPS.
- Each request has a configurable timeout (1–300 seconds; default 60) and maximum response size (1 KiB–10 MiB; default 1 MiB).
- Model output is non-streaming in this increment. The cancellation token is passed through connection and response-body reads.
- Provider error messages expose only the provider name and HTTP status; upstream response bodies are not echoed because they can contain sensitive request or provider details.
- The gateway preserves provider/model, response identifier where provided, completion reason and input/output token counts.
- Optional JSON Schema output is passed through each provider's structured-output contract. The adapter rejects invalid or non-object JSON output before returning it.
- The provider readiness endpoint does not expose API keys or endpoint URLs and requires the Reader authorization policy.
- Unconfigured providers are listed as unconfigured without attempting a network connection.
- AI remains advisory. Deterministic scope/policy services and human approval workflows retain exclusive authorization authority.

## Configuration

Set values through a secret manager or environment variables. Example environment-variable names:

| Provider | Required values | Optional endpoint |
|---|---|---|
| OpenAI | AI__Providers__OpenAI__ApiKey, AI__Providers__OpenAI__Model | AI__Providers__OpenAI__Endpoint |
| Anthropic | AI__Providers__Anthropic__ApiKey, AI__Providers__Anthropic__Model | AI__Providers__Anthropic__Endpoint |
| Ollama | AI__Providers__Ollama__Model | AI__Providers__Ollama__Endpoint (default http://127.0.0.1:11434/) |

All providers also support TimeoutSeconds, MaxResponseBytes and DefaultMaxOutputTokens under their provider configuration section. Anthropic supports an ApiVersion setting, defaulting to 2023-06-01.

No provider is enabled by default. A missing API key or model causes the provider to report configured=false; application startup and non-AI workflows continue normally.

## Diagnostics

Authenticated readers can query:

    GET /api/v1/ai/providers

Example response shape:

    {
      "checkedAtUtc": "2026-11-04T00:00:00Z",
      "providers": [
        { "provider": "anthropic", "configured": false, "healthy": false },
        { "provider": "ollama", "configured": true, "healthy": true },
        { "provider": "openai", "configured": false, "healthy": false }
      ]
    }

Health checks use a maximum five-second timeout and are skipped for unconfigured providers. The response does not include model names, endpoint URLs or secrets.

## Remaining Phase 4 work

This gateway does not yet invoke AI during assessment triage or report generation. Next increments should add:
1. Evidence-grounded analysis contracts and schema-versioned result types.
2. Persisted analysis provenance (provider, model, prompt-template version, input evidence hashes, token usage, timestamp and structured result).
3. Human-reviewed AI prioritization and natural-language explanations that cannot mutate findings or policy.
4. Scheduled re-assessment, drift detection and alert workflows.

## References

- OpenAI Responses API: https://developers.openai.com/api/reference/resources/responses/methods/create
- Anthropic Messages API: https://platform.claude.com/docs/en/api/messages/create
- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
