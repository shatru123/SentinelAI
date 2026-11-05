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

## Subsequent Phase 4 increments

The provider gateway is a transport and provenance layer; it deliberately does not invoke AI automatically during assessment or triage. The following operator-controlled, advisory-only capabilities have since been implemented:

1. **Phase 4.2 — Evidence-grounded finding analysis:** bounded/redacted evidence input, schema-validated output, evidence-ID allow-listing, tenant-scoped persistence and provider/model/prompt/input-hash/token provenance. See `phase4-finding-analysis.md`.
2. **Phase 4.3 — Finding analysis experience:** explicit provider selection and analysis request for Admin/Security Analyst roles, Reader-visible persisted history, and no automatic provider call when opening a finding. See `phase4-finding-analysis-ui.md`.
3. **Phase 4.4 — Scheduled reassessment and drift alerts:** bounded scope-bound schedules, authorization revalidation, transactional outbox dispatch, deterministic drift and tenant-scoped in-app notifications. Its real API lifecycle, processor reconciliation and PostgreSQL dispatch/reconciliation concurrency acceptance suite passed in PR #9 CI run #555 (340 total tests across the Phase 4 solution). See `phase4-scheduled-reassessment.md`.
4. **Optional report advisory summaries:** explicitly opt-in export of persisted analysis only; no provider request is made during export, and summaries remain labeled for human review.

These features do not grant AI authority to confirm findings, change severity or policy, authorize targets, or dispatch work.

## References

- OpenAI Responses API: https://developers.openai.com/api/reference/resources/responses/methods/create
- Anthropic Messages API: https://platform.claude.com/docs/en/api/messages/create
- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
