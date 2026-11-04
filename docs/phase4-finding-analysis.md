# Phase 4.2 — Evidence-grounded finding analysis

## Goal

Allow an operator to request a structured AI explanation of one existing finding, grounded only in its stored evidence. Persist the explanation and provenance so readers can inspect the result later. The model is advisory: it does not confirm a finding, change severity, edit remediation state, authorize a target, expand scope, create a job or dispatch a worker.

## API

- `POST /api/v1/findings/{findingId}/ai-analysis` — Operator role (Admin or Security Analyst). Body: `{ "providerName": "ollama" }`. Provider is explicit; the API does not silently choose another provider.
- `GET /api/v1/findings/{findingId}/ai-analyses` — Reader role. Returns the latest 50 analyses for the tenant and finding.

The selected provider must be configured. Provider transport remains subject to the Phase 4.1 timeout and response-size bounds. Unconfigured or unavailable providers produce a service-unavailable response. A finding without stored evidence cannot be submitted for analysis.

## Evidence and privacy boundary

- Analysis is explicitly initiated by an Operator; there is no background or automatic submission of findings.
- The analysis input contains finding title, severity, category, confidence, description, impact and existing remediation guidance. It deliberately excludes the affected URL, reproduction instructions, screenshots, and raw evidence payloads.
- Evidence input is limited to 20 records and 18,000 characters, and uses only evidence summaries and the field already designated as redacted content.
- Evidence and finding fields are treated as untrusted prompt data. The system prompt instructs the model to ignore embedded instructions.
- Every recommended action must cite one or more evidence IDs from the exact input set. The service independently validates those identifiers before saving.
- Structured output is bounded and validated for required fields, confidence values, collection sizes and text lengths.

## Persisted provenance

Each result stores tenant, finding and requesting actor IDs; provider and model; prompt-template version; SHA-256 of the exact serialized analysis input; structured result; input/output token counts; provider response ID and finish reason where available; and creation time. The child record has a composite tenant/finding foreign key and is deleted with its finding.

## Safety

AI recommendations are text for human review only. The analysis service does not update the source finding or invoke scan, authorization, approval, remediation, scope or worker services. Deterministic policy and operator approval remain authoritative.

## Remaining Phase 4 work

- Add a Findings UI action and analysis-history panel.
- Add optional AI summaries to exported reports with clear advisory labeling.
- Introduce scheduled reassessment, drift detection and alert workflows under explicit operator-configured schedules.
