# Phase 4.3 — Finding AI analysis experience

## Operator workflow

The finding dossier displays an AI Security Analysis section. Administrators and Security Analysts can select a configured provider and explicitly request an analysis. The page does not submit finding data to a provider just because it was opened; provider readiness is checked only when an Operator opens a finding dossier.

## Reader workflow

Readers can review persisted analyses but cannot trigger new requests. The dossier displays provider/model, time, prompt-template version, confidence, evidence-input hash, token usage, summary, technical impact, recommendations, evidence references and uncertainties.

## UI safety rules

- The section is clearly labelled **Advisory only**.
- Provider selection includes only providers marked configured by the API.
- Recommendations are displayed as human-reviewed actions, not automated remediation controls.
- The source finding severity and assessment lifecycle are not changed by analysis.
- The UI does not expose provider endpoints, secrets or configuration values.
- API authorization is authoritative; hiding the action for a Viewer is a usability measure, not the security boundary.
- History is loaded from the tenant-scoped Reader endpoint; analysis requests use the Operator endpoint.

## Verification

The component uses the existing authenticated Sentinel API client and standardized error handling. Browser acceptance should cover Admin/Analyst request flows, Viewer history-only behavior, no configured provider, provider failure, and findings with no stored evidence.
