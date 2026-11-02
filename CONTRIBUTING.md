# Contributing

1. Open an issue describing the change and its security implications.
2. Keep domain logic independent of infrastructure and UI.
3. Add tests for normal, invalid, unauthorized and cross-tenant paths.
4. Do not add unrestricted command execution or broaden target scope through AI.
5. Run formatting, build and tests before submitting a pull request.
6. Update documentation and threat-model notes when changing execution boundaries.

## Engineering expectations
- Nullable reference types enabled.
- Async APIs accept CancellationToken.
- Store timestamps in UTC.
- Validate all external input.
- Prefer typed options and dependency injection.
- Never commit secrets, tokens, production targets or private evidence.
