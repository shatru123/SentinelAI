# Phase 2 — Authorized network inventory

## Implemented scope

This increment delivers the safe passive foundation of the Phase 2 roadmap:

- workers advertise and are admitted for the `passive-inventory` capability;
- `network-inventory-passive` uses a fixed typed adapter;
- every target is revalidated through `TargetScopeValidator` before adapter execution;
- the adapter is bounded, cancellation-aware and rate-limited by the authorized scope;
- observations create tenant-scoped assets and optional tenant-scoped service records;
- readers can query an asset’s services without crossing tenant boundaries;
- the PostgreSQL migration adds `AssetServices` and a tenant/asset/protocol/port uniqueness constraint.

## Safety boundary

The adapter is deliberately passive. It records only validated scope declarations as offline observations and performs no DNS lookup, socket connection, port probe, active discovery, exploitation or command execution. The existing policy engine remains authoritative for target, exclusion, expiry, tenant and lease checks. A future active adapter is out of scope for this increment and requires a separate security review.

## Verification

Use the normal commands in [development.md](development.md). The Phase 2 tests cover passive adapter cancellation and non-reachability claims, persisted service inventory, tenant isolation, migration application, and the existing architecture/security/reliability suites.

## Acceptance criteria for this increment

- A worker advertising `passive-inventory` can execute an approved passive inventory profile.
- Every observation is produced only after current tenant, scope, exclusion, expiry and lease checks.
- Inventory never claims an asset is online without an explicit observation source.
- Asset services are unique and tenant isolated in PostgreSQL and through the API.
- Cancellation and lease loss stop the adapter before further persisted side effects.
- No active network or command execution is present in the adapter.
- The complete solution build, test suite and Compose configuration validation pass.
