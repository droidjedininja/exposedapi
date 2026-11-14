# Optional scope validation

Decision: user explicitly approved making `--scope` optional across all commands.
Omitted scope is represented as null; supplied empty or unreadable files fail.
No external provider or deployment is involved. Existing code and CLI regression
cases establish the required semantics; no assumptions about third-party behavior
are needed. External product comparisons are not relevant to this user-selected default.

Live measurement: 20 CLI scans against a real loopback HTTP server, 10 URL shapes
with scope omitted and the same 10 with an explicit matching allowlist. All 20
returned the expected HTTP status and scope metadata. The server was stopped afterward.
These exercise transport and report behavior, not vulnerability detection quality.
HAR and account-matrix branches are covered separately by mocked transport tests.

| Scope | URL path | Status | Metadata |
|---|---|---|---|
| omitted | `/health` | 200 | pass |
| omitted | `/v1/profile` | 200 | pass |
| omitted | `/v1/objects/123` | 200 | pass |
| omitted | `/v1/objects/abc-def` | 200 | pass |
| omitted | `/v2/organizations/test` | 200 | pass |
| omitted | `/items?page=1` | 200 | pass |
| omitted | `/items?view=summary` | 200 | pass |
| omitted | `/search?q=test` | 200 | pass |
| omitted | `/api/roles` | 200 | pass |
| omitted | `/api/shared` | 200 | pass |
| supplied | `/health` | 200 | pass |
| supplied | `/v1/profile` | 200 | pass |
| supplied | `/v1/objects/123` | 200 | pass |
| supplied | `/v1/objects/abc-def` | 200 | pass |
| supplied | `/v2/organizations/test` | 200 | pass |
| supplied | `/items?page=1` | 200 | pass |
| supplied | `/items?view=summary` | 200 | pass |
| supplied | `/search?q=test` | 200 | pass |
| supplied | `/api/roles` | 200 | pass |
| supplied | `/api/shared` | 200 | pass |
