# ExposedAPI

ExposedAPI is a API security triage with optional hostname filtering CLI for authorized testing. It inventories responses, records reproducible metadata, and identifies review candidates without claiming unverified vulnerabilities.

The interactive product demo lives in [`demo/`](demo/). It uses synthetic data and never contacts an external target.

## Install on Kali Linux

```bash
git clone https://github.com/droidjedininja/exposedapi.git
cd exposedapi
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
exposedapi --help
```

## Prepare an authorized scan

The `--scope` option is optional for every command: scans, `import-har`,
`compare-har`, and `account-matrix`. Omit it to accept supplied target URLs
(or eligible HAR URLs) without hostname filtering. Reports use `"scope": null`
when filtering is disabled. Authorization acknowledgement, credential protection,
rate limits, and redirect restrictions still apply.

To restrict hosts, create `scope.txt` with one approved hostname or wildcard per line.
A supplied empty or unreadable scope file is an error:

```text
api.example.com
*.api.example.com
```

Create `targets.txt` with exact HTTP(S) endpoints:

```text
https://api.example.com/health
https://api.example.com/v1/profile
```

## Import browser traffic

Export a HAR from your browser or Burp, keep the original file private, and build a redacted inventory:

```bash
exposedapi import-har \
  --har ~/captures/account-a.har \
  --scope scope.txt \
  --output output/account-a.json
```

The importer keeps only eligible GET/HEAD endpoints (filtered by scope when supplied), removes common static assets, deduplicates paths, and ranks likely API and authorization-test candidates. It never writes request headers, cookies, request or response bodies, or query-string values to the inventory.

Validate without sending traffic:

```bash
exposedapi --targets targets.txt --scope scope.txt --dry-run --acknowledge-authorization
```

Run low-rate, read-only triage:

```bash
exposedapi \
  --targets targets.txt \
  --scope scope.txt \
  --rate-limit 2 \
  --workers 4 \
  --researcher mrfixit347 \
  --format json \
  --output output/scan.json \
  --acknowledge-authorization
```

`--workers` is bounded to 1–8, and `--rate-limit` is enforced globally across workers. Scans remain read-only GET requests; redirects are never followed.

Only use `--researcher` when the program permits or requires the `X-HackerOne-Research` header.

Authenticated requests require HTTPS. ExposedAPI rejects credential-bearing HTTP requests and target URLs containing sensitive query parameters such as `token`, `access_token`, `api_key`, or `password`.

For authenticated requests, keep the token out of command history:

```bash
read -rsp "Test-account token: " EXPOSEDAPI_TOKEN; export EXPOSEDAPI_TOKEN; echo
exposedapi \
  --targets targets.txt \
  --scope scope.txt \
  --auth-env EXPOSEDAPI_TOKEN \
  --auth-scheme Bearer \
  --rate-limit 1 \
  --output output/authenticated.json \
  --acknowledge-authorization
unset EXPOSEDAPI_TOKEN
```

For API keys or other secret headers, keep the value in an environment variable instead of placing it in shell history:

```bash
read -rsp "Test API key: " EXPOSEDAPI_API_KEY; export EXPOSEDAPI_API_KEY; echo
exposedapi \\
  --targets targets.txt \\
  --scope scope.txt \\
  --header-env X-API-Key=EXPOSEDAPI_API_KEY \\
  --output output/authenticated.json \\
  --acknowledge-authorization
unset EXPOSEDAPI_API_KEY
```

`--header` remains available for non-secret values. Use `--header-env` or `--auth-env` for credentials.

## Compare two authorized sessions

Export separate HAR files for two test accounts, optionally using the same approved scope. Comparison replays only matching HTTPS GET endpoints (filtered by scope when supplied) that carry a consistent cookie for that endpoint; it skips unsafe paths and any URL containing a known sensitive query parameter:

```bash
exposedapi compare-har \
  --har-a ~/captures/account-a.har \
  --har-b ~/captures/account-b.har \
  --scope scope.txt \
  --rate-limit 0.5 \
  --output output/account-comparison.json \
  --acknowledge-authorization
```

The comparison report contains status codes and response fingerprints, not cookies or bodies. Matching responses are review candidates only; identical responses do not by themselves establish an authorization vulnerability. Review differing or inconclusive results manually before drawing conclusions.

## Check an account access matrix

Use known resources belonging to your authorized test accounts. Create `matrix.json`
with named accounts and an explicit list of accounts allowed to access each resource:

```json
{
  "accounts": {
    "account_a": {"headers_env": {"Authorization": "ACCOUNT_A_AUTH"}},
    "account_b": {"headers_env": {"Cookie": "ACCOUNT_B_COOKIE"}}
  },
  "resources": [
    {
      "url": "https://api.example.com/v1/documents/123",
      "allowed_accounts": ["account_a"]
    },
    {
      "url": "https://api.example.com/v1/documents/456",
      "allowed_accounts": ["account_b"]
    }
  ]
}
```

Set those environment variables privately. Values are complete header values
(for example, `Bearer ...` for Authorization or `session=...` for Cookie).
`X-API-Key` and `API-Key` are also supported. Never put credentials in the JSON.
Account names can represent roles such as `member` and `admin`.

```bash
exposedapi account-matrix \
  --matrix matrix.json \
  --scope scope.txt \
  --dry-run \
  --acknowledge-authorization

exposedapi account-matrix \
  --matrix matrix.json \
  --scope scope.txt \
  --rate-limit 0.5 \
  --output output/matrix.json \
  --acknowledge-authorization
```

Every resource is requested once with each account and once without credentials.
The reserved account `anonymous` may appear in `allowed_accounts` for public resources.
Every omitted account is expected to be denied. Resources need not appear in
multiple HAR files. All URLs and credentials are validated before traffic starts;
hostname filtering applies only when `--scope` is supplied;
HTTPS is required, redirects are disabled, and the global rate limit is capped at
2 requests per second. Use only known read endpoints: GET endpoints can still
have side effects. Common unsafe replay paths are rejected.

A 2xx response from an account expected to be denied becomes an
`unexpected access review candidate` only when an allowed account also has a
successful baseline. Matching body hashes provide supporting evidence. Statuses
401, 403, and 404 are recorded as expected denials; redirects, request errors, and
other ambiguous outcomes remain inconclusive. HTTP success may contain an error
or public content, so candidates require manual verification.

Reports retain account labels, zero-based resource indices, query-free endpoint
URLs, statuses, lengths, and body hashes. They omit credential values, query
values, response bodies, redirect locations, and raw request errors. Keep account
labels and resource paths free of secrets. Dry runs also require valid credential
environment variables, but send no requests.

## Safety model

- HTTP `GET` only; HTTPS is mandatory whenever credentials are attached
- Hostname allowlist validation before requests when `--scope` is supplied
- Redirects are not followed
- Explicit authorization acknowledgement required
- Configurable rate limit and timeout
- Authentication header and cookie values are never written to reports
- Sensitive query parameters are rejected before any request
- Response bodies are not stored; reports contain length and SHA-256 only
- Results are review candidates, not vulnerability claims
