# ExposedAPI

ExposedAPI is a scope-enforced API security triage CLI for authorized testing. It inventories responses, records reproducible metadata, and identifies review candidates without claiming unverified vulnerabilities.

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

Create `scope.txt` with one approved hostname or wildcard per line:

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

The importer keeps only in-scope GET/HEAD endpoints, removes common static assets, deduplicates paths, and ranks likely API and authorization-test candidates. It never writes request headers, cookies, request or response bodies, or query-string values to the inventory.

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
  --researcher mrfixit347 \
  --format json \
  --output output/scan.json \
  --acknowledge-authorization
```

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

## Safety model

- HTTP `GET` only; HTTPS is mandatory whenever credentials are attached
- Exact scope validation before requests
- Redirects are not followed
- Explicit authorization acknowledgement required
- Configurable rate limit and timeout
- Authentication header and cookie values are never written to reports
- Sensitive query parameters are rejected before any request
- Response bodies are not stored; reports contain length and SHA-256 only
- Results are review candidates, not vulnerability claims
