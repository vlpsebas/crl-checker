# crl-checker

Single Worker: mTLS cert validation + custom CRL revocation at the edge for BYOCA.
Cloudflare WAF handles the mTLS handshake; this Worker checks the client cert serial against
a CRL published to KV, fail-closed. Shared as a generic demo — **you must set the parameters
below before it will run.**

## Files

| File | Role |
|------|------|
| `index.js` | Entry + router (exports `CRLProcessor` DO class) |
| `importer.js` | CRL import/parse/publish: cron, manual, URL fetch, chunked upload (DO) |
| `validator.js` | mTLS + CRL check (fail-closed) |
| `admin.js` | Shared utils + usage counters + `/admin/usage` pricing report |
| `telemetry.js` | OPTIONAL per-request usage log (import in index.js to enable) |
| `wrangler.toml` | Config: KV, DO, cron `0 6,18 * * *`, vars |

---

## Parameters to set before deploy (checklist)

Every value below is **yours to choose/replace** — the repo ships with placeholders.

### 1. Worker name — `wrangler.toml`
```toml
name = "crl-checker"   # ← replace with your own, e.g. "my-crl-demo"
```
This becomes your Worker's default subdomain: `<name>.<account>.workers.dev`.

### 2. KV namespace — `wrangler.toml` `[[kv_namespaces]]`
This Worker needs ONE KV namespace (binding name is fixed in code: `REVOKED_CERTS`).
```bash
wrangler kv namespace create REVOKED_CERTS
```
Copy the returned **namespace id** into `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "REVOKED_CERTS"
id = "REPLACE_WITH_KV_ID"   # ← paste your id here
```
You may also create it in the dashboard (Workers & Pages → KV → Create namespace).

### 3. Durable Object — `wrangler.toml` `[durable_objects]` + `[[migrations]]`
No separate "creation" step — the DO class (`CRLProcessor`) is exported from `index.js`.
Keep these two blocks as-is (they register the class with the Worker):
```toml
[durable_objects]
bindings = [{ name = "CRL_PROCESSOR", class_name = "CRLProcessor" }]

[[migrations]]
tag = "v1"
new_classes = ["CRLProcessor"]
```
`CRL_PROCESSOR` (binding name) and `CRLProcessor` (class name) are referenced in code —
do not rename unless you update `importer.js` / `index.js` too.

### 4. CRL source URL — `wrangler.toml` `[vars]`
```toml
[vars]
CRL_ORIGIN_URL = "https://your-crl-source.example.com/crl.pem"   # ← your CRL endpoint (PEM or DER)
CRL_FORMAT = "pem"                                               # "pem" or "der"
```
The cron job and `POST /crl/import` fetch from this URL. For demo, it can be any
HTTPS endpoint returning a CRL file (or a mock origin Worker you control).

### 5. Staleness / fail-closed window — `wrangler.toml` `[vars]`
```toml
CRL_MAX_AGE_HOURS = "24"   # ← max allowed age of the imported CRL before requests are blocked
```
Validator blocks (503) if the loaded CRL is older than this, or past its `nextUpdate` expiry.

### 6. Optional telemetry — `wrangler.toml` `[vars]`
```toml
TELEMETRY = "false"   # "true" → count requests + cpu_ms into KV usage counters
```
Pricing reference only; leave `false` if you don't need it.

### 7. Admin secret — set as a SECRET, not a var
```bash
wrangler secret put ADMIN_SECRET
```
Protects all write endpoints (`/crl/import`, `/crl/fetch`, `/crl/upload/*`, `/admin/*`).
Requests must send header `X-Admin-Secret: <value>`. **Never** put it in `[vars]` —
secrets in vars get baked into the deployed bundle.

### 8. Cron schedule (optional) — `wrangler.toml` `[triggers]`
```toml
[triggers]
crons = ["0 6,18 * * *"]   # ← default: 06:00 & 18:00 UTC (twice daily)
```
Adjust to match how often your source CRL's `nextUpdate` changes.

### 9. Compatibility date
```toml
compatibility_date = "2024-11-01"   # ← bump if wrangler warns about deprecated runtime features
```

---

## Quick setup (after the checklist)

```bash
npm install
wrangler kv namespace create REVOKED_CERTS   # paste id into wrangler.toml
wrangler secret put ADMIN_SECRET
wrangler deploy
```
Local dev (needs remote KV/DO): `npm run dev` (runs `wrangler dev --remote`).

## Endpoints

- `GET /health` — liveness + CRL freshness
- `GET /crl/check?serial=<hex>` — revocation lookup (no mTLS)
- `POST /crl/import` — manual import (`{url?, format?}`, admin)
- `POST /crl/fetch` — import from URL, Worker Range-pages it & assembles in the DO (any size, admin)
- `POST /crl/upload` — single raw CRL file body (≤100MB); Worker slices internally, NO manual chunking (`?format=pem|der|auto`, admin)
- `GET /crl/status`, `GET /crl/raw` — metadata / revoked list (debug)
- `GET /test/mtls?serial=<hex>` — simulated mTLS flow (demo)
- `GET /admin/usage` — requests, KV reads/writes, KV bytes, cpu_ms (pricing reference)
- default (any other path) — real mTLS validation, requires client cert via WAF mTLS rule

## Pricing note

Workers don't expose true CPU time/memory; `cpu_ms` ≈ wall-clock duration (billing proxy).
Exact request volume: Cloudflare Analytics. `telemetry.js` logs one KV entry per request
if you want per-request reference data.
