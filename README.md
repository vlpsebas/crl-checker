# CRL Checker Demo - Two Worker Architecture

This demo implements custom Certificate Revocation List (CRL) checking for mTLS at the edge using two separate Cloudflare Workers.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Client with mTLS Cert                                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Cloudflare WAF      │  ◄── mTLS handshake
        │  (Initial mTLS)      │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  crl-checker Worker  │  ◄── Validates cert against KV
        │  (Validator)         │
        └──────────┬───────────┘
                   │
                   ├─── ✅ Valid → Proxy to Origin
                   └─── ❌ Revoked → Block (403)

CRL Update Flow:
        ┌──────────────────────┐
        │  file-origin Worker  │  ◄── Generic R2 file storage
        │  (File Storage)      │
        └──────────┬───────────┘
                   │
                   ▼ (fetch /file/crl.pem)
        ┌──────────────────────┐
        │  crl-checker Worker  │
        │  (Importer)          │  ◄── Parses CRL, updates KV
        └──────────────────────┘
```

## Workers

### 1. `crl-checker` (Port 8787)
**Purpose:** Validate mTLS certificates, import CRL data (fetch, direct upload, chunked), emit telemetry

**Routes:**
- `/mtls/check`, `/mtls/allow` — Validate certificate
- `/crl/import/fetch?file=<name>` — Fetch PEM bundle (CA certs / CRL / both) from file-origin / R2 and update KV
- `/crl/import/upload` — **Direct PEM upload** (<100MB request body limit): CA certs, CRL, or combined bundle → auto-cross-references revoked serials against certs, blocks by exact fingerprint
- `/crl/import/chunk` + `/crl/import/finalize` — **Chunked upload** via `CRL_PROCESSOR` Durable Object (files > request limit)
- `/crl/import/status`, `/crl/import/chunks/status` — Check import / session status
- `/health` — Health check

**Dependencies:**
- KV: `REVOKED_CERTS` (hot path), `CRL_DATA` (metadata)
- **DO: `CRL_PROCESSOR`** — assembles chunked uploads (emulates real customer direct-upload environments)
- Optional R2: `CRL_BUCKET` (direct access)
- Env: `FILE_ORIGIN_URL` (points to file-origin worker), `CRL_MAX_AGE_HOURS`, `TELEMETRY`
- Cron: `0 6,18 * * *` (twice-daily scheduled CRL sync)

### R2 Dual-Use: CRL + CA List in One Bucket

The optional `CRL_BUCKET` R2 bucket stores **both** the CRL and the CA certificate list:

| Object key | Contents |
|-----------|----------|
| `crl.pem` | Revocation list (default fetch target) |
| `ca.pem`  | CA certificate bundle (for fingerprint cross-referencing) |
| anything else | Any file (via generic file-origin upload) |

Import them together (cross-references revoked serials → exact fingerprints):
```bash
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/fetch?file=crl.pem&ca_file=ca.pem" \
  -H "X-Admin-Secret: dev-secret-12345"
```

Or grab every object under a prefix in one shot:
```bash
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/fetch?all=crl/" \
  -H "X-Admin-Secret: dev-secret-12345"
```

Files land in R2 via the generic file-origin worker:
```bash
curl -X POST "https://file-origin.<subdomain>.workers.dev/upload?filename=crl.pem" \
  -H "X-Admin-Secret: dev-secret-12345" --data-binary @crl.pem
curl -X POST "https://file-origin.<subdomain>.workers.dev/upload?filename=ca.pem" \
  -H "X-Admin-Secret: dev-secret-12345" --data-binary @ca.pem
```

> Both workers can share the same R2 bucket: file-origin writes (`FILES` binding), crl-checker reads (`CRL_BUCKET` binding).

### 2. `file-origin` (Port 8788)
**Purpose:** Generic file upload/download service (not CRL-specific, reusable standalone — upload a file, get an HTTP reference anywhere)

**Routes:**
- `POST /upload?filename=<name>` — Upload any file (raw binary `--data-binary` or multipart `-F file=@`)
- `GET /file/<name>` — Download file (public HTTP reference)
- `GET /file/<name>/info` — File metadata (admin)
- `DELETE /file/<name>` — Delete file (admin)
- `GET /list` — List all files (admin)

**Dependencies:**
- R2: `FILES` bucket

## Quick Start

### Prerequisites
```bash
# Install Wrangler
npm install -g wrangler

# Authenticate
wrangler login
```

### 1. Deploy File Origin Worker

```bash
cd workers/file-origin

# Create R2 bucket
wrangler r2 bucket create file-storage

# Update wrangler.toml with your bucket name (if different)

# Deploy
npm run deploy
```

### 2. Deploy CRL Checker Worker

```bash
cd workers/crl-checker

# Create KV namespaces
wrangler kv:namespace create REVOKED_CERTS
wrangler kv:namespace create CRL_DATA

# Update wrangler.toml with your KV namespace IDs

# Update FILE_ORIGIN_URL in wrangler.toml to your deployed file-origin URL
# e.g., FILE_ORIGIN_URL = "https://file-origin.<subdomain>.workers.dev"

# Deploy
npm run deploy
```

### 3. Test the Flow

```bash
# 1. Upload a CRL to file-origin
curl -X POST "https://file-origin.<subdomain>.workers.dev/upload?filename=crl.pem" \
  -H "X-Admin-Secret: dev-secret-12345" \
  --data-binary @sample-crl.pem

# 2a. Import via fetch (from file-origin / R2)
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/fetch?file=crl.pem" \
  -H "X-Admin-Secret: dev-secret-12345"

# 2b. OR direct upload (emulates real customer environment — file goes straight to the importer)
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/upload" \
  -H "X-Admin-Secret: dev-secret-12345" \
  --data-binary @sample-crl.pem

# 2b-ii. OR combined CA bundle + CRL on ONE upload (cross-references revoked
#        serials against certs, blocks by exact fingerprint)
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/upload" \
  -H "X-Admin-Secret: dev-secret-12345" \
  --data-binary @ca-bundle-and-crl.pem

#        (JSON form also accepted: {"ca_pem":"...", "crl_pem":"..."})

# 2c. OR chunked upload via Durable Object (for CRLs > request body limit)
#   Split file into base64 chunks, e.g. 512KB each:
#   split -b 512k sample-crl.pem; base64 each part; POST each as:
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/chunk" \
  -H "X-Admin-Secret: dev-secret-12345" \
  -H "content-type: application/json" \
  -d '{"session_id":"crl-2026-01","chunk_index":0,"total_chunks":3,"data":"<base64-chunk-0>"}'
#   ... repeat for chunks 1..N, then:
curl -X POST "https://crl-checker.<subdomain>.workers.dev/crl/import/finalize" \
  -H "X-Admin-Secret: dev-secret-12345" \
  -H "content-type: application/json" \
  -d '{"session_id":"crl-2026-01"}'

# 3. Check import status
curl "https://crl-checker.<subdomain>.workers.dev/crl/import/status" \
  -H "X-Admin-Secret: dev-secret-12345"

# 4. Test mTLS validation
curl "https://crl-checker.<subdomain>.workers.dev/mtls/check" \
  --cert client.pem \
  --key client-key.pem
```

## Local Development

Run both workers locally in separate terminals:

```bash
# Terminal 1: File Origin
cd workers/file-origin
npm run dev  # Runs on http://localhost:8788

# Terminal 2: CRL Checker
cd workers/crl-checker
npm run dev  # Runs on http://localhost:8787
```

**Test locally:**
```bash
# Upload a file
curl -X POST "http://localhost:8788/upload?filename=test-crl.pem" \
  -H "X-Admin-Secret: dev-secret-12345" \
  --data-binary @test-crl.pem

# Import CRL
curl -X POST "http://localhost:8787/crl/import/fetch?file=test-crl.pem" \
  -H "X-Admin-Secret: dev-secret-12345"

# Check status
curl -s http://localhost:8787/crl/import/status \
  -H "X-Admin-Secret: dev-secret-12345" | jq
```

## Production Configuration

### file-origin (wrangler.toml)
```toml
[env.production]
[[env.production.r2_buckets]]
binding = "FILES"
bucket_name = "prod-file-storage"
```

### crl-checker (wrangler.toml)
```toml
[env.production]
vars = { FILE_ORIGIN_URL = "https://file-origin.your-domain.workers.dev" }

[[env.production.kv_namespaces]]
binding = "REVOKED_CERTS"
id = "prod-crl-revoked-certs"

[[env.production.kv_namespaces]]
binding = "CRL_DATA"
id = "prod-crl-data-store"
```

Deploy to production:
```bash
npm run deploy:prod
```

## Scheduled CRL Updates

Add to `crl-checker/wrangler.toml`:
```toml
[triggers]
crons = ["0 */12 * * *"]  # Every 12 hours
```

Add cron handler to `crl-checker/src/index.js`:
```javascript
export default {
  async fetch(request, env) { /* ... */ },
  
  async scheduled(event, env, ctx) {
    const response = await fetch(`${env.FILE_ORIGIN_URL.replace('http://', 'https://')}/crl/import/fetch?file=crl.pem`, {
      method: "POST",
      headers: { "X-Admin-Secret": env.ADMIN_SECRET }
    });
    console.log("Scheduled CRL sync:", await response.json());
  }
};
```

## Security Notes

1. **Admin Secret:** Change `ADMIN_SECRET` in production for both workers
2. **R2 Access:** R2 buckets are private by default
3. **Public Endpoints:** `/file/<name>` on file-origin is public (no auth) — use for serving public files only
4. **Private Uploads:** All admin endpoints require `X-Admin-Secret` header

## Use Cases for file-origin

This worker is **generic** and can be used for:
- CRL files (this demo)
- Configuration files
- Static assets
- Backup storage
- Any file that needs to be accessible via HTTP

## License
MIT
