// validator.js — mTLS + CRL revocation check, fail-closed.
// Runs on every client request (KV-only: no origin roundtrip for the check).
// Fail-closed rules:
//   - no CRL loaded              -> block (503)
//   - CRL stale (past nextUpdate) -> block (503)
//   - CRL older than CRL_MAX_AGE_HOURS -> block (503)
//   - serial in revocation list   -> block (403)

import { json, fail, normSerial, bump } from "./admin.js";

async function crlState(kv, maxAgeHours) {
  const meta = await kv.get("crl:current:meta", "json");
  if (!meta) return { ok: false, reason: "no CRL loaded (run /crl/import or wait for cron)" };
  const now = Date.now();
  if (new Date(meta.expiry).getTime() < now) return { ok: false, reason: "CRL expired at " + meta.expiry };
  const maxAge = (maxAgeHours ? +maxAgeHours : 24) * 3600e3;
  if (new Date(meta.fetched_at).getTime() < now - maxAge) return { ok: false, reason: "CRL older than " + maxAgeHours + "h (fetched " + meta.fetched_at + ")" };
  return { ok: true, meta };
}

async function checkSerial(kv, serial) {
  const entry = await kv.get("serial:" + normSerial(serial));
  return entry !== null;
}

// Real mTLS validation via Cloudflare's TLS Client Auth properties
async function validateCert(request, kv, maxAgeHours) {
  const tls = request.cf?.tlsClientAuth;
  if (!tls || tls.certPresented !== "1") throw Object.assign(new Error("mTLS: client certificate not presented"), { status: 403 });
  if (tls.certVerified !== "SUCCESS") throw Object.assign(new Error("mTLS: certificate not verified (" + tls.certVerified + ")"), { status: 403 });

  const state = await crlState(kv, maxAgeHours);
  if (!state.ok) throw Object.assign(new Error("CRL unavailable: " + state.reason), { status: 503 });

  const serial = tls.certSerial;
  if (serial && await checkSerial(kv, serial)) {
    throw Object.assign(new Error("mTLS: certificate revoked (serial " + serial + ")"), { status: 403 });
  }
  return {
    fingerprint: tls.certFingerprintSHA256,
    serial,
    issuer: tls.certIssuerDN,
    subject: tls.certSubjectDN,
  };
}

export async function handleValidator(request, env) {
  const url = new URL(request.url); const path = url.pathname;
  const kv = env.REVOKED_CERTS;
  const maxAge = env.CRL_MAX_AGE_HOURS || "24";

  // GET /health — liveness + CRL freshness (no mTLS required)
  if (path === "/health" || path === "/health/status") {
    const state = await crlState(kv, maxAge);
    const status = await kv.get("crl:status", "json");
    await bump(kv, { requests: 0, kv_reads: 2 }); // count reads for pricing
    return json({
      ok: true, status: "healthy",
      crl: { loaded: state.ok, ...(state.meta ? { fetched_at: state.meta.fetched_at, serial_count: state.meta.serial_count, expiry: state.meta.expiry } : {}), reason: state.ok ? null : state.reason },
      last_sync: status,
    });
  }

  // GET /crl/check?serial=<hex> — manual revocation lookup (no mTLS needed)
  if (path === "/crl/check") {
    const serial = url.searchParams.get("serial");
    if (!serial) return fail("serial query param required", 400);
    const revoked = await checkSerial(kv, serial);
    await bump(kv, { requests: 1, kv_reads: 1 });
    return json({ ok: true, serial: normSerial(serial), revoked });
  }

  // GET /test/mtls?serial=<hex> — simulate an mTLS request flow (for demo without real cert)
  if (path === "/test/mtls") {
    const serial = url.searchParams.get("serial");
    const state = await crlState(kv, maxAge);
    await bump(kv, { requests: 1, kv_reads: 2 });
    if (!state.ok) return json({ ok: false, blocked: true, reason: state.reason, stage: "crl-availability" }, 503);
    if (serial && await checkSerial(kv, serial)) return json({ ok: false, blocked: true, reason: "revoked", stage: "revocation" }, 403);
    return json({ ok: true, allowed: true, certificate: { serial: serial || "(none)" } });
  }

  // Default: real mTLS validation (requires client cert presented via WAF mTLS rule)
  try {
    const certInfo = await validateCert(request, kv, maxAge);
    await bump(kv, { requests: 1, kv_reads: 2 });
    return json({ ok: true, allowed: true, message: "certificate valid and not revoked", certificate: certInfo });
  } catch (e) {
    await bump(kv, { requests: 1, kv_reads: 2 });
    return fail(e.message, e.status || 403);
  }
}
