// admin.js — shared utilities + usage/telemetry endpoints (pricing data).
// Tracks: request count, KV reads/writes, KV storage bytes, CPU ms.
// NOTE: Workers do not expose true CPU time or memory (RSS); wall-clock
// duration of the request is the closest billing proxy. KV storage is
// estimated from key+value byte lengths — good enough for cost reference.

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

export const fail = (msg, status = 400) => json({ ok: false, error: msg }, status);

// lowercase hex, strip leading zeros, colons/spaces (matches Cloudflare cert serial format)
export const normSerial = (s) =>
  s.toLowerCase().replace(/^0+/, "").replace(/[:\s]/g, "") || "0";

export const authorized = (req, secret) =>
  !secret || req.headers.get("X-Admin-Secret") === secret;

// ---------- usage counters (KV key: usage:counters) ----------
const EMPTY = { requests: 0, kv_reads: 0, kv_writes: 0, kv_bytes: 0, cpu_ms: 0 };

export async function getCounters(kv) {
  return (await kv.get("usage:counters", "json")) || { ...EMPTY };
}

export async function saveCounters(kv, c) {
  await kv.put("usage:counters", JSON.stringify(c));
}

export async function bump(kv, patch) {
  const c = await getCounters(kv);
  for (const k in patch) c[k] = (c[k] || 0) + patch[k];
  await saveCounters(kv, c);
  return c;
}

// ---------- pricing-oriented usage report ----------
export async function usageReport(kv) {
  const c = await getCounters(kv);
  const listed = await kv.list({ prefix: "serial:" });
  const serialBytes = listed.keys.reduce((t, k) => t + k.name.length + 7, 0); // value "revoked" ≈ 7 bytes
  const current = await kv.get("crl:current");
  const meta = await kv.get("crl:current:meta", "json");
  const kvBytes =
    serialBytes +
    (current ? current.length : 0) +
    (meta ? JSON.stringify(meta).length : 0) +
    200; // counters + status keys slack
  return {
    ok: true,
    usage: {
      requests: c.requests,
      kv_reads: c.kv_reads,
      kv_writes: c.kv_writes,
      cpu_ms: c.cpu_ms,
      kv_storage_bytes: kvBytes,
      revoked_entries: listed.keys.length,
      last_import: meta?.fetched_at || null,
    },
    pricing_notes: [
      "cpu_ms ≈ wall-clock duration (billing proxy; real CPU time not exposed)",
      "kv_storage_bytes ≈ key+value byte lengths (billing is per GB-month stored)",
      "requests = KV counter (eventually consistent; for exact volume use Cloudflare Analytics)",
      "per-request log available via optional telemetry.js",
    ],
  };
}
