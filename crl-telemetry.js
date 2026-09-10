// telemetry.js — OPTIONAL per-request usage log (customer decides whether to use it).
// Logs one KV entry per request: wall-clock duration (CPU billing proxy),
// KV op deltas, and total request count. Enable by importing in index.js:
//   import withTelemetry from "./telemetry.js";
//   export default { fetch: withTelemetry(handler) ... }
// Reads via: GET /admin/usage  (aggregates) or the telemetry:<ts> KV keys directly.

export default function withTelemetry(handler) {
  return async (request, env, ctx) => {
    const kv = env.REVOKED_CERTS;
    const t0 = Date.now();
    const before = (await kv.get("usage:counters", "json")) || { requests: 0, kv_reads: 0, kv_writes: 0, kv_bytes: 0, cpu_ms: 0 };
    const res = await handler(request, env, ctx);
    const ms = Date.now() - t0;
    const after = (await kv.get("usage:counters", "json")) || before;
    const entry = {
      ts: new Date().toISOString(),
      url: request.url,
      method: request.method,
      status: res.status,
      cpu_ms: ms, // wall-clock ≈ CPU billing proxy (true CPU time not exposed)
      kv_reads: (after.kv_reads || 0) - (before.kv_reads || 0),
      kv_writes: (after.kv_writes || 0) - (before.kv_writes || 0),
      kv_bytes: (after.kv_bytes || 0) - (before.kv_bytes || 0),
      total_requests: after.requests,
      note: "memory (RSS) is not exposed by the Workers runtime",
    };
    await kv.put("telemetry:" + Date.now(), JSON.stringify(entry));
    return res;
  };
}
