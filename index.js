// index.js — entry point + router for crl-checker Worker.
// Deploy unit: wrangler.toml sets main = "index.js"; everything else is a
// library module imported here. Routes:
//   importer:  /crl/upload/*, /crl/fetch, /crl/import, /crl/status, /crl/raw
//   validator: /, /health, /mtls/check, /crl/check, /test/mtls
//   admin:     /admin/usage, /admin/telemetry/reset
// scheduled:   twice-daily CRL refresh (cron in wrangler.toml [triggers])
//
// Optional per-request usage logging (customer opt-in): uncomment the import
// and wrap fetch with withTelemetry() below — no other code changes needed.

import { json, fail, authorized, usageReport, getCounters, saveCounters, bump } from "./admin.js";
import { handleImport, runImport, CRLProcessor } from "./importer.js";
import { handleValidator } from "./validator.js";
// import withTelemetry from "./telemetry.js";

export { CRLProcessor }; // required: DO class must be exported from entrypoint

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const t0 = Date.now();

    let res;
    try {
      // importer routes (everything under /crl/ except the manual check)
      if (path.startsWith("/crl/") && !path.startsWith("/crl/check")) {
        res = await handleImport(request, env);
      }
      // admin routes
      else if (path.startsWith("/admin/")) {
        if (!authorized(request, env.ADMIN_SECRET)) res = fail("unauthorized", 401);
        else if (path === "/admin/usage") res = json(await usageReport(env.REVOKED_CERTS));
        else if (path === "/admin/telemetry/reset") {
          await saveCounters(env.REVOKED_CERTS, { requests: 0, kv_reads: 0, kv_writes: 0, kv_bytes: 0, cpu_ms: 0 });
          res = json({ ok: true, reset: "usage counters cleared" });
        } else res = fail("admin endpoint not found", 404);
      }
      // validator (default)
      else {
        res = await handleValidator(request, env);
      }
    } catch (e) {
      res = fail("internal: " + e.message, 500);
    }

    // TELEMETRY=true (wrangler.toml [vars]) → count every request for pricing
    if (env.TELEMETRY === "true") {
      await bump(env.REVOKED_CERTS, { requests: 1, cpu_ms: Date.now() - t0 });
    }
    return res;
  },

  // twice-daily CRL refresh (06:00 + 18:00 UTC)
  async scheduled(event, env) {
    try {
      const r = await runImport(env, {});
      console.log("CRL refresh OK:", JSON.stringify(r));
    } catch (e) {
      console.error("CRL refresh failed:", e.message);
      await env.REVOKED_CERTS.put("crl:status", JSON.stringify({ last_success: null, last_error: e.message, serial_count: 0 }));
    }
  },
};
