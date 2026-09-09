// importer.js — CRL import & parse for crl-checker.
// ONE module handles every import path (no separate files needed):
//   - POST /crl/import            manual run (body: { url?, format? })
//   - POST /crl/fetch             pull CRL from a URL (e.g. mock origin worker)
//   - POST /crl/upload/*          chunked upload via Durable Object (large CRLs)
//   - scheduled (cron, 2x daily)  same runImport() as manual
// Parsing on a schedule costs nothing on the request path: cron invocations are
// separate billable events, so import CPU never slows down client requests.

import { json, fail, normSerial, bump, authorized } from "./admin.js";

// ---------- PEM / DER helpers ----------
const ascii = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return s; };
const b64ToBuf = (b64) => {
  const bin = atob(b64); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
};
const pemToDER = (pem) => {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  if (!b64) throw new Error("no base64 payload found in PEM");
  return new Uint8Array(b64ToBuf(b64));
};
const sha256Hex = async (bytes) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");

// ---------- minimal ASN.1 DER parser (CertificateList) ----------
// CertificateList ::= SEQUENCE { tbsCertList, sigAlg, sig }
// tbsCertList ::= SEQUENCE { version?, sig, issuer, thisUpdate, nextUpdate?, revokedCertificates? }
function parseTLV(b, o) {
  const start = o; const tag = b[o++];
  let len = b[o++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[o++]; }
  const end = o + len;
  if (end > b.length) throw new Error("truncated DER");
  const node = { tag, value: b.subarray(o, end), children: [], start, end };
  if (tag & 0x20) { let p = o; while (p < end) { const c = parseTLV(b, p); node.children.push(c); p = c.end; } }
  return node;
}
const intToHex = (v) => {
  let h = ""; for (const b of v) h += b.toString(16).padStart(2, "0");
  return h.replace(/^(00)+/, "") || "0"; // strip positive-INTEGER padding
};
function parseCRL(der) {
  const root = parseTLV(der, 0);
  if (root.tag !== 0x30 || root.children.length < 1) throw new Error("not a DER SEQUENCE — is this actually a CRL?");
  const tbs = root.children[0];
  const serials = [], times = [];
  for (const c of tbs.children) {
    if (c.tag === 0x17 || c.tag === 0x18) times.push(ascii(c.value)); // thisUpdate / nextUpdate
    // revokedCertificates: SEQUENCE whose children are all SEQUENCEs
    if (c.tag === 0x30 && c.children.length && c.children.every((x) => x.tag === 0x30)) {
      for (const entry of c.children) {
        const first = entry.children && entry.children[0];
        if (first && first.tag === 0x02) serials.push(intToHex(first.value)); // userCertificate INTEGER
      }
    }
  }
  return { serials, thisUpdate: times[0] || null, nextUpdate: times[1] || null };
}
const parseASN1Time = (str) => {
  if (!str) return null;
  const m = str.match(/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) return null;
  let y = parseInt(m[1], 10);
  if (m[1].length === 2) y = y < 50 ? 2000 + y : 1900 + y;
  const d = new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  return isNaN(d.getTime()) ? null : d.toISOString();
};

// ---------- publish parsed CRL to KV ----------
export async function publish(kv, der, source, format) {
  const t0 = Date.now();
  const { serials, thisUpdate, nextUpdate } = parseCRL(der);
  const sha = await sha256Hex(der);
  const meta = {
    fetched_at: new Date().toISOString(),
    source, format, source_version: sha, serial_count: serials.length,
    checksum: sha,
    expiry: parseASN1Time(nextUpdate) || new Date(Date.now() + 12 * 3600e3).toISOString(),
    this_update: parseASN1Time(thisUpdate),
  };
  const currentJson = JSON.stringify(serials);
  await kv.put("crl:current", currentJson);
  await kv.put("crl:current:meta", JSON.stringify(meta));
  await kv.put("crl:version", sha);
  for (const s of serials) await kv.put("serial:" + normSerial(s), "revoked");
  // prune serials from previous imports that are no longer revoked
  const cur = new Set(serials.map(normSerial));
  const listed = await kv.list({ prefix: "serial:" });
  let pruned = 0;
  for (const k of listed.keys) if (!cur.has(k.name.slice(7))) { await kv.delete(k.name); pruned++; }
  await kv.put("crl:status", JSON.stringify({ last_success: new Date().toISOString(), last_error: null, serial_count: serials.length }));
  const ms = Date.now() - t0;
  await bump(kv, { kv_writes: 3 + serials.length + pruned, kv_reads: 1, kv_bytes: currentJson.length + JSON.stringify(meta).length, cpu_ms: ms });
  return { ok: true, serial_count: serials.length, checksum: sha, expiry: meta.expiry, cpu_ms: ms };
}

// ---------- runImport: used by cron + POST /crl/import + POST /crl/fetch ----------
export async function runImport(env, { url, format } = {}) {
  const crlUrl = url || env.CRL_ORIGIN_URL;
  if (!crlUrl) throw new Error("no CRL source URL (set CRL_ORIGIN_URL or pass url)");
  const res = await fetch(crlUrl);
  if (!res.ok) throw new Error("CRL source returned " + res.status);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const fmt = format || env.CRL_FORMAT || "pem";
  const der = fmt === "der" ? bytes : pemToDER(new TextDecoder().decode(bytes));
  return await publish(env.REVOKED_CERTS, der, crlUrl, fmt);
}

// ---------- chunked upload via Durable Object (large CRLs) ----------
export class CRLProcessor {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const url = new URL(request.url); const path = url.pathname;
    try {
      if (request.method === "POST" && path === "/start") {
        const { totalChunks, format } = await request.json();
        if (!totalChunks || totalChunks < 1 || totalChunks > 10000) return fail("totalChunks must be 1..10000", 400);
        await this.state.storage.put("meta", { totalChunks, format: format === "der" ? "der" : "pem", received: 0 });
        return json({ ok: true });
      }
      if (request.method === "POST" && path === "/chunk") {
        const meta = await this.state.storage.get("meta");
        if (!meta) return fail("session not started", 400);
        let index, data;
        const idx = request.headers.get("X-Chunk-Index");
        if (idx) { index = +idx; data = await request.arrayBuffer(); }
        else { const b = await request.json(); index = b.index; data = b64ToBuf(b.data); }
        if (isNaN(index) || index < 0 || index >= meta.totalChunks) return fail("bad chunk index " + index, 400);
        if (!(await this.state.storage.get("have:" + index))) {
          await this.state.storage.put("chunk:" + index, data);
          await this.state.storage.put("have:" + index, 1);
          meta.received++; await this.state.storage.put("meta", meta);
        }
        return json({ ok: true, received: meta.received, total: meta.totalChunks });
      }
      if (request.method === "POST" && path === "/complete") {
        const meta = await this.state.storage.get("meta");
        if (!meta) return fail("session not started", 400);
        if (meta.received !== meta.totalChunks) return fail("incomplete: " + meta.received + "/" + meta.totalChunks, 409);
        const parts = []; let total = 0;
        for (let i = 0; i < meta.totalChunks; i++) {
          const c = await this.state.storage.get("chunk:" + i);
          if (!c) return fail("missing chunk " + i, 409);
          parts.push(c); total += c.byteLength;
        }
        const assembled = new Uint8Array(total); let off = 0;
        for (const p of parts) { assembled.set(new Uint8Array(p), off); off += p.byteLength; }
        const der = meta.format === "der" ? assembled : pemToDER(new TextDecoder().decode(assembled));
        const result = await publish(this.env.REVOKED_CERTS, der, "manual-upload", meta.format);
        for (let i = 0; i < meta.totalChunks; i++) { await this.state.storage.delete("chunk:" + i); await this.state.storage.delete("have:" + i); }
        await this.state.storage.delete("meta");
        return json(result);
      }
      if (request.method === "POST" && path === "/abort") {
        const meta = await this.state.storage.get("meta");
        if (meta) for (let i = 0; i < meta.totalChunks; i++) { await this.state.storage.delete("chunk:" + i); await this.state.storage.delete("have:" + i); }
        await this.state.storage.delete("meta");
        return json({ ok: true });
      }
      if (request.method === "GET" && path === "/status") {
        return json({ ok: true, session: await this.state.storage.get("meta") });
      }
      return fail("unknown DO action", 404);
    } catch (e) { return fail(e.message, 500); }
  }
}

// ---------- HTTP routes for importer (used by index.js) ----------
export async function handleImport(request, env) {
  const url = new URL(request.url); const path = url.pathname;

  if (request.method !== "GET" && !authorized(request, env.ADMIN_SECRET)) {
    return fail("unauthorized", 401);
  }

  // chunked upload session
  if (path.startsWith("/crl/upload/")) {
    const parts = path.split("/"); // ["", "crl", "upload", action, sessionId?]
    const action = parts[3]; const sid = parts[4];
    const stub = () => env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sid));
    if (action === "start") {
      const body = await request.json();
      const sid2 = crypto.randomUUID();
      const r = await env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sid2)).fetch("https://do/start", { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
      if (!r.ok) return r;
      return json({ ok: true, sessionId: sid2 });
    }
    if (!sid) return fail("missing session id", 400);
    if (action === "chunk") {
      const headers = { "content-type": request.headers.get("content-type") || "application/octet-stream" };
      const idx = request.headers.get("X-Chunk-Index");
      if (idx) headers["x-chunk-index"] = idx;
      return stub().fetch("https://do/chunk", { method: "POST", headers, body: await request.arrayBuffer() });
    }
    if (action === "complete") return stub().fetch("https://do/complete", { method: "POST" });
    if (action === "abort") return stub().fetch("https://do/abort", { method: "POST" });
    if (action === "status") return stub().fetch("https://do/status", { method: "GET" });
    return fail("unknown upload action", 404);
  }

  // POST /crl/import — manual run (cron calls runImport directly)
  if (path === "/crl/import" && request.method === "POST") {
    try {
      const body = await request.json().catch(() => ({}));
      return json(await runImport(env, body));
    } catch (e) { return fail("import failed: " + e.message, 500); }
  }

  // POST /crl/fetch — pull from a specific URL (e.g. mock origin worker)
  if (path === "/crl/fetch" && request.method === "POST") {
    try {
      const { url: u, format } = await request.json();
      if (!u) return fail("url required", 400);
      return json(await runImport(env, { url: u, format }));
    } catch (e) { return fail("fetch failed: " + e.message, 500); }
  }

  // GET /crl/status — metadata + sync status
  if (path === "/crl/status") {
    const kv = env.REVOKED_CERTS;
    const meta = await kv.get("crl:current:meta", "json");
    const status = await kv.get("crl:status", "json");
    return json({ ok: true, meta, status });
  }

  // GET /crl/raw — current revoked serial list (debug)
  if (path === "/crl/raw") {
    const list = await env.REVOKED_CERTS.get("crl:current", "json");
    return json({ ok: true, revoked_serials: list || [] });
  }

  return fail("importer endpoint not found", 404);
}
