// importer.js — CRL import & parse for crl-checker.
// ONE module handles every import path:
//   - POST /crl/import        manual run (body: { url?, format? }) — same as cron
//   - POST /crl/fetch         pull CRL from a URL via Range requests, assembled
//                             inside the Durable Object — handles any size
//   - POST /crl/upload        single streaming upload (≤100MB body). The Worker
//                             forwards the raw body stream to the DO, which slices
//                             it internally. The client sends ONE request — there
//                             is NO manual chunking protocol.
//   - scheduled (cron)        runImport() — same as manual
//
// Why a DO: a >100MB CRL cannot ride in a single HTTP request. The DO assembles
// it server-side, piece by piece. Platform constraints honored here:
//   - DO storage value limit: 128 KiB  → internal slices are 96 KiB
//   - KV value limit: 25 MB            → crl:current is skipped above ~20 MB
//                                        (per-serial keys are always written; the
//                                        validator only needs serial:<hex>)

import { json, fail, normSerial, bump, authorized } from "./admin.js";

const SLICE = 96 * 1024; // < 128 KiB DO storage value cap
const KV_CURRENT_MAX = 20 * 1024 * 1024; // headroom under KV's 25 MB value cap

// ---------- PEM / DER helpers ----------
const ascii = (bytes) => { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return s; };
const b64ToBuf = (b64) => {
  const bin = atob(b64); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
};
export const pemToDER = (pem) => {
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  if (!b64) throw new Error("no base64 payload found in PEM");
  return new Uint8Array(b64ToBuf(b64));
};
const sha256Hex = async (bytes) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
export const detectFormat = (bytes) => {
  const head = new TextDecoder().decode(bytes.slice(0, 4096));
  return head.includes("BEGIN") ? "pem" : "der";
};

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
export function parseCRL(der) {
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
  let writes = 0;
  if (currentJson.length <= KV_CURRENT_MAX) {
    await kv.put("crl:current", currentJson);
    writes++;
  } else {
    // too big for a KV value — keep per-serial keys only (validator doesn't need crl:current)
    meta.crl_current_overflow = true;
    meta.crl_current_bytes = currentJson.length;
  }
  await kv.put("crl:current:meta", JSON.stringify(meta));
  writes++;
  for (const s of serials) { await kv.put("serial:" + normSerial(s), "revoked"); }
  writes += serials.length;

  // prune serial:* entries no longer revoked (bounded)
  const cur = new Set(serials.map(normSerial));
  let pruned = 0, cursor = null;
  do {
    const opts = { prefix: "serial:" };
    if (cursor) opts.cursor = cursor;
    const listed = await kv.list(opts);
    for (const k of listed.keys) if (!cur.has(k.name.slice(7))) { await kv.delete(k.name); pruned++; }
    cursor = listed.list_complete ? null : listed.cursor;
    if (pruned > 20000) break; // safety cap
  } while (cursor);

  await kv.put("crl:status", JSON.stringify({ last_success: new Date().toISOString(), last_error: null, serial_count: serials.length }));
  writes++;
  const ms = Date.now() - t0;
  await bump(kv, { kv_writes: writes, kv_reads: 1, kv_bytes: currentJson.length + JSON.stringify(meta).length, cpu_ms: ms });
  return { ok: true, serial_count: serials.length, checksum: sha, expiry: meta.expiry, cpu_ms: ms, crl_current_stored: !meta.crl_current_overflow };
}

// ---------- runImport: cron + POST /crl/import (small/medium CRLs) ----------
// For very large CRLs use POST /crl/fetch instead (DO Range-paged assembly).
export async function runImport(env, { url, format } = {}) {
  const crlUrl = url || env.CRL_ORIGIN_URL;
  if (!crlUrl) throw new Error("no CRL source URL (set CRL_ORIGIN_URL or pass url)");
  const res = await fetch(crlUrl);
  if (!res.ok) throw new Error("CRL source returned " + res.status);
  const bytes = new Uint8Array(await res.arrayBuffer());
  const fmt = format || env.CRL_FORMAT || "auto";
  const der = fmt === "der" ? bytes : (fmt === "auto" && detectFormat(bytes) === "der") ? bytes : pemToDER(new TextDecoder().decode(bytes));
  return await publish(env.REVOKED_CERTS, der, crlUrl, fmt);
}

// ---------- Durable Object: server-side assembly (no client chunking) ----------
export class CRLProcessor {
  constructor(state, env) { this.state = state; this.env = env; }

  async fetch(request) {
    const url = new URL(request.url); const path = url.pathname;
    try {
      // POST /fetch — Range-paged URL import (any size)
      if (path === "/fetch" && request.method === "POST") {
        const { url: crlUrl, format } = await request.json();
        if (!crlUrl) return fail("url required", 400);
        return await this.importFromUrl(crlUrl, format || "auto");
      }
      // POST /upload — single streaming body; sliced internally
      if (path === "/upload" && request.method === "POST") {
        return await this.importFromStream(request.body, request.headers.get("x-crl-format") || "auto");
      }
      return fail("unknown DO action", 404);
    } catch (e) { return fail(e.message, 500); }
  }

  async storeSplit(buf) {
    const u8 = new Uint8Array(buf);
    for (let i = 0; i < u8.length; i += SLICE) {
      await this.state.storage.put("piece:" + this.pieceIndex++, u8.slice(i, i + SLICE));
    }
    await this.state.storage.put("count", this.pieceIndex);
  }

  async importFromUrl(crlUrl, fmt) {
    this.pieceIndex = 0;
    let offset = 0;
    while (true) {
      const end = offset + SLICE - 1;
      const res = await fetch(crlUrl, { headers: { Range: `bytes=${offset}-${end}` } });
      if (res.status === 416) break; // requested past EOF
      if (!res.ok) throw new Error("CRL source returned " + res.status);
      const buf = await res.arrayBuffer();
      if (res.status === 206) {
        await this.storeSplit(buf);
        if (buf.byteLength < SLICE) break;
        const cr = res.headers.get("content-range");
        const m = cr && cr.match(/\/(\d+)$/);
        if (m && offset + buf.byteLength >= +m[1]) break;
        offset += buf.byteLength;
      } else {
        // 200: server ignored Range → this is the whole body
        await this.storeSplit(buf);
        break;
      }
    }
    return await this.assembleAndPublish(fmt, crlUrl);
  }

  async importFromStream(stream, fmt) {
    this.pieceIndex = 0;
    const reader = stream.getReader();
    let buffer = new Uint8Array(0);
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const combined = new Uint8Array(buffer.length + value.length);
      combined.set(buffer); combined.set(value, buffer.length);
      buffer = combined;
      if (buffer.length >= SLICE) {
        await this.storeSplit(buffer);
        buffer = new Uint8Array(0);
      }
    }
    if (buffer.length) await this.storeSplit(buffer);
    return await this.assembleAndPublish(fmt, "manual-upload");
  }

  async assembleAndPublish(fmt, source) {
    const count = (await this.state.storage.get("count")) || 0;
    const parts = []; let total = 0;
    for (let i = 0; i < count; i++) {
      const p = await this.state.storage.get("piece:" + i);
      if (!p) throw new Error("missing piece " + i);
      parts.push(p); total += p.byteLength;
    }
    const assembled = new Uint8Array(total); let off = 0;
    for (const p of parts) { assembled.set(new Uint8Array(p), off); off += p.byteLength; }
    const f = fmt === "auto" ? detectFormat(assembled) : fmt;
    const der = f === "der" ? assembled : pemToDER(new TextDecoder().decode(assembled));
    const result = await publish(this.env.REVOKED_CERTS, der, source, f);
    for (let i = 0; i < count; i++) await this.state.storage.delete("piece:" + i);
    await this.state.storage.delete("count");
    return json(result);
  }
}

// ---------- HTTP routes for importer (used by index.js) ----------
export async function handleImport(request, env) {
  const url = new URL(request.url); const path = url.pathname;

  if (request.method !== "GET" && !authorized(request, env.ADMIN_SECRET)) {
    return fail("unauthorized", 401);
  }

  // POST /crl/upload — ONE request, raw CRL file body (≤100MB). No client chunking:
  // the Worker forwards the body stream to the DO, which slices it internally.
  if (path === "/crl/upload" && request.method === "POST") {
    const sid = crypto.randomUUID();
    const stub = env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sid));
    const headers = { "content-type": "application/octet-stream" };
    const fmt = url.searchParams.get("format"); // ?format=pem|der|auto (default auto)
    if (fmt) headers["x-crl-format"] = fmt;
    return await stub.fetch("https://do/upload", { method: "POST", headers, body: request.body });
  }

  // POST /crl/fetch — Range-paged URL import, assembled in the DO (any size)
  if (path === "/crl/fetch" && request.method === "POST") {
    const { url: u, format } = await request.json();
    if (!u) return fail("url required", 400);
    const sid = crypto.randomUUID();
    const stub = env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sid));
    return await stub.fetch("https://do/fetch", {
      method: "POST",
      body: JSON.stringify({ url: u, format: format || "auto" }),
      headers: { "content-type": "application/json" },
    });
  }

  // POST /crl/import — manual run (cron calls runImport directly)
  if (path === "/crl/import" && request.method === "POST") {
    try {
      const body = await request.json().catch(() => ({}));
      return json(await runImport(env, body));
    } catch (e) { return fail("import failed: " + e.message, 500); }
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
    const kv = env.REVOKED_CERTS;
    const list = await kv.get("crl:current", "json");
    const meta = await kv.get("crl:current:meta", "json");
    return json({ ok: true, revoked_serials: list || [], serial_count: meta?.serial_count || 0, crl_current_stored: !(meta && meta.crl_current_overflow) });
  }

  return fail("importer endpoint not found", 404);
}
