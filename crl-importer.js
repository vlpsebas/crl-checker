// ============================================================
// CRL Importer Worker — chunked CRL upload via Durable Objects
// ============================================================
// Upload a (potentially large) CRL file from your laptop over a
// tunnel, parse it, and publish the revoked serial list to KV
// where the mTLS Ingress Worker reads it.
//
// KV schema (shared with Ingress Worker):
//   crl:current            -> JSON array of revoked serial hex strings
//   crl:current:meta       -> { fetched_at, source, source_version, serial_count, checksum, expiry, format, this_update }
//   crl:version            -> checksum of latest import (staleness check)
//   crl:status             -> { last_success, last_error, in_progress }
//   serial:<hex>           -> "revoked" (O(1) lookups, normalized hex)
//
// Upload protocol (chunked, for large CRLs):
//   1. POST /crl/upload/start          { totalChunks, expectedSize, format } -> { sessionId }
//   2. POST /crl/upload/chunk/<id>     raw bytes + header X-Chunk-Index: <n>
//                                      (or JSON { index, data: base64 })
//   3. POST /crl/upload/complete/<id>  -> { ok, serial_count, checksum, expiry }
//   GET  /crl/upload/status/<id>       session progress
//   POST /crl/upload/abort/<id>        discard session
//
// Other endpoints:
//   POST /crl/fetch  { url, format? }  pull CRL from a URL (e.g. mock origin worker)
//   GET  /crl/status                   KV metadata + last sync status
//   GET  /crl/raw                      current revoked list from KV (debug)
//   GET  /health                       liveness
//   GET  /test/endpoints               endpoint map
//
// All POST endpoints require X-Admin-Secret when ADMIN_SECRET is set.
// ============================================================

// ---------- Helpers ----------

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function normalizeSerial(serial) {
  return serial.toLowerCase().replace(/^0+/, "").replace(/[:\s]/g, "") || "0";
}

function ascii(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function pemToDER(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!b64) throw new Error("no base64 payload found in PEM");
  return new Uint8Array(base64ToArrayBuffer(b64));
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function authorized(request, secret) {
  return request.headers.get("X-Admin-Secret") === secret;
}

// ---------- Minimal DER TLV parser (CRL skeleton) ----------

function parseTLV(bytes, offset) {
  const start = offset;
  const tag = bytes[offset++];
  if (offset >= bytes.length) throw new Error("truncated TLV header");
  let len = bytes[offset++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("bad length octets");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[offset++];
  }
  const end = offset + len;
  if (end > bytes.length) throw new Error("truncated TLV value");
  const node = { tag, value: bytes.subarray(offset, end), children: [], start, end };
  if (tag & 0x20) {
    let p = offset;
    while (p < end) {
      const child = parseTLV(bytes, p);
      node.children.push(child);
      p = child.end;
    }
  }
  return node;
}

function derIntToHex(intBytes) {
  let hex = "";
  for (const b of intBytes) hex += b.toString(16).padStart(2, "0");
  hex = hex.replace(/^(00)+/, ""); // strip positive-INTEGER padding
  return hex || "0";
}

// CertificateList ::= SEQUENCE { tbsCertList, sigAlg, sig }
// tbsCertList ::= SEQUENCE { version?, sig, issuer, thisUpdate,
//                            nextUpdate?, revokedCertificates? }
// revokedCertificates ::= SEQUENCE OF SEQUENCE { userCertificate INTEGER, ... }
function parseCRLSerials(der) {
  const root = parseTLV(der, 0);
  if (root.tag !== 0x30 || root.children.length < 1)
    throw new Error("not a DER SEQUENCE (is the file actually a CRL?)");
  const tbs = root.children[0];
  const serials = [];
  const times = [];
  for (const child of tbs.children) {
    if (child.tag === 0x17 || child.tag === 0x18) times.push(ascii(child.value));
    // revokedCertificates: SEQUENCE whose children are all SEQUENCEs
    if (
      child.tag === 0x30 &&
      child.children.length > 0 &&
      child.children.every((c) => c.tag === 0x30)
    ) {
      for (const entry of child.children) {
        const first = entry.children && entry.children[0];
        if (first && first.tag === 0x02) serials.push(derIntToHex(first.value));
      }
    }
  }
  return { serials, thisUpdate: times[0] || null, nextUpdate: times[1] || null };
}

// UTCTime: YYMMDDHHMMSSZ | GeneralizedTime: YYYYMMDDHHMMSSZ
function parseASN1Time(str) {
  if (!str) return null;
  const m = str.match(/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) return null;
  let year = parseInt(m[1], 10);
  if (m[1].length === 2) year = year < 50 ? 2000 + year : 1900 + year;
  const d = new Date(
    Date.UTC(year, parseInt(m[2], 10) - 1, parseInt(m[3], 10),
      parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6], 10))
  );
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// ---------- KV publish (shared by upload-complete and fetch) ----------

async function publishToKV(kv, der, sourceInfo) {
  const { serials, thisUpdate, nextUpdate } = parseCRLSerials(der);
  const sha = await sha256Hex(der);
  const nowIso = new Date().toISOString();
  const expiry =
    parseASN1Time(nextUpdate) ||
    new Date(Date.now() + 12 * 3600 * 1000).toISOString();

  await kv.put("crl:current", JSON.stringify(serials));
  await kv.put("crl:current:meta", JSON.stringify({
    fetched_at: nowIso,
    source: sourceInfo.source,
    source_version: sha,
    serial_count: serials.length,
    checksum: sha,
    expiry,
    format: sourceInfo.format,
    this_update: parseASN1Time(thisUpdate),
  }));
  await kv.put("crl:version", sha);
  for (const s of serials) await kv.put(`serial:${normalizeSerial(s)}`, "revoked");

  // prune serials from previous imports that are no longer revoked
  const current = new Set(serials.map(normalizeSerial));
  const listed = await kv.list({ prefix: "serial:" });
  for (const key of listed.keys) {
    if (!current.has(key.name.slice(7))) await kv.delete(key.name);
  }

  await kv.put("crl:status", JSON.stringify({
    last_success: nowIso, last_error: null, in_progress: false,
  }));
  return { ok: true, serial_count: serials.length, checksum: sha, expiry,
    this_update: parseASN1Time(thisUpdate) };
}

// ---------- Durable Object: chunk assembly ----------

export class CRLProcessor {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "POST" && path === "/start") {
        const { totalChunks, expectedSize, format } = await request.json();
        if (!totalChunks || totalChunks < 1 || totalChunks > 10000)
          return jsonResponse({ ok: false, error: "totalChunks must be 1..10000" }, 400);
        const meta = {
          totalChunks, expectedSize: expectedSize || 0,
          format: format === "der" ? "der" : "pem",
          received: 0, startedAt: new Date().toISOString(),
        };
        await this.state.storage.put("meta", meta);
        return jsonResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/chunk") {
        const meta = await this.state.storage.get("meta");
        if (!meta) return jsonResponse({ ok: false, error: "session not started" }, 400);
        let index, data;
        const idxHeader = request.headers.get("X-Chunk-Index");
        if (idxHeader) {
          index = parseInt(idxHeader, 10);
          data = await request.arrayBuffer();
        } else {
          const body = await request.json();
          index = body.index;
          data = base64ToArrayBuffer(body.data);
        }
        if (isNaN(index) || index < 0 || index >= meta.totalChunks)
          return jsonResponse({ ok: false, error: `bad chunk index ${index}` }, 400);
        await this.state.storage.put(`chunk:${index}`, data);
        if (!(await this.state.storage.get(`have:${index}`))) {
          await this.state.storage.put(`have:${index}`, 1);
          meta.received += 1;
          await this.state.storage.put("meta", meta);
        }
        return jsonResponse({ ok: true, received: meta.received, total: meta.totalChunks });
      }

      if (request.method === "POST" && path === "/complete") {
        const meta = await this.state.storage.get("meta");
        if (!meta) return jsonResponse({ ok: false, error: "session not started" }, 400);
        if (meta.received !== meta.totalChunks)
          return jsonResponse({ ok: false, error: `incomplete: ${meta.received}/${meta.totalChunks}` }, 409);

        const parts = [];
        let total = 0;
        for (let i = 0; i < meta.totalChunks; i++) {
          const chunk = await this.state.storage.get(`chunk:${i}`);
          if (!chunk) return jsonResponse({ ok: false, error: `missing chunk ${i}` }, 409);
          parts.push(chunk);
          total += chunk.byteLength;
        }
        const assembled = new Uint8Array(total);
        let off = 0;
        for (const p of parts) { assembled.set(new Uint8Array(p), off); off += p.byteLength; }

        let der;
        if (meta.format === "der") der = assembled;
        else der = pemToDER(new TextDecoder().decode(assembled));

        const result = await publishToKV(this.env.REVOKED_CERTS, der, {
          source: "manual-upload", format: meta.format,
        });

        // cleanup session storage
        await this.state.storage.delete("meta");
        await this.state.storage.delete(await this.state.storage.list({ prefix: "chunk:" }));
        await this.state.storage.delete(await this.state.storage.list({ prefix: "have:" }));
        return jsonResponse(result);
      }

      if (request.method === "POST" && path === "/abort") {
        await this.state.storage.delete("meta");
        await this.state.storage.delete(await this.state.storage.list({ prefix: "chunk:" }));
        await this.state.storage.delete(await this.state.storage.list({ prefix: "have:" }));
        return jsonResponse({ ok: true });
      }

      if (request.method === "GET" && path === "/status") {
        const meta = await this.state.storage.get("meta");
        return jsonResponse({ ok: true, session: meta || null });
      }

      return jsonResponse({ ok: false, error: "unknown DO action" }, 404);
    } catch (e) {
      return jsonResponse({ ok: false, error: e.message }, 500);
    }
  }
}

// ---------- Worker fetch handler ----------

async function handleUpload(request, path, env) {
  const parts = path.split("/"); // ["", "crl", "upload", action, id?]
  const action = parts[3];
  const sessionId = parts[4];

  if (action === "start") {
    const sid = crypto.randomUUID();
    const stub = env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sid));
    const body = await request.json();
    const res = await stub.fetch("https://do/start", {
      method: "POST", body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    if (!res.ok) return res;
    return jsonResponse({ ok: true, sessionId: sid });
  }

  if (!sessionId) return jsonResponse({ ok: false, error: "missing session id" }, 400);
  const stub = env.CRL_PROCESSOR.get(env.CRL_PROCESSOR.idFromName(sessionId));

  if (action === "chunk") {
    const headers = {
      "content-type": request.headers.get("content-type") || "application/octet-stream",
    };
    const idx = request.headers.get("X-Chunk-Index");
    if (idx) headers["x-chunk-index"] = idx;
    return await stub.fetch("https://do/chunk", {
      method: "POST", headers, body: await request.arrayBuffer(),
    });
  }
  if (action === "complete") return await stub.fetch("https://do/complete", { method: "POST" });
  if (action === "abort") return await stub.fetch("https://do/abort", { method: "POST" });
  if (action === "status") return await stub.fetch("https://do/status", { method: "GET" });

  return jsonResponse({ ok: false, error: "unknown upload action" }, 404);
}

async function handleFetch(request, env) {
  const { url: crlUrl, format } = await request.json();
  if (!crlUrl) return jsonResponse({ ok: false, error: "url required" }, 400);
  const res = await fetch(crlUrl);
  if (!res.ok) return jsonResponse({ ok: false, error: `origin returned ${res.status}` }, res.status);
  const bytes = new Uint8Array(await res.arrayBuffer());
  let der;
  if (format === "der") der = bytes;
  else {
    const text = new TextDecoder().decode(bytes);
    if (!text.includes("BEGIN")) return jsonResponse({ ok: false, error: "expected PEM, got binary" }, 400);
    der = pemToDER(text);
  }
  const result = await publishToKV(env.REVOKED_CERTS, der, {
    source: crlUrl, format: format === "der" ? "der" : "pem",
  });
  return jsonResponse(result);
}

async function handleStatus(env) {
  const kv = env.REVOKED_CERTS;
  const meta = await kv.get("crl:current:meta", "json");
  const status = await kv.get("crl:status", "json");
  return jsonResponse({ ok: true, meta, status });
}

function endpointList(adminEnabled) {
  return jsonResponse({
    ok: true,
    service: "crl-importer",
    admin_auth: adminEnabled ? "required (X-Admin-Secret)" : "disabled",
    upload_flow: [
      "POST /crl/upload/start          { totalChunks, expectedSize, format: 'pem'|'der' } -> { sessionId }",
      "POST /crl/upload/chunk/<id>     raw bytes + header X-Chunk-Index: <n>  (or JSON { index, data: base64 })",
      "POST /crl/upload/complete/<id>  assemble + parse + publish to KV",
      "GET  /crl/upload/status/<id>    session progress",
      "POST /crl/upload/abort/<id>     discard session",
    ],
    other: [
      "POST /crl/fetch                 { url, format? } pull CRL from a URL (e.g. mock origin worker)",
      "GET  /crl/status                KV metadata + last sync status",
      "GET  /crl/raw                   current revoked serial list (debug)",
      "GET  /health                    liveness",
      "GET  /test/endpoints            this list",
    ],
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (env.ADMIN_SECRET && request.method !== "GET" && !authorized(request, env.ADMIN_SECRET)) {
      return jsonResponse({ ok: false, error: "unauthorized" }, 401);
    }

    try {
      if (path === "/health")
        return jsonResponse({ ok: true, service: "crl-importer", ts: new Date().toISOString() });
      if (path === "/test/endpoints")
        return endpointList(!!env.ADMIN_SECRET);
      if (path === "/crl/status") return handleStatus(env);
      if (path === "/crl/raw") {
        const list = await env.REVOKED_CERTS.get("crl:current", "json");
        return jsonResponse({ ok: true, revoked_serials: list || [] });
      }
      if (path === "/crl/fetch" && request.method === "POST") return handleFetch(request, env);
      if (path.startsWith("/crl/upload/")) return handleUpload(request, path, env);
      return jsonResponse({ ok: false, error: "not found" }, 404);
    } catch (e) {
      return jsonResponse({ ok: false, error: e.message }, 500);
    }
  },
};
