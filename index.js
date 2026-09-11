// ============================================================
// CRL Checker Worker - mTLS Validator + CRL Importer + Updater
// ============================================================
//
// ENDPOINTS:
//   mTLS Validator:
//     GET  /health               - Service health check
//     GET  /debug/cert           - Show presented certificate fields
//     GET  /debug/kv             - Show KV contents (admin only)
//     GET  /mtls/check           - Validate current mTLS cert
//     GET  /mtls/allow           - Confirm allowed certificate
//     GET  /                     - Default endpoint (requires mTLS)
//
//   CRL Importer (admin, X-Admin-Secret required):
//     POST /crl/import/fetch?file=<name>   - Fetch CRL from file-origin (HTTP) or R2
//     POST /crl/import/upload              - Direct CRL PEM upload (<100MB request limit)
//     POST /crl/import/chunk               - Chunked upload for large files (Durable Object)
//     POST /crl/import/finalize            - Finalize chunked assembly and process
//     GET  /crl/import/chunks/status       - Active DO upload sessions
//     GET  /crl/import/status              - Import metadata + sync status
//     POST /crl/import/manual              - Manually revoke a serial
//
//   Test:
//     GET  /test/ping            - Simple connectivity test
//     GET  /test/file-origin     - Verify file-origin is reachable
//     GET  /test/endpoints       - List all endpoints
//
// KV BINDINGS:
//   REVOKED_CERTS  - revocation entries (serial:*, fingerprint:*) - hot path
//   CRL_DATA       - import metadata (crl:metadata, crl:serials, crl:last_fetch)
//
// DURABLE OBJECT:
//   CRL_PROCESSOR  - assembles chunked CRL uploads (files > request body limit)
//
// ============================================================

// --- Helpers ---

const jsonResponse = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });

const errorResponse = (message, status = 400) =>
  jsonResponse({ success: false, error: message }, status);

const normalizeSerial = (serial) =>
  (serial || "")
    .toLowerCase()
    .replace(/^0+/, "")
    .replace(/[:\s]/g, "") || "0";

const normalizeFingerprint = (fp) => (fp || "").replace(/:/g, "").toLowerCase();

// Revoked-serial sharding: FNV-1a hash -> bucket. Keeps the revocation set in a
// fixed number of KV values instead of one key per serial, so large CRL imports
// finish in a handful of parallel writes (no per-serial subrequest latency).
const REVOKED_SHARDS = 256;
function serialShardIndex(serial) {
  let h = 0x811c9dc5;
  for (let i = 0; i < serial.length; i++) {
    h ^= serial.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % REVOKED_SHARDS;
}

// --- PEM / Base64 utilities ---

function splitPEMBlocks(pem, type) {
  const beginMarker = `-----BEGIN ${type}-----`;
  const endMarker = `-----END ${type}-----`;
  const blocks = [];
  let start = 0;

  while (true) {
    const beginIdx = pem.indexOf(beginMarker, start);
    if (beginIdx === -1) break;
    const endIdx = pem.indexOf(endMarker, beginIdx);
    if (endIdx === -1) break;

    const b64 = pem
      .slice(beginIdx + beginMarker.length, endIdx)
      .replace(/\s/g, "");
    blocks.push(b64);
    start = endIdx + endMarker.length;
  }

  return blocks;
}

function base64ToArrayBuffer(b64) {
  // Tolerate real-world PEM quirks: URL-safe base64 (- _), backslash
  // line-continuation chars (RTF/TextEdit export), CRLF, stray non-base64
  // characters, and whitespace inside the body.
  const cleaned = (b64 || '')
    .replace(/\\/g, '')          // strip backslash continuations
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .replace(/[^A-Za-z0-9+/=]/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- ASN.1 DER parsing ---

function parseASN1(buffer, offset = 0) {
  const view = new Uint8Array(buffer);
  const tag = view[offset];
  let lengthByte = view[offset + 1];
  let length;
  let headerLength;

  if (lengthByte < 0x80) {
    length = lengthByte;
    headerLength = 2;
  } else {
    const numLengthBytes = lengthByte & 0x7f;
    length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | view[offset + 2 + i];
    }
    headerLength = 2 + numLengthBytes;
  }

  return {
    tag,
    headerLength,
    length,
    totalLength: headerLength + length,
    contentOffset: offset + headerLength,
    content: buffer.slice(offset + headerLength, offset + headerLength + length),
  };
}

function parseASN1Children(buffer) {
  const children = [];
  let offset = 0;
  const view = new Uint8Array(buffer);

  while (offset < view.length) {
    const element = parseASN1(buffer, offset);
    children.push({ ...element, contentOffset: undefined });
    offset += element.totalLength;
  }

  return children;
}

function parseASN1Time(element) {
  try {
    const timeStr = new TextDecoder().decode(element.content);
    if (element.tag === 0x17) {
      // UTCTime YYMMDDHHMMSSZ
      const year = parseInt(timeStr.slice(0, 2));
      const fullYear = year >= 50 ? 1900 + year : 2000 + year;
      return `${fullYear}-${timeStr.slice(2, 4)}-${timeStr.slice(4, 6)}T${timeStr.slice(6, 8)}:${timeStr.slice(8, 10)}:${timeStr.slice(10, 12)}Z`;
    } else if (element.tag === 0x18) {
      // GeneralizedTime YYYYMMDDHHMMSSZ
      return `${timeStr.slice(0, 4)}-${timeStr.slice(4, 6)}-${timeStr.slice(6, 8)}T${timeStr.slice(8, 10)}:${timeStr.slice(10, 12)}:${timeStr.slice(12, 14)}Z`;
    }
    return null;
  } catch (e) {
    return null;
  }
}

// --- CRL field extraction ---

function extractCRLIssuerDN(derBuffer) {
  try {
    const crl = parseASN1(derBuffer);
    const crlChildren = parseASN1Children(crl.content);
    const tbsCertList = crlChildren[0];
    const tbsFields = parseASN1Children(tbsCertList.content);
    let issuerIdx = tbsFields[0].tag === 0x02 ? 2 : 1;
    const issuerField = tbsFields[issuerIdx];
    if (issuerField && issuerField.tag === 0x30) {
      return new TextDecoder().decode(issuerField.content);
    }
    return "Unknown";
  } catch (e) {
    return "Unknown";
  }
}

function extractCRLDates(derBuffer) {
  try {
    const crl = parseASN1(derBuffer);
    const crlChildren = parseASN1Children(crl.content);
    const tbsCertList = crlChildren[0];
    const tbsFields = parseASN1Children(tbsCertList.content);
    let dateStartIdx = tbsFields[0].tag === 0x02 ? 3 : 2;
    const thisUpdate = parseASN1Time(tbsFields[dateStartIdx]);
    const nextUpdate =
      tbsFields[dateStartIdx + 1] &&
      (tbsFields[dateStartIdx + 1].tag === 0x17 ||
        tbsFields[dateStartIdx + 1].tag === 0x18)
        ? parseASN1Time(tbsFields[dateStartIdx + 1])
        : null;
    return { thisUpdate, nextUpdate };
  } catch (e) {
    return { thisUpdate: null, nextUpdate: null };
  }
}

function extractCRLRevokedSerials(derBuffer) {
  const serials = [];
  try {
    const crl = parseASN1(derBuffer);
    const crlChildren = parseASN1Children(crl.content);
    const tbsCertList = crlChildren[0];
    const tbsFields = parseASN1Children(tbsCertList.content);

    let revokedCertsField = null;
    for (let i = 0; i < tbsFields.length; i++) {
      const field = tbsFields[i];
      if (field.tag === 0x30) {
        const innerChildren = parseASN1Children(field.content);
        if (innerChildren.length > 0 && innerChildren[0].tag === 0x30) {
          const firstEntry = parseASN1Children(innerChildren[0].content);
          if (firstEntry.length > 0 && firstEntry[0].tag === 0x02) {
            revokedCertsField = field;
            break;
          }
        }
      }
    }

    if (!revokedCertsField) return serials;

    const revokedEntries = parseASN1Children(revokedCertsField.content);
    for (const entry of revokedEntries) {
      if (entry.tag === 0x30) {
        const entryFields = parseASN1Children(entry.content);
        if (entryFields.length > 0 && entryFields[0].tag === 0x02) {
          const serial = bufferToHex(entryFields[0].content).replace(/^0+/, "") || "0";
          let revocationDate = null;
          if (
            entryFields.length > 1 &&
            (entryFields[1].tag === 0x17 || entryFields[1].tag === 0x18)
          ) {
            revocationDate = parseASN1Time(entryFields[1]);
          }
          serials.push({ serial, revocationDate });
        }
      }
    }
  } catch (e) {
    // Return what we have
  }
  return serials;
}

// --- Certificate parsing (for CA bundle cross-referencing) ---

function extractDNString(nameBuffer) {
  try {
    const rdnSequences = parseASN1Children(nameBuffer);
    const parts = [];
    for (const rdnSeq of rdnSequences) {
      if (rdnSeq.tag === 0x31) {
        const rdnChildren = parseASN1Children(rdnSeq.content);
        for (const rdn of rdnChildren) {
          if (rdn.tag === 0x30) {
            const attrChildren = parseASN1Children(rdn.content);
            if (attrChildren.length >= 2) {
              const oid = bufferToHex(attrChildren[0].content);
              const value = new TextDecoder().decode(attrChildren[1].content);
              const oidMap = {
                "550403": "CN", "55040a": "O", "55040b": "OU",
                "550406": "C", "550408": "ST", "550407": "L",
              };
              const oidName = oidMap[oid] || oid;
              parts.push(oidName + "=" + value);
            }
          }
        }
      }
    }
    return parts.join(", ") || "Unknown";
  } catch (e) {
    return "Unknown";
  }
}

function extractCertSubjectDN(derBuffer) {
  try {
    const cert = parseASN1(derBuffer);
    const certChildren = parseASN1Children(cert.content);
    const tbs = certChildren[0];
    const tbsFields = parseASN1Children(tbs.content);
    const subjectIdx = tbsFields[0].tag === 0xa0 ? 5 : 4;
    const subjectField = tbsFields[subjectIdx];
    if (subjectField && subjectField.tag === 0x30) {
      return extractDNString(subjectField.content);
    }
    return "Unknown";
  } catch (e) {
    return "Unknown";
  }
}

function extractCertIssuerDN(derBuffer) {
  try {
    const cert = parseASN1(derBuffer);
    const certChildren = parseASN1Children(cert.content);
    const tbs = certChildren[0];
    const tbsFields = parseASN1Children(tbs.content);
    const issuerIdx = tbsFields[0].tag === 0xa0 ? 3 : 2;
    const issuerField = tbsFields[issuerIdx];
    if (issuerField && issuerField.tag === 0x30) {
      return extractDNString(issuerField.content);
    }
    return "Unknown";
  } catch (e) {
    return "Unknown";
  }
}

function extractCertSerial(derBuffer) {
  try {
    const cert = parseASN1(derBuffer);
    const certChildren = parseASN1Children(cert.content);
    const tbs = certChildren[0];
    const tbsFields = parseASN1Children(tbs.content);
    const serialIdx = tbsFields[0].tag === 0xa0 ? 1 : 0;
    const serialField = tbsFields[serialIdx];
    if (serialField && serialField.tag === 0x02) {
      return bufferToHex(serialField.content).replace(/^0+/, "") || "0";
    }
    return null;
  } catch (e) {
    return null;
  }
}

function extractCertValidity(derBuffer) {
  try {
    const cert = parseASN1(derBuffer);
    const certChildren = parseASN1Children(cert.content);
    const tbs = certChildren[0];
    const tbsFields = parseASN1Children(tbs.content);
    const validityIdx = tbsFields[0].tag === 0xa0 ? 4 : 3;
    const validityField = tbsFields[validityIdx];
    if (validityField && validityField.tag === 0x30) {
      const vChildren = parseASN1Children(validityField.content);
      return {
        notBefore: parseASN1Time(vChildren[0]),
        notAfter: parseASN1Time(vChildren[1]),
      };
    }
    return { notBefore: null, notAfter: null };
  } catch (e) {
    return { notBefore: null, notAfter: null };
  }
}

async function computeCertFingerprint(derBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", derBuffer);
  return bufferToHex(hashBuffer);
}

async function parseCertificates(caPem) {
  const certBlocks = splitPEMBlocks(caPem, "CERTIFICATE");
  const certs = [];
  for (const certB64 of certBlocks) {
    const certDer = base64ToArrayBuffer(certB64);
    const fingerprint = await computeCertFingerprint(certDer);
    const serial = extractCertSerial(certDer);
    const subjectDN = extractCertSubjectDN(certDer);
    const issuerDN = extractCertIssuerDN(certDer);
    const { notBefore, notAfter } = extractCertValidity(certDer);
    certs.push({
      fingerprint,
      serial,
      subjectDN,
      issuerDN,
      notBefore,
      notAfter,
    });
  }
  return certs;
}

// --- Core CRL processing ---
// Writes revoked serials to REVOKED_CERTS (hot path), metadata to CRL_DATA.
// Replace strategy: clears previous serial:* entries before writing new ones.

async function processCRLData(crlPem, env, source, sourceUrl = null) {
  const startTime = Date.now();
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const CRL_DATA = env.CRL_DATA;

  const crlBlocks = splitPEMBlocks(crlPem, "X509 CRL");
  if (crlBlocks.length === 0) {
    throw new Error("No X509 CRL blocks found in data");
  }

  let totalSerialsFound = 0;
  let totalSerialsWritten = 0;
  let previousEntriesCleared = 0;
  const crlInfoList = [];
  const allRevokedSerials = [];

  for (const crlB64 of crlBlocks) {
    const crlDer = base64ToArrayBuffer(crlB64);
    const issuerDN = extractCRLIssuerDN(crlDer);
    const { thisUpdate, nextUpdate } = extractCRLDates(crlDer);

    // Clear existing serial entries (replace strategy)
    const existingList = await REVOKED_CERTS.list({ prefix: "serial:" });
    for (const key of existingList.keys) {
      await REVOKED_CERTS.delete(key.name);
      previousEntriesCleared++;
    }

    // Extract and store revoked serials
    const revokedSerials = extractCRLRevokedSerials(crlDer);
    totalSerialsFound += revokedSerials.length;

    for (const { serial, revocationDate } of revokedSerials) {
      allRevokedSerials.push(serial);
      const normalizedSerial = normalizeSerial(serial);
      await REVOKED_CERTS.put(
        `serial:${normalizedSerial}`,
        JSON.stringify({
          reason: "CRL import",
          revokedAt: revocationDate || new Date().toISOString(),
          issuerDN,
          source,
          sourceUrl,
          importedAt: new Date().toISOString(),
        })
      );
      totalSerialsWritten++;
    }

    crlInfoList.push({
      issuerDN,
      thisUpdate,
      nextUpdate,
      serialsFound: revokedSerials.length,
    });
  }

  // Update CRL_DATA metadata
  await CRL_DATA.put(
    "crl:metadata",
    JSON.stringify({
      lastSync: new Date().toISOString(),
      source,
      sourceUrl,
      serialEntryCount: totalSerialsWritten,
      crlInfo: crlInfoList,
    })
  );
  await CRL_DATA.put("crl:serials", JSON.stringify(allRevokedSerials));
  await CRL_DATA.put("crl:last_fetch", new Date().toISOString());

  return {
    summary: {
      serials_found: totalSerialsFound,
      serials_written: totalSerialsWritten,
      previous_entries_cleared: previousEntriesCleared,
    },
    crl_info: crlInfoList,
    processing_time_ms: Date.now() - startTime,
  };
}

// --- Unified import dispatcher ---
// Auto-detects whether a PEM payload contains CA certificates, a CRL, or both.
// Single payload with both -> cross-references revoked serials against cert
// serials and blocks by exact fingerprint.


// --- Streaming PEM block splitter ---
// Reads a ReadableStream and invokes handler(type, base64Body) for each complete
// PEM block as it arrives. Only a partial trailing block is retained in memory,
// so total payload size is unbounded (each block is processed and discarded).

async function forEachPEMBlock(stream, handler) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let pending = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });

    while (true) {
      const beginMatch = pending.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
      if (!beginMatch) {
        pending = pending.slice(-64); // keep tail in case a marker straddles chunks
        break;
      }
      const beginIdx = pending.indexOf(beginMatch[0]);
      const type = beginMatch[1];
      const endMarker = `-----END ${type}-----`;
      const endIdx = pending.indexOf(endMarker, beginIdx + beginMatch[0].length);
      if (endIdx === -1) {
        pending = pending.slice(beginIdx); // incomplete block — keep from BEGIN
        break;
      }
      const body = pending.slice(beginIdx + beginMatch[0].length, endIdx);
      await handler(type, body);
      pending = pending.slice(endIdx + endMarker.length);
    }
  }
  decoder.decode(); // flush trailing bytes
}

// --- Streaming import (bounded memory) ---
// Processes a streamed PEM bundle: collects certificates, writes revoked
// serials to KV as CRL blocks arrive, then cross-references fingerprints
// order-independently. Skips oversized metadata values to respect KV limits.

async function processStreamedImport(stream, env, source) {
  const startTime = Date.now();
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const CRL_DATA = env.CRL_DATA;
  const CROSS_REF_MAX = 100000; // cap on in-memory serial list for cross-ref

  const shardSets = new Map(); // shardIndex -> Set<normalized serial>

  const certs = [];
  const certsBySerial = new Map();
  const crlInfoList = [];
  const allRevokedSerials = [];
  const revokedCertificates = [];
  let totalSerialsFound = 0;
  let totalSerialsWritten = 0;
  let fingerprintMatches = 0;
  let previousSerialsCleared = 0;
  let previousFingerprintsCleared = 0;
  let crossRefComplete = true;

  // Clear strategy: wipe previous CRL-derived entries once, before streaming
  for (const prefix of ["serial:", "serialset:"]) {
    const existingSerials = await REVOKED_CERTS.list({ prefix });
    for (const key of existingSerials.keys) {
      await REVOKED_CERTS.delete(key.name);
      previousSerialsCleared++;
    }
  }
  const existingFp = await REVOKED_CERTS.list({ prefix: "fingerprint:" });
  for (const key of existingFp.keys) {
    const val = await REVOKED_CERTS.get(key.name, "json");
    if (!val || val.source !== "manual") {
      await REVOKED_CERTS.delete(key.name);
      previousFingerprintsCleared++;
    }
  }

  await forEachPEMBlock(stream, async (type, body) => {
    if (type === "CERTIFICATE") {
      const certDer = base64ToArrayBuffer(body);
      const cert = {
        fingerprint: await computeCertFingerprint(certDer),
        serial: extractCertSerial(certDer),
        subjectDN: extractCertSubjectDN(certDer),
        issuerDN: extractCertIssuerDN(certDer),
      };
      certs.push(cert);
      if (cert.serial) certsBySerial.set(normalizeSerial(cert.serial), cert);
    } else if (type === "X509 CRL") {
      const crlDer = base64ToArrayBuffer(body);
      const issuerDN = extractCRLIssuerDN(crlDer);
      const { thisUpdate, nextUpdate } = extractCRLDates(crlDer);
      const serials = extractCRLRevokedSerials(crlDer);
      totalSerialsFound += serials.length;
      for (const s of serials) {
        const normalized = normalizeSerial(s.serial);
        if (allRevokedSerials.length < CROSS_REF_MAX) {
          allRevokedSerials.push(normalized);
        } else {
          crossRefComplete = false;
        }
        const idx = serialShardIndex(normalized);
        if (!shardSets.has(idx)) shardSets.set(idx, new Set());
        shardSets.get(idx).add(normalized);
        totalSerialsWritten++;
      }
      crlInfoList.push({ issuerDN, thisUpdate, nextUpdate, serialsFound: serials.length });
    }
  });

  // Write the revocation set as shards: few parallel KV writes, no per-serial latency
  await Promise.all([...shardSets].map(([idx, set]) =>
    REVOKED_CERTS.put(`serialset:${idx}`, [...set].join("\n"))
  ));

  // Order-independent cross-reference: revoked serial -> cert fingerprint
  const revokedSet = new Set(allRevokedSerials);
  for (const cert of certs) {
    const normalizedSerial = normalizeSerial(cert.serial);
    if (revokedSet.has(normalizedSerial)) {
      await REVOKED_CERTS.put(`fingerprint:${cert.fingerprint}`, JSON.stringify({
        reason: "CRL import (serial cross-reference)",
        revokedAt: new Date().toISOString(),
        serial: normalizedSerial,
        subjectDN: cert.subjectDN,
        issuerDN: cert.issuerDN,
        source,
        importedAt: new Date().toISOString(),
      }));
      fingerprintMatches++;
      revokedCertificates.push({
        fingerprint: cert.fingerprint,
        serial: normalizedSerial,
        subjectDN: cert.subjectDN,
        issuerDN: cert.issuerDN,
      });
    }
  }

  // Metadata (skip oversized lists to respect KV 25MB value limit)
  const serialsJson = JSON.stringify(allRevokedSerials);
  if (serialsJson.length <= 20 * 1024 * 1024) {
    await CRL_DATA.put("crl:serials", serialsJson);
  }
  await CRL_DATA.put("crl:metadata", JSON.stringify({
    lastSync: new Date().toISOString(),
    source,
    certs_parsed: certs.length,
    revoked_serials: allRevokedSerials.length,
    serials_written: totalSerialsWritten,
    fingerprint_matches: fingerprintMatches,
    cross_reference_complete: crossRefComplete,
    crlInfo: crlInfoList,
  }));
  await CRL_DATA.put("crl:last_fetch", new Date().toISOString());

  return {
    summary: {
      certs_parsed: certs.length,
      revoked_serials_found: totalSerialsFound,
      serials_written: totalSerialsWritten,
      fingerprint_matches: fingerprintMatches,
      previous_serials_cleared: previousSerialsCleared,
      previous_fingerprints_cleared: previousFingerprintsCleared,
    },
    revoked_certificates: revokedCertificates,
    crl_info: crlInfoList,
    processing_time_ms: Date.now() - startTime,
  };
}


async function importPEMData(pemData, env, source, sourceUrl = null) {
  const certBlocks = splitPEMBlocks(pemData, "CERTIFICATE");
  const crlBlocks = splitPEMBlocks(pemData, "X509 CRL");

  if (crlBlocks.length > 0 && certBlocks.length > 0) {
    // Combined: cross-reference serials -> exact fingerprints
    return await processCombinedData(pemData, pemData, env, source, sourceUrl);
  }
  if (crlBlocks.length > 0) {
    return await processCRLData(pemData, env, source, sourceUrl);
  }
  if (certBlocks.length > 0) {
    // Certs only: no CRL to cross-reference, just parse + store
    return await processCombinedData(pemData, null, env, source, sourceUrl);
  }
  throw new Error("No CERTIFICATE or X509 CRL blocks found in data");
}

// --- Combined CA + CRL processing ---
// Parses CA cert bundle + CRL on one upload. Cross-references revoked serials
// against certificate serials, stores the EXACT revoked cert fingerprints in
// REVOKED_CERTS (fingerprint:<hash>) so the validator blocks by fingerprint.

async function processCombinedData(caPem, crlPem, env, source, sourceUrl = null) {
  const startTime = Date.now();
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const CRL_DATA = env.CRL_DATA;

  // 1. Parse CA bundle (if present)
  const certs = caPem ? await parseCertificates(caPem) : [];
  const certsBySerial = new Map();
  for (const cert of certs) {
    certsBySerial.set(normalizeSerial(cert.serial), cert);
  }

  // 2. Parse CRL (if present) -> revoked serials
  const revokedSerials = [];
  const crlInfoList = [];
  if (crlPem) {
    const crlBlocks = splitPEMBlocks(crlPem, "X509 CRL");
    for (const crlB64 of crlBlocks) {
      const crlDer = base64ToArrayBuffer(crlB64);
      const issuerDN = extractCRLIssuerDN(crlDer);
      const { thisUpdate, nextUpdate } = extractCRLDates(crlDer);
      const serials = extractCRLRevokedSerials(crlDer);
      for (const s of serials) {
        revokedSerials.push(normalizeSerial(s.serial));
      }
      crlInfoList.push({ issuerDN, thisUpdate, nextUpdate, serialsFound: serials.length });
    }
  }

  // 3. Clear previous CRL-derived fingerprint entries (keep manual ones)
  const existingFp = await REVOKED_CERTS.list({ prefix: "fingerprint:" });
  let previousFingerprintsCleared = 0;
  for (const key of existingFp.keys) {
    const val = await REVOKED_CERTS.get(key.name, "json");
    if (!val || val.source !== "manual") {
      await REVOKED_CERTS.delete(key.name);
      previousFingerprintsCleared++;
    }
  }

  // 4. Clear previous serial entries (replace strategy)
  const existingSerials = await REVOKED_CERTS.list({ prefix: "serial:" });
  let previousSerialsCleared = 0;
  for (const key of existingSerials.keys) {
    await REVOKED_CERTS.delete(key.name);
    previousSerialsCleared++;
  }

  // 5. Cross-reference: revoked serial -> exact certificate fingerprint
  const revokedSerialSet = new Set(revokedSerials);
  const revokedCertificates = [];
  let fingerprintMatches = 0;

  for (const cert of certs) {
    const normalizedSerial = normalizeSerial(cert.serial);
    if (revokedSerialSet.has(normalizedSerial)) {
      await REVOKED_CERTS.put(`fingerprint:${cert.fingerprint}`, JSON.stringify({
        reason: "CRL import (serial cross-reference)",
        revokedAt: new Date().toISOString(),
        serial: normalizedSerial,
        subjectDN: cert.subjectDN,
        issuerDN: cert.issuerDN,
        source,
        sourceUrl,
        importedAt: new Date().toISOString(),
      }));
      fingerprintMatches++;
      revokedCertificates.push({
        fingerprint: cert.fingerprint,
        serial: normalizedSerial,
        subjectDN: cert.subjectDN,
        issuerDN: cert.issuerDN,
      });
    }
  }

  // 6. Store serial entries from CRL (for serial-based checks too)
  let serialsWritten = 0;
  for (const serial of revokedSerials) {
    await REVOKED_CERTS.put(`serial:${serial}`, JSON.stringify({
      reason: "CRL import",
      revokedAt: new Date().toISOString(),
      source,
      sourceUrl,
      importedAt: new Date().toISOString(),
    }));
    serialsWritten++;
  }

  // 7. Metadata
  await CRL_DATA.put("crl:metadata", JSON.stringify({
    lastSync: new Date().toISOString(),
    source,
    sourceUrl,
    certs_parsed: certs.length,
    revoked_serials: revokedSerials.length,
    fingerprint_matches: fingerprintMatches,
    crlInfo: crlInfoList,
  }));
  await CRL_DATA.put("crl:serials", JSON.stringify(revokedSerials));
  await CRL_DATA.put("crl:last_fetch", new Date().toISOString());

  return {
    summary: {
      certs_parsed: certs.length,
      revoked_serials_found: revokedSerials.length,
      serials_written: serialsWritten,
      fingerprint_matches: fingerprintMatches,
      previous_serials_cleared: previousSerialsCleared,
      previous_fingerprints_cleared: previousFingerprintsCleared,
    },
    revoked_certificates: revokedCertificates,
    crl_info: crlInfoList,
    processing_time_ms: Date.now() - startTime,
  };
}

// ============================================================
// DURABLE OBJECT: CRLProcessor
// ============================================================
// Assembles chunked CRL uploads for files larger than the request
// body limit. Chunks stored in DO storage, assembled on finalize.
// ============================================================

export class CRLProcessor {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");

    try {
      switch (action) {
        case "upload_chunk":
          return await this.handleChunk(request);
        case "finalize":
          return await this.handleFinalize(request);
        case "status":
          return await this.handleStatus();
        case "clear":
          return await this.handleClear();
        default:
          return errorResponse("Unknown action");
      }
    } catch (e) {
      return errorResponse(e.message, 500);
    }
  }

  async handleChunk(request) {
    const body = await request.json();
    const { session_id, chunk_index, total_chunks, data } = body;

    if (!session_id || chunk_index === undefined || !data) {
      return errorResponse("session_id, chunk_index, and data are required");
    }

    // Store chunk in DO storage (strongly consistent)
    await this.state.storage.put(`chunk:${session_id}:${chunk_index}`, data);

    // Update metadata
    let meta = await this.state.storage.get(`meta:${session_id}`);
    if (!meta) {
      meta = {
        total_chunks,
        received: [],
        created_at: new Date().toISOString(),
      };
    }
    if (!meta.received.includes(chunk_index)) {
      meta.received.push(chunk_index);
    }
    await this.state.storage.put(`meta:${session_id}`, {
      total_chunks: meta.total_chunks,
      received: meta.received,
      created_at: meta.created_at,
    });

    return jsonResponse({
      success: true,
      status: "chunk_received",
      chunk_index,
      received_count: meta.received.length,
      total_chunks,
    });
  }

  async handleFinalize(request) {
    const body = await request.json();
    const { session_id } = body;

    if (!session_id) {
      return errorResponse("session_id is required");
    }

    const meta = await this.state.storage.get(`meta:${session_id}`);
    if (!meta) {
      return errorResponse("Session not found");
    }

    // Collect all chunks
    const chunks = [];
    for (let i = 0; i < meta.total_chunks; i++) {
      const chunk = await this.state.storage.get(`chunk:${session_id}:${i}`);
      if (!chunk) {
        return errorResponse(`Missing chunk ${i}`);
      }
      chunks.push(chunk);
    }

    // Reassemble (chunks are base64 fragments of the original file)
    const fullBase64 = chunks.join("");
    let pemData;
    try {
      pemData = atob(fullBase64);
    } catch (e) {
      return errorResponse("Failed to decode base64 data");
    }

    // Process (auto-detects CA certs, CRL, or combined bundle)
    const result = await importPEMData(pemData, this.env, "chunked_upload");

    // Clean up chunks
    for (let i = 0; i < meta.total_chunks; i++) {
      await this.state.storage.delete(`chunk:${session_id}:${i}`);
    }
    await this.state.storage.delete(`meta:${session_id}`);

    return jsonResponse({
      success: true,
      status: "complete",
      ...result,
    });
  }

  async handleStatus() {
    const sessions = [];
    const allKeys = await this.state.storage.list({ prefix: "meta:" });

    for (const [key, value] of allKeys) {
      sessions.push({
        session_id: key.replace("meta:", ""),
        ...value,
      });
    }

    return jsonResponse({
      success: true,
      active_sessions: sessions,
    });
  }

  async handleClear() {
    await this.state.storage.deleteAll();
    return jsonResponse({
      success: true,
      message: "All sessions cleared",
    });
  }
}

// ============================================================
// CRL Importer handler
// ============================================================

async function handleCRLImport(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ADMIN_SECRET = env.ADMIN_SECRET || "dev-secret-12345";
  const FILE_ORIGIN_URL = env.FILE_ORIGIN_URL || "http://localhost:8788";

  const authenticate = () => {
    const providedSecret = request.headers.get("X-Admin-Secret");
    if (!providedSecret || providedSecret !== ADMIN_SECRET) {
      throw new Error("Unauthorized");
    }
  };

  try {
    // POST /crl/import/fetch — fetch CRL + CA list from file-origin / R2 and import.
    // R2 holds BOTH files: CRL (default key "crl.pem") and CA cert list (key "ca.pem").
    // Query params:
    //   ?file=<name>    — CRL key (default "crl.pem")
    //   ?ca_file=<name> — CA certificate list key (optional; fetched and combined for cross-reference)
    //   ?all=<prefix>   — fetch every object under a prefix and combine (e.g. all=crl/)
    if (path === "/crl/import/fetch" && request.method === "POST") {
      authenticate();

      const filename = url.searchParams.get("file") || "crl.pem";
      const caFilename = url.searchParams.get("ca_file");
      const allPrefix = url.searchParams.get("all");

      // Shared fetch helper: R2-first, falls back to file-origin HTTP
      const fetchObject = async (key) => {
        if (env.CRL_BUCKET) {
          const r2Object = await env.CRL_BUCKET.get(key);
          if (!r2Object) {
            throw new Error(`File not found in R2 bucket: ${key}`);
          }
          return { data: await r2Object.text(), source: "R2", sourceUrl: `r2://${key}` };
        }
        const fetchUrl = `${FILE_ORIGIN_URL}/file/${key}`;
        const response = await fetch(fetchUrl);
        if (!response.ok) {
          throw new Error(
            `Failed to fetch from file-origin: ${response.status} ${response.statusText}`
          );
        }
        return { data: await response.text(), source: FILE_ORIGIN_URL, sourceUrl: fetchUrl };
      };

      let pemParts = [];
      let sourceLabel;
      let sourceUrls = [];

      try {
        if (allPrefix) {
          // Fetch every object under a prefix (e.g. all CRL + CA files in one shot)
          if (env.CRL_BUCKET) {
            const listed = await env.CRL_BUCKET.list({ prefix: allPrefix });
            for (const obj of listed.objects) {
              const { data, sourceUrl } = await fetchObject(obj.key);
              pemParts.push(data);
              sourceUrls.push(sourceUrl);
            }
            sourceLabel = "R2";
          } else {
            return errorResponse("all= prefix fetch requires the R2 binding (CRL_BUCKET)");
          }
        } else {
          // CRL (required) + CA list (optional)
          const crl = await fetchObject(filename);
          pemParts.push(crl.data);
          sourceUrls.push(crl.sourceUrl);
          sourceLabel = crl.source;

          if (caFilename) {
            const ca = await fetchObject(caFilename);
            pemParts.push(ca.data);
            sourceUrls.push(ca.sourceUrl);
          }
        }
      } catch (e) {
        return errorResponse(e.message, 404);
      }

      const pemData = pemParts.join("\n");
      const result = await importPEMData(
        pemData,
        env,
        sourceLabel,
        sourceUrls.join(", ")
      );

      return jsonResponse({ success: true, message: "Data imported successfully", ...result });
    }

    // POST /crl/import/upload — direct PEM upload (CA certs, CRL, or both; <100MB request body limit)
    // Auto-detects payload: CRL only, certs only, or combined CA bundle + CRL.
    // Combined payload -> cross-references revoked serials against cert serials
    // and blocks by EXACT fingerprint.
    if (path === "/crl/import/upload" && request.method === "POST") {
      authenticate();

      let pemData;
      const contentType = request.headers.get("content-type") || "";

      if (contentType.includes("application/json")) {
        const body = await request.json();
        // Accept: ca_pem + crl_pem (two fields), or a single combined pem
        if (body.ca_pem && body.crl_pem) {
          pemData = body.ca_pem + "\n" + body.crl_pem;
        } else {
          pemData = body.crl_pem || body.ca_pem || body.pem;
        }
        if (!pemData) {
          return errorResponse("crl_pem, ca_pem, or pem required in JSON body");
        }
      } else {
        // Raw PEM body (curl --data-binary @bundle.pem) — may contain both certs and CRL.
        // Streamed: parsed block-by-block so large bundles don't exhaust memory.
        const result = await processStreamedImport(request.body, env, "direct_upload");
        const message = result.summary.fingerprint_matches > 0
          ? `Uploaded and imported: ${result.summary.fingerprint_matches} revoked cert(s) matched by fingerprint`
          : "Uploaded and imported";
        return jsonResponse({ success: true, message, ...result });
      }

      const message = result.summary.fingerprint_matches > 0
        ? `Uploaded and imported: ${result.summary.fingerprint_matches} revoked cert(s) matched by fingerprint`
        : "Uploaded and imported";
      return jsonResponse({ success: true, message, ...result });
    }

    // POST /crl/import/chunk — chunked upload via Durable Object (large files)
    if (path === "/crl/import/chunk" && request.method === "POST") {
      authenticate();

      const body = await request.json();
      const { session_id } = body;
      if (!session_id) {
        return errorResponse("session_id required");
      }

      const id = env.CRL_PROCESSOR.idFromName(session_id);
      const stub = env.CRL_PROCESSOR.get(id);
      return await stub.fetch(`${url.origin}/crl/import/chunk?action=upload_chunk`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    }

    // POST /crl/import/finalize — finalize chunked assembly and process
    if (path === "/crl/import/finalize" && request.method === "POST") {
      authenticate();

      const body = await request.json();
      const { session_id } = body;
      if (!session_id) {
        return errorResponse("session_id required");
      }

      const id = env.CRL_PROCESSOR.idFromName(session_id);
      const stub = env.CRL_PROCESSOR.get(id);
      return await stub.fetch(`${url.origin}/crl/import/finalize?action=finalize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
    }

    // GET /crl/import/chunks/status — active DO upload sessions
    if (path === "/crl/import/chunks/status" && request.method === "GET") {
      authenticate();

      const id = env.CRL_PROCESSOR.idFromName("session-status");
      const stub = env.CRL_PROCESSOR.get(id);
      return await stub.fetch(`${url.origin}/crl/import/chunks/status?action=status`);
    }

    // GET /crl/import/status — import metadata + sync status
    if (path === "/crl/import/status" && request.method === "GET") {
      authenticate();

      const metadata = await env.CRL_DATA.get("crl:metadata", "json");
      const lastFetch = await env.CRL_DATA.get("crl:last_fetch");
      const serials = await env.CRL_DATA.get("crl:serials", "json");

      return jsonResponse({
        success: true,
        metadata: metadata || null,
        last_fetch: lastFetch || null,
        serial_count: serials ? serials.length : 0,
      });
    }

    // POST /crl/import/manual — manually revoke a serial OR fingerprint
    if (path === "/crl/import/manual" && request.method === "POST") {
      authenticate();

      const body = await request.json();
      const serial = body.serial;
      const fingerprint = body.fingerprint;
      const reason = body.reason || "manual_revocation";

      if (!serial && !fingerprint) {
        return errorResponse("serial or fingerprint required");
      }

      if (serial) {
        const normalized = normalizeSerial(serial);
        await env.REVOKED_CERTS.put(`serial:${normalized}`, JSON.stringify({
          revoked: true,
          added_at: new Date().toISOString(),
          source: "manual",
          reason,
        }));
        return jsonResponse({
          success: true,
          message: "Serial revoked manually",
          serial: normalized,
        });
      }

      if (fingerprint) {
        const normalized = normalizeFingerprint(fingerprint);
        await env.REVOKED_CERTS.put(`fingerprint:${normalized}`, JSON.stringify({
          revoked: true,
          added_at: new Date().toISOString(),
          source: "manual",
          reason,
        }));
        return jsonResponse({
          success: true,
          message: "Fingerprint revoked manually",
          fingerprint: normalized,
        });
      }
    }

    return errorResponse("CRL Import endpoint not found", 404);
  } catch (e) {
    if (e.message === "Unauthorized") {
      return errorResponse("Unauthorized: invalid or missing X-Admin-Secret", 401);
    }
    return errorResponse(`Import handler error: ${e.message}`, 500);
  }
}

// ============================================================
// mTLS Validator
// ============================================================

async function validateMTLS(request, REVOKED_CERTS) {
  const certPem = request.headers.get("cf-client-cert-pem");
  const certSerial = request.headers.get("cf-client-cert-serial");
  const certFingerprint = request.headers.get("cf-client-cert-fingerprint");
  const certIssuer = request.headers.get("cf-client-cert-issuer");
  const certSubject = request.headers.get("cf-client-cert-subject");

  if (!certPem && !certSerial) {
    throw new Error("No client certificate presented");
  }

  const certInfo = { serial: certSerial, fingerprint: certFingerprint, issuer: certIssuer, subject: certSubject };

  if (certSerial) {
    const normalized = normalizeSerial(certSerial);
    // manual single-key revocation first, then the sharded CRL-import set
    let revoked = await REVOKED_CERTS.get(`serial:${normalized}`);
    if (!revoked) {
      const shard = await REVOKED_CERTS.get(`serialset:${serialShardIndex(normalized)}`);
      if (shard && shard.split("\n").includes(normalized)) revoked = true;
    }
    if (revoked) {
      throw new Error(`Certificate revoked (serial: ${normalized})`);
    }
  }

  if (certFingerprint) {
    const normalized = normalizeFingerprint(certFingerprint);
    // New format: fingerprint:<hash> (from combined CA+CRL cross-reference)
    let revoked = await REVOKED_CERTS.get(`fingerprint:${normalized}`);
    // Legacy format: fp:<hash> (from earlier manual revocations)
    if (!revoked) {
      revoked = await REVOKED_CERTS.get(`fp:${normalized}`);
    }
    if (revoked) {
      throw new Error(`Certificate revoked (fingerprint: ${normalized})`);
    }
  }

  return certInfo;
}

async function handleMTLSValidator(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const ADMIN_SECRET = env.ADMIN_SECRET || "dev-secret-12345";

  // GET /health
  if (path === "/health") {
    return jsonResponse({
      success: true,
      service: "crl-checker",
      timestamp: new Date().toISOString(),
      kv_configured: !!REVOKED_CERTS,
      do_configured: !!env.CRL_PROCESSOR,
    });
  }

  // GET /debug/cert
  if (path === "/debug/cert") {
    return jsonResponse({
      success: true,
      certificate: {
        serial: request.headers.get("cf-client-cert-serial"),
        fingerprint: request.headers.get("cf-client-cert-fingerprint"),
        issuer: request.headers.get("cf-client-cert-issuer"),
        subject: request.headers.get("cf-client-cert-subject"),
        not_before: request.headers.get("cf-client-cert-not-before"),
        not_after: request.headers.get("cf-client-cert-not-after"),
      },
    });
  }

  // GET /debug/kv (admin)
  if (path === "/debug/kv") {
    const providedSecret = request.headers.get("X-Admin-Secret");
    if (!providedSecret || providedSecret !== ADMIN_SECRET) {
      return errorResponse("Unauthorized: invalid or missing X-Admin-Secret", 401);
    }

    const metadata = await env.CRL_DATA.get("crl:metadata", "json");
    const serials = await env.CRL_DATA.get("crl:serials", "json");
    const lastFetch = await env.CRL_DATA.get("crl:last_fetch");

    return jsonResponse({
      success: true,
      crl_data: {
        metadata,
        serial_count: serials ? serials.length : 0,
        last_fetch: lastFetch,
      },
    });
  }

  // GET /mtls/check
  if (path === "/mtls/check") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({ success: true, message: "Certificate is valid and not revoked", certificate: certInfo });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  // GET /mtls/allow
  if (path === "/mtls/allow") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({ success: true, message: "Request allowed: Certificate is valid", certificate: certInfo });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  // GET / (requires valid mTLS cert)
  if (path === "/" || path === "") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({ success: true, message: "mTLS authentication successful", certificate: certInfo });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  return errorResponse("Endpoint not found", 404);
}

// ============================================================
// Test endpoints
// ============================================================

async function handleTest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // GET /test/ping
  if (path === "/test/ping") {
    return jsonResponse({ success: true, message: "pong", timestamp: new Date().toISOString() });
  }

  // GET /test/file-origin
  if (path === "/test/file-origin") {
    try {
      const originUrl = env.FILE_ORIGIN_URL || "http://localhost:8788";
      const response = await fetch(`${originUrl}/health`);
      if (response.ok) {
        const data = await response.json();
        return jsonResponse({ success: true, message: "File origin is reachable", origin_url: originUrl, origin_health: data });
      }
      return errorResponse(`File origin returned ${response.status}`, response.status);
    } catch (e) {
      return errorResponse(`Failed to reach file origin: ${e.message}`, 500);
    }
  }

  // GET /test/endpoints
  if (path === "/test/endpoints") {
    return jsonResponse({
      success: true,
      endpoints: {
        crl_import: [
          "POST /crl/import/fetch?file=<name>  — Fetch PEM bundle (CA certs / CRL / both) from file-origin or R2 (admin)",
          "POST /crl/import/upload             — Direct PEM upload: CA certs, CRL, or combined bundle (admin)",
          "POST /crl/import/chunk              — Chunked upload via DO, large files (admin)",
          "POST /crl/import/finalize           — Finalize chunked assembly (admin)",
          "GET  /crl/import/chunks/status      — Active DO upload sessions (admin)",
          "GET  /crl/import/status             — Import metadata (admin)",
          "POST /crl/import/manual             — Manually revoke a serial or fingerprint (admin)",
        ],
        mtls_validator: [
          "GET  /health           — Service health check",
          "GET  /debug/cert       — Show presented certificate fields",
          "GET  /debug/kv         — Show KV contents (admin only)",
          "GET  /mtls/check       — Validate current mTLS cert",
          "GET  /mtls/allow       — Confirm allowed certificate",
          "GET  /                 — Default endpoint (requires mTLS)",
        ],
        test: [
          "GET  /test/ping        — Simple connectivity test",
          "GET  /test/file-origin — Verify file-origin is reachable",
          "GET  /test/endpoints   — List all endpoints",
        ],
      },
    });
  }

  return errorResponse("Test endpoint not found", 404);
}

// ============================================================
// Main router
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path.startsWith("/crl/import")) {
        return await handleCRLImport(request, env);
      }
      if (path.startsWith("/test")) {
        return await handleTest(request, env);
      }
      return await handleMTLSValidator(request, env);
    } catch (e) {
      return errorResponse(`Unhandled error: ${e.message}`, 500);
    }
  },

  async scheduled(event, env, ctx) {
    // Scheduled CRL sync: fetch from file-origin and import
    const url = `${(env.FILE_ORIGIN_URL || "http://localhost:8788").replace(/\/$/, "")}/file/crl.pem`;
    try {
      const response = await fetch(url);
      if (response.ok) {
        const pemData = await response.text();
        const result = await importPEMData(pemData, env, "scheduled_sync", url);
        console.log("Scheduled CRL sync OK:", JSON.stringify(result.summary));
      } else {
        console.error(`Scheduled CRL sync failed: HTTP ${response.status}`);
      }
    } catch (e) {
      console.error("Scheduled CRL sync error:", e.message);
    }
  },
};
