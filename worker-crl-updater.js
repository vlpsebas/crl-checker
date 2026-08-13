// ============================================================
// CRL Updater Worker (with Durable Objects)
// ============================================================
//
// Separate worker for managing CRL and CA certificate uploads.
// Handles large CRL files via chunked uploads using Durable Objects.
// Updates REVOKED_CERTS KV with serial numbers (serial: prefix).
//
// This worker runs independently from the mTLS validator,
// so CRL updates do not add latency to client requests.
//
// ENDPOINTS:
//   POST   /admin/ca/upload    - Upload CA certificate(s) PEM
//   GET    /admin/ca/list      - List uploaded CA certificates
//   DELETE /admin/ca           - Delete a CA certificate
//
//   POST   /admin/crl/upload   - Direct CRL PEM upload (< 100MB)
//   POST   /admin/crl/chunk    - Chunked upload for large files (uses DO)
//   POST   /admin/crl/fetch    - Fetch CRL from origin URL
//   GET    /admin/crl/status   - View sync metadata and counts
//   POST   /admin/crl/clear    - Clear all serial-based entries
//
// KV BINDINGS REQUIRED:
//   REVOKED_CERTS  - Shared with validator worker (stores serial: entries)
//   CA_STORE       - Stores CA certificates
//
// DURABLE OBJECT BINDING:
//   CRL_PROCESSOR  - Durable Object for chunked upload assembly
//
// SECRETS REQUIRED:
//   ADMIN_SECRET   - Admin authentication header value
//
// All endpoints require: X-Admin-Secret: <ADMIN_SECRET>
//
// WRANGLER.TOML CONFIGURATION:
// ```toml
// name = "crl-updater"
// main = "worker-crl-updater.js"
// compatibility_date = "2024-01-01"
//
// [durable_objects]
// bindings = [
//   { name = "CRL_PROCESSOR", class_name = "CRLProcessor" }
// ]
//
// [[migrations]]
// tag = "v1"
// new_classes = ["CRLProcessor"]
//
// [[kv_namespaces]]
// binding = "REVOKED_CERTS"
// id = "<your-kv-id>"
//
// [[kv_namespaces]]
// binding = "CA_STORE"
// id = "<your-ca-store-kv-id>"
// ```
// ============================================================

// --- Utility Functions ---

const jsonResponse = (data, status = 200) => {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
};

const errorResponse = (message, status = 400) => {
  return jsonResponse({ success: false, error: message }, status);
};

// Normalize serial: lowercase, remove leading zeros, no colons/spaces
const normalizeSerial = (serial) => {
  return serial.toLowerCase().replace(/^0+/, "").replace(/[:\s]/g, "") || "0";
};

// --- PEM Parsing Utilities ---

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
  const binary = atob(b64);
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

// --- ASN.1 DER Parsing ---

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
    children.push({
      ...element,
      absoluteOffset: offset,
    });
    offset += element.totalLength;
  }

  return children;
}

// --- Certificate Parsing ---

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
                "550403": "CN",
                "55040a": "O",
                "55040b": "OU",
                "550406": "C",
                "550408": "ST",
                "550407": "L",
              };
              const oidName = oidMap[oid] || oid;
              parts.push(`${oidName}=${value}`);
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
    let subjectIdx = tbsFields[0].tag === 0xa0 ? 5 : 4;
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
    let issuerIdx = tbsFields[0].tag === 0xa0 ? 3 : 2;
    const issuerField = tbsFields[issuerIdx];
    if (issuerField && issuerField.tag === 0x30) {
      return extractDNString(issuerField.content);
    }
    return "Unknown";
  } catch (e) {
    return "Unknown";
  }
}

function extractCertValidity(derBuffer) {
  try {
    const cert = parseASN1(derBuffer);
    const certChildren = parseASN1Children(cert.content);
    const tbs = certChildren[0];
    const tbsFields = parseASN1Children(tbs.content);
    let validityIdx = tbsFields[0].tag === 0xa0 ? 4 : 3;
    const validityField = tbsFields[validityIdx];
    if (validityField && validityField.tag === 0x30) {
      const validityChildren = parseASN1Children(validityField.content);
      const notBefore = parseASN1Time(validityChildren[0]);
      const notAfter = parseASN1Time(validityChildren[1]);
      return { notBefore, notAfter };
    }
    return { notBefore: null, notAfter: null };
  } catch (e) {
    return { notBefore: null, notAfter: null };
  }
}

function parseASN1Time(element) {
  try {
    const timeStr = new TextDecoder().decode(element.content);
    if (element.tag === 0x17) {
      const year = parseInt(timeStr.slice(0, 2));
      const fullYear = year >= 50 ? 1900 + year : 2000 + year;
      return `${fullYear}-${timeStr.slice(2, 4)}-${timeStr.slice(4, 6)}T${timeStr.slice(6, 8)}:${timeStr.slice(8, 10)}:${timeStr.slice(10, 12)}Z`;
    } else if (element.tag === 0x18) {
      return `${timeStr.slice(0, 4)}-${timeStr.slice(4, 6)}-${timeStr.slice(6, 8)}T${timeStr.slice(8, 10)}:${timeStr.slice(10, 12)}:${timeStr.slice(12, 14)}Z`;
    }
    return null;
  } catch (e) {
    return null;
  }
}

async function computeCertFingerprint(derBuffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", derBuffer);
  return bufferToHex(hashBuffer);
}

// --- CRL Parsing ---

function extractCRLIssuerDN(derBuffer) {
  try {
    const crl = parseASN1(derBuffer);
    const crlChildren = parseASN1Children(crl.content);
    const tbsCertList = crlChildren[0];
    const tbsFields = parseASN1Children(tbsCertList.content);
    let issuerIdx = tbsFields[0].tag === 0x02 ? 2 : 1;
    const issuerField = tbsFields[issuerIdx];
    if (issuerField && issuerField.tag === 0x30) {
      return extractDNString(issuerField.content);
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

    if (!revokedCertsField) {
      return serials;
    }

    const revokedEntries = parseASN1Children(revokedCertsField.content);
    for (const entry of revokedEntries) {
      if (entry.tag === 0x30) {
        const entryFields = parseASN1Children(entry.content);
        if (entryFields.length > 0 && entryFields[0].tag === 0x02) {
          const serial =
            bufferToHex(entryFields[0].content).replace(/^0+/, "") || "0";
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

// --- Core CRL Processing Logic ---

async function processCRLData(crlPem, REVOKED_CERTS, CA_STORE, source, sourceUrl = null) {
  const startTime = Date.now();
  
  const crlBlocks = splitPEMBlocks(crlPem, "X509 CRL");
  if (crlBlocks.length === 0) {
    throw new Error("No X509 CRL blocks found in data");
  }

  let totalSerialsFound = 0;
  let totalSerialsWritten = 0;
  let previousEntriesCleared = 0;
  const crlInfoList = [];

  for (const crlB64 of crlBlocks) {
    const crlDer = base64ToArrayBuffer(crlB64);
    const issuerDN = extractCRLIssuerDN(crlDer);
    const { thisUpdate, nextUpdate } = extractCRLDates(crlDer);

    // Check for matching CA
    let caFound = false;
    if (CA_STORE) {
      const caList = await CA_STORE.list({ prefix: "ca:" });
      for (const caKey of caList.keys) {
        const caData = await CA_STORE.get(caKey.name, { type: "json" });
        if (caData && caData.subjectDN === issuerDN) {
          caFound = true;
          break;
        }
      }
    }

    if (!caFound) {
      console.log(`Warning: No CA certificate found for CRL issuer: ${issuerDN}`);
    }

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
      caVerified: caFound,
    });
  }

  // Update metadata
  await REVOKED_CERTS.put(
    "_crl_metadata",
    JSON.stringify({
      lastSync: new Date().toISOString(),
      source,
      sourceUrl,
      serialEntryCount: totalSerialsWritten,
      crlInfo: crlInfoList,
    })
  );

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

// ============================================================
// DURABLE OBJECT: CRLProcessor
// ============================================================
// Handles chunked uploads with strong consistency.
// Stores chunks in DO storage, assembles on finalization.
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
        received: new Set(),
        created_at: new Date().toISOString(),
      };
    }
    meta.received.add(chunk_index);
    await this.state.storage.put(`meta:${session_id}`, {
      total_chunks: meta.total_chunks,
      received: Array.from(meta.received),
      created_at: meta.created_at,
    });

    return jsonResponse({
      success: true,
      status: "chunk_received",
      chunk_index,
      received_count: meta.received.size,
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

    // Reassemble
    const fullBase64 = chunks.join("");
    let crlPem;
    try {
      crlPem = atob(fullBase64);
    } catch (e) {
      return errorResponse("Failed to decode base64 data");
    }

    // Process CRL
    const result = await processCRLData(
      crlPem,
      this.env.REVOKED_CERTS,
      this.env.CA_STORE,
      "chunked_upload"
    );

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

// --- CA Certificate Handler ---

async function handleCAUpload(request, CA_STORE) {
  try {
    const body = await request.json();
    const { ca_pem } = body;

    if (!ca_pem) {
      return errorResponse("ca_pem is required");
    }

    const certBlocks = splitPEMBlocks(ca_pem, "CERTIFICATE");
    if (certBlocks.length === 0) {
      return errorResponse("No CERTIFICATE blocks found in ca_pem");
    }

    const stored = [];
    for (const certB64 of certBlocks) {
      const certDer = base64ToArrayBuffer(certB64);
      const fingerprint = await computeCertFingerprint(certDer);
      const subjectDN = extractCertSubjectDN(certDer);
      const issuerDN = extractCertIssuerDN(certDer);
      const { notBefore, notAfter } = extractCertValidity(certDer);

      await CA_STORE.put(
        `ca:${fingerprint}`,
        JSON.stringify({
          pem: `-----BEGIN CERTIFICATE-----\n${certB64}\n-----END CERTIFICATE-----`,
          derBase64: certB64,
          subjectDN,
          issuerDN,
          notBefore,
          notAfter,
          uploadedAt: new Date().toISOString(),
        })
      );

      stored.push({ fingerprint, subjectDN, issuerDN, notAfter });
    }

    // Update metadata
    const existingMeta = await CA_STORE.get("_ca_metadata", { type: "json" });
    const issuers = new Set(existingMeta?.issuers || []);
    stored.forEach((c) => issuers.add(c.subjectDN));

    await CA_STORE.put(
      "_ca_metadata",
      JSON.stringify({
        count: (existingMeta?.count || 0) + stored.length,
        issuers: Array.from(issuers),
        lastUpdated: new Date().toISOString(),
      })
    );

    return jsonResponse({
      success: true,
      certificates_stored: stored.length,
      certificates: stored,
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

async function handleCAList(CA_STORE) {
  try {
    const list = await CA_STORE.list({ prefix: "ca:" });
    const certificates = [];

    for (const key of list.keys) {
      const value = await CA_STORE.get(key.name, { type: "json" });
      if (value) {
        certificates.push({
          fingerprint: key.name.replace("ca:", ""),
          subjectDN: value.subjectDN,
          issuerDN: value.issuerDN,
          notBefore: value.notBefore,
          notAfter: value.notAfter,
          uploadedAt: value.uploadedAt,
        });
      }
    }

    return jsonResponse({ success: true, count: certificates.length, certificates });
  } catch (e) {
    return errorResponse(e.message, 500);
  }
}

async function handleCADelete(request, CA_STORE) {
  try {
    const body = await request.json();
    const { fingerprint } = body;

    if (!fingerprint) {
      return errorResponse("fingerprint is required");
    }

    const normalizedFP = fingerprint.toLowerCase().replace(/[:\s]/g, "");
    const existing = await CA_STORE.get(`ca:${normalizedFP}`);

    if (!existing) {
      return errorResponse("CA certificate not found", 404);
    }

    await CA_STORE.delete(`ca:${normalizedFP}`);
    return jsonResponse({ success: true, message: `CA certificate ${normalizedFP} deleted` });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// --- Direct CRL Upload Handler (for smaller files) ---

async function handleCRLUpload(request, REVOKED_CERTS, CA_STORE) {
  try {
    const contentType = request.headers.get("content-type") || "";
    let crlPem;

    if (contentType.includes("application/json")) {
      // JSON body with crl_pem field
      const body = await request.json();
      if (!body.crl_pem) {
        return errorResponse("crl_pem is required in JSON body");
      }
      crlPem = body.crl_pem;
    } else if (
      contentType.includes("text/plain") ||
      contentType.includes("application/x-pem-file") ||
      contentType.includes("application/octet-stream")
    ) {
      // Raw PEM file upload
      crlPem = await request.text();
    } else {
      // Try to parse as text anyway
      crlPem = await request.text();
    }

    if (!crlPem || crlPem.trim().length === 0) {
      return errorResponse("Empty CRL data");
    }

    const result = await processCRLData(crlPem, REVOKED_CERTS, CA_STORE, "direct_upload");

    return jsonResponse({
      success: true,
      ...result,
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// --- Chunked Upload Handler (via DO) ---

async function handleCRLChunk(request, env) {
  const CRL_PROCESSOR = env.CRL_PROCESSOR;
  
  if (!CRL_PROCESSOR) {
    return errorResponse("CRL_PROCESSOR Durable Object not bound", 500);
  }

  const body = await request.json();
  const { session_id, chunk_index, total_chunks, is_final, data } = body;

  if (!session_id) {
    return errorResponse("session_id is required");
  }

  // Get or create the DO instance (single instance for simplicity)
  const id = CRL_PROCESSOR.idFromName("crl-processor");
  const stub = CRL_PROCESSOR.get(id);

  // Upload chunk
  const chunkResponse = await stub.fetch(
    new Request(`https://do/chunk?action=upload_chunk`, {
      method: "POST",
      body: JSON.stringify({ session_id, chunk_index, total_chunks, data }),
    })
  );

  if (!chunkResponse.ok) {
    return chunkResponse;
  }

  // If final chunk, trigger finalization
  if (is_final) {
    const finalizeResponse = await stub.fetch(
      new Request(`https://do/finalize?action=finalize`, {
        method: "POST",
        body: JSON.stringify({ session_id }),
      })
    );
    return finalizeResponse;
  }

  return chunkResponse;
}

// --- CRL Fetch from URL Handler ---

async function handleCRLFetch(request, REVOKED_CERTS, CA_STORE) {
  try {
    const body = await request.json();
    const { crl_url } = body;

    if (!crl_url) {
      return errorResponse("crl_url is required");
    }

    console.log(`Fetching CRL from: ${crl_url}`);
    const response = await fetch(crl_url);

    if (!response.ok) {
      return errorResponse(`Failed to fetch CRL: ${response.status} ${response.statusText}`);
    }

    const contentType = response.headers.get("content-type") || "";
    let crlPem;

    if (
      contentType.includes("application/pkix-crl") ||
      contentType.includes("application/x-x509-crl") ||
      crl_url.endsWith(".crl")
    ) {
      // Binary DER format - convert to PEM
      const derBuffer = await response.arrayBuffer();
      const b64 = btoa(String.fromCharCode(...new Uint8Array(derBuffer)));
      crlPem = `-----BEGIN X509 CRL-----\n${b64}\n-----END X509 CRL-----`;
    } else {
      // Assume PEM format
      crlPem = await response.text();
    }

    const result = await processCRLData(crlPem, REVOKED_CERTS, CA_STORE, "fetch", crl_url);

    return jsonResponse({
      success: true,
      fetched_from: crl_url,
      ...result,
    });
  } catch (e) {
    return errorResponse(e.message);
  }
}

// --- Status Handler ---

async function handleCRLStatus(REVOKED_CERTS, CA_STORE) {
  try {
    const crlMeta = await REVOKED_CERTS.get("_crl_metadata", { type: "json" });

    let serialCount = 0;
    let fingerprintCount = 0;
    const list = await REVOKED_CERTS.list();
    
    for (const key of list.keys) {
      if (key.name.startsWith("serial:")) {
        serialCount++;
      } else if (key.name.startsWith("fp:")) {
        fingerprintCount++;
      } else if (!key.name.startsWith("_")) {
        fingerprintCount++;
      }
    }

    const caMeta = await CA_STORE.get("_ca_metadata", { type: "json" });

    return jsonResponse({
      success: true,
      crl: {
        last_sync: crlMeta?.lastSync || null,
        source: crlMeta?.source || null,
        source_url: crlMeta?.sourceUrl || null,
        serial_entry_count: serialCount,
        crl_info: crlMeta?.crlInfo || null,
      },
      manual_revocations: {
        fingerprint_entry_count: fingerprintCount,
      },
      ca_certificates: {
        count: caMeta?.count || 0,
        issuers: caMeta?.issuers || [],
        last_updated: caMeta?.lastUpdated || null,
      },
    });
  } catch (e) {
    return errorResponse(e.message, 500);
  }
}

// --- Clear Handler ---

async function handleCRLClear(request, REVOKED_CERTS) {
  try {
    const body = await request.json().catch(() => ({}));
    const { clear_fingerprints } = body;

    let serialsCleared = 0;
    let fingerprintsCleared = 0;
    const list = await REVOKED_CERTS.list();

    for (const key of list.keys) {
      if (key.name.startsWith("serial:")) {
        await REVOKED_CERTS.delete(key.name);
        serialsCleared++;
      } else if (clear_fingerprints && key.name.startsWith("fp:")) {
        await REVOKED_CERTS.delete(key.name);
        fingerprintsCleared++;
      } else if (clear_fingerprints && !key.name.startsWith("_")) {
        await REVOKED_CERTS.delete(key.name);
        fingerprintsCleared++;
      }
    }

    await REVOKED_CERTS.delete("_crl_metadata");

    return jsonResponse({
      success: true,
      serials_cleared: serialsCleared,
      fingerprints_cleared: fingerprintsCleared,
    });
  } catch (e) {
    return errorResponse(e.message, 500);
  }
}

// --- Main Request Handler ---

export default {
  async fetch(request, env) {
    const REVOKED_CERTS = env.REVOKED_CERTS;
    const CA_STORE = env.CA_STORE;
    const ADMIN_SECRET = env.ADMIN_SECRET;

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Authenticate all requests
    const providedSecret = request.headers.get("X-Admin-Secret");
    if (!providedSecret || providedSecret !== ADMIN_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }

    // Check required bindings
    if (!REVOKED_CERTS) {
      return errorResponse("REVOKED_CERTS KV namespace not bound", 500);
    }
    if (!CA_STORE) {
      return errorResponse("CA_STORE KV namespace not bound", 500);
    }

    // --- CA Endpoints ---
    if (path === "/admin/ca/upload" && method === "POST") {
      return handleCAUpload(request, CA_STORE);
    }
    if (path === "/admin/ca/list" && method === "GET") {
      return handleCAList(CA_STORE);
    }
    if (path === "/admin/ca" && method === "DELETE") {
      return handleCADelete(request, CA_STORE);
    }

    // --- CRL Endpoints ---
    if (path === "/admin/crl/upload" && method === "POST") {
      return handleCRLUpload(request, REVOKED_CERTS, CA_STORE);
    }
    if (path === "/admin/crl/chunk" && method === "POST") {
      return handleCRLChunk(request, env);
    }
    if (path === "/admin/crl/fetch" && method === "POST") {
      return handleCRLFetch(request, REVOKED_CERTS, CA_STORE);
    }
    if (path === "/admin/crl/status" && method === "GET") {
      return handleCRLStatus(REVOKED_CERTS, CA_STORE);
    }
    if (path === "/admin/crl/clear" && method === "POST") {
      return handleCRLClear(request, REVOKED_CERTS);
    }

    // --- Default ---
    return jsonResponse(
      {
        error: "Not found",
        endpoints: {
          ca: [
            "POST   /admin/ca/upload  - Upload CA certificate(s) PEM",
            "GET    /admin/ca/list    - List CA certificates",
            "DELETE /admin/ca         - Delete a CA certificate",
          ],
          crl: [
            "POST   /admin/crl/upload - Direct CRL PEM upload (file or JSON)",
            "POST   /admin/crl/chunk  - Chunked upload for large files (uses DO)",
            "POST   /admin/crl/fetch  - Fetch CRL from origin URL",
            "GET    /admin/crl/status - View status and counts",
            "POST   /admin/crl/clear  - Clear serial entries",
          ],
        },
      },
      404
    );
  },
};
