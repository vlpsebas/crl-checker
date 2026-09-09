// ============================================================
// CRL Checker Worker - mTLS Validator + CRL Importer + Telemetry
// ============================================================

// Helper functions
const jsonResponse = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });

const errorResponse = (message, status = 400) =>
  jsonResponse({ success: false, error: message }, status);

// Normalize serial number (lowercase, strip leading zeros, remove colons/spaces)
const normalizeSerial = (serial) => {
  if (!serial) return "0";
  return serial
    .toLowerCase()
    .replace(/^0+/, "")
    .replace(/[:\s]/g, "");
};

// Normalize fingerprint (lowercase, remove colons)
const normalizeFingerprint = (fp) => fp.replace(/:/g, "").toLowerCase();

// ============================================================
// CRL Importer - Fetch CRL from file origin and update KV
// ============================================================

// Simplified PEM CRL parser (extracts serial numbers)
function extractRevokeSerialsFromPEM(pem) {
  // In production, use a proper DER/ASN.1 parser
  // This is a placeholder that extracts hex-like patterns
  const serials = [];
  const lines = pem.split('\n');
  
  for (const line of lines) {
    const match = line.match(/[0-9A-Fa-f:]{16,}/g);
    if (match) {
      match.forEach(serial => {
        const normalized = normalizeSerial(serial);
        if (normalized && normalized !== "0") {
          serials.push(normalized);
        }
      });
    }
  }
  
  return [...new Set(serials)]; // dedupe
}

async function handleCRLImport(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ADMIN_SECRET = env.ADMIN_SECRET || "dev-secret-12345";
  const FILE_ORIGIN_URL = env.FILE_ORIGIN_URL || "http://localhost:8788";
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const CRL_DATA = env.CRL_DATA;

  // Authenticate admin requests
  const providedSecret = request.headers.get("X-Admin-Secret");
  if (!providedSecret || providedSecret !== ADMIN_SECRET) {
    return errorResponse("Unauthorized: invalid or missing X-Admin-Secret", 401);
  }

  // POST /crl/import/fetch - Fetch CRL from file origin (HTTP or R2) and update KV
  if (path === "/crl/import/fetch" && request.method === "POST") {
    try {
      let crlPem;
      const crlFilename = url.searchParams.get("file") || "crl.pem";
      
      // Check if R2 binding is available (direct access)
      if (env.CRL_BUCKET) {
        console.log(`Fetching CRL from R2 bucket: ${crlFilename}`);
        const r2Object = await env.CRL_BUCKET.get(crlFilename);
        if (!r2Object) {
          return errorResponse(`CRL not found in R2 bucket: ${crlFilename}`, 404);
        }
        crlPem = await r2Object.text();
      } else {
        // Fallback to HTTP fetch from file origin
        const fetchUrl = `${FILE_ORIGIN_URL}/file/${crlFilename}`;
        console.log(`Fetching CRL from file origin: ${fetchUrl}`);
        const response = await fetch(fetchUrl);
        if (!response.ok) {
          return errorResponse(
            `Failed to fetch CRL: ${response.status} ${response.statusText}`,
            response.status
          );
        }
        crlPem = await response.text();
      }

      // Parse and extract serial numbers
      const serials = extractRevokeSerialsFromPEM(crlPem);

      // Update KV with revoked serials
      const metadata = {
        fetched_at: new Date().toISOString(),
        source: env.CRL_BUCKET ? "R2" : FILE_ORIGIN_URL,
        serial_count: serials.length,
        file: crlFilename,
      };

      await CRL_DATA.put("crl:metadata", JSON.stringify(metadata));
      await CRL_DATA.put("crl:serials", JSON.stringify(serials));
      await CRL_DATA.put("crl:last_fetch", new Date().toISOString());

      // Store each serial in REVOKED_CERTS KV
      for (const serial of serials) {
        await REVOKED_CERTS.put(`serial:${serial}`, JSON.stringify({
          revoked: true,
          added_at: new Date().toISOString(),
          source: "crl_import",
        }));
      }

      return jsonResponse({
        success: true,
        message: "CRL imported successfully",
        serials_imported: serials.length,
        metadata: metadata,
      });

    } catch (e) {
      return errorResponse(`Import failed: ${e.message}`, 500);
    }
  }

  // GET /crl/import/status - Check CRL import status
  if (path === "/crl/import/status" && request.method === "GET") {
    try {
      const metadata = await CRL_DATA.get("crl:metadata", "json");
      const lastFetch = await CRL_DATA.get("crl:last_fetch");
      const serials = await CRL_DATA.get("crl:serials", "json");

      return jsonResponse({
        success: true,
        metadata: metadata || null,
        last_fetch: lastFetch || null,
        serial_count: serials ? serials.length : 0,
      });
    } catch (e) {
      return errorResponse(`Status check failed: ${e.message}`, 500);
    }
  }

  // POST /crl/import/manual - Manually revoke a serial number
  if (path === "/crl/import/manual" && request.method === "POST") {
    try {
      const body = await request.json();
      const serial = body.serial;
      const reason = body.reason || "manual_revocation";

      if (!serial) {
        return errorResponse("Serial number required");
      }

      const normalized = normalizeSerial(serial);
      await REVOKED_CERTS.put(`serial:${normalized}`, JSON.stringify({
        revoked: true,
        added_at: new Date().toISOString(),
        source: "manual",
        reason: reason,
      }));

      return jsonResponse({
        success: true,
        message: "Serial revoked manually",
        serial: normalized,
      });

    } catch (e) {
      return errorResponse(`Manual revocation failed: ${e.message}`, 500);
    }
  }

  return errorResponse("CRL Import endpoint not found", 404);
}

// ============================================================
// mTLS Validator - Check certificate against KV
// ============================================================

async function validateMTLS(request, REVOKED_CERTS) {
  // Extract client certificate from Cloudflare mTLS headers
  const certPem = request.headers.get("cf-client-cert-pem");
  const certSerial = request.headers.get("cf-client-cert-serial");
  const certFingerprint = request.headers.get("cf-client-cert-fingerprint");
  const certIssuer = request.headers.get("cf-client-cert-issuer");
  const certSubject = request.headers.get("cf-client-cert-subject");

  if (!certPem && !certSerial) {
    throw new Error("No client certificate presented");
  }

  const certInfo = {
    serial: certSerial,
    fingerprint: certFingerprint,
    issuer: certIssuer,
    subject: certSubject,
  };

  // Check revocation by serial
  if (certSerial) {
    const normalized = normalizeSerial(certSerial);
    const revoked = await REVOKED_CERTS.get(`serial:${normalized}`);
    if (revoked) {
      throw new Error(`Certificate revoked (serial: ${normalized})`);
    }
  }

  // Check revocation by fingerprint
  if (certFingerprint) {
    const normalized = normalizeFingerprint(certFingerprint);
    const revoked = await REVOKED_CERTS.get(`fingerprint:${normalized}`);
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
    });
  }

  // GET /debug/cert - Show presented certificate fields
  if (path === "/debug/cert") {
    const certInfo = {
      serial: request.headers.get("cf-client-cert-serial"),
      fingerprint: request.headers.get("cf-client-cert-fingerprint"),
      issuer: request.headers.get("cf-client-cert-issuer"),
      subject: request.headers.get("cf-client-cert-subject"),
      not_before: request.headers.get("cf-client-cert-not-before"),
      not_after: request.headers.get("cf-client-cert-not-after"),
    };

    return jsonResponse({
      success: true,
      certificate: certInfo,
    });
  }

  // GET /debug/kv - Show KV contents (admin only)
  if (path === "/debug/kv") {
    const providedSecret = request.headers.get("X-Admin-Secret");
    if (!providedSecret || providedSecret !== ADMIN_SECRET) {
      return errorResponse("Unauthorized: invalid or missing X-Admin-Secret", 401);
    }

    try {
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
    } catch (e) {
      return errorResponse(`KV debug failed: ${e.message}`, 500);
    }
  }

  // GET /mtls/check - Validate current mTLS cert
  if (path === "/mtls/check") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({
        success: true,
        message: "Certificate is valid and not revoked",
        certificate: certInfo,
      });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  // GET /mtls/allow - Confirm allowed certificate
  if (path === "/mtls/allow") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({
        success: true,
        message: "Request allowed: Certificate is valid",
        certificate: certInfo,
      });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  // GET / - Default endpoint (requires valid mTLS cert)
  if (path === "/" || path === "") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({
        success: true,
        message: "mTLS authentication successful",
        certificate: certInfo,
      });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  return errorResponse("Endpoint not found", 404);
}

// ============================================================
// Test Endpoints
// ============================================================

async function handleTest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // GET /test/ping
  if (path === "/test/ping") {
    return jsonResponse({
      success: true,
      message: "pong",
      timestamp: new Date().toISOString(),
    });
  }

  // GET /test/file-origin - Verify file origin is reachable
  if (path === "/test/file-origin") {
    try {
      const originUrl = env.FILE_ORIGIN_URL || "http://localhost:8788";
      const response = await fetch(`${originUrl}/health`);
      if (response.ok) {
        const data = await response.json();
        return jsonResponse({
          success: true,
          message: "File origin is reachable",
          origin_url: originUrl,
          origin_health: data,
        });
      } else {
        return errorResponse(`File origin returned ${response.status}`, response.status);
      }
    } catch (e) {
      return errorResponse(`Failed to reach file origin: ${e.message}`, 500);
    }
  }

  // GET /test/endpoints - List all endpoints
  if (path === "/test/endpoints") {
    return jsonResponse({
      success: true,
      endpoints: {
        crl_import: [
          "POST /crl/import/fetch?file=<filename> — Fetch CRL from file origin (HTTP or R2) and update KV (admin only)",
          "GET  /crl/import/status — Check import status (admin only)",
          "POST /crl/import/manual — Manually revoke a serial (admin only)",
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
          "GET  /test/file-origin — Verify file origin is reachable",
          "GET  /test/endpoints   — List all endpoints",
        ],
      },
    });
  }

  return errorResponse("Test endpoint not found", 404);
}

// ============================================================
// Main Router
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route to appropriate handler
      if (path.startsWith("/crl/import")) {
        return await handleCRLImport(request, env);
      }
      if (path.startsWith("/test")) {
        return await handleTest(request, env);
      }
      // Default: mTLS validator routes
      return await handleMTLSValidator(request, env);
    } catch (e) {
      return errorResponse(`Unhandled error: ${e.message}`, 500);
    }
  },
};
