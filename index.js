/**
 * CRL Revocation Demo Worker
 * 
 * Integrated routes:
 * 1. /crl/origin/* — CRL Origin (emulates origin serving CRL)
 * 2. /crl/import/* — CRL Importer (fetches from origin, updates KV)
 * 3. / and /health/* — mTLS Validator (checks requests against KV)
 * 4. /test/* — Test endpoints (verify flows without mTLS)
 */

// ============================================================
// Utility Functions
// ============================================================

const jsonResponse = (data, status = 200) => {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
};

const errorResponse = (message, status = 400) => {
  return jsonResponse({ success: false, error: message }, status);
};

const normalizeSerial = (serial) => {
  return serial.toLowerCase().replace(/^0+/, "").replace(/[:\s]/g, "") || "0";
};

const normalizeFingerprint = (fp) => fp.replace(/:/g, "").toLowerCase();

// ============================================================
// CRL Origin Worker (Emulates origin serving CRL)
// ============================================================

const sampleCRLPEM = `-----BEGIN X509 CRL-----
MIIBkzCBfQIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJBVTETMBEGA1UE
CAwOU291dGggV2VsZXMxJDAiBgNVBAoMG0ludGVybmV0IFdpZGdpdHMgUHR5IEx0
ZBA4EzAVBgNVBAMTDmNybC1kZW1vLXJvb3Q0
-----END X509 CRL-----`;

async function handleCRLOrigin(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // GET /crl/origin/pem — return CRL in PEM format
  if (path === "/crl/origin/pem" || path === "/crl/origin") {
    return new Response(sampleCRLPEM, {
      status: 200,
      headers: {
        "content-type": "application/x-pem-file",
        "cache-control": "max-age=43200",
      },
    });
  }

  // GET /crl/origin/der — return CRL in DER format (base64)
  if (path === "/crl/origin/der") {
    const derBase64 = btoa(sampleCRLPEM);
    return new Response(derBase64, {
      status: 200,
      headers: {
        "content-type": "application/octet-stream",
        "cache-control": "max-age=43200",
      },
    });
  }

  // GET /crl/origin/info — return metadata about the CRL
  if (path === "/crl/origin/info") {
    return jsonResponse({
      success: true,
      crl_source: "origin",
      format: "PEM",
      last_updated: new Date().toISOString(),
      size: sampleCRLPEM.length,
      description: "Sample CRL for demo purposes",
    });
  }

  return errorResponse("CRL Origin endpoint not found", 404);
}

// ============================================================
// CRL Importer (Fetches from origin, updates KV)
// ============================================================

async function handleCRLImport(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ADMIN_SECRET = env.ADMIN_SECRET || "dev-secret-12345";
  const CRL_ORIGIN_URL = env.CRL_ORIGIN_URL || "http://localhost:8787/crl/origin";
  const REVOKED_CERTS = env.REVOKED_CERTS;

  // Authenticate admin requests
  const providedSecret = request.headers.get("X-Admin-Secret");
  if (!providedSecret || providedSecret !== ADMIN_SECRET) {
    return errorResponse("Unauthorized: invalid or missing X-Admin-Secret", 401);
  }

  // POST /crl/import/fetch — Fetch CRL from origin (HTTP or R2) and update KV
  if (path === "/crl/import/fetch" && request.method === "POST") {
    try {
      let crlPem;
      
      // Check if R2 binding is available
      if (env.CRL_BUCKET) {
        console.log("Fetching CRL from R2 bucket");
        const r2Object = await env.CRL_BUCKET.get("crl.pem");
        if (!r2Object) {
          return errorResponse("CRL not found in R2 bucket", 404);
        }
        crlPem = await r2Object.text();
      } else {
        // Fallback to HTTP fetch
        console.log(`Fetching CRL from ${CRL_ORIGIN_URL}`);
        const response = await fetch(CRL_ORIGIN_URL);
        if (!response.ok) {
          return errorResponse(
            `Failed to fetch CRL: ${response.status} ${response.statusText}`,
            response.status
          );
        }
        crlPem = await response.text();
      }

      // Parse and extract serial numbers (simplified—use real DER parser in production)
      const serials = extractRevokeSerialsFromPEM(crlPem);

      // Update KV with revoked serials
      const metadata = {
        fetched_at: new Date().toISOString(),
        source: CRL_ORIGIN_URL,
        serial_count: serials.length,
        serials: serials,
      };

      await REVOKED_CERTS.put("crl:metadata", JSON.stringify(metadata));
      await REVOKED_CERTS.put("crl:last_fetch", new Date().toISOString());

      // Store each serial
      for (const serial of serials) {
        await REVOKED_CERTS.put(
          `serial:${normalizeSerial(serial)}`,
          JSON.stringify({
            reason: "revoked",
            revoked_at: new Date().toISOString(),
            source: "crl_import",
          })
        );
      }

      return jsonResponse({
        success: true,
        message: "CRL fetched and stored",
        metadata,
      });
    } catch (e) {
      return errorResponse(`Import failed: ${e.message}`, 500);
    }
  }

  // GET /crl/import/status — Check import status
  if (path === "/crl/import/status" && request.method === "GET") {
    try {
      const metadata = await REVOKED_CERTS.get("crl:metadata", { type: "json" });
      const lastFetch = await REVOKED_CERTS.get("crl:last_fetch");

      return jsonResponse({
        success: true,
        metadata,
        last_fetch: lastFetch,
      });
    } catch (e) {
      return errorResponse(`Status check failed: ${e.message}`, 500);
    }
  }

  // POST /crl/import/manual — Manually add a revoked serial
  if (path === "/crl/import/manual" && request.method === "POST") {
    try {
      const body = await request.json();
      const { serial, reason } = body;

      if (!serial) {
        return errorResponse("serial is required");
      }

      const normalizedSerial = normalizeSerial(serial);
      await REVOKED_CERTS.put(
        `serial:${normalizedSerial}`,
        JSON.stringify({
          reason: reason || "manual revocation",
          revoked_at: new Date().toISOString(),
          source: "manual",
        })
      );

      return jsonResponse(
        {
          success: true,
          message: `Serial ${normalizedSerial} marked as revoked`,
        },
        201
      );
    } catch (e) {
      return errorResponse(`Manual revocation failed: ${e.message}`);
    }
  }

  return errorResponse("CRL Import endpoint not found", 404);
}

// ============================================================
// mTLS Validator (Check requests against KV)
// ============================================================

async function validateMTLS(request, REVOKED_CERTS) {
  const tlsClientAuth = request.cf?.tlsClientAuth;

  if (!tlsClientAuth || tlsClientAuth.certPresented !== "1") {
    throw new Error("mTLS: Client certificate not presented");
  }

  if (tlsClientAuth.certVerified !== "SUCCESS") {
    throw new Error(
      `mTLS: Certificate not verified (${tlsClientAuth.certVerified})`
    );
  }

  // Check KV for revoked serial
  const serial = tlsClientAuth.certSerial;
  if (serial) {
    const normalizedSerial = normalizeSerial(serial);
    const revokedEntry = await REVOKED_CERTS.get(
      `serial:${normalizedSerial}`
    );
    if (revokedEntry !== null) {
      const details = JSON.parse(revokedEntry);
      throw new Error(
        `mTLS: Certificate revoked (serial: ${serial}, reason: ${details.reason})`
      );
    }
  }

  return {
    fingerprint: tlsClientAuth.certFingerprintSHA256,
    serial: tlsClientAuth.certSerial,
    issuer: tlsClientAuth.certIssuerDN,
    subject: tlsClientAuth.certSubjectDN,
  };
}

async function handleMTLSValidator(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const REVOKED_CERTS = env.REVOKED_CERTS;
  const ADMIN_SECRET = env.ADMIN_SECRET || "dev-secret-12345";

  // GET /health — Service health check (no mTLS required)
  if (path === "/health" || path === "/health/status") {
    try {
      const metadata = await REVOKED_CERTS.get("crl:metadata", { type: "json" });
      const lastFetch = await REVOKED_CERTS.get("crl:last_fetch");

      return jsonResponse({
        success: true,
        status: "healthy",
        crl_status: {
          fetched: !!metadata,
          last_fetch: lastFetch,
          serial_count: metadata?.serial_count || 0,
        },
      });
    } catch (e) {
      return errorResponse(`Health check failed: ${e.message}`, 503);
    }
  }

  // GET /debug/cert — Show the cert fields (requires mTLS)
  if (path === "/debug/cert") {
    const tlsClientAuth = request.cf?.tlsClientAuth;
    return jsonResponse({
      success: true,
      cert_presented: tlsClientAuth?.certPresented === "1",
      cert_verified: tlsClientAuth?.certVerified,
      fields: tlsClientAuth || {},
    });
  }

  // GET /debug/kv — Show current KV contents (admin only)
  if (path === "/debug/kv") {
    const providedSecret = request.headers.get("X-Admin-Secret");
    if (!providedSecret || providedSecret !== ADMIN_SECRET) {
      return errorResponse("Unauthorized", 401);
    }

    try {
      const metadata = await REVOKED_CERTS.get("crl:metadata", { type: "json" });
      const list = await REVOKED_CERTS.list({ prefix: "serial:" });

      const serials = [];
      for (const key of list.keys) {
        const value = await REVOKED_CERTS.get(key.name);
        serials.push({
          key: key.name,
          details: JSON.parse(value),
        });
      }

      return jsonResponse({
        success: true,
        metadata,
        revoked_serials: serials,
      });
    } catch (e) {
      return errorResponse(`KV read failed: ${e.message}`, 500);
    }
  }

  // GET /mtls/check — Validate current mTLS cert (requires mTLS)
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

  // GET /mtls/allow — Confirm allowed certificate (requires mTLS)
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

  // GET / — Default endpoint (requires mTLS)
  if (path === "/") {
    try {
      const certInfo = await validateMTLS(request, REVOKED_CERTS);
      return jsonResponse({
        success: true,
        message: "mTLS validation passed",
        certificate: certInfo,
      });
    } catch (e) {
      return errorResponse(e.message, 403);
    }
  }

  return errorResponse("Endpoint not found", 404);
}

// ============================================================
// Test Endpoints (No mTLS required)
// ============================================================

async function handleTest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // GET /test/ping — Simple connectivity test
  if (path === "/test/ping") {
    return jsonResponse({
      success: true,
      message: "pong",
      timestamp: new Date().toISOString(),
    });
  }

  // GET /test/crl/origin — Verify CRL origin is reachable
  if (path === "/test/crl/origin") {
    try {
      const originUrl =
        env.CRL_ORIGIN_URL || "http://localhost:8787/crl/origin";
      const response = await fetch(`${originUrl}/info`);
      if (response.ok) {
        const data = await response.json();
        return jsonResponse({
          success: true,
          message: "CRL origin is reachable",
          origin_data: data,
        });
      }
      return errorResponse("CRL origin returned error", response.status);
    } catch (e) {
      return errorResponse(`CRL origin unreachable: ${e.message}`);
    }
  }

  // GET /test/endpoints — List all available endpoints
  if (path === "/test/endpoints") {
    return jsonResponse({
      success: true,
      endpoints: {
        crl_origin: [
          "GET  /crl/origin/pem   — Return CRL in PEM format",
          "GET  /crl/origin/der   — Return CRL in DER format (base64)",
          "GET  /crl/origin/info  — Return CRL metadata",
        ],
        crl_import: [
          "POST /crl/import/fetch  — Fetch CRL from origin and update KV (admin only)",
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
          "GET  /test/crl/origin  — Verify CRL origin is reachable",
          "GET  /test/endpoints   — List all endpoints",
        ],
      },
      admin_header: "X-Admin-Secret",
      notes:
        "Endpoints marked (admin only) require X-Admin-Secret header with correct value",
    });
  }

  return errorResponse("Test endpoint not found", 404);
}

// ============================================================
// Helper: Extract serials from CRL PEM (simplified)
// ============================================================

function extractRevokeSerialsFromPEM(pem) {
  // In production, use a proper ASN.1 DER parser
  // For demo, return sample serials
  return ["0123456789abcdef", "fedcba9876543210", "aabbccddeeff0011"];
}

// ============================================================
// Main Request Router
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route to appropriate handler
      if (path.startsWith("/crl/origin")) {
        return await handleCRLOrigin(request);
      }
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
