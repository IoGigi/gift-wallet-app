const PROJECT_ID = "giftwallet-628bd";
const ISSUER = `https://securetoken.google.com/${PROJECT_ID}`;
const JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

let jwksCache = null;
let jwksCacheAt = 0;

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET, PUT, OPTIONS"
    }
  });
}

function base64urlToBytes(input) {
  const s = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);

  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }

  return out;
}

function decodeJsonPart(part) {
  return JSON.parse(
    new TextDecoder().decode(base64urlToBytes(part))
  );
}

async function getJwks() {
  const now = Date.now();

  if (jwksCache && now - jwksCacheAt < 3600000) {
    return jwksCache;
  }

  const response = await fetch(JWKS_URL);

  if (!response.ok) {
    throw new Error(
      "Impossibile recuperare le chiavi pubbliche Firebase."
    );
  }

  jwksCache = await response.json();
  jwksCacheAt = now;

  return jwksCache;
}

async function verifyFirebaseToken(token) {
  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Token Firebase non valido.");
  }

  const [
    encodedHeader,
    encodedPayload,
    encodedSignature
  ] = parts;

  const header = decodeJsonPart(encodedHeader);
  const payload = decodeJsonPart(encodedPayload);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Firma del token Firebase non valida.");
  }

  if (payload.aud !== PROJECT_ID) {
    throw new Error("Audience Firebase non valida.");
  }

  if (payload.iss !== ISSUER) {
    throw new Error("Issuer Firebase non valido.");
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    !payload.sub ||
    typeof payload.sub !== "string" ||
    payload.sub.length > 128
  ) {
    throw new Error("UID Firebase non valido.");
  }

  if (!payload.exp || payload.exp <= now) {
    throw new Error("Token Firebase scaduto.");
  }

  if (payload.iat && payload.iat > now + 300) {
    throw new Error("Token Firebase non ancora valido.");
  }

  let jwks = await getJwks();

  let jwk = jwks.keys.find(
    key => key.kid === header.kid
  );

  if (!jwk) {
    jwksCache = null;
    jwks = await getJwks();

    jwk = jwks.keys.find(
      key => key.kid === header.kid
    );
  }

  if (!jwk) {
    throw new Error("Chiave Firebase non trovata.");
  }

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    base64urlToBytes(encodedSignature),
    new TextEncoder().encode(
      `${encodedHeader}.${encodedPayload}`
    )
  );

  if (!valid) {
    throw new Error("Firma Firebase non valida.");
  }

  return payload;
}

function getBearerToken(request) {
  const authorization =
    request.headers.get("Authorization") || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice(7).trim();
}

async function ensureStateColumn(env) {
  try {
    await env.DB
      .prepare(
        "ALTER TABLE users ADD COLUMN data_json TEXT"
      )
      .run();
  } catch (e) {
    // La colonna esiste già.
  }
}

async function authenticate(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    throw new Error(
      "Manca Authorization: Bearer <Firebase ID token>."
    );
  }

  const claims = await verifyFirebaseToken(token);

  const uid = claims.sub;

  const email =
    typeof claims.email === "string"
      ? claims.email
      : null;

  await env.DB
    .prepare(`
      INSERT INTO users (uid, email)
      VALUES (?, ?)
      ON CONFLICT(uid)
      DO UPDATE SET email = excluded.email
    `)
    .bind(uid, email)
    .run();

  return {
    uid,
    email
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers":
            "Authorization, Content-Type",
          "Access-Control-Allow-Methods":
            "GET, PUT, OPTIONS"
        }
      });
    }

    if (pathname === "/api/db-test") {
      try {
        const result = await env.DB
          .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
          )
          .all();

        return json({
          success: true,
          database: "giftwallet-db",
          tables: result.results
        });
      } catch (error) {
        return json({
          success: false,
          error: String(
            error?.message || error
          )
        }, 500);
      }
    }

    if (pathname === "/api/auth-test") {
      try {
        const auth = await authenticate(
          request,
          env
        );

        return json({
          success: true,
          authenticated: true,
          uid: auth.uid,
          email: auth.email,
