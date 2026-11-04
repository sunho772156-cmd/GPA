export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export function normalizeUsername(value) {
  if (typeof value !== "string") return null;
  const username = value.trim().toLowerCase();
  return /^[a-z0-9_]{3,20}$/.test(username) ? username : null;
}

export function decodeBase64(value, expectedLength) {
  if (typeof value !== "string" || value.length > 3_000_000) return null;
  try {
    const binary = atob(value);
    if (expectedLength !== undefined && binary.length !== expectedLength) return null;
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

export function isValidVault(vault) {
  if (!vault || vault.version !== 1) return false;
  return Boolean(
    decodeBase64(vault.iv, 12) &&
      decodeBase64(vault.ciphertext) &&
      decodeBase64(vault.ciphertext).length >= 16,
  );
}

export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function safeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  let mismatch = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    mismatch |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
  }
  return mismatch === 0;
}

export async function parseJson(request, maxBytes = 2_500_000) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > maxBytes) return null;
  try {
    const text = await request.text();
    if (new TextEncoder().encode(text).length > maxBytes) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export async function authenticate(request, env) {
  const token = request.headers.get("Authorization")?.match(/^Bearer ([A-Za-z0-9+/]{43}=?)$/)?.[1];
  const proof = token && decodeBase64(token, 32);
  if (!proof) return null;
  const row = await env.DB.prepare(
    "SELECT username, auth_hash, vault_iv, vault_ciphertext, revision FROM user_vaults WHERE auth_hash = ?",
  ).bind(await sha256Hex(proof)).first();
  if (!row) return null;
  return row;
}

export async function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

export function vaultFromRow(row) {
  return { version: 1, iv: row.vault_iv, ciphertext: row.vault_ciphertext };
}
