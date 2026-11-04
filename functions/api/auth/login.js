import {
  decodeBase64,
  json,
  normalizeUsername,
  parseJson,
  safeEqual,
  sameOrigin,
  sha256Hex,
  vaultFromRow,
} from "../../_lib/auth.js";

async function isRateLimited(request, env, username) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const bucket = await sha256Hex(new TextEncoder().encode(`${username}:${ip}`));
  const windowStart = Math.floor(Date.now() / 300000);
  if (windowStart % 12 === 0) {
    await env.DB.prepare("DELETE FROM login_attempts WHERE window_start < ?").bind(windowStart - 2).run();
  }
  await env.DB.prepare(
    "INSERT INTO login_attempts (bucket, window_start, attempts) VALUES (?, ?, 1) ON CONFLICT(bucket, window_start) DO UPDATE SET attempts = attempts + 1",
  ).bind(bucket, windowStart).run();
  const row = await env.DB.prepare(
    "SELECT attempts FROM login_attempts WHERE bucket = ? AND window_start = ?",
  ).bind(bucket, windowStart).first();
  return Number(row?.attempts || 0) > 10;
}

export async function onRequestPost({ request, env }) {
  if (!(await sameOrigin(request))) return json({ error: "요청 출처를 확인할 수 없습니다." }, 403);
  const body = await parseJson(request, 16_000);
  const username = normalizeUsername(body?.username);
  const proof = decodeBase64(body?.proof, 32);
  if (!username || !proof) return json({ error: "아이디 또는 비밀번호를 확인해 주세요." }, 400);
  if (await isRateLimited(request, env, username)) {
    return json({ error: "로그인 시도가 많습니다. 5분 뒤 다시 시도해 주세요." }, 429);
  }
  const row = await env.DB.prepare(
    "SELECT username, auth_hash, vault_iv, vault_ciphertext, revision FROM user_vaults WHERE username = ?",
  ).bind(username).first();
  if (!row || !safeEqual(await sha256Hex(proof), row.auth_hash)) {
    return json({ error: "아이디 또는 비밀번호를 확인해 주세요." }, 401);
  }
  return json({ vault: vaultFromRow(row), revision: Number(row.revision) });
}
