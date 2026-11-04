import {
  decodeBase64,
  isValidVault,
  json,
  normalizeUsername,
  parseJson,
  sameOrigin,
  sha256Hex,
} from "../../_lib/auth.js";

export async function onRequestPost({ request, env }) {
  if (!(await sameOrigin(request))) return json({ error: "요청 출처를 확인할 수 없습니다." }, 403);
  const body = await parseJson(request);
  const username = normalizeUsername(body?.username);
  const salt = decodeBase64(body?.salt, 16);
  const proof = decodeBase64(body?.proof, 32);
  if (!username || !salt || !proof || !isValidVault(body?.vault)) {
    return json({ error: "입력 내용을 확인해 주세요." }, 400);
  }

  try {
    await env.DB.prepare(
      "INSERT INTO user_vaults (username, salt, auth_hash, vault_iv, vault_ciphertext, revision) VALUES (?, ?, ?, ?, ?, 1)",
    )
      .bind(username, body.salt, await sha256Hex(proof), body.vault.iv, body.vault.ciphertext)
      .run();
  } catch {
    return json({ error: "이미 사용 중인 아이디이거나 계정을 만들 수 없습니다." }, 409);
  }

  return json({ vault: body.vault, revision: 1 }, 201);
}
