import { authenticate, isValidVault, json, parseJson, sameOrigin, vaultFromRow } from "../_lib/auth.js";

export async function onRequestGet({ request, env }) {
  const row = await authenticate(request, env);
  if (!row) return json({ error: "로그인이 만료되었습니다. 다시 로그인해 주세요." }, 401);
  return json({ vault: vaultFromRow(row), revision: Number(row.revision) });
}

export async function onRequestPut({ request, env }) {
  if (!(await sameOrigin(request))) return json({ error: "요청 출처를 확인할 수 없습니다." }, 403);
  const row = await authenticate(request, env);
  if (!row) return json({ error: "로그인이 만료되었습니다. 다시 로그인해 주세요." }, 401);
  const body = await parseJson(request);
  const expectedRevision = Number(body?.expectedRevision);
  if (!Number.isSafeInteger(expectedRevision) || !isValidVault(body?.vault)) {
    return json({ error: "저장할 데이터를 확인할 수 없습니다." }, 400);
  }
  const result = await env.DB.prepare(
    "UPDATE user_vaults SET vault_iv = ?, vault_ciphertext = ?, revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE username = ? AND revision = ?",
  )
    .bind(body.vault.iv, body.vault.ciphertext, row.username, expectedRevision)
    .run();
  if (Number(result.meta?.changes || 0) !== 1) {
    return json({ error: "다른 창에서 성적이 변경되었습니다. 최신 내용이 사라지지 않도록 다시 로그인해 주세요." }, 409);
  }
  return json({ revision: expectedRevision + 1 });
}
