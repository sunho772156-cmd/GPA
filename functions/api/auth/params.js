import { json, normalizeUsername } from "../../_lib/auth.js";

export async function onRequestGet({ request, env }) {
  const username = normalizeUsername(new URL(request.url).searchParams.get("username"));
  if (!username) return json({ error: "아이디 또는 비밀번호를 확인해 주세요." }, 400);
  const row = await env.DB.prepare("SELECT salt FROM user_vaults WHERE username = ?").bind(username).first();
  if (!row) return json({ error: "아이디 또는 비밀번호를 확인해 주세요." }, 401);
  return json({ salt: row.salt, iterations: 600000, version: 1 });
}
