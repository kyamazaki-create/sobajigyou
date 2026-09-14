// 資料・タスク管理台帳 — Cloudflare Worker API
// D1 (DB) + KV (FILES) + 共通パスワード認証。静的ファイルは assets が配信。

const COOKIE = "kanri_sess";
const MAX_UPLOAD = 25 * 1024 * 1024; // KV 1値の上限 25MiB

/* ---------- utils ---------- */
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
const enc = (s) => new TextEncoder().encode(s);
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : "id" + Date.now() + Math.random().toString(36).slice(2));
const nowISO = () => new Date().toISOString();

async function sessionToken(password) {
  const key = await crypto.subtle.importKey("raw", enc(password), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc("authorized-v1"));
  return hex(sig);
}
function readCookie(req, name) {
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? m[1] : null;
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
async function isAuthed(req, env) {
  if (!env.APP_PASSWORD) return false;
  const tok = readCookie(req, COOKIE);
  if (!tok) return false;
  const expect = await sessionToken(env.APP_PASSWORD);
  return timingSafeEqual(tok, expect);
}

/* ---------- entry ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path === "/api/login" && req.method === "POST") return login(req, env);
      if (path === "/api/logout" && req.method === "POST") return logout();
      if (path === "/api/me") return (await isAuthed(req, env)) ? json({ ok: true }) : json({ ok: false }, 401);

      if (path.startsWith("/api/") || path.startsWith("/file/")) {
        if (!(await isAuthed(req, env))) return json({ error: "unauthorized" }, 401);
        return route(req, env, url);
      }
      // それ以外は静的アセット（public/）へ
      return env.ASSETS.fetch(req);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};

async function login(req, env) {
  if (!env.APP_PASSWORD) return json({ error: "server_not_configured", message: "APP_PASSWORD が未設定です" }, 503);
  let body = {};
  try { body = await req.json(); } catch {}
  const pw = (body && body.password) || "";
  if (!timingSafeEqual(String(pw), String(env.APP_PASSWORD))) return json({ error: "invalid" }, 401);
  const tok = await sessionToken(env.APP_PASSWORD);
  return json({ ok: true }, 200, {
    "set-cookie": `${COOKIE}=${tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`,
  });
}
function logout() {
  return json({ ok: true }, 200, { "set-cookie": `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0` });
}

/* ---------- router (authed) ---------- */
async function route(req, env, url) {
  const p = url.pathname;
  const m = req.method;
  const DB = env.DB;

  // GET /file/:id  — KV からファイル配信
  let fm = p.match(/^\/file\/([^/]+)$/);
  if (fm && m === "GET") return serveFile(env, fm[1]);

  if (p === "/api/state" && m === "GET") return getState(DB);

  if (p === "/api/projects" && m === "POST") {
    const b = await req.json();
    const id = b.id || uid();
    const cnt = (await DB.prepare("SELECT COUNT(*) AS c FROM projects").first()).c;
    await DB.prepare("INSERT INTO projects (id,name,color,ord,created_at) VALUES (?,?,?,?,?)")
      .bind(id, b.name || "無題", b.color || "#107569", cnt, nowISO()).run();
    return json({ id });
  }
  let pm = p.match(/^\/api\/projects\/([^/]+)$/);
  if (pm && m === "DELETE") {
    await DB.prepare("DELETE FROM projects WHERE id=?").bind(pm[1]).run();
    await DB.prepare("UPDATE materials SET project_id='' WHERE project_id=?").bind(pm[1]).run();
    await DB.prepare("UPDATE tasks SET project_id='' WHERE project_id=?").bind(pm[1]).run();
    return json({ ok: true });
  }

  if (p === "/api/materials" && m === "POST") {
    const b = await req.json();
    const now = nowISO();
    if (b.id) {
      await DB.prepare("UPDATE materials SET title=?, project_id=?, descr=?, updated_at=? WHERE id=?")
        .bind(b.title || "無題", b.projectId || "", b.desc || "", now, b.id).run();
      return json({ id: b.id });
    }
    const id = uid();
    await DB.prepare("INSERT INTO materials (id,title,project_id,descr,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?)")
      .bind(id, b.title || "無題", b.projectId || "", b.desc || "", b.by || "", now, now).run();
    return json({ id });
  }
  let mm = p.match(/^\/api\/materials\/([^/]+)$/);
  if (mm && m === "DELETE") {
    const mid = mm[1];
    const fs = (await DB.prepare("SELECT kv_key FROM files WHERE material_id=? AND kind='file'").bind(mid).all()).results;
    for (const f of fs) if (f.kv_key) await env.FILES.delete(f.kv_key);
    await DB.prepare("DELETE FROM files WHERE material_id=?").bind(mid).run();
    await DB.prepare("DELETE FROM notes WHERE material_id=?").bind(mid).run();
    await DB.prepare("UPDATE tasks SET material_id='' WHERE material_id=?").bind(mid).run();
    await DB.prepare("DELETE FROM materials WHERE id=?").bind(mid).run();
    return json({ ok: true });
  }

  let nm = p.match(/^\/api\/materials\/([^/]+)\/notes$/);
  if (nm && m === "POST") {
    const b = await req.json();
    await DB.prepare("INSERT INTO notes (id,material_id,author,text,at) VALUES (?,?,?,?,?)")
      .bind(uid(), nm[1], b.by || "匿名", b.text || "", nowISO()).run();
    await touch(DB, nm[1]);
    return json({ ok: true });
  }

  let lm = p.match(/^\/api\/materials\/([^/]+)\/links$/);
  if (lm && m === "POST") {
    const b = await req.json();
    await DB.prepare("INSERT INTO files (id,material_id,kind,url,name,uploaded_by,at) VALUES (?,?,?,?,?,?,?)")
      .bind(uid(), lm[1], "link", b.url || "", b.name || b.url || "リンク", b.by || "", nowISO()).run();
    await touch(DB, lm[1]);
    return json({ ok: true });
  }

  let um = p.match(/^\/api\/materials\/([^/]+)\/files$/);
  if (um && m === "POST") return uploadFile(req, env, um[1]);

  let fdm = p.match(/^\/api\/files\/([^/]+)$/);
  if (fdm && m === "DELETE") {
    const row = await DB.prepare("SELECT kv_key, material_id FROM files WHERE id=?").bind(fdm[1]).first();
    if (row) {
      if (row.kv_key) await env.FILES.delete(row.kv_key);
      await DB.prepare("DELETE FROM files WHERE id=?").bind(fdm[1]).run();
      if (row.material_id) await touch(DB, row.material_id);
    }
    return json({ ok: true });
  }

  if (p === "/api/tasks" && m === "POST") {
    const b = await req.json();
    const now = nowISO();
    if (b.id) {
      await DB.prepare("UPDATE tasks SET title=?,assignee=?,due=?,status=?,priority=?,project_id=?,material_id=?,note=?,updated_at=? WHERE id=?")
        .bind(b.title || "無題", b.assignee || "", b.due || "", b.status || "未着手", b.priority || "通常", b.projectId || "", b.materialId || "", b.note || "", now, b.id).run();
      return json({ id: b.id });
    }
    const id = uid();
    await DB.prepare("INSERT INTO tasks (id,title,assignee,due,status,priority,project_id,material_id,note,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(id, b.title || "無題", b.assignee || "", b.due || "", b.status || "未着手", b.priority || "通常", b.projectId || "", b.materialId || "", b.note || "", b.by || "", now, now).run();
    return json({ id });
  }
  let tm = p.match(/^\/api\/tasks\/([^/]+)$/);
  if (tm && m === "DELETE") {
    await DB.prepare("DELETE FROM tasks WHERE id=?").bind(tm[1]).run();
    return json({ ok: true });
  }

  // ---- 研究・開発 ----
  if (p === "/api/rnd/themes" && m === "POST") {
    const b = await req.json();
    const now = nowISO();
    if (b.id) {
      await DB.prepare("UPDATE rnd_themes SET name=?, descr=?, updated_at=? WHERE id=?")
        .bind(b.name || "無題", b.desc || "", now, b.id).run();
      return json({ id: b.id });
    }
    const id = uid();
    await DB.prepare("INSERT INTO rnd_themes (id,name,descr,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?)")
      .bind(id, b.name || "無題", b.desc || "", b.by || "", now, now).run();
    return json({ id });
  }
  let rtm = p.match(/^\/api\/rnd\/themes\/([^/]+)$/);
  if (rtm && m === "DELETE") {
    const tid = rtm[1];
    const trials = (await DB.prepare("SELECT id FROM rnd_trials WHERE theme_id=?").bind(tid).all()).results;
    for (const tr of trials) await deleteTrialFiles(env, tr.id);
    await DB.prepare("DELETE FROM rnd_trials WHERE theme_id=?").bind(tid).run();
    await DB.prepare("DELETE FROM rnd_themes WHERE id=?").bind(tid).run();
    return json({ ok: true });
  }
  let rtr = p.match(/^\/api\/rnd\/themes\/([^/]+)\/trials$/);
  if (rtr && m === "POST") {
    const b = await req.json();
    const themeId = rtr[1];
    const mx = await DB.prepare("SELECT MAX(seq) AS mx FROM rnd_trials WHERE theme_id=?").bind(themeId).first();
    const seq = (mx && mx.mx ? mx.mx : 0) + 1;
    const id = uid();
    await DB.prepare("INSERT INTO rnd_trials (id,theme_id,seq,ingredients,method,result,rating,aroma,tie_before,tie_after,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(id, themeId, seq, JSON.stringify(b.ingredients || []), b.method || "", b.result || "", b.rating || 0, b.aroma || "", b.tieBefore || "", b.tieAfter || "", b.by || "", nowISO()).run();
    await DB.prepare("UPDATE rnd_themes SET updated_at=? WHERE id=?").bind(nowISO(), themeId).run();
    return json({ id, seq });
  }
  let rtu = p.match(/^\/api\/rnd\/trials\/([^/]+)$/);
  if (rtu && m === "POST") {
    const b = await req.json();
    await DB.prepare("UPDATE rnd_trials SET ingredients=?, method=?, result=?, rating=?, aroma=?, tie_before=?, tie_after=? WHERE id=?")
      .bind(JSON.stringify(b.ingredients || []), b.method || "", b.result || "", b.rating || 0, b.aroma || "", b.tieBefore || "", b.tieAfter || "", rtu[1]).run();
    const row = await DB.prepare("SELECT theme_id FROM rnd_trials WHERE id=?").bind(rtu[1]).first();
    if (row) await DB.prepare("UPDATE rnd_themes SET updated_at=? WHERE id=?").bind(nowISO(), row.theme_id).run();
    return json({ ok: true });
  }
  if (rtu && m === "DELETE") {
    await deleteTrialFiles(env, rtu[1]);
    await DB.prepare("DELETE FROM rnd_trials WHERE id=?").bind(rtu[1]).run();
    return json({ ok: true });
  }
  let rtf = p.match(/^\/api\/rnd\/trials\/([^/]+)\/files$/);
  if (rtf && m === "POST") return uploadFile(req, env, rtf[1]);

  return json({ error: "not_found" }, 404);
}

async function touch(DB, materialId) {
  await DB.prepare("UPDATE materials SET updated_at=? WHERE id=?").bind(nowISO(), materialId).run();
}

async function deleteTrialFiles(env, ownerId) {
  const fs = (await env.DB.prepare("SELECT kv_key FROM files WHERE material_id=? AND kind='file'").bind(ownerId).all()).results;
  for (const f of fs) if (f.kv_key) await env.FILES.delete(f.kv_key);
  await env.DB.prepare("DELETE FROM files WHERE material_id=?").bind(ownerId).run();
}

async function uploadFile(req, env, materialId) {
  const form = await req.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "no_file" }, 400);
  const size = file.size;
  if (size > MAX_UPLOAD) return json({ error: "too_large", message: "25MBを超えています" }, 413);
  const ct = file.type || form.get("contentType") || "application/octet-stream";
  const name = form.get("name") || file.name || "file";
  const id = uid();
  const key = "f/" + id;
  const buf = await file.arrayBuffer();
  await env.FILES.put(key, buf, { metadata: { contentType: ct, name } });
  await env.DB.prepare("INSERT INTO files (id,material_id,kind,kv_key,name,content_type,size,uploaded_by,at) VALUES (?,?,?,?,?,?,?,?,?)")
    .bind(id, materialId, "file", key, name, ct, size, form.get("by") || "", nowISO()).run();
  await touch(env.DB, materialId);
  return json({ id });
}

async function serveFile(env, fileId) {
  const row = await env.DB.prepare("SELECT kv_key, content_type, name FROM files WHERE id=? AND kind='file'").bind(fileId).first();
  if (!row || !row.kv_key) return new Response("Not found", { status: 404 });
  const obj = await env.FILES.get(row.kv_key, "arrayBuffer");
  if (!obj) return new Response("Not found", { status: 404 });
  return new Response(obj, {
    headers: {
      "content-type": row.content_type || "application/octet-stream",
      "content-disposition": `inline; filename*=UTF-8''${encodeURIComponent(row.name || "file")}`,
      "cache-control": "private, max-age=3600",
    },
  });
}

async function getState(DB) {
  const [projects, materials, files, notes, tasks, rndThemes, rndTrials] = await Promise.all([
    DB.prepare("SELECT * FROM projects ORDER BY ord, created_at").all(),
    DB.prepare("SELECT * FROM materials").all(),
    DB.prepare("SELECT * FROM files").all(),
    DB.prepare("SELECT * FROM notes ORDER BY at").all(),
    DB.prepare("SELECT * FROM tasks").all(),
    DB.prepare("SELECT * FROM rnd_themes").all(),
    DB.prepare("SELECT * FROM rnd_trials ORDER BY seq").all(),
  ]);
  const filesByMat = {}, notesByMat = {};
  for (const f of files.results) {
    (filesByMat[f.material_id] ||= []).push({
      id: f.id, kind: f.kind, url: f.kind === "link" ? f.url : null,
      name: f.name, contentType: f.content_type, size: f.size, by: f.uploaded_by, at: f.at,
    });
  }
  for (const n of notes.results) {
    (notesByMat[n.material_id] ||= []).push({ by: n.author, text: n.text, at: n.at });
  }
  return json({
    projects: projects.results.map((p) => ({ id: p.id, name: p.name, color: p.color, order: p.ord, createdAt: p.created_at })),
    materials: materials.results.map((m) => ({
      id: m.id, title: m.title, projectId: m.project_id, desc: m.descr,
      createdBy: m.created_by, createdAt: m.created_at, updatedAt: m.updated_at,
      files: filesByMat[m.id] || [], notes: notesByMat[m.id] || [],
    })),
    tasks: tasks.results.map((t) => ({
      id: t.id, title: t.title, assignee: t.assignee, due: t.due, status: t.status,
      priority: t.priority || "通常", projectId: t.project_id, materialId: t.material_id, note: t.note,
      createdBy: t.created_by, createdAt: t.created_at, updatedAt: t.updated_at,
    })),
    rnd: rndThemes.results.map((th) => ({
      id: th.id, name: th.name, desc: th.descr, createdBy: th.created_by, createdAt: th.created_at, updatedAt: th.updated_at,
      trials: rndTrials.results.filter((tr) => tr.theme_id === th.id).map((tr) => ({
        id: tr.id, seq: tr.seq, ingredients: safeJson(tr.ingredients, []), method: tr.method,
        result: tr.result, rating: tr.rating || 0, aroma: tr.aroma || "", tieBefore: tr.tie_before || "", tieAfter: tr.tie_after || "",
        createdBy: tr.created_by, createdAt: tr.created_at,
        photos: filesByMat[tr.id] || [],
      })),
    })),
  });
}
function safeJson(s, fb) { try { return JSON.parse(s); } catch { return fb; } }
