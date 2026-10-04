/* 光罩交付中心共享 JS（零依赖） */
const $ = (id) => document.getElementById(id);
async function api(method, path, body) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  if (window.CURRENT_USER) opt.headers["X-User"] = window.CURRENT_USER;
  const res = await fetch(path, opt);
  const j = await res.json();
  if (!res.ok) throw j;
  return j;
}
function by() { return { by: window.CURRENT_USER }; }
function tag(v) { return `<span class="tag ${v}">${v}</span>`; }
function toast(msg, ok) {
  const t = document.createElement("div");
  t.className = "toast " + (ok ? "ok" : "err");
  t.textContent = typeof msg === "string" ? msg :
    (msg.error + ": " + msg.message + (msg.detail && Object.keys(msg.detail).length
      ? "\n" + JSON.stringify(msg.detail, null, 1) : ""));
  $("toast").appendChild(t);
  setTimeout(() => t.remove(), 7000);
}
async function loadUsers(active) {
  const { users } = await api("GET", "/api/mask/users");
  const sel = $("user");
  sel.innerHTML = users.map(u => `<option value="${u.id}">${u.name}（${u.roles.join("/")}）</option>`).join("");
  if (active) sel.value = active;
  sel.onchange = () => { window.CURRENT_USER = sel.value; location.reload(); };
}
function short(x) { return x ? x.slice(0, 12) + "…" : ""; }

/* ---------------- 首页：发行/上传/核验 ---------------- */
let CUR = null;
const DEMO = [
  ["layermap", "layer.map", "LAYERMAP chip-A\nLAYER 1 diff\nLAYER 2 poly\nLAYER 3 metal1\n", null],
  ["recipe", "fab.recipe",
   "RECIPE FAB-X12-R3\nLAYER 1\nLAYER 2\nLAYER 3\nCORNER ss_0p81v_m40c\nCORNER ff_0p99v_125c\n", null],
  ["die", "die.dim", "DIE 5000 3000\n", null],
  ["scribe", "scribe.cfg", "SCRIBE WIDTH 80\n", null],
  ["corner", "ss.corner", "CORNER ss_0p81v_m40c\nvdd=0.81\ntemp=-40\n", null],
  ["corner", "ff.corner", "CORNER ff_0p99v_125c\nvdd=0.99\ntemp=125\n", null],
  ["layout", "L01.gds", "# GDS placeholder\n@LAYER 1\n", 1],
  ["layout", "L02.gds", "# GDS placeholder\n@LAYER 2\n", 2],
  ["layout", "L03.gds", "# GDS placeholder\n@LAYER 3\n", 3],
];

async function initHome() {
  if (!document.body.dataset.home) return;
  await loadUsers("u_op");
  window.CURRENT_USER = $("user").value;
  await refreshReleases();
}

async function refreshReleases() {
  const { releases } = await api("GET", "/api/mask/releases");
  $("releases").innerHTML = releases.length ? releases.map(r => `
    <div class="item ${CUR === r.id ? "sel" : ""}" onclick="pickRelease('${r.id}')">
      <b>${r.name}</b> <span class="muted mono">${r.id}</span><br>
      ${tag(r.status)} ${r.delivery_no ? `<span class="mono">${r.delivery_no}</span>` : ""}
      <span class="muted">构件 ${r.artifact_count}</span>
    </div>`).join("") : `<p class="muted">还没有发行</p>`;
  if (CUR) await loadDetail();
  loadQuarantine();
}

async function createRelease() {
  try {
    const r = await api("POST", "/api/mask/releases", { ...by(), name: $("rname").value });
    CUR = r.id; $("uploadPanel").hidden = false;
    toast("已创建发行 " + r.id, true);
    await refreshReleases();
  } catch (e) { toast(e); }
}

async function pickRelease(rid) {
  CUR = rid;
  $("uploadPanel").hidden = false;
  await refreshReleases();
}

async function loadDetail() {
  const r = await api("GET", `/api/mask/releases/${CUR}`);
  $("detailPanel").hidden = false;
  $("dtitle").textContent = `${r.name} · ${r.id}`;
  $("delivery").innerHTML = r.delivery_no
    ? `稳定交付编号 <b class="mono">${r.delivery_no}</b>${r.status === "FINALIZED" ? tag(r.status) : ""}`
    : "";
  const arts = r.artifacts;
  // 构件关系图：layermap/recipe/corners ↔ 版图层
  const layers = arts.filter(a => a.kind === "layout").sort((a, b) => a.slot.localeCompare(b.slot));
  let g = "";
  const lm = arts.find(a => a.kind === "layermap");
  const rp = arts.find(a => a.kind === "recipe");
  const corners = arts.filter(a => a.kind === "corner");
  g += `layermap: ${lm ? lm.name : "（缺）"}\n`;
  g += `recipe  : ${rp ? rp.name : "（缺）"}\n`;
  g += `corners : ${corners.map(c => c.name).join(", ") || "（缺）"}\n`;
  g += `die/scribe: ${arts.find(a => a.kind === "die")?.name || "（缺）"} / `
    + `${arts.find(a => a.kind === "scribe")?.name || "（缺）"}\n`;
  g += "\n版图层（GDS/OASIS）:\n";
  for (const l of layers) {
    g += `  └─ <span class="slot">${l.slot}</span> ${l.name}  ${short(l.sha256)}\n`;
  }
  $("graph").innerHTML = g;
  $("artTable").querySelector("tbody").innerHTML = arts.map(a => `
    <tr><td class="mono">${a.slot}</td><td>${a.kind}</td><td>${a.name}</td>
    <td>v${a.version}</td><td class="mono">${short(a.sha256)}</td>
    <td><a href="/api/mask/artifacts/${a.id}/raw" style="color:var(--accent)">下载</a></td></tr>`).join("");
  const { verifications } = await api("GET", `/api/mask/releases/${CUR}/verifications`);
  $("vrfs").innerHTML = verifications.slice().reverse().map(v => `
    <div style="margin:6px 0">${tag(v.verdict)} <span class="muted">${v.stage} · ${v.created_at}</span>
    ${v.findings.map(f => `<div style="margin-left:14px"><code class="rej">${f.code}</code>
      <span class="tag ${f.severity}">${f.severity}</span> ${f.message}
      <span class="muted">@${f.component || f.slot || "-"}</span></div>`).join("")}
    </div>`).join("") || `<p class="muted">尚无核验</p>`;
}

async function upload() {
  const kind = $("kind").value;
  const payload = { ...by(), kind, name: $("fname").value, content: $("fcontent").value,
    declared_sha256: $("fdigest").value || null, layer_no: null,
    op_id: $("fop").value || null };
  if (kind === "layout") payload.layer_no = Number($("flayer").value) || null;
  try {
    const a = await api("POST", `/api/mask/releases/${CUR}/artifacts`, payload);
    toast(`已入库 ${a.slot}（blob ${short(a.sha256)}）` +
      (a.quarantined ? "\n⚠ 同名异物已进隔离区等待处置" : ""), true);
    $("fop").value = "";
    await refreshReleases();
  } catch (e) { toast(e); await refreshReleases(); }
}

async function verify() {
  try {
    const v = await api("POST", `/api/mask/releases/${CUR}/verify`);
    toast("核验 " + v.verdict + (v.verdict === "FAIL" ? `：${v.findings.length} 条问题` : ""),
      v.verdict === "PASS");
    await loadDetail();
  } catch (e) { toast(e); }
}

async function finalizeRel() {
  const op = "op-fin-" + Math.random().toString(16).slice(2, 10);
  try {
    const r = await api("POST", `/api/mask/releases/${CUR}/finalize`,
      { ...by(), op_id: op });
    toast(`交付编号 ${r.delivery_no}` + (r.deduped ? "（重复导入，复用编号）" : ""), true);
    await refreshReleases();
  } catch (e) { toast(e); }
}

async function makeSet() {
  try {
    const s = await api("POST", "/api/mask/sets",
      { ...by(), release_id: CUR, name: "mask-set-" + CUR.slice(-6) });
    toast("主版 mask set 已生成 " + s.id, true);
  } catch (e) { toast(e); }
}

async function loadQuarantine() {
  const { quarantines } = await api("GET", "/api/mask/quarantine");
  $("quarantine").innerHTML = quarantines.length ? quarantines.map(q => `
    <div class="item">
      <b>${q.name}</b> <span class="tag ${q.status}">${q.status}</span>
      <div class="muted">${q.kind} · 既有 ${short(q.existing_blob)} vs 新入 ${short(q.incoming_blob)}</div>
      <div class="row">
        <button class="danger" onclick="resolveQ('${q.id}','REJECT_INCOMING')">退回异物</button>
        <button class="ghost" onclick="resolveQ('${q.id}','ACCEPT_NEW')">登记知悉（保留）</button>
      </div>
    </div>`).join("") : `<p class="muted">无待处置冲突</p>`;
}

async function resolveQ(qid, resolution) {
  try {
    await api("POST", `/api/mask/quarantine/${qid}/resolve`, { ...by(), resolution });
    toast("已处置", true); await refreshReleases();
  } catch (e) { toast(e); }
}

function fillDemo() {
  const kind = $("kind").value;
  const found = DEMO.filter(d => d[0] === kind);
  const idx = DEMO_UPLOAD[kind] = (DEMO_UPLOAD[kind] || 0) % Math.max(found.length, 1);
  const [, name, content, lno] = found[idx] || [];
  if (!name) { toast("该类型演示资料已填完"); return; }
  DEMO_UPLOAD[kind]++;
  $("fname").value = name; $("fcontent").value = content;
  if (lno) $("flayer").value = lno;
}
const DEMO_UPLOAD = {};

/* ---------------- 引导 ---------------- */
document.addEventListener("DOMContentLoaded", () => {
  if (document.body.dataset.home) initHome().catch(e => toast(e));
  if (document.body.dataset.schedule) initSchedule().catch(e => toast(e));
  if (document.body.dataset.fab) initFab().catch(e => toast(e));
});
