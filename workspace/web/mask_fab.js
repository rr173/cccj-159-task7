/* 晶圆厂交付包页 JS（零依赖） */
let SETS = null;

async function initFab() {
  await loadUsers("u_op");
  window.CURRENT_USER = $("user").value;
  await refresh();
}

async function refresh() {
  const [{ mask_sets }, { exports }] = await Promise.all([
    api("GET", "/api/mask/sets"), api("GET", "/api/mask/exports")]);
  SETS = mask_sets;
  const full = await Promise.all(SETS.map(s => api("GET", `/api/mask/sets/${s.id}`)));
  window._setsFull = full;
  $("set").innerHTML = full.map(s => `
    <option value="${s.id}">${s.name} [${s.kind}] — R${s.nodes.at(-1).seq}
      节点, ${s.release_id.slice(0,10)}…</option>`).join("");
  loadNodes(exports);
  renderJobs(exports);
  const { events } = await api("GET", "/api/mask/audit?limit=40");
  $("audit").innerHTML = events.map(e => `
    <tr><td class="muted" style="font-size:11px">${e.at.slice(0,19)}</td>
    <td>${e.action}</td><td class="mono" style="font-size:11px">${(e.entity||"").slice(0,16)}</td>
    <td>${tag(e.result)}</td>
    <td>${e.reason ? `<code class="rej">${e.reason}</code>` : ""}</td>
    <td>${e.actor || "-"}</td></tr>`).join("");
}

function loadNodes(exports) {
  const s = window._setsFull.find(x => x.id === $("set").value);
  $("node").innerHTML = (s?.nodes || []).map(n => `
    <option value="${n.id}">R${n.seq} ${n.kind} ${n.label} [${n.status}]</option>`).join("");
  if (exports) renderJobs(exports);
}

function renderJobs(exports) {
  $("jobs").innerHTML = exports.slice().reverse().slice(0, 20).map(e => `
    <tr><td class="mono" style="font-size:11px">${e.id.slice(4,14)}</td>
    <td class="mono" style="font-size:11px">${e.node_id.slice(8,18)}</td>
    <td>${tag(e.state)}</td>
    <td>${e.state === "DONE" ? `
      <a href="/api/mask/exports/${e.id}/zip" style="color:var(--accent)">下载 ZIP</a>
      <a href="#" onclick="showManifest('${e.id}');return false" style="color:var(--accent)">清单</a>`
      : e.state === "FAILED" ? `<code class="rej">${e.error}</code>` : ""}</td></tr>`).join("");
}

async function doExport() {
  try {
    const e = await api("POST", "/api/mask/exports",
      { ...by(), node_id: $("node").value, op_id: $("op").value });
    toast(`导出作业 ${e.id} 已排队`, true);
    await new Promise(r => setTimeout(r, 1200));
    await refresh();
    const done = await api("GET", `/api/mask/exports/${e.id}`);
    if (done.state === "DONE") $("op").value = "op-export-" + Math.random().toString(16).slice(2, 8);
    if (done.manifest_json) showManifestObj(JSON.parse(done.manifest_json));
  } catch (err) { toast(err); }
}

async function recover() {
  try {
    const r = await api("POST", "/api/mask/admin/recover", {});
    toast(`已恢复/续完 ${r.recovered.length} 个作业`, true);
    await refresh();
  } catch (e) { toast(e); }
}

async function showManifest(eid) {
  const e = await api("GET", `/api/mask/exports/${eid}`);
  showManifestObj(JSON.parse(e.manifest_json));
}

function showManifestObj(m) {
  $("manifest").textContent = JSON.stringify(m, null, 2);
}
