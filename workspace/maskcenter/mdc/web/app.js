/* 光罩投片交付中心 —— 原生 JS 单页界面 */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const view = $("#view"), nav = $("#nav"), actorSel = $("#actor");

const TABS = [
  ["dashboard", "总览"], ["content", "资料上传"], ["import", "发行导入"],
  ["artifacts", "构件关系"], ["sets", "发行 / Mask Set"],
  ["schedule", "曝光排程"], ["replace", "替换与返工"], ["packages", "交付包"],
  ["quarantine", "隔离处置"], ["audit", "审计 / 裁决"],
];

function toast(msg, kind = "info", ms = 6000) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toast").appendChild(el);
  setTimeout(() => el.remove(), ms);
}

async function api(path, opts = {}) {
  const headers = Object.assign({"X-Person-Id": actorSel.value}, opts.headers || {});
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
    delete opts.json;
  }
  if (opts.op) headers["X-Op-Id"] = opts.op;
  const r = await fetch(path, Object.assign({headers}, opts));
  const ct = r.headers.get("Content-Type") || "";
  if (ct.includes("application/json")) {
    const data = await r.json();
    if (!r.ok) throw Object.assign(new Error(data.message || data.error), data);
    return data;
  }
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r;
}

function tag(v) { return `<span class="tag t-${v}">${v ?? ""}</span>`; }
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function tsShort(s) { return s ? s.replace("T", " ").replace("Z", "Z") : ""; }

function findingsBlock(findings) {
  if (!findings || !findings.length)
    return `<div class="muted">无不一致（全部校验通过）</div>`;
  return findings.map(f => `
    <div class="finding ${f.severity}">
      <b>${f.severity === "error" ? "拒收" : "警告"} · ${esc(f.code)}</b> — ${esc(f.message)}
      <div class="muted mono">${esc(JSON.stringify(f.locator || {}))}</div>
    </div>`).join("");
}

// --------------------------------------------------------------- 框架
async function init() {
  nav.innerHTML = TABS.map(([id, name]) =>
    `<button data-tab="${id}">${name}</button>`).join("");
  nav.onclick = e => { const t = e.target.closest("button"); if (t) go(t.dataset.tab); };
  const people = await api("/api/people");
  actorSel.innerHTML = people.map(p =>
    `<option value="${p.id}">${esc(p.name)}（${p.roles.join("/")}）</option>`).join("");
  actorSel.value = "u_disp1";
  const hash = location.hash.slice(1) || "dashboard";
  go(TABS.some(t => t[0] === hash) ? hash : "dashboard");
}
function go(tab) {
  $$("#nav button").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  location.hash = tab;
  (PAGES[tab] || PAGES.dashboard)();
}

const PAGES = {};

// --------------------------------------------------------------- 总览
PAGES.dashboard = async () => {
  view.innerHTML = `<div class="card"><h2>中心状态</h2><div id="d"></div></div>`;
  const [sets, lots, windows, pkgs, q] = await Promise.all([
    api("/api/sets"), api("/api/lots"), api("/api/windows"),
    api("/api/packages"), api("/api/quarantine?status=PENDING")]);
  const counts = (rows, key) => rows.reduce((a, r) =>
    (a[r[key]] = (a[r[key]] || 0) + 1, a), {});
  $("#d").innerHTML = `
    <div class="grid">
      <div><b>Mask set 节点</b><div class="pillline">${
        Object.entries(counts(sets, "status")).map(([k, v]) =>
          `${tag(k)}×${v}`).join(" ")}</div><div class="muted">谱系 ${new Set(sets.map(s=>s.lineage_id)).size} 条</div></div>
      <div><b>Wafer lot</b><div class="pillline">${
        Object.entries(counts(lots, "state")).map(([k, v]) =>
          `${tag(k)}×${v}`).join(" ") || '<span class="muted">无</span>'}</div></div>
      <div><b>曝光窗口</b><div class="pillline">${
        Object.entries(counts(windows, "state")).map(([k, v]) =>
          `${tag(k)}×${v}`).join(" ") || '<span class="muted">无</span>'}</div></div>
      <div><b>交付包</b><div class="pillline">${
        Object.entries(counts(pkgs, "status")).map(([k, v]) =>
          `${tag(k)}×${v}`).join(" ") || '<span class="muted">无</span>'}</div></div>
      <div><b>待处置隔离</b><div class="pillline">${
        q.length ? `<span class="tag t-QUARANTINED">PENDING×${q.length}</span>`
                 : '<span class="muted">无</span>'}</div></div>
    </div>
    <p class="muted" style="margin-top:14px">稳定交付编号在"发行导入"成功后生成（<code>MS-…</code>）；
    排程抢占由系统产生唯一赢家；曝光一旦开始，原节点永久封存。</p>`;
};

// --------------------------------------------------------------- 上传
PAGES.content = () => {
  view.innerHTML = `
  <div class="card"><h2>上传资料（内容寻址，重复内容不复制实体）</h2>
    <div class="row">
      <div class="field"><label>文件</label><input type="file" id="f"></div>
      <div class="field"><label>逻辑名</label><input id="nm" placeholder="chipA.gds"></div>
      <div class="field"><label>类型</label><select id="kd">
        <option>GDS</option><option>OASIS</option><option>LAYERMAP</option>
        <option>RECIPE</option><option selected>OTHER</option></select></div>
      <div class="field"><label>声明 SHA-256（可选，错则拒收）</label>
        <input id="dsha" style="width:280px" placeholder="留空由服务端计算"></div>
      <button class="btn" id="up">上传</button>
    </div>
  </div>
  <div class="card"><h2>已登记构件</h2><div id="lst"><span class="muted">加载中…</span></div></div>`;
  $("#up").onclick = async () => {
    const f = $("#f").files[0]; if (!f) return toast("先选文件", "err");
    $("#nm").value || ($("#nm").value = f.name);
    try {
      const r = await api("/api/content", {
        method: "POST", body: f, headers: {
          "X-Logical-Name": $("#nm").value, "X-Kind": $("#kd").value,
          ...($("#dsha").value ? {"X-Sha256": $("#dsha").value} : {})}});
      toast(r.quarantined
        ? `同名异物，已隔离等待处置：${r.quarantine_id}`
        : (r.dedup ? `内容去重，复用既有构件 ${r.sha256.slice(0, 12)}…`
                   : `登记成功 ${r.sha256.slice(0, 12)}…`),
        r.quarantined ? "info" : "ok");
      PAGES.content();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  loadArtifacts("#lst");
};

async function loadArtifacts(sel) {
  const rows = await api("/api/artifacts");
  $(sel).innerHTML = `<table><thead><tr><th>逻辑名</th><th>类型</th><th>SHA-256</th>
    <th>大小</th><th>状态</th><th>摘要核验</th></tr></thead><tbody>${
    rows.map(a => `<tr><td><a onclick="detailArtifact('${a.sha256}')">${esc(a.logical_name)}</a></td>
      <td>${a.kind}</td><td class="mono">${a.sha256.slice(0,16)}…</td>
      <td>${a.size}</td><td>${tag(a.status)}</td>
      <td>${a.verified ? "✅" : "❌ 篡改"}</td></tr>`).join("")}
  </tbody></table>`;
}
window.detailArtifact = async (sha) => { go("artifacts"); setTimeout(() => {
  $("#q").value = sha; $("#run").click(); }, 50); };

// --------------------------------------------------------------- 导入
const EXAMPLE = () => ({
  release_name: "DEMO-RX", corner: "TT_0p90_25C", fab: "FAB12",
  foundry_recipe_id: "FAB12-RCP-7",
  die: {width_um: 5000, height_um: 3000}, scribe_um: 80,
  entries: [
    {role: "GDS", logical_name: "DEMO.gds", sha256: "<上传 GDS 后填入>",
     layer_inventory: ["L100.0", "L101.0", "L200.0"]},
    {role: "LAYERMAP", logical_name: "DEMO.layers.json", sha256: "<…>"},
    {role: "RECIPE", logical_name: "FAB12-RCP-7.json", sha256: "<…>"},
    {role: "MASK:M_MAIN", logical_name: "m_main.gds", sha256: "<…>"},
    {role: "MASK:M_IL", logical_name: "m_il.gds", sha256: "<…>"},
  ]});

PAGES.import = () => {
  view.innerHTML = `
  <div class="card"><h2>导入某次芯片发行</h2>
    <div class="row" style="margin-bottom:8px">
      <button class="btn sec" id="ex">填入示例骨架</button>
      <button class="btn sec" id="demo">一键生成可导入演示资料</button>
      <span class="muted">完整资料通过校验后得到稳定交付编号；重复导入不复制实体。</span>
    </div>
    <textarea id="packet" rows="20" style="width:100%;font-family:ui-monospace,monospace;
      font-size:12px" placeholder='{"release_name":...}'></textarea>
    <div class="row" style="margin-top:8px">
      <button class="btn" id="go">校验并规范化导入</button></div>
    <div id="res" style="margin-top:12px"></div>
  </div>`;
  $("#ex").onclick = () => $("#packet").value = JSON.stringify(EXAMPLE(), null, 2);
  $("#demo").onclick = async () => {
    const p = await api("/api/demo-packet", {}).catch(() => null);
    if (p && p.packet) $("#packet").value = JSON.stringify(p.packet, null, 2);
    else toast("演示接口不可用，请手工上传后填写", "err");
  };
  $("#go").onclick = async () => {
    let packet;
    try { packet = JSON.parse($("#packet").value); }
    catch (e) { return toast("JSON 格式错误：" + e.message, "err"); }
    try {
      const r = await api("/api/imports", {method: "POST", json: packet});
      $("#res").innerHTML = `
        <div class="pillline">${tag(r.status)}
          ${r.delivery_no ? `<b>交付编号 <code>${r.delivery_no}</code></b>` : ""}
          ${r.replayed ? '<span class="tag t-READY">重复导入·回放未复制实体</span>' : ""}
        </div>
        <div class="muted">release_id=${r.release_id} · 错误 ${r.error_count} · 警告 ${r.warning_count}</div>
        ${findingsBlock(r.findings)}`;
      if (r.status === "VALID") toast(`导入成功：${r.delivery_no}`, "ok");
    } catch (e) {
      $("#res").innerHTML = `<div class="finding error"><b>${esc(e.error)}</b> — ${esc(e.message)}
        <div class="muted mono">${esc(JSON.stringify(e.detail || {}))}</div></div>`;
      toast(`${e.error}: ${e.message}`, "err");
    }
  };
};

// --------------------------------------------------------------- 构件关系
PAGES.artifacts = () => {
  view.innerHTML = `
  <div class="card"><h2>构件关系与可追溯链路</h2>
    <div class="row"><div class="field"><label>SHA-256 或逻辑名</label>
      <input id="q" style="width:340px"></div>
      <button class="btn" id="run">查询</button></div>
    <div id="out" style="margin-top:10px"></div></div>
  <div class="card"><h2>全部构件</h2><div id="lst"></div></div>`;
  $("#run").onclick = async () => {
    const key = $("#q").value.trim(); if (!key) return;
    const isSha = /^[0-9a-fA-F]{64}$/.test(key);
    try {
      const r = await api(`/api/artifacts/${key}?${isSha ? "" : "name=1"}`);
      $("#out").innerHTML = `
        <h3>${esc(r.artifact.logical_name)} <span class="muted mono">${r.artifact.sha256.slice(0,16)}…</span></h3>
        <div class="muted">别名：${r.aliases.map(esc).join(", ") || "—"}</div>
        <h4>所属发行</h4>
        <table><thead><tr><th>release</th><th>名称</th><th>角色</th><th>交付编号</th><th>状态</th></tr></thead>
        <tbody>${r.releases.map(x => `<tr><td class="mono">${x.release_id}</td><td>${esc(x.release_name)}</td>
          <td>${x.role}</td><td>${x.delivery_no ? `<a onclick="go('sets')">${x.delivery_no}</a>` : "—"}</td>
          <td>${tag(x.status)}</td></tr>`).join("") || '<tr><td colspan=5 class=muted>无</td></tr>'}</tbody></table>
        <h4>Mask set 成员关系</h4>
        <table><thead><tr><th>set</th><th>交付编号</th><th>mask</th><th>角色</th><th>set 状态</th></tr></thead>
        <tbody>${r.mask_set_memberships.map(x => `<tr><td class="mono">${x.set_id}</td>
          <td>${x.delivery_no}</td><td>${x.mask_name}</td><td>${tag(x.role_type)}</td>
          <td>${tag(x.status)}</td></tr>`).join("") || '<tr><td colspan=5 class=muted>无</td></tr>'}</tbody></table>`;
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  loadArtifacts("#lst");
};

// --------------------------------------------------------------- 发行 / Sets
PAGES.sets = async () => {
  view.innerHTML = `<div class="card"><h2>发行与 Mask Set 谱系</h2><div id="s">加载中…</div></div>
  <div class="card" id="detail" hidden><h2>节点详情 / 核验结论</h2><div id="dc"></div></div>`;
  const [rels, sets] = await Promise.all([api("/api/releases"), api("/api/sets")]);
  $("#s").innerHTML = `
  <table><thead><tr><th>发行</th><th>名称</th><th>状态</th><th>Mask Set 节点</th></tr></thead><tbody>${
    rels.map(r => {
      const ss = sets.filter(x => true);
      return `<tr><td class="mono">${r.id}</td><td>${esc(r.name)}</td><td>${tag(r.status)}</td>
      <td><a onclick="releaseDetail('${r.id}')">查看核验</a></td></tr>`;
    }).join("")}</tbody></table>
  <h3 style="margin-top:16px">谱系节点</h3>
  <table><thead><tr><th>交付编号</th><th>谱系</th><th>#</th><th>类型</th><th>状态</th>
  <th>标题</th><th></th></tr></thead><tbody>${
    sets.map(s => `<tr><td><code>${s.delivery_no}</code></td><td class="mono">${s.lineage_id}</td>
      <td>${s.seq}</td><td>${tag(s.kind)}</td><td>${tag(s.status)}</td>
      <td>${esc(s.title)}</td>
      <td><a onclick="setDetail('${s.delivery_no}')">构件关系/次序</a></td></tr>`).join("")}
  </tbody></table>`;
};
window.releaseDetail = async (id) => {
  const r = await api("/api/releases/" + id);
  $("#detail").hidden = false;
  $("#dc").innerHTML = `<div class="pillline">${tag(r.status)}
    ${r.delivery_no ? `<b>${r.delivery_no}</b>` : ""}</div>
    <div class="muted">die ${r.die_width_um}×${r.die_height_um} µm · scribe ${r.scribe_um} µm
    · 工艺角 ${esc(r.corner)} · ${esc(r.fab)} / ${esc(r.foundry_recipe_id)}</div>
    <h4>构件角色</h4><table><thead><tr><th>角色</th><th>逻辑名</th><th>SHA</th></tr></thead>
    <tbody>${r.artifacts.map(a => `<tr><td>${a.role}</td><td>${esc(a.logical_name)}</td>
      <td class="mono">${a.sha256.slice(0,16)}…</td></tr>`).join("")}</tbody></table>
    <h4>核验结论（${r.findings_json.length} 条，定位到构件）</h4>${findingsBlock(r.findings_json)}`;
  $("#detail").scrollIntoView({behavior: "smooth"});
};
window.setDetail = async (key) => {
  const s = await api("/api/sets/" + key);
  $("#detail").hidden = false;
  $("#dc").innerHTML = `
    <div class="pillline">${tag(s.status)} ${tag(s.kind)} <code>${s.delivery_no}</code>
      ${s.sealed_at ? `<span class="muted">封存于 ${tsShort(s.sealed_at)}</span>` : ""}</div>
    <h4>曝光先后次序（主版→修正版→派生层）</h4>
    <div>${s.order.map((m, i) => `${i + 1}. ${m}`).join(" → ")}</div>
    <h4>构件</h4>
    <table><thead><tr><th>mask</th><th>角色</th><th>层</th><th>构件</th><th>SHA</th></tr></thead>
    <tbody>${s.members.map(m => `<tr><td>${m.mask_name}</td><td>${tag(m.role_type)}</td>
      <td>${m.layer ?? ""}</td><td>${esc(m.logical_name)}</td>
      <td class="mono">${m.sha256.slice(0,14)}…</td></tr>`).join("")}</tbody></table>
    <h4>依赖边</h4><div>${s.edges.map(e =>
      `${e.src} → ${e.dst} <span class=muted>(${esc(e.reason)})</span>`).join("<br>") || "无"}</div>`;
  $("#detail").scrollIntoView({behavior: "smooth"});
};

// --------------------------------------------------------------- 排程
PAGES.schedule = async () => {
  view.innerHTML = `
  <div class="card"><h2>曝光机与 lot</h2>
    <div class="row">
      <div class="field"><label>新曝光机</label><input id="tn" placeholder="STEPPER-A"></div>
      <button class="btn" id="ct">登记曝光机</button>
      <div class="field" style="margin-left:20px"><label>新 lot</label><input id="ln" placeholder="LOT-2026-A1"></div>
      <button class="btn" id="cl">登记 lot</button></div>
    <div id="res" style="margin-top:10px"></div></div>
  <div class="card"><h2>预订曝光窗口（每台曝光机时间段排他）</h2>
    <div class="grid">
      <div class="field"><label>曝光机</label><select id="wtool"></select></div>
      <div class="field"><label>Mask Set</label><select id="wset"></select></div>
      <div class="field"><label>mask</label><select id="wmask"></select></div>
      <div class="field"><label>lot（可选）</label><select id="wlot"><option value="">—</option></select></div>
      <div class="field"><label>开始</label><input id="ws" value="2026-10-10T08:00:00Z"></div>
      <div class="field"><label>结束</label><input id="we" value="2026-10-10T10:00:00Z"></div>
      <div class="field"><label>操作编号（可选）</label><input id="wop" placeholder="OP-…"></div>
    </div>
    <div class="row" style="margin-top:8px"><button class="btn" id="wr">预订</button></div>
  </div>
  <div class="card"><h2>窗口 / 绑定 / 曝光</h2><div id="wl"></div></div>`;
  const [tools, sets, lots, wins] = await Promise.all([
    api("/api/tools"), api("/api/sets"), api("/api/lots"), api("/api/windows")]);
  $("#res").innerHTML = `
    <table style="margin-bottom:10px"><thead><tr><th>曝光机</th><th>id</th></tr></thead>
    <tbody>${tools.map(t => `<tr><td>${esc(t.name)}</td><td class="mono">${t.id}</td></tr>`).join("") || '<tr><td colspan=2 class=muted>无</td></tr>'}</tbody></table>
    <table><thead><tr><th>lot</th><th>id</th><th>状态</th><th>当前 set</th><th>绑定</th></tr></thead>
    <tbody>${lots.map(l => `<tr><td>${esc(l.display_name)}</td><td class="mono">${l.id}</td>
      <td>${tag(l.state)}</td><td>${l.set_id ? `<code>${l.set_id}</code>` : "—"}</td>
      <td><select id="bind-${l.id}"><option value="">（解绑目标）</option>${
        sets.filter(s => s.status !== "SUPERSEDED").map(s =>
          `<option value="${s.delivery_no}" ${l.set_id === s.id ? "selected" : ""}>${s.delivery_no}</option>`).join("")}
      </select> <a onclick="doBind('${l.id}', document.getElementById('bind-${l.id}').value)">绑定</a></td></tr>`).join("")
      || '<tr><td colspan=5 class=muted>无</td></tr>'}</tbody></table>`;
  $("#wtool").innerHTML = tools.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join("");
  const activeSets = sets.filter(s => s.status === "ACTIVE");
  $("#wset").innerHTML = activeSets.map(s =>
    `<option value="${s.delivery_no}">${s.delivery_no}（${esc(s.title)}）</option>`).join("");
  $("#wlot").innerHTML = '<option value="">—</option>' + lots.map(l =>
    `<option value="${l.id}">${esc(l.display_name)}</option>`).join("");
  async function refreshMasks() {
    if (!$("#wset").value) return;
    const s = await api("/api/sets/" + $("#wset").value);
    $("#wmask").innerHTML = s.order.map(m => `<option>${m}</option>`).join("");
  }
  $("#wset").onchange = refreshMasks;
  if (activeSets.length) refreshMasks();
  $("#ct").onclick = async () => api("/api/tools", {method: "POST", json: {name: $("#tn").value}})
    .then(() => { toast("已登记", "ok"); PAGES.schedule(); }).catch(e => toast(e.message, "err"));
  $("#cl").onclick = async () => api("/api/lots", {method: "POST", json: {display_name: $("#ln").value}})
    .then(() => { toast("已登记", "ok"); PAGES.schedule(); }).catch(e => toast(e.message, "err"));
  $("#wr").onclick = async () => {
    try {
      const r = await api("/api/windows", {method: "POST",
        json: {tool_id: $("#wtool").value, set: $("#wset").value, mask: $("#wmask").value,
               lot_id: $("#wlot").value || null,
               start_ts: $("#ws").value, end_ts: $("#we").value},
        op: $("#wop").value || undefined});
      toast(`窗口已预订 ${r.window_id}`, "ok"); refreshWins();
    } catch (e) {
      const d = e.detail || {};
      toast(`${e.error}\n${e.message}` + (d.winner_op_id ? `\n赢家操作：${d.winner_op_id}` : ""),
            "err", 9000);
    }
  };
  window.doBind = async (lot, set) => {
    if (!set) return toast("请选择要绑定的 set", "err");
    try { await api(`/api/lots/${lot}/bind`, {method: "POST", json: {set}});
      toast("已绑定（同一 lot 仅一个当前 set）", "ok"); PAGES.schedule();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  async function refreshWins() {
    const [ws, ss, ts] = await Promise.all([api("/api/windows"), api("/api/sets"), api("/api/tools")]);
    const sn = Object.fromEntries(ss.map(s => [s.id, s.delivery_no]));
    const tn = Object.fromEntries(ts.map(t => [t.id, t.name]));
    $("#wl").innerHTML = `<table><thead><tr><th>窗口</th><th>曝光机</th><th>set</th><th>mask</th>
      <th>lot</th><th>开始</th><th>结束</th><th>状态</th><th>操作</th></tr></thead><tbody>${
      ws.map(w => `<tr><td class="mono">${w.id}</td><td>${esc(tn[w.tool_id] || w.tool_id)}</td>
        <td><code>${sn[w.set_id] || w.set_id}</code></td><td>${w.mask_name}</td>
        <td>${w.lot_id || "—"}</td><td>${tsShort(w.start_ts)}</td><td>${tsShort(w.end_ts)}</td>
        <td>${tag(w.state)}</td><td>${
          w.state === "RESERVED"
            ? `<a onclick="doExpose('${w.id}')">执行曝光</a> · <a onclick="doCancel('${w.id}')">取消</a>`
            : ""}</td></tr>`).join("") || '<tr><td colspan=9 class=muted>无窗口</td></tr>'}</tbody></table>`;
  }
  window.doExpose = async (id) => {
    try { const r = await api(`/api/windows/${id}/expose`, {method: "POST"});
      toast(r.first_exposure ? "曝光成功：原节点已永久封存" : "曝光成功", "ok");
      PAGES.schedule();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  window.doCancel = async (id) => {
    try { await api(`/api/windows/${id}/cancel`, {method: "POST"});
      toast("已取消", "ok"); PAGES.schedule();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  refreshWins();
};

// --------------------------------------------------------------- 替换 / 返工
PAGES.replace = async () => {
  view.innerHTML = `
  <div class="card"><h2>曝光前替换单构件（制造工程师 + 版图负责人两签，不可同一自然人）</h2>
    <div class="grid">
      <div class="field"><label>当前 ACTIVE set</label><select id="rset"></select></div>
      <div class="field"><label>mask</label><select id="rmask"></select></div>
      <div class="field"><label>新构件 SHA-256</label><input id="rsha" style="width:260px"></div>
      <div class="field"><label>原因</label><input id="rwhy"></div>
    </div>
    <div class="row" style="margin-top:8px">
      <button class="btn" id="rreq">发起替换（以当前登录人）</button></div>
  </div>
  <div class="card"><h2>待决 / 已决替换</h2><div id="rps"></div></div>
  <div class="card"><h2>曝光后：Delta set + 返工计划（原节点永久封存）</h2>
    <div class="grid">
      <div class="field"><label>已封存 set</label><select id="dset"></select></div>
      <div class="field"><label>变化项 mask=SHA（每行一个）</label>
        <textarea id="dch" rows="2" style="width:320px" placeholder="M_MAIN=sha256&#10;M_IL=sha256"></textarea></div>
      <div class="field"><label>已曝光 lot</label><select id="dlot"></select></div>
    </div>
    <div class="row" style="margin-top:8px">
      <button class="btn" id="dgo">创建 delta</button>
      <button class="btn sec" id="rwk">为 lot 创建返工计划</button></div>
    <div id="rwlist" style="margin-top:10px"></div></div>`;
  const [sets, arts, lots, rps, rws] = await Promise.all([
    api("/api/sets"), api("/api/artifacts"), api("/api/lots"),
    api("/api/replacements"), api("/api/rework-plans")]);
  const act = sets.filter(s => s.status === "ACTIVE");
  $("#rset").innerHTML = act.map(s =>
    `<option value="${s.delivery_no}">${s.delivery_no}</option>`).join("");
  async function rmasks() {
    const s = await api("/api/sets/" + $("#rset").value);
    $("#rmask").innerHTML = s.order.map(m => `<option>${m}</option>`).join("");
  }
  $("#rset").onchange = rmasks; if (act.length) rmasks();
  $("#dset").innerHTML = sets.filter(s => s.status === "SEALED").map(s =>
    `<option value="${s.delivery_no}">${s.delivery_no}（${esc(s.title)}）</option>`).join("")
    || '<option value="">（无封存节点）</option>';
  $("#dlot").innerHTML = '<option value="">—</option>' + lots.filter(l => l.state === "EXPOSED")
    .map(l => `<option value="${l.id}">${esc(l.display_name)}</option>`).join("");
  $("#rreq").onclick = async () => {
    try { const r = await api("/api/replacements", {method: "POST", json: {
      set: $("#rset").value, mask: $("#rmask").value, new_sha: $("#rsha").value.trim(),
      reason: $("#rwhy").value}});
      toast(`替换申请 ${r.replacement_id}，等待两签`, "ok"); PAGES.replace();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  $("#dgo").onclick = async () => {
    const changes = $("#dch").value.trim().split("\n").filter(Boolean).map(line => {
      const [mask_name, new_sha] = line.split("=").map(x => x.trim());
      return {mask_name, new_sha};
    });
    try { const r = await api("/api/deltas", {method: "POST",
      json: {set: $("#dset").value, changes}});
      toast(`Delta 已创建：${r.delivery_no}`, "ok"); PAGES.replace();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err", 9000); }
  };
  $("#rwk").onclick = async () => {
    const lot = $("#dlot").value; if (!lot) return toast("选择已曝光 lot", "err");
    try { const r = await api("/api/rework-plans", {method: "POST",
      json: {lot_id: lot, delta: $("#dset").value}});
      toast(`返工计划 ${r.rework_plan_id}`, "ok");
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  $("#rps").innerHTML = `<table><thead><tr><th>申请</th><th>set</th><th>mask</th>
    <th>新构件</th><th>状态</th><th>批准</th><th>操作</th></tr></thead><tbody>${
    rps.map(r => `<tr><td class="mono">${r.id}</td><td>${r.set_id.slice(0,18)}…</td>
      <td>${r.mask_name}</td><td class="mono">${r.new_sha.slice(0,12)}…</td>
      <td>${tag(r.status)}</td><td>${(r.approvers || []).map(a =>
        `<code>${esc(a)}</code>`).join(" ") || "—"}</td>
      <td>${r.status === "PENDING"
        ? `<a onclick="rpApprove('${r.id}')">批准（当前登录人）</a> ·
           <a onclick="rpReject('${r.id}')">驳回</a>` : (r.new_set_id || "")}</td></tr>`)
      .join("") || '<tr><td colspan=7 class=muted>无</td></tr>'}</tbody></table>`;
  window.rpApprove = async (id) => {
    try { const r = await api(`/api/replacements/${id}/approve`, {method: "POST"});
      if (r.status === "PENDING") toast("已记录第一签，等待另一角色（不同自然人）", "ok");
      else toast(`替换执行：新节点 ${r.new_delivery_no}，${r.migrated_windows.length} 个窗口已重排`, "ok");
      PAGES.replace();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  window.rpReject = async (id) => {
    try { await api(`/api/replacements/${id}/reject`, {method: "POST"});
      toast("已驳回", "ok"); PAGES.replace();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  $("#rwlist").innerHTML = `<h4>返工计划</h4><table><thead><tr><th>计划</th><th>lot</th>
    <th>delta set</th><th>状态</th><th>备注</th></tr></thead><tbody>${
    rws.map(r => `<tr><td class="mono">${r.id}</td><td>${r.lot_id}</td>
      <td>${r.delta_set_id.slice(0,18)}…</td><td>${tag(r.status)}</td>
      <td>${esc(r.note)}</td></tr>`).join("") || '<tr><td colspan=5 class=muted>无</td></tr>'}
    </tbody></table>`;
};

// --------------------------------------------------------------- 交付包
PAGES.packages = async () => {
  view.innerHTML = `
  <div class="card"><h2>导出晶圆厂只读交付包</h2>
    <div class="row"><div class="field"><label>Mask Set（编号或 id）</label>
      <select id="ps"></select></div>
      <div class="field"><label>操作编号（可选）</label><input id="pop"></div>
      <button class="btn" id="b">构建/复用交付包</button></div>
    <div class="muted">崩溃后重启会自动续建 BUILDING 的包；包文件 0444 只读，下载时重新校验摘要。</div>
  </div><div class="card" id="lst"></div>`;
  const [sets, pkgs] = await Promise.all([api("/api/sets"), api("/api/packages")]);
  $("#ps").innerHTML = sets.filter(s => s.status !== "SUPERSEDED").map(s =>
    `<option value="${s.delivery_no}">${s.delivery_no}（${tag(s.status)} ${s.kind}）</option>`).join("");
  $("#b").onclick = async () => {
    try { const r = await api("/api/packages", {method: "POST",
      json: {set: $("#ps").value}, op: $("#pop").value || undefined});
      toast(r.reused ? `复用既有交付包 ${r.package_id}` : `交付包就绪 ${r.package_id}`, "ok");
      load();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
  async function load() {
    const ps = await api("/api/packages");
    $("#lst").innerHTML = `<h2>已构建</h2><table><thead><tr><th>包</th><th>set</th><th>状态</th>
      <th>摘要</th><th></th></tr></thead><tbody>${ps.map(p => `<tr><td class="mono">${p.id}</td>
      <td>${p.set_id.slice(0,16)}…</td><td>${tag(p.status)}</td>
      <td class="mono">${(p.sha256 || "").slice(0,16)}…</td>
      <td>${p.status === "READY"
        ? `<a href="/api/packages/${p.id}/download">下载只读包</a>` : (p.error || "")}</td></tr>`)
      .join("")}</tbody></table>`;
  }
  load();
};

// --------------------------------------------------------------- 隔离
PAGES.quarantine = async () => {
  view.innerHTML = `<div class="card"><h2>同名异物 / 同名发行 隔离处置</h2><div id="q"></div></div>`;
  const rows = await api("/api/quarantine");
  $("#q").innerHTML = `<table><thead><tr><th>隔离项</th><th>逻辑名</th><th>对象 SHA</th>
    <th>原因</th><th>状态</th><th>检出时间</th><th>处置</th></tr></thead><tbody>${
    rows.map(q => `<tr><td class="mono">${q.id}</td><td>${esc(q.logical_name)}</td>
      <td class="mono">${q.sha256.slice(0,14)}…</td><td>${esc(q.reason)}</td>
      <td>${tag(q.status)}</td><td>${tsShort(q.detected_at)}</td>
      <td>${q.status === "PENDING" ? `
        <input placeholder="唯一名（接受时）" id="qn-${q.id}" style="width:160px">
        <a onclick="qResolve('${q.id}','ACCEPT_AS_ALIAS')">作为唯一名接受</a> ·
        <a onclick="qResolve('${q.id}','REJECT')">拒绝</a>` : "—"}</td></tr>`).join("")
      || '<tr><td colspan=7 class=muted>无</td></tr>'}</tbody></table>`;
  window.qResolve = async (id, decision) => {
    const nn = $(`#qn-${id}`)?.value || null;
    try { const r = await api(`/api/quarantine/${id}/resolve`, {method: "POST",
      json: {decision, new_name: nn}});
      toast("处置完成：" + r.status, "ok"); PAGES.quarantine();
    } catch (e) { toast(`${e.error}: ${e.message}`, "err"); }
  };
};

// --------------------------------------------------------------- 审计
PAGES.audit = async () => {
  view.innerHTML = `<div class="card"><h2>操作日志与资源裁决</h2>
    <div class="row"><button class="btn sec" id="r">刷新</button>
      <span class="muted">所有资料、占用、批准、谱系、打包均带审计；抢占冲突在 arbitration 表给出唯一赢家。</span></div>
    <div id="a" style="margin-top:10px"></div></div>`;
  $("#r").onclick = load;
  async function load() {
    const [logs, arbs] = await Promise.all([api("/api/audit?limit=300"), api("/api/arbitrations")]);
    $("#a").innerHTML = `<h3>资源裁决（唯一赢家）</h3>
      <table><thead><tr><th>资源</th><th>区间</th><th>赢家操作</th><th>输家操作</th><th>时间</th></tr></thead>
      <tbody>${arbs.map(a => `<tr><td>${a.resource_key}</td>
        <td>${tsShort(a.start_ts)} ~ ${tsShort(a.end_ts)}</td>
        <td class="mono">${esc(a.winner_op_id)}</td>
        <td class="mono">${esc(a.loser_op_id || "")}</td><td>${tsShort(a.decided_at)}</td></tr>`)
        .join("") || '<tr><td colspan=5 class=muted>无</td></tr>'}</tbody></table>
      <h3>操作日志（最近 300 条）</h3>
      <table><thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>对象</th><th>操作编号</th>
      <th>细节</th></tr></thead><tbody>${logs.map(l => `<tr><td>${tsShort(l.at)}</td>
      <td>${esc(l.actor || "")}</td><td>${esc(l.action)}</td>
      <td class="mono">${esc(l.target || "")}</td><td class="mono">${esc(l.op_id || "")}</td>
      <td><code>${esc(JSON.stringify(l.detail))}</code></td></tr>`).join("")}</tbody></table>`;
  }
  load();
};

init().catch(e => toast("初始化失败：" + e.message, "err", 20000));
