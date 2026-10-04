/* 排程页 JS（零依赖） */
let CUR_LOT = null, SETS = [], LOTS = [];

async function initSchedule() {
  await loadUsers("u_disp1");
  window.CURRENT_USER = $("user").value;
  await refreshAll();
}

async function refreshAll() {
  const [{ lots }, { mask_sets }, { machines }, { windows }, { arbitrations },
         { replacements }, { reworks }] = await Promise.all([
    api("GET", "/api/mask/lots"), api("GET", "/api/mask/sets"),
    api("GET", "/api/mask/machines"), api("GET", "/api/mask/windows"),
    api("GET", "/api/mask/arbitrations"), api("GET", "/api/mask/replacements"),
    api("GET", "/api/mask/reworks"),
  ]);
  LOTS = lots; SETS = mask_sets;
  $("lots").innerHTML = lots.map(l => `
    <div class="item ${CUR_LOT === l.id ? "sel" : ""}" onclick="pickLot('${l.id}')">
      <b>${l.name}</b> <span class="muted mono">${l.id}</span><br>
      ${tag(l.status)}
      <span class="muted">set: ${l.mask_set_id ? l.mask_set_id.slice(0,14)+"…" : "未绑定"}</span>
      <span class="muted">node: ${l.current_node_id ? l.current_node_id.slice(0,14)+"…" : "-"}</span>
    </div>`).join("") || `<p class="muted">还没有 lot</p>`;

  const setOpts = SETS.map(s => `<option value="${s.id}">${s.name} ${s.kind}
    (${s.id.slice(0,10)}…, ${s.nodes} 节点)</option>`).join("");
  $("bset").innerHTML = setOpts; $("rset").innerHTML = setOpts;
  $("bmachine").innerHTML = machines.map(m => `<option value="${m.id}">${m.name}</option>`).join("");
  if (CUR_LOT) $("bookPanel").hidden = false;

  await loadSetSlots();
  await loadReplaceForm();
  renderLineage();
  renderWindows(windows);
  $("arbs").innerHTML = arbitrations.map(a => `
    <tr><td class="muted">${a.decided_at.slice(11,19)}</td><td class="mono">${a.resource}</td>
    <td>${a.contender}</td><td>${tag(a.decision)}</td>
    <td>${a.reason ? `<code class="rej">${a.reason}</code>` : ""}</td>
    <td class="mono">${a.op_id || ""}</td></tr>`).join("");
  $("repls").innerHTML = replacements.slice().reverse().slice(0, 6).map(r => `
    <div style="margin-top:6px;font-size:12px">
      ${tag(r.status)} ${r.slot} <span class="muted">ME:${r.me_user || "-"} / LO:${r.lo_user || "-"}</span>
      ${r.new_node_id ? `→ <span class="mono">${r.new_node_id.slice(0,12)}…</span>` : ""}
    </div>`).join("");
  $("reworks").innerHTML = reworks.slice().reverse().slice(0, 5).map(r => `
    <div style="font-size:12px">${tag(r.status)} ${tag("DELTA")}
      <span class="mono">${r.delta_set_id.slice(0,12)}…</span>
      <span class="muted">${r.reason}</span></div>`).join("");
}

async function pickLot(id) {
  CUR_LOT = id;
  const l = await api("GET", `/api/mask/lots/${id}`);
  if (l.mask_set_id) $("bset").value = l.mask_set_id;
  $("bookPanel").hidden = false;
  await loadSetSlots();
  await refreshAll();
}

async function loadSetSlots() {
  const sid = $("bset").value;
  if (!sid) return;
  const s = await api("GET", `/api/mask/sets/${sid}`);
  window._curSet = s;
  $("bnode").innerHTML = s.nodes.map(n => `<option value="${n.id}">
    R${n.seq} ${n.kind} ${n.label} [${n.status}]</option>`).join("");
  loadNodeSlotOptions();
}

function loadNodeSlotOptions() {
  const nid = $("bnode").value;
  const n = window._curSet?.nodes.find(x => x.id === nid);
  $("bslot").innerHTML = (n?.slots || []).map(s =>
    `<option value="${s.slot}">${s.slot} — ${s.name}</option>`).join("");
}

async function loadReplaceForm() {
  const sid = $("rset").value;
  if (!sid) return;
  const s = await api("GET", `/api/mask/sets/${sid}`);
  window._rSet = s;
  $("rnode").innerHTML = s.nodes.map(n => `<option value="${n.id}">
    R${n.seq} ${n.kind} [${n.status}]</option>`).join("");
  loadReplaceSlots();
}

async function loadReplaceSlots() {
  const nid = $("rnode").value;
  const n = window._rSet?.nodes.find(x => x.id === nid);
  $("rslot").innerHTML = (n?.slots || []).filter(s => s.kind === "layout").map(s =>
    `<option value="${s.slot}">${s.slot} — ${s.name}</option>`).join("");
}

function renderLineage() {
  let g = "";
  for (const s of SETS) {
    g += `■ ${s.name} [${s.kind}] ${s.id.slice(0,12)}…\n`;
  }
  // 当前所选 set 的节点明细
  const sid = $("bset")?.value;
  const s = window._curSet;
  if (s) {
    for (const n of s.nodes) {
      g += `  ${n.status === "ACTIVE" ? "●" : n.status === "SEALED" ? "■" : "○"} R${n.seq} `
        + `${n.kind.padEnd(8)} ${n.label}  ${tag(n.status)}\n`;
      for (const p of n.parents) g += `        ↑ 依赖 ${p.slice(0,14)}…\n`;
    }
  }
  $("lineage").textContent = g;
}

function renderWindows(wins) {
  $("wins").innerHTML = wins.map(w => `
    <tr><td>${w.machine_id}</td><td>${w.lot_id.slice(8,14)}</td>
    <td class="mono">${w.node_id.slice(8,14)}/${w.slot}</td>
    <td class="mono" style="font-size:11px">${w.start_ts.slice(0,16)}<br>${w.end_ts.slice(0,16)}</td>
    <td>${tag(w.state)}</td><td class="mono" style="font-size:11px">${w.op_id || ""}</td>
    <td>${w.state === "PLANNED" ? `
      <button class="ghost" onclick="exposeWin('${w.id}')">曝光</button>
      <button class="danger" onclick="cancelWin('${w.id}')">取消</button>` : ""}</td></tr>`).join("");
}

async function createLot() {
  try { await api("POST", "/api/mask/lots", { ...by(), name: $("lname").value });
    await refreshAll(); toast("lot 已创建", true);
  } catch (e) { toast(e); }
}

async function bindLot() {
  if (!CUR_LOT) return toast("先选择一个 lot");
  try {
    await api("POST", `/api/mask/lots/${CUR_LOT}/bind`,
      { ...by(), mask_set_id: $("bset").value, op_id: "op-bind-" + Date.now() });
    toast("绑定成功", true); await refreshAll();
  } catch (e) { toast(e); }
}

async function bookWin() { await _book($("bop").value.trim()); }
async function sameOpAgain() {
  toast("用完全相同的 op_id 重放：应返回同一窗口，不产生重复占用", true);
  await _book($("bop").value.trim());
}
async function _book(op) {
  if (!CUR_LOT) return toast("先选择一个 lot");
  if (!op) return toast("预订窗口必须填写 op_id");
  try {
    const w = await api("POST", "/api/mask/windows", {
      ...by(), lot_id: CUR_LOT, machine_id: $("bmachine").value,
      node_id: $("bnode").value, slot: $("bslot").value,
      start: $("bstart").value, end: $("bend").value, op_id: op,
    });
    toast(`窗口已获胜：${w.id}（${w.start_ts} ~ ${w.end_ts}）`, true);
    // 自动把下一个建议时段顺延 2 小时
    const next = `op-win-${Math.random().toString(16).slice(2, 8)}`;
    $("bop").value = next;
    await refreshAll();
  } catch (e) { toast(e); await refreshAll(); }
}

async function exposeWin(id) {
  try { await api("POST", `/api/mask/windows/${id}/expose`, by());
    toast("已记录曝光；首个曝光会把当前 mask set 全部节点永久封存", true);
    await refreshAll();
  } catch (e) { toast(e); }
}
async function cancelWin(id) {
  try { await api("POST", `/api/mask/windows/${id}/cancel`, by());
    await refreshAll();
  } catch (e) { toast(e); }
}

let _replId = null;
async function replaceReq() {
  try {
    const s = window._rSet;
    const r = await api("POST", `/api/mask/sets/${s.id}/replacements`, {
      ...by(), release_id: s.release_id, node_id: $("rnode").value, slot: $("rslot").value,
      name: $("rname").value, content: $("rcontent").value,
      reason: $("rreason").value, op_id: "op-rpl-" + Date.now(),
    });
    _replId = r.id;
    toast(`替换申请 ${r.id}：等待 ME + LO 两名不同自然人批准`, true);
    await refreshAll();
  } catch (e) { toast(e); }
}
async function approve(role, user) {
  const pending = (await api("GET", "/api/mask/replacements")).replacements
    .filter(r => r.status === "PENDING").pop();
  if (!pending) return toast("没有 PENDING 的替换申请");
  try {
    const r = await api("POST", `/api/mask/replacements/${pending.id}/approve`,
      { role, by: user });
    if (r.status === "DONE") {
      toast(`双签齐备 → 新节点 ${r.new_node_id.slice(0,12)}…，`
        + `取消 ${r.reschedule_required.length} 个下游 PLANNED 窗口待重排`, true);
    } else toast(`${role} 已批准，等待另一角色`, true);
    await refreshAll();
  } catch (e) { toast(e); }
}

async function rework() {
  if (!CUR_LOT) return toast("先选择一个已曝光 lot");
  try {
    const r = await api("POST", "/api/mask/reworks", {
      ...by(), lot_id: CUR_LOT, reason: $("dwreason").value,
      op_id: "op-rw-" + Date.now(),
      changes: [{ slot: $("dwslot").value, name: $("dwname").value,
        content: $("dwcontent").value }],
    });
    toast(`delta set ${r.delta_set_id.slice(0,12)}… 已就绪，lot 可绑定返工集`, true);
    await refreshAll();
  } catch (e) { toast(e); }
}
