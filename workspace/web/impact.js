const $ = (id) => document.getElementById(id);
let TOPO, WB, SNAP;
const esc = (s) => String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
function toast(msg, kind=""){const t=document.createElement("div");t.className=`toast ${kind}`;t.innerHTML=msg;$("toast").appendChild(t);setTimeout(()=>t.remove(),7000)}
async function api(path, method="GET", body){
  const opt={method,headers:{"Content-Type":"application/json"}};
  if(body) opt.body=JSON.stringify(body);
  const r=await fetch(path,opt), j=await r.json();
  if(!r.ok) throw Object.assign(new Error(j.message),{resp:j});
  return j;
}
function selectedRoots(){
  const manual=$("roots").value.split(",").map(x=>x.trim()).filter(Boolean);
  const sel=[...$("rootSelect").selectedOptions].map(x=>x.value);
  return [...new Set([...manual,...sel])];
}
function renderTopo(){
  $("topoMeta").textContent=`topology v${TOPO.version} · ${TOPO.fingerprint.slice(0,12)}…`;
  const g=TOPO.graph;
  $("topoSummary").innerHTML=`<div class="row"><span class="chip">节点 ${g.nodes.length}</span>
    <span class="chip">传播边 ${g.edges.length}</span><span class="chip">约束引用 ${g.constraint_refs.length}</span>
    <span class="chip">强制策略 ${g.policies.length}</span><span class="chip warn">${esc(TOPO.status)}</span></div>`;
  $("rootSelect").innerHTML=g.nodes.map(n=>`<option value="${esc(n.id)}">${esc(n.id)} / ${esc(n.module)} / ${esc(n.clock_domain)}</option>`).join("");
  if(!$("topoJson").value) $("topoJson").value=JSON.stringify(g,null,2);
}
function renderEcos(){
  $("ecoList").innerHTML = WB.ecos.length ? `<table><tr><th>ECO</th><th>状态</th><th>闭包</th><th></th></tr>`+
    WB.ecos.map(e=>{
      const im=e.impact; const good=im?.usable_for_review;
      return `<tr><td class="mono">${e.id}<div class="mut">${esc(e.title)}</div></td>
      <td>${esc(e.status)}</td>
      <td class="${good?'ok':'bad'}"><b>${good?'当前可用':'旧/不可用'}</b><div class="mut mono">${im?im.snapshot_id:'—'}</div>
      v${im?im.topology_version:'-'} · ${im?im.accepted_nodes.length:0} 节点</td>
      <td>${im?`<button class="sec" onclick="openSnapshot('${im.snapshot_id}')">打开</button>`:''}</td></tr>`;
    }).join("")+"</table>" : '<div class="mut">暂无 ECO</div>';
}
function candidateRows(r){
  return `<table><tr><th>实例 / 模块</th><th>时钟域</th><th>强制</th><th>路径</th><th>排除</th></tr>`+
    r.candidates.map(c=>`<tr><td><b>${esc(c.node_id)}</b><div class="mut">${esc(c.module)}</div></td>
    <td>${esc(c.clock_domain)}</td><td>${c.mandatory?'<b class="bad">不能排除</b>':'<span class="ok">可说明排除</span>'}</td>
    <td class="mono mut">${c.path.map(esc).join(' → ')}</td>
    <td>${c.excluded?'<b class="warn">已排除</b>':(c.mandatory?'<span class="mut">锁定</span>':`<input id="ex-${esc(c.node_id)}" placeholder="理由" style="width:170px"/>`)}</td></tr>`).join("")+"</table>";
}
function renderSnapshot(s){
  SNAP=s; const r=s.result;
  $("snapshot").innerHTML=`<div class="card">
    <div class="row"><b class="mono">${esc(s.id)}</b> r${s.revision}
      <span class="chip ${s.usable_for_review?'ok':'bad'}">${s.usable_for_review?'当前可用于冻结/发布':'旧结果不可用'}</span>
      <span style="flex:1"></span><span class="mut mono">result ${r.result_fingerprint.slice(0,12)}…</span></div>
    <div class="row mut">拓扑 v${s.topology_version} (${s.topology_fingerprint.slice(0,10)}…) · 起点 ${r.roots.map(x=>`<span class="chip">${esc(x)}</span>`).join(" ")}</div>
    <div class="row"><b>必须复验节点：</b>${r.accepted_nodes.map(x=>`<span class="chip ok">${esc(x)}</span>`).join(" ")}</div>
    <div class="row"><b>已排除：</b>${r.excluded_nodes.length?r.excluded_nodes.map(x=>`<span class="chip warn">${esc(x)}</span>`).join(" "):'<span class="mut">无</span>'}</div>
    <div class="row"><b>模块：</b>${r.accepted_modules.map(x=>`<span class="chip">${esc(x)}</span>`).join(" ")}</div>
    <details open><summary><b>检查类型（${r.counts.check_types}）</b></summary>
      <table><tr><th>检查</th><th>节点/边</th><th>原因</th></tr>${r.check_types.map(c=>`<tr>
      <td><b>${esc(c.check_type)}</b></td><td>${c.nodes.map(esc).join(", ")}${c.edges.length?'<div class="mut">'+c.edges.map(e=>`${esc(e.from)}→${esc(e.to)} (${esc(e.type)})`).join("<br>")+'</div>':''}</td>
      <td class="mut">${c.reasons.map(esc).join("<br>")}</td></tr>`).join("")}</table></details>
    <details open><summary><b>传播边解释（${r.propagation_edges.length}）</b></summary>${r.propagation_edges.map(e=>`<div class="row"><span class="${e.cross_clock?'bad':e.interface_contract?'warn':'ok'}">${e.seq}. ${esc(e.explanation)}</span></div>`).join("")}</details>
    <details><summary><b>候选节点与人工排除</b></summary>${candidateRows(r)}
      <div class="row"><button class="sec" onclick="submitExclusions()">提交排除（必须填写理由）</button></div></details>
  </div>`;
}
async function openSnapshot(id){renderSnapshot(await api(`/api/impact/snapshots/${id}`))}
async function compute(){
  let summary;
  try{summary=JSON.parse($("summary").value||"{}")}catch{toast("变更摘要不是合法 JSON","err");return}
  const d=await api("/api/impact/compute","POST",{scope:$("scope").value||"ad-hoc",roots:selectedRoots(),change_summary:summary,by:$("by").value||"?"});
  renderSnapshot(d); toast(d.replayed?"相同输入返回原快照":"已生成自动影响闭包","ok"); await loadAudit();
}
async function submitExclusions(){
  const exclusions=SNAP.result.candidates.filter(c=>!c.mandatory && $(`ex-${c.node_id}`)?.value.trim())
    .map(c=>({node:c.node_id,reason:$(`ex-${c.node_id}`).value.trim()}));
  if(!exclusions){toast("没有填写排除理由","err");return}
  try{const d=await api(`/api/impact/snapshots/${SNAP.id}/exclusions`,"POST",{by:$("by").value||"?",exclusions});
    renderSnapshot(d); toast("人工覆盖已形成新当前版本；旧版本仅保留审计","ok"); await loadAudit();}
  catch(e){toast(`⛔ ${e.resp?.error||""}: ${e.message}`,"err"); console.error(e.resp)}
}
async function publishTopology(){
  let graph; try{graph=JSON.parse($("topoJson").value)}catch{toast("拓扑 JSON 不合法","err");return}
  try{const d=await api("/api/impact/topology","POST",{graph,by:$("topoBy").value,note:$("topoNote").value});
    toast(d.deduped?"拓扑指纹未变化，返回同一版本":`已发布 v${d.version}；冻结中 ECO 已要求重算`,"ok");await refresh()}
  catch(e){toast(`⛔ ${e.resp?.error||"TOPOLOGY_ERROR"}: ${e.message}`,"err"); console.error(e.resp)}
}
async function loadAudit(){
  const d=await api("/api/impact/audit?limit=30");
  $("audit").innerHTML=d.events.length?`<table><tr><th>#</th><th>动作</th><th>人</th><th>对象</th><th>时间</th></tr>`+
    d.events.map(e=>`<tr><td>${e.seq}</td><td class="${e.action.includes('override')?'warn':'ok'}">${esc(e.action)}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.entity)}</td><td class="mut">${esc(e.at)}</td></tr>`).join("")+"</table>":'<div class="mut">暂无审计</div>';
}
async function refresh(){
  [TOPO,WB]=await Promise.all([api("/api/impact/topology"),api("/api/workbench")]);
  renderTopo(); renderEcos(); await loadAudit();
}
refresh().catch(e=>toast(e.message,"err"));
