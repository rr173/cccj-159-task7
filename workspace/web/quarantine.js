let BOARD = null;

function $(id){return document.getElementById(id)}
function esc(s){return String(s ?? '').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function toast(msg, ok=true){
  const el=document.createElement('div'); el.className='toast '+(ok?'ok':'err'); el.textContent=msg;
  $('toast').appendChild(el); setTimeout(()=>el.remove(),4500);
}
async function api(method,url,body){
  const opt={method,headers:{'Content-Type':'application/json'}};
  if(body!==undefined) opt.body=JSON.stringify(body);
  const r=await fetch(url,opt), data=await r.json().catch(()=>({}));
  if(!r.ok) throw Object.assign(new Error(data.message||r.statusText),{data});
  return data;
}
function statusChip(s){
  const cls=s==='ISOLATED'?'bad':s==='RESTORED'?'ok':s==='PENDING'?'warn':'mut';
  return `<span class="chip ${cls}">${esc(s)}</span>`;
}
function loadBaselines(){
  const cur=$('baseline').value;
  $('baseline').innerHTML=(BOARD.affected_lineage||[]).map(b=>
    `<option value="${esc(b.id)}">${esc(b.id)} / rev ${b.revision} / parent ${esc(b.parent_id||'-')} ${b.trusted?'':'（不可信）'}</option>`
  ).join('');
  if(cur) $('baseline').value=cur;
}
function renderTrusted(){
  const xs=BOARD.current_trusted_ancestors||[];
  $('trusted').innerHTML=xs.length?xs.map(b=>`<div class="card"><b class="mono">${esc(b.id)}</b>
    <div class="mut">revision ${b.revision}，信任代次 ${b.trust_generation}</div></div>`).join('')
    :'<span class="mut">当前无活动隔离；trunk 为最新可信发行。</span>';
}
function renderChanges(){
  // 页面只突出活动隔离中仍需重新对齐的变更；历史记录放在事故详情审计内。
  const activeIds=new Set((BOARD.incidents||[]).filter(i=>i.status==='ISOLATED').map(i=>i.id));
  const xs=(BOARD.pending_changes||[]).filter(x=>activeIds.has(x.incident_id));
  if(!xs.length){$('changes').innerHTML='<span class="mut">无待处理变更。</span>';return}
  $('changes').innerHTML='<table><tr><th>事故</th><th>ECO</th><th>原状态</th><th>动作</th><th>父版本</th><th>当前</th></tr>'+
    xs.map(x=>`<tr><td class="mono">${esc(x.incident_id)}</td><td class="mono">${esc(x.eco_id)}<br/><span class="mut">${esc(x.title)}</span></td>
    <td>${esc(x.previous_status)}</td><td>${esc(x.action)}</td><td class="mono">${esc(x.parent_baseline_id||'-')}</td>
    <td>${esc(x.current_status)} / gen ${x.eco_trust_generation}</td></tr>`).join('')+'</table>';
}
function renderLineage(){
  $('lineage').innerHTML='<table><tr><th>版本</th><th>父</th><th>修订</th><th>信任状态</th><th>事故</th><th>代次</th><th>指纹</th></tr>'+
    (BOARD.affected_lineage||[]).map(b=>`<tr><td class="mono">${esc(b.id)}</td><td class="mono">${esc(b.parent_id||'-')}</td>
    <td>${b.revision}</td><td>${b.trusted?'<span class="ok">TRUSTED</span>':'<span class="bad">UNTRUSTED</span>'}</td>
    <td>${b.active_incidents.map(x=>`<span class="chip bad">${esc(x)}</span>`).join('')||'-'}</td>
    <td>${b.trust_generation}</td><td class="mono mut">${esc(b.fingerprint)}</td></tr>`).join('')+'</table>';
}
function incidentCard(i){
  const affected=i.affected_baselines||[];
  const confirms=i.confirmations||[];
  const restore = i.status==='ISOLATED'?`<div class="row">
    <input id="quser-${esc(i.id)}" value="" placeholder="确认人" style="width:150px"/>
    <button class="sec" onclick="confirmRestore('${esc(i.id)}','QUALITY_LEAD')">质量负责人确认</button>
    <button class="ok" onclick="confirmRestore('${esc(i.id)}','RELEASE_MANAGER')">发布负责人确认</button>
  </div>`:'';
  return `<div class="card"><div class="row"><b class="mono">${esc(i.id)}</b>${statusChip(i.status)}
    <span class="mut">批次 ${esc(i.batch_no)}</span><span style="flex:1"></span><span class="mut">代次 ${i.generation||'-'}</span></div>
  <div><b>原因：</b>${esc(i.reason)}</div>
  <details><summary class="mut">证据</summary><pre>${esc(JSON.stringify(i.evidence,null,2))}</pre></details>
  <div class="mut">命中 ${esc(i.baseline_id)}；可信祖先 <b class="mono">${esc(i.trusted_ancestor_id||'-')}</b>；防护修订 ${i.guard_revision??'-'}</div>
  <div>${affected.map(a=>`<span class="chip ${a.trust_status==='UNTRUSTED'?'bad':'ok'}">${esc(a.baseline_id)} ${esc(a.relation)} ${esc(a.trust_status)}</span>`).join('')}</div>
  <div class="mut">确认：${confirms.map(c=>`${esc(c.role)}=${esc(c.user)}`).join('，')||'无'}；等待：${(i.awaiting_roles||[]).join(', ')||'-'}</div>${restore}</div>`;
}
function renderIncidents(){
  $('incidents').innerHTML=(BOARD.incidents||[]).slice().reverse().map(incidentCard).join('')||
    '<span class="mut">尚未登记事故。</span>';
}
function renderAudit(){
  $('audit').innerHTML='<table><tr><th>seq</th><th>事故</th><th>事件</th><th>操作者</th><th>时间</th><th>详情</th></tr>'+
    (BOARD.audit||[]).map(a=>`<tr><td>${a.seq}</td><td class="mono">${esc(a.incident_id)}</td><td>${esc(a.event)}</td>
    <td>${esc(a.actor)}</td><td>${esc(a.at)}</td><td><pre>${esc(JSON.stringify(a.detail,null,2))}</pre></td></tr>`).join('')+'</table>';
}
async function load(){
  try{
    BOARD=await api('GET','/api/quarantine/board');
    $('meta').textContent=`${BOARD.incidents.length} 起事故`;
    loadBaselines(); renderTrusted(); renderChanges(); renderLineage(); renderIncidents(); renderAudit();
  }catch(e){toast(e.message,false)}
}
async function register(){
  let evidence=$('evidence').value;
  try{evidence=JSON.parse(evidence)}catch(e){toast('证据必须是合法 JSON',false);return}
  const body={baseline_id:$('baseline').value,batch_no:$('batch').value,reason:$('reason').value,
    evidence,by:$('by').value,incident_id:$('incidentId').value||undefined};
  try{
    const d=await api('POST','/api/quarantine/incidents',body);
    toast(d.replayed?'相同事故请求已回放，未产生第二次迁移':'隔离裁决完成'); await load();
  }catch(e){toast(`${e.data?.error||'ERROR'}: ${e.message}`,false)}
}
async function recover(){
  try{const d=await api('POST','/api/quarantine/recover-all',{});toast(`恢复 ${d.count} 起未完成裁决`);await load()}
  catch(e){toast(`${e.data?.error||'ERROR'}: ${e.message}`,false)}
}
async function confirmRestore(id,role){
  const user=$(`quser-${id}`).value.trim() || (role==='QUALITY_LEAD'?'quality.zhang':'release.wang');
  try{const d=await api('POST',`/api/quarantine/incidents/${encodeURIComponent(id)}/restore-confirm`,
    {role,user,note:'操作页双角色恢复确认'});
  toast(d.status==='RESTORED'?'双角色确认完成，可信状态已恢复':'确认已记录，仍等待另一角色');await load()}
  catch(e){toast(`${e.data?.error||'ERROR'}: ${e.message}`,false)}
}
load();
