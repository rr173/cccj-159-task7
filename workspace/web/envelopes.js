let current = {};
const $ = id => document.getElementById(id);
async function api(path, opt={}) {
  const res = await fetch(path, {method: opt.method || 'GET', headers: {'Content-Type':'application/json'},
    body: opt.body ? JSON.stringify(opt.body) : undefined});
  const data = await res.json();
  if (!res.ok) { show(data); throw Object.assign(new Error(data.error), {data}); }
  return data;
}
function show(x){ $('output').textContent = JSON.stringify(x,null,2); }
function esc(s){ return String(s ?? '').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function hex(buf){ return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function b64url(buf){ let s=btoa(String.fromCharCode(...new Uint8Array(buf))); return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function ub64url(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; return Uint8Array.from(atob(s),c=>c.charCodeAt(0)); }

async function keygen(){
  const k = await api('/api/envelope/keys/generate',{method:'POST',body:{}});
  $('kid').value=k.kid; $('pubkey').value=k.public_key; $('privkey').value=k.private_seed; show(k);
}
async function registerSigner(){
  const d=await api('/api/envelope/signers',{method:'POST',body:{kid:$('kid').value,signer:$('signer').value,role:$('role').value,public_key:$('pubkey').value,by:'web-admin'}});
  show(d); refreshAll();
}
async function revoke(){
  show(await api(`/api/envelope/signers/${encodeURIComponent($('kid').value)}/revoke`,{method:'POST',body:{reason:'WEB_REVOKED',by:'web-admin'}})); refreshAll();
}
async function createSession(){
  const d=await api('/api/envelope/sessions',{method:'POST',body:{by:'web',metadata:{ui:true}}});
  current.sid=d.id; show(d); await refreshAll();
}
async function addArtifact(){
  if(!current.sid) throw new Error('请先创建会话');
  let content=$('content').value;
  try{content=JSON.parse(content)}catch{}
  const d=await api(`/api/envelope/sessions/${current.sid}/artifacts`,{method:'POST',
    body:{slot:$('slot').value,kind:$('kind').value,content,by:'web'}});
  show(d); await refreshAll();
}
async function prepare(){
  show(await api(`/api/envelope/sessions/${current.sid}/prepare`,{method:'POST',body:{by:'web'}})); await refreshAll();
}
async function browserSign(){
  const sid=current.sid, kid=$('kid').value;
  const ch=await api(`/api/envelope/sessions/${sid}/challenge/${encodeURIComponent(kid)}`);
  const s=await api(`/api/envelope/sessions/${sid}`);
  const message={schema:'design-envelope-signature/1',envelope_id:ch.envelope_id,
    content_hash:s.envelope_id,merkle_root:(await api('/api/envelope/envelopes/'+ch.envelope_id)).merkle_root,
    kid,signed_at:ch.signed_at};
  const key=await crypto.subtle.importKey('pkcs8', pkcs8Seed($('privkey').value), {name:'Ed25519'},false,['sign']).catch(()=>null);
  if(!key){show({error:'浏览器不支持 Ed25519 WebCrypto，请用 CLI 签名'});return;}
  const sig=hex(await crypto.subtle.sign(null,key,new TextEncoder().encode(JSON.stringify(message))));
  show(await api(`/api/envelope/sessions/${sid}/signatures`,{method:'POST',body:{signed_payload:ch,signature:sig,by:$('signer').value}}));
  refreshAll();
}
function pkcs8Seed(seedHex){
  // Ed25519 PKCS#8 DER prefix + 32-byte seed
  const pfx=Uint8Array.from([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]);
  const out=new Uint8Array(48); out.set(pfx); out.set(seedHex.match(/../g).map(x=>parseInt(x,16)),16); return out;
}
async function seal(){ show(await api(`/api/envelope/sessions/${current.sid}/seal`,{method:'POST',body:{by:'web'}})); refreshAll(); }
async function publish(){ show(await api(`/api/envelope/sessions/${current.sid}/publish`,{method:'POST',body:{name:$('pubname').value,by:'web'}})); refreshAll(); }

async function verify(eid){
  try{ show(await api(`/api/envelope/envelopes/${eid}/verify`)); }catch(e){ show(e.data); }
}
async function lineage(name,eid){
  const q=new URLSearchParams(); if(name)q.set('name',name); if(eid)q.set('envelope_id',eid);
  show(await api('/api/envelope/lineage?'+q));
}
async function refreshAll(){
  const root=await api('/api/envelope/root'); $('root').innerHTML=`<span class="pill">root: ${esc(root.kid)} · ${esc(root.status)}</span>`;
  const sg=await api('/api/envelope/signers');
  $('signers').innerHTML='<table><tr><th>KID</th><th>人/角色</th><th>事件</th></tr>'+sg.signers.map(s=>`<tr><td>${esc(s.kid)}</td><td>${esc(s.signer)}<br><span class=muted>${esc(s.role)}</span></td><td>${esc(s.event)}</td></tr>`).join('')+'</table>';
  const ss=await api('/api/envelope/sessions');
  if(!current.sid && ss.sessions.length) current.sid=ss.sessions.at(-1).id;
  $('sessionInfo').textContent=current.sid ? '当前会话 '+current.sid : '尚无会话';
  $('sessions').innerHTML=ss.sessions.map(s=>`<div class="pill">${esc(s.id)} ${esc(s.state)} ${s.envelope_id?esc(s.envelope_id.slice(0,12)):''} <a href="#" onclick="current.sid='${esc(s.id)}';return false">选择</a></div>`).join('');
  const es=await api('/api/envelope/envelopes');
  $('envelopes').innerHTML='<h2>已计算信封</h2><table><tr><th>ID</th><th>签名</th><th>名称</th><th></th></tr>'+es.envelopes.map(e=>`<tr><td>${esc(e.id.slice(0,16))}…</td><td>${e.signature_count}</td><td>${esc(e.publications.join(','))}</td><td><button onclick="verify('${e.id}')">验真</button><button class=secondary onclick="lineage(null,'${e.id}')">谱系</button></td></tr>`).join('')+'</table>';
}
refreshAll().catch(show);
