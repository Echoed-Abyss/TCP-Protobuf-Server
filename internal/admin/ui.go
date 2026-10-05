package admin

import "net/http"

// uiHTML is the single-page admin UI. It is intentionally dependency-free
// (no external JS/CSS) so it works fully offline. It polls /admin/stats
// and /admin/config, and allows hot-config edits and connection closes.
const uiHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>secproto admin</title>
<style>
  body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:1.5rem;background:#fafafa;color:#222}
  h1{font-size:1.3rem;margin:0 0 1rem}
  .card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin-bottom:1rem}
  .row{display:flex;flex-wrap:wrap;gap:1rem}
  .stat{flex:1 1 140px;background:#f0f4ff;border-radius:6px;padding:.75rem}
  .stat .n{font-size:1.5rem;font-weight:700}
  .stat .l{font-size:.8rem;color:#666}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee}
  input[type=number],input[type=text]{width:140px;padding:.3rem;border:1px solid #ccc;border-radius:4px}
  button{padding:.4rem .8rem;border:none;border-radius:4px;background:#2563eb;color:#fff;cursor:pointer}
  button:hover{background:#1d4ed8}
  .ok{color:#16a34a}
</style>
</head>
<body>
<h1>secproto 管理面板</h1>
<div class="card">
  <div class="row" id="stats"></div>
</div>
<div class="card">
  <h2>热改配置</h2>
  <form id="cfgform">
    <table>
      <tr><td>心跳间隔 (ns)</td><td><input type="number" name="heartbeat_interval_ns"></td></tr>
      <tr><td>Dummy 帧间隔 (ns)</td><td><input type="number" name="dummy_frame_interval_ns"></td></tr>
      <tr><td>Dummy 抖动 (ns)</td><td><input type="number" name="dummy_frame_jitter_ns"></td></tr>
      <tr><td>Dummy 开关</td><td><select name="dummy_frames_enabled"><option value="true">开</option><option value="false">关</option></select></td></tr>
      <tr><td>填充块大小</td><td><input type="number" name="padding_block_size"></td></tr>
      <tr><td>数据时间窗口 (ns)</td><td><input type="number" name="data_time_window_ns"></td></tr>
    </table>
    <button type="submit">保存</button> <span id="cfgmsg" class="ok"></span>
  </form>
</div>
<div class="card">
  <h2>活跃连接</h2>
  <table id="conns"><thead><tr><th>ID</th><th>Peer</th><th>地址</th><th>KeyID</th><th>发/收字节</th><th>操作</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
  <h2>动作管理（运行时定义，无需改代码）</h2>
  <p><button id="actNew" type="button">新建动作</button> <span id="actmsg" class="ok"></span></p>
  <table id="actlist"><thead><tr><th>名称</th><th>状态</th><th>说明</th><th>操作</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
  <h2>动作定义</h2>
  <table>
    <tr><td>名称</td><td><input type="text" id="actName" placeholder="get_xuan_accpass"></td></tr>
    <tr><td>启用</td><td><select id="actEnabled"><option value="true">是</option><option value="false">否</option></select></td></tr>
    <tr><td>说明</td><td><input type="text" id="actDesc" placeholder="查询玄账号密码"></td></tr>
    <tr><td>必填字段</td><td><input type="text" id="actRequired" placeholder="qq,appid（逗号分隔，可空）"></td></tr>
    <tr><td>查表键</td><td><input type="text" id="actKey" placeholder="qq（留空表示纯模板，不查表）"></td></tr>
    <tr><td>数据行</td><td><textarea id="actRows" rows="5" style="width:360px;font-family:monospace">[]</textarea></td></tr>
    <tr><td>响应模板</td><td><textarea id="actResp" rows="6" style="width:360px;font-family:monospace">{}</textarea></td></tr>
  </table>
  <p><button id="actSave" type="button">保存</button> <button id="actDel" type="button">删除</button></p>
  <h2>试运行</h2>
  <p>请求 payload：<textarea id="actPayload" rows="3" style="width:360px;font-family:monospace">{"qq":10001}</textarea></p>
  <p><button id="actTest" type="button">试运行</button></p>
  <pre id="actResult" style="max-height:220px;overflow:auto;background:#f5f5f5;padding:8px;border-radius:6px;font-size:.8rem"></pre>
</div>
<script>
const TOKEN = prompt("请输入 admin token") || "";
// Write requests require the X-Admin-Action custom header as a CSRF
// defence (browsers cannot set custom headers on cross-origin requests
// without a CORS preflight, which this server does not allow).
const H = {"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json","X-Admin-Action":"1"};
const H_READ = {"Authorization":"Bearer "+TOKEN};

// Escape HTML-special characters so controllable strings (peer fingerprint,
// remote address) cannot inject markup. textContent is preferred for
// inserting text; this is a fallback for cases where markup is required.
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}

async function get(p){const r=await fetch(p,{headers:H_READ});return r.json()}
async function refresh(){
  try{
    const s=await get("/admin/stats");
    const m=s.metrics||{};
    const items=[
      ["活跃连接",s.active_conns],["累计连接",m.connections_total],
      ["握手成功",m.handshake_ok],["握手失败",m.handshake_failed],
      ["解密失败",m.decrypt_failed],["重放拦截",m.replay_rejected],
      ["过期包",m.expired_rejected],["重协商",m.renegotiations],
      ["Dummy帧",m.dummy_frames_sent],["帧数(发/收)",(m.frames_sent||0)+"/"+(m.frames_received||0)]
    ];
    // Use textContent to prevent XSS from numeric/string values.
    const host=document.getElementById("stats");
    host.textContent="";
    for(const [l,n] of items){
      const d=document.createElement("div");d.className="stat";
      const nn=document.createElement("div");nn.className="n";nn.textContent=n;
      const ll=document.createElement("div");ll.className="l";ll.textContent=l;
      d.appendChild(nn);d.appendChild(ll);host.appendChild(d);
    }
    const c=await get("/admin/config");
    const f=document.forms.cfgform;
    for(const k in c.hot){const el=f.elements[k];if(el)el.value=c.hot[k]}
    const cs=await get("/admin/connections");
    const tb=document.querySelector("#conns tbody");
    tb.textContent="";
    for(const c of cs){
      const tr=document.createElement("tr");
      const cells=[String(c.id),esc(c.peer_fingerprint),esc(c.remote_addr),
        String(c.key_id),c.bytes_sent+"/"+c.bytes_recv];
      for(const v of cells){const td=document.createElement("td");td.textContent=v;tr.appendChild(td)}
      const td=document.createElement("td");
      const b=document.createElement("button");b.textContent="断开";
      b.onclick=()=>closeConn(c.id);td.appendChild(b);tr.appendChild(td);
      tb.appendChild(tr);
    }
  }catch(e){console.error(e)}
}
document.forms.cfgform.addEventListener("submit",async e=>{
  e.preventDefault();
  const f=e.target;const body={};
  for(const el of f.elements){if(el.name&&el.value!==""){
    body[el.name]=el.type==="number"?Number(el.value):(el.value==="true");
  }}
  const r=await fetch("/admin/config",{method:"PUT",headers:H,body:JSON.stringify(body)});
  const j=await r.json();
  document.getElementById("cfgmsg").textContent=j.ok?"已生效":"失败: "+(j.error||"");
});
async function closeConn(id){
  await fetch("/admin/connections/"+id+"/close",{method:"POST",headers:H});
  refresh();
}
// ---- 运行时动作管理 ----
// 动作定义保存在服务端的 JSON store 里，保存后立即对所有连接生效，
// 不需要重启服务或改代码。
function actMsg(s){document.getElementById("actmsg").textContent=s}
async function refreshActions(){
  try{
    const list=await get("/admin/actions");
    const tb=document.querySelector("#actlist tbody");tb.textContent="";
    for(const a of (list||[])){
      const tr=document.createElement("tr");
      const cells=[a.name,a.enabled?"启用":"停用",a.desc||""];
      for(const v of cells){const td=document.createElement("td");td.textContent=v;tr.appendChild(td)}
      const td=document.createElement("td");
      const b1=document.createElement("button");b1.type="button";b1.textContent="编辑";b1.onclick=()=>loadAction(a);
      const b2=document.createElement("button");b2.type="button";b2.textContent="删除";b2.style.marginLeft="6px";b2.onclick=()=>removeAction(a.name);
      td.appendChild(b1);td.appendChild(b2);tr.appendChild(td);tb.appendChild(tr);
    }
  }catch(e){console.error(e)}
}
function loadAction(a){
  document.getElementById("actName").value=a.name;
  document.getElementById("actEnabled").value=a.enabled?"true":"false";
  document.getElementById("actDesc").value=a.desc||"";
  document.getElementById("actRequired").value=(a.required||[]).join(",");
  document.getElementById("actKey").value=(a.lookup&&a.lookup.key)||"";
  document.getElementById("actRows").value=JSON.stringify((a.lookup&&a.lookup.rows)||[],null,2);
  document.getElementById("actResp").value=JSON.stringify(a.response||{},null,2);
  actMsg("已载入 "+a.name);
}
async function saveAction(){
  let rows,resp;
  try{rows=JSON.parse(document.getElementById("actRows").value||"[]")}catch(e){actMsg("数据行不是合法 JSON");return}
  try{resp=JSON.parse(document.getElementById("actResp").value||"{}")}catch(e){actMsg("响应模板不是合法 JSON");return}
  const key=document.getElementById("actKey").value.trim();
  const def={
    name:document.getElementById("actName").value.trim(),
    enabled:document.getElementById("actEnabled").value==="true",
    desc:document.getElementById("actDesc").value.trim(),
    required:document.getElementById("actRequired").value.split(",").map(s=>s.trim()).filter(s=>s.length>0),
    response:resp
  };
  if(key){def.lookup={key:key,rows:rows}}
  const r=await fetch("/admin/actions",{method:"PUT",headers:H,body:JSON.stringify(def)});
  const j=await r.json();
  actMsg(j.ok?("已保存 "+def.name):("失败: "+(j.error||"")));
  refreshActions();
}
async function removeAction(name){
  const r=await fetch("/admin/actions/"+encodeURIComponent(name),{method:"DELETE",headers:H});
  const j=await r.json();
  actMsg(j.ok?("已删除 "+name):("失败: "+(j.error||"")));
  refreshActions();
}
async function testAction(){
  let payload;
  try{payload=JSON.parse(document.getElementById("actPayload").value||"{}")}catch(e){actMsg("payload 不是合法 JSON");return}
  const r=await fetch("/admin/actions/test",{method:"POST",headers:H,body:JSON.stringify({name:document.getElementById("actName").value.trim(),payload:payload})});
  const j=await r.json();
  document.getElementById("actResult").textContent=JSON.stringify(j,null,2);
}
document.getElementById("actNew").onclick=()=>{
  ["actName","actDesc","actRequired","actKey"].forEach(i=>{document.getElementById(i).value=""});
  document.getElementById("actRows").value="[]";
  document.getElementById("actResp").value=JSON.stringify({message:"hello"},null,2);
  actMsg("填写后点保存");
};
document.getElementById("actSave").onclick=saveAction;
document.getElementById("actDel").onclick=()=>{const n=document.getElementById("actName").value.trim();if(n)removeAction(n)};
document.getElementById("actTest").onclick=testAction;
refreshActions();

refresh();setInterval(refresh,3000);
</script>
</body>
</html>`

// handleUI serves the embedded single-page admin UI.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}
