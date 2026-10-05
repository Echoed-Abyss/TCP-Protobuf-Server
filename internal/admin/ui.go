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
refresh();setInterval(refresh,3000);
</script>
</body>
</html>`

// handleUI serves the embedded single-page admin UI.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}
