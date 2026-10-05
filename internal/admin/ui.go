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
const H = {"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"};
async function get(p){const r=await fetch(p,{headers:H});return r.json()}
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
    document.getElementById("stats").innerHTML=items.map(([l,n])=>
      '<div class="stat"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>').join("");
    const c=await get("/admin/config");
    const f=document.forms.cfgform;
    for(const k in c.hot){const el=f.elements[k];if(el)el.value=c.hot[k]}
    const cs=await get("/admin/connections");
    document.querySelector("#conns tbody").innerHTML=cs.map(c=>
      '<tr><td>'+c.id+'</td><td>'+c.peer_fingerprint+'</td><td>'+c.remote_addr+
      '</td><td>'+c.key_id+'</td><td>'+c.bytes_sent+'/'+c.bytes_recv+
      '</td><td><button onclick="closeConn('+c.id+')">断开</button></td></tr>').join("");
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
