let hideSelf=0,lastPorts=[];
let _diskPath=['/'],_diskData=null;

document.getElementById('tabNav').addEventListener('click',e=>{
  const t=e.target.closest('.tab');if(!t)return;
  document.querySelectorAll('.tab,.tab-content').forEach(el=>el.classList.remove('active'));
  t.classList.add('active');document.getElementById('tab-'+t.dataset.tab).classList.add('active');
  if(t.dataset.tab==='system'&&!window._diskLoaded)loadDiskAnalyzer();
});

const evtSource=new EventSource('/api/stream');
evtSource.onmessage=e=>{
  try{
    const d=JSON.parse(e.data);
    if(d.ports)renderPorts(d.ports);
    if(d.firewall)renderFirewall(d.firewall);
    if(d.system)renderSystem(d.system);
    if(d.cpu_hogs)renderCPUHogs(d.cpu_hogs);
    if(d.memory)renderMemory(d.memory);
    if(d.services)renderServices(d.services);
    if(d.network)renderNetwork(d.network);
    const vc=document.getElementById('viewerCount');
    if(d.subscribers!==undefined){
      vc.textContent=d.subscribers>0?'👁️ '+d.subscribers+' viewer'+(d.subscribers>1?'s':''):'';
      vc.style.display=d.subscribers>0?'':'none'
    }
    document.getElementById('statusLabel').textContent='live';
  }catch(_){}
};
evtSource.onerror=()=>document.getElementById('statusLabel').textContent='reconnecting...';

fetch('/api/specs').then(r=>r.json()).then(s=>{
  if(s.cpu&&s.cpu!=='-'){document.getElementById('spCPU').textContent=s.cpu.replace(/Intel\(R\)|Core\(TM\)|CPU|\s+/g,' ').trim().replace(/@\s+/g,'@ ').substring(0,40);document.getElementById('spCPU').title=s.cpu}
  document.getElementById('spGPU').textContent=s.gpu&&s.gpu!=='-'?s.gpu.split('(')[0].trim().substring(0,35):'-';
  document.getElementById('spRAM').textContent=s.ram;
  document.getElementById('spDisk').textContent=s.disk;
  document.getElementById('spOS').textContent=s.os;
  document.getElementById('spKernel').textContent=s.kernel;
  document.getElementById('spCPUCores').textContent=(s.cpu_cores||'?')+' core(s)';
}).catch(()=>{});

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function fmtBytes(b){
  if(!b)return'0 B';const u=['B','KB','MB','GB','TB'];let i=0,v=b;
  while(v>=1024&&i<u.length-1){v/=1024;i++}return v.toFixed(i>0?1:0)+' '+u[i]
}

/* DISK DELEGATION — click on data-diskpath elements */
document.getElementById('diskAnalyzerContent').addEventListener('click',e=>{
  const el=e.target.closest('[data-diskpath]');
  if(el)drillDisk(el.getAttribute('data-diskpath'));
});

/* ⇧ END GLOBALS — implementations below ⇧ */

function loadDiskAnalyzer(){
  window._diskLoaded=1;_diskPath=['/'];_diskData=null;
  document.getElementById('diskAnalyzerStatus').textContent='⏳ scanning...';
  fetch('/api/disk-analyzer').then(r=>r.json()).then(d=>{_diskData=d;renderDiskAnalyzer(d)})
    .catch(()=>document.getElementById('diskAnalyzerContent').innerHTML='<div style="color:#da3633;font-size:.82rem">Gagal memuat</div>')
    .finally(()=>document.getElementById('diskAnalyzerStatus').textContent='');
}

function renderDiskAnalyzer(d){
  const el=document.getElementById('diskAnalyzerContent');let h='';
  if(d.mounts&&d.mounts.length){
    h+='<div style="font-size:.72rem;color:#6c7086;margin-bottom:.4rem">📌 Mount Points</div>';
    h+=d.mounts.map(m=>{
      const p=parseInt(m.use_pct)||0,c=p>85?'#f85149':p>60?'#d29922':'#7ee787',dir=esc(m.mounted_on);
      return '<div class="mnt-row" data-diskpath="'+dir+'"><div class="mnt-info"><span class="mnt-fs">'+esc(m.filesystem)+'</span><span class="mnt-dir">'+dir+'</span></div><div class="mnt-bar-wrap"><div class="mnt-bar" style="width:'+p+'%;background:'+c+'"></div></div><div class="mnt-stats"><span style="color:'+c+';font-weight:600">'+esc(m.use_pct)+'</span><span style="color:#6c7086">'+esc(m.used)+'/'+esc(m.size)+'</span></div><span class="mnt-btn">🔍</span></div>'
    }).join('');
  }
  h+='<div style="margin-top:.6rem;display:flex;justify-content:space-between;align-items:center"><span style="font-size:.72rem;color:#6c7086">📁 Folder Sizes</span><span style="font-size:.72rem;color:#484f58">'+(d.total?'total '+d.total:'')+'</span></div>';
  if(_diskPath.length>1){
    h+='<div class="drill-bar">'+_diskPath.map((p,i)=>{
      if(i===_diskPath.length-1)return'<span class="db-crumb db-cur">'+esc(p||'/')+'</span>';
      return '<span class="db-crumb" data-diskpath="'+esc(_diskPath.slice(0,i+1).join('/').replace(/\/+/g,'/')||'/')+'">'+esc(p||'/')+'</span><span class="db-sep">/</span>';
    }).join('')+'</div><button class="db-back" data-diskpath="'+esc(_diskPath.slice(0,-1).join('/').replace(/\/+/g,'/')||'/')+'">⬆ Kembali</button>';
  }
  if(d.folders&&d.folders.length){
    const mx=Math.max(...d.folders.map(f=>f.size_mb),1);
    h+='<div class="flist">'+d.folders.map(f=>{
      const pct=Math.min(f.size_mb/mx*100,100),c=f.size_mb>1024?'#f0883e':f.size_mb>100?'#d29922':'#7ee787',cl=!f.path.includes('.')||f.size_mb>10;
      return '<div class="flist-row'+(cl?' fl-click':'')+'" data-diskpath="'+esc(f.path)+'"><div class="flist-bar" style="width:'+pct+'%;background:'+c+';opacity:.3"></div><span class="flist-name">'+esc(f.name)+'</span><span class="flist-size">'+esc(f.size)+'</span><span class="flist-arrow">'+(cl?'›':'')+'</span></div>'
    }).join('')+'</div>';
  }else h+='<div style="color:#6c7086;font-size:.82rem;margin-top:.3rem">Kosong</div>';
  el.innerHTML=h||'<div style="color:#6c7086;font-size:.82rem">Tidak ada data disk</div>';
}

async function drillDisk(path){
  document.getElementById('diskAnalyzerStatus').textContent='⏳ scanning...';
  try{
    const r=await fetch('/api/disk-analyzer/scan/'+encodeURIComponent(path));
    const d=await r.json();
    _diskPath=d.path.replace(/\/+$/,'').split('/').filter(Boolean);
    if(!_diskPath.length)_diskPath=['/'];
    if(d.folders){d.mounts=_diskData&&_diskData.mounts||[];renderDiskAnalyzer(d)}
    else toast('Gagal scan path','error');
  }catch(e){toast('❌ '+e.message,'error')}
  finally{document.getElementById('diskAnalyzerStatus').textContent='';}
}

/* PORTS */
function renderPorts(ports){
  lastPorts=ports;
  const filtered=hideSelf?ports.filter(p=>p.port!==5001):ports;
  const tbody=document.getElementById('portList');
  const existing=new Map();
  for(const r of tbody.children)if(r.id&&r.id.startsWith('pr-'))existing.set(r.id,r);
  const e=tbody.querySelector('.empty-state');if(e)e.remove();
  if(!filtered||!filtered.length){if(existing.size===0)tbody.innerHTML='<tr><td colspan="7" class="empty-state">✅ Tidak ada port aktif</td></tr>';return}
  const g={'node.js':0,'python':0,other:0};
  for(const p of ports){const gr=(p.process_group||'').toLowerCase();if(gr.includes('node'))g['node.js']++;else if(gr.includes('python'))g.python++;else g.other++}
  document.getElementById('sTotal').textContent=ports.length;
  document.getElementById('sNode').textContent=g['node.js'];
  document.getElementById('sPython').textContent=g.python;
  document.getElementById('sOther').textContent=g.other;
  const seen=new Set();
  for(const p of filtered){
    const rid='pr-'+p.port;seen.add(rid);
    const grp=esc(p.process_group||'-'),gc=grp.toLowerCase().includes('node')?'g-nodejs':grp.toLowerCase().includes('python')?'g-python':'g-unknown';
    const isSelf=p.port===5001;
    const html='<td><span class="port-num">'+p.port+'</span></td><td><span class="pid-num">'+(p.pid||'-')+'</span></td><td>'+esc(p.name||p.command||'-')+'</td><td><span class="g-badge '+gc+'">'+grp+'</span></td><td><div class="cmd-txt" title="'+esc(p.cmd||'')+'">'+esc(p.cmd||'<span style=color:#31364a>—</span>')+'</div></td><td><span style=color:#7ee787;font-size:.74rem>'+(p.uptime||'—')+'</span></td><td>'+(isSelf?'<span style=color:#31364a;font-size:.68rem>self</span>':'<button class=k-btn onclick=killPort('+p.port+')>✕</button>')+'</td>';
    if(existing.has(rid))existing.get(rid).innerHTML=html;
    else{const tr=document.createElement('tr');tr.id=rid;tr.innerHTML=html;tbody.appendChild(tr);requestAnimationFrame(()=>{})}
  }
  for(const[rid,row]of existing)if(!seen.has(rid)){row.style.transition='opacity .2s,transform .2s';row.style.opacity='0';row.style.transform='translateX(-8px)';setTimeout(()=>row.remove(),210)}
}

async function killPort(port){
  if(!confirm('Kill port '+port+'?'))return;
  const btn=event.target;btn.disabled=1;btn.textContent='...';
  try{const r=await fetch('/api/kill/'+port,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Port '+port+' dibersihkan':'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
}

/* FIREWALL */
function renderFirewall(fw){
  if(!fw)return;
  const b=document.getElementById('fwBadge'),c=document.getElementById('fwCount');
  b.className='fw-badge '+(fw.status==='active'?'active':'inactive');b.innerHTML=fw.status==='active'?'🟢 Active':'🔴 Inactive';
  if(fw.error){b.innerHTML+=' · error';return}
  document.getElementById('fwRules').innerHTML=fw.rules.length===0
    ?'<div style="color:#6c7086;font-size:.82rem">Tidak ada rules</div>'
    :fw.rules.map(r=>'<div class="rule-row"><span class="rule-port">'+esc(r.port)+'</span><span class="rule-'+r.action+'">'+r.action+'</span><span style="flex:1;color:#6c7086;font-size:.72rem">'+esc(r.comment)+'</span><button class="fw-btn deny" onclick="fwDelete('+r.num+')">✕</button></div>').join('');
  c.textContent=fw.rules.length+' rule'+(fw.rules.length!==1?'s':'');
}

async function fwAllow(){
  const inp=document.getElementById('fwPortInput'),port=inp.value.trim();
  if(!port)return toast('Masukkan port','error');inp.value='';
  try{const r=await fetch('/api/firewall/allow/'+port,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Allow '+port:'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
}
async function fwDeny(){
  const inp=document.getElementById('fwPortInput'),port=inp.value.trim();
  if(!port)return toast('Masukkan port','error');inp.value='';
  try{const r=await fetch('/api/firewall/deny/'+port,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Deny '+port:'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
}
async function fwDelete(num){
  try{const r=await fetch('/api/firewall/delete/'+num,{method:'POST'});
  if(!r.ok)return toast('❌ Server error '+r.status,'error');
  const d=await r.json();toast(d.status==='ok'?'✅ Rule #'+num+' dihapus':'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
}

/* SYSTEM */
function renderSystem(sys){
  if(!sys)return;
  document.getElementById('sysHost').textContent=sys.hostname||'-';
  document.getElementById('hostLabel').textContent='· '+(sys.hostname||'PC');
  document.getElementById('sysUptime').textContent=sys.uptime||'-';
  if(sys.cpu){
    document.getElementById('cpuUsage').textContent=sys.cpu.usage+'%';
    document.getElementById('cpuIdle').textContent=(100-sys.cpu.usage).toFixed(1)+'%';
    document.getElementById('cpuBar').style.width=sys.cpu.usage+'%';
    document.getElementById('cpuBar').className='pbar used '+(sys.cpu.usage>80?'red':sys.cpu.usage>50?'yellow':'blue');
    document.getElementById('cpuCores').textContent=sys.cpu.cores+' core(s)';
  }
  const te=document.getElementById('cpuTemp');
  if(sys.temp&&sys.temp.length>0){
    const max=Math.max(...sys.temp.map(t=>t.temp)),c=max>80?'#f85149':max>65?'#d29922':'#7ee787';
    te.innerHTML='🌡️ <span style=color:'+c+'>'+max.toFixed(0)+'°C</span>';
    te.title=sys.temp.map(t=>t.label+' '+t.temp+'°').join(' · ');
  }else te.textContent='';
  if(sys.load&&sys.load.length===3){
    const c=sys.cpu.cores||2,thr=[c*0.6,c*0.9];
    const color=v=>v<thr[0]?'green':v<thr[1]?'yellow':'red';
    document.getElementById('cpuLoad').textContent=sys.load.map(v=>v.toFixed(1)).join(' / ');
    document.getElementById('l1').textContent=sys.load[0].toFixed(1);
    document.getElementById('l5').textContent=sys.load[1].toFixed(1);
    document.getElementById('l15').textContent=sys.load[2].toFixed(1);
    document.getElementById('d1').className='lb-dot '+color(sys.load[0]);
    document.getElementById('d5').className='lb-dot '+color(sys.load[1]);
    document.getElementById('d15').className='lb-dot '+color(sys.load[2]);
    ['l1','l5','l15'].forEach((id,i)=>{const v=sys.load[i];document.getElementById(id).style.color=v<thr[0]?'#3fb950':v<thr[1]?'#d29922':'#da3633'});
  }
  if(sys.ram){
    document.getElementById('ramUsed').textContent=sys.ram.used;
    document.getElementById('ramTotal').textContent=sys.ram.total;
    document.getElementById('ramAvail').textContent=sys.ram.avail||'-';
    const rb=document.getElementById('ramBar');rb.style.width=sys.ram.pct+'%';rb.className='pbar used '+(sys.ram.pct>80?'red':sys.ram.pct>50?'yellow':'green');
  }
  if(sys.disk){
    document.getElementById('diskUsed').textContent=sys.disk.used;
    document.getElementById('diskTotal').textContent=sys.disk.total;
    document.getElementById('diskFree').textContent=sys.disk.free||'-';
    const db=document.getElementById('diskBar');db.style.width=sys.disk.pct+'%';db.className='pbar used '+(sys.disk.pct>85?'red':sys.disk.pct>60?'yellow':'green');
  }
}

/* PERFORMANCE: CPU HOGS */
function renderCPUHogs(hogs){
  document.getElementById('cpuHogsList').innerHTML=!hogs||!hogs.length
    ?'<div style="color:#6c7086;font-size:.82rem">Tidak ada proses berat</div>'
    :hogs.map(h=>'<div class="hog-row"><span class="hp">'+esc(h.pid)+'</span><div class="hcw"><span class="hc" title="'+esc(h.command)+'">'+esc(h.user)+'/'+esc(h.command).substring(0,40)+'</span><span class="hmeta">⏱ '+esc(h.etime||'-')+' · 💾 '+esc(h.rss_mb||0)+'MB</span></div><span style="display:flex;gap:.5rem;align-items:center"><span class="hu" style="color:#f0883e;font-weight:600">🔥 '+esc(h.cpu)+'%</span><span class="hu">💿 '+esc(h.mem)+'%</span></span></div>').join('');
}

/* PERFORMANCE: MEMORY */
function renderMemory(mem){
  if(!mem)return;
  document.getElementById('memBuffers').textContent=mem.cache_info&&mem.cache_info.buffers?fmtBytes(parseInt(mem.cache_info.buffers)*1024):'-';
  document.getElementById('memCached').textContent=mem.cache_info&&mem.cache_info.cached?fmtBytes(parseInt(mem.cache_info.cached)*1024):'-';
  const el=document.getElementById('memTopProcs');
  if(!mem.processes||!mem.processes.length){el.innerHTML='<div style="color:#6c7086;font-size:.82rem">Tidak ada data</div>';return}
  el.innerHTML=mem.processes.map(p=>'<div class="hog-row"><span class="hp">'+esc(p.pid)+'</span><div class="hcw"><span class="hc" title="'+esc(p.command)+'">'+esc(p.user)+'/'+esc(p.command).substring(0,40)+'</span><span class="hmeta">⏱ '+esc(p.etime||'-')+' · '+esc(p.rss_mb||0)+'MB</span></div><span class="hu" style="color:#f0883e;font-weight:600">💿 '+esc(p.mem)+'%</span></div>').join('');
}

async function clearMemory(){
  if(!confirm('Drop all memory caches? This may slow things temporarily.'))return;
  const btn=event.target;btn.disabled=1;btn.textContent='⏳...';
  try{const r=await fetch('/api/memory/clear',{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Cache dibersihkan':'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
  btn.disabled=0;btn.textContent='🧹 Clear Memory Cache';
}

/* PERFORMANCE: SERVICES */
function renderServices(services){
  const el=document.getElementById('servicesList');
  if(!services||!services.length){el.innerHTML='<div style="color:#6c7086;font-size:.82rem">Tidak ada data services</div>';return}
  el.innerHTML=services.map(s=>'<div class="svc-row"><span class="svc-dot '+(s.status==='active'?'active':'inactive')+'"></span><span class="svc-name">'+esc(s.name)+'</span><span class="svc-type">'+esc(s.type||'')+'</span><span style="font-size:.7rem;color:'+(s.status==='active'?'#7ee787':'#f85149')+';margin-right:.4rem">'+esc(s.status)+'</span><button class="svc-btn '+(s.status==='active'?'stop':'')+'" onclick="serviceAction(\''+esc(s.name)+'\',\''+(s.status==='active'?'stop':'start')+'\')">'+(s.status==='active'?'⏹ Stop':'▶ Start')+'</button><button class="svc-btn" onclick="serviceAction(\''+esc(s.name)+'\',\'restart\')" '+(s.status!=='active'?'disabled':'')+'>🔄</button></div>').join('');
}

async function serviceAction(name,action){
  const btns=event.target.closest('.svc-row').querySelectorAll('.svc-btn');
  btns.forEach(b=>b.disabled=1);
  try{const r=await fetch('/api/services/'+encodeURIComponent(name)+'/'+action,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ '+name+' '+action+'ed':'❌ '+(d.output||'gagal'),d.status)}
  catch(e){toast('❌ '+e.message,'error')}
}

/* NETWORK */
function renderNetwork(net){
  if(!net)return;
  const c=net.connections;
  if(c){document.getElementById('connEst').textContent=c.established??'-';document.getElementById('connTW').textContent=c.time_wait??'-';document.getElementById('connListen').textContent=c.listen??'-';document.getElementById('connTotal').textContent=c.total??'-'}
  const el=document.getElementById('interfaceList'),ifs=net.interfaces;
  if(!ifs||!ifs.length){el.innerHTML='<div style="color:#6c7086;font-size:.82rem">Tidak ada interface aktif</div>';return}
  const groupIcon={phy:'📶',vpn:'🔒',docker:'🐳',other:'🔌'};
  const groupLabel={phy:'Fisik',vpn:'VPN',docker:'Docker Bridge',other:'Lainnya'};
  const groups={};
  for(const i of ifs){if(!groups[i.group])groups[i.group]=[];groups[i.group].push(i)}
  let h='';
  for(const g of ['phy','vpn','docker','other']){
    const list=groups[g];if(!list||!list.length)continue;
    const isDocker=g==='docker';
    h+='<details style="margin-bottom:.1rem"'+(isDocker?'':' open')+'><summary style="cursor:pointer;font-size:.72rem;font-weight:600;color:#6c7086;padding:.3rem 0;display:flex;align-items:center;gap:.3rem">'+groupIcon[g]+' '+groupLabel[g]+' <span style="color:#484f58;font-weight:400;font-size:.65rem">'+list.length+'</span></summary>';
    h+=list.map(i=>'<div class="iface-card"><div class="iface-hd"><span class="iface-name">'+esc(i.name)+'</span></div><div class="iface-grid"><div class="iface-metric"><div class="im-val">'+fmtBytes(i.rx_speed)+'/s</div><div class="im-lbl">⬇ RX</div></div><div class="iface-metric"><div class="im-val">'+fmtBytes(i.tx_speed)+'/s</div><div class="im-lbl">⬆ TX</div></div><div class="iface-metric"><div class="im-val" style="color:#6c7086;font-size:.78rem">'+fmtBytes(i.rx)+'</div><div class="im-lbl">Total RX</div></div><div class="iface-metric"><div class="im-val" style="color:#6c7086;font-size:.78rem">'+fmtBytes(i.tx)+'</div><div class="im-lbl">Total TX</div></div></div></div>').join('');
    h+='</details>';
  }
  el.innerHTML=h;
}

/* TOAST */
function toast(msg,type='success'){
  const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;
  document.getElementById('toastContainer').appendChild(t);
  setTimeout(()=>t.remove(),2800);
}
