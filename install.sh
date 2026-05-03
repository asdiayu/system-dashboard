#!/usr/bin/env bash
# =============================================================================
# System Dashboard Installer
# Dashboard all-in-one: Port Monitor + Firewall + System Info + Performance + Network
# https://github.com/yourusername/system-dashboard
# =============================================================================

set -e

# ─── Warna ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

# ─── Konfigurasi ────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-$HOME/dashboard}"
SERVICE_NAME="dashboard"
PORT=5001
REQUIRE_SUDO=false

# Deteksi OS + arsitektur
OS="$(uname -s 2>/dev/null || echo 'Linux')"
ARCH="$(uname -m 2>/dev/null || echo 'x86_64')"
HAS_SYSTEMD=false
HAS_UFW=false

[ -d /run/systemd/system ] && HAS_SYSTEMD=true
command -v ufw >/dev/null 2>&1 && HAS_UFW=true

# ─── Header ─────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      System Dashboard Installer v1.0        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo "  OS     : $OS $ARCH"
echo "  Target : $INSTALL_DIR"
echo "  Port   : $PORT"
echo ""

# ─── Cek Dependencies ──────────────────────────────
info "Memeriksa dependencies..."

command -v python3 >/dev/null 2>&1 || err "Python 3 tidak ditemukan. Install: sudo apt install python3 python3-venv"
python3 -c "import venv" 2>/dev/null || err "Python venv tidak tersedia. Install: sudo apt install python3-venv"
command -v pip3 >/dev/null 2>&1 && PIP="pip3" || PIP="pip"

ok "Python 3: $(python3 --version)"
ok "Pip: $($PIP --version | head -1)"

# sudo? Cek ketersediaan
if command -v sudo >/dev/null 2>&1; then
    REQUIRE_SUDO=true
    ok "sudo tersedia"
else
    warn "sudo tidak tersedia — fitur firewall tidak akan berfungsi"
fi

# UFW
if $HAS_UFW; then
    ok "UFW tersedia"
fi

# systemd
if $HAS_SYSTEMD; then
    ok "systemd tersedia"
fi

echo ""

# ─── Install Dashboard ──────────────────────────────
info "Menginstall dashboard ke $INSTALL_DIR ..."

# Buat direktori
mkdir -p "$INSTALL_DIR/templates"

# Buat app.py
cat > "$INSTALL_DIR/app.py" << 'PYEOF'
#!/usr/bin/env python3
"""System Dashboard — Port Monitor + Firewall + System Info + Performance + Network (SSE real-time)"""

import json, os, subprocess, threading, time, queue, re, socket, pwd
from flask import Flask, jsonify, render_template, Response, stream_with_context

app = Flask(__name__)
PORT_KILL = os.path.expanduser("~/.local/bin/port-kill")

_port_cache=[]; _fw_cache={}; _sys_cache={}; _cpu_hogs_cache=[]; _mem_cache={}
_services_cache=[]; _network_cache={}; _disk_analyzer_cache={}
_cache_lock=threading.Lock(); _subscribers=[]; _sub_lock=threading.Lock()

def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1

def get_process_info(pid):
    info={"cmd":"-","cwd":"-","uptime":"-","username":"-"}
    try:
        with open(f"/proc/{pid}/cmdline","rb") as f:
            info["cmd"]=f.read().replace(b"\x00",b" ").strip().decode("utf-8",errors="replace")[:120]
        cwd=os.readlink(f"/proc/{pid}/cwd")
        home=os.path.expanduser("~")
        if cwd.startswith(home): cwd="~"+cwd[len(home):]
        info["cwd"]=cwd
        with open(f"/proc/{pid}/stat") as f:
            parts=f.read().split(); start_ticks=int(parts[21])
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "): boot_time=int(line.split()[1]); break
        clk_tck=os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        elapsed=int(time.time()-(boot_time+start_ticks/clk_tck))
        info["uptime"]=f"{elapsed//86400}h {elapsed%86400//3600}j" if elapsed>=86400 else f"{elapsed//3600}j {elapsed%3600//60}m" if elapsed>=3600 else f"{elapsed//60}m"
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"): info["username"]=pwd.getpwuid(int(line.split()[1])).pw_name; break
    except: pass
    return info

def scan_ports():
    try:
        out,_,_=run(["ss","-tlnp"]); ports=[]
        for line in out.splitlines():
            if "LISTEN" not in line: continue
            parts=line.split()
            if len(parts)<5: continue
            addr=parts[3]
            if ":" not in addr: continue
            try: port=int(addr.rsplit(":",1)[-1])
            except: continue
            proc_info={"pid":None,"name":None}
            proc_col=parts[-1] if parts[-1].startswith("users") else None
            if proc_col:
                m=re.search(r'"([^"]+)".*?pid=(\d+)',proc_col)
                if m: proc_info={"name":m.group(1),"pid":int(m.group(2))}
            entry={"port":port,"pid":proc_info["pid"],"name":proc_info["name"],"process_group":None}
            if proc_info["pid"]:
                extra=get_process_info(proc_info["pid"]); entry.update(extra)
                nl=(proc_info["name"]or"").lower()
                if any(x in nl for x in["node","npm","npx"]): entry["process_group"]="Node.js"
                elif "python" in nl: entry["process_group"]="Python"
                elif any(x in nl for x in["go","goland"]): entry["process_group"]="Go"
                else: entry["process_group"]="Other"
            ports.append(entry)
        return ports
    except: return []

def scan_firewall():
    result={"status":"inactive","rules":[],"error":None}
    try:
        out,_,_=run(["sudo","-n","ufw","status","numbered"])
        if "Status: active" in out: result["status"]="active"
        elif "Status: inactive" in out: return result
        for line in out.splitlines():
            line=line.strip()
            if line.startswith("[") and "]" in line:
                p=line.split(None,3)
                if len(p)>=3: result["rules"].append({"num":p[0].strip("[]"),"port":p[1],"action":p[2].lower(),"comment":p[3] if len(p)>3 else ""})
    except: pass
    return result

def scan_system():
    info={"hostname":"-","uptime":"-","cpu":{},"ram":{},"disk":{},"load":[],"temp":[]}
    try:
        info["hostname"]=socket.gethostname()
        with open("/proc/uptime") as f:
            up=float(f.read().split()[0])
            h=int(up//3600); d=int(up//86400)
            info["uptime"]=f"{d}h {h}j" if d else f"{h}j"
        with open("/proc/loadavg") as f:
            info["load"]=[float(x) for x in f.read().split()[:3]]
        with open("/proc/stat") as f:
            c=f.readline().split()
            if c[0]=="cpu":
                total=sum(int(x) for x in c[1:])
                info["cpu"]={"usage":round((1-int(c[4])/total)*100,1),"cores":os.cpu_count() or 1}
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"): total_kb=int(line.split()[1])
                elif line.startswith("MemAvailable"): avail_kb=int(line.split()[1]); break
            info["ram"]={"total":f"{total_kb/1024:.0f} MB","used":f"{(total_kb-avail_kb)/1024:.0f} MB","pct":round((total_kb-avail_kb)/total_kb*100,1)}
        st=os.statvfs("/")
        total_gb=st.f_blocks*st.f_frsize/(1024**3)
        used_gb=(st.f_blocks-st.f_bfree)*st.f_frsize/(1024**3)
        info["disk"]={"total":f"{total_gb:.1f} GB","used":f"{used_gb:.1f} GB","pct":round(used_gb/total_gb*100,1)}
        out,_,_=run(["sensors"])
        for line in out.splitlines():
            if "Core" in line and "\u00b0C" in line:
                p=line.split(":")
                if len(p)>=2:
                    try: info["temp"].append({"label":p[0].strip(),"temp":float(p[1].split("(")[0].strip().strip("+").replace("\u00b0C",""))})
                    except: pass
    except: pass
    return info

def scan_cpu_hogs():
    try:
        out,_,_=run(["ps","aux","--sort=-%cpu","--no-headers"])
        hogs=[]
        for line in out.splitlines()[:6]:
            p=line.split(None,10)
            if len(p)>=11: hogs.append({"user":p[0],"pid":int(p[1]),"cpu":float(p[2]),"mem":float(p[3]),"command":p[10][:60]})
        return hogs
    except: return []

def scan_top_mem():
    try:
        out,_,_=run(["ps","aux","--sort=-%mem","--no-headers"])
        procs=[]
        for line in out.splitlines()[:6]:
            p=line.split(None,10)
            if len(p)>=11: procs.append({"user":p[0],"pid":int(p[1]),"mem":float(p[3]),"command":p[10][:60]})
        result={"top_procs":procs}
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"): result["mem_total"]=int(line.split()[1])//1024
                elif line.startswith("MemAvailable"): result["mem_available"]=int(line.split()[1])//1024
                elif line.startswith("Buffers"): result["buffers"]=int(line.split()[1])//1024
                elif line.startswith("Cached"): result["cached"]=int(line.split()[1])//1024
        result["cached_pct"]=round(result.get("cached",0)/result.get("mem_total",1)*100,1) if result.get("mem_total") else 0
        return result
    except: return {}

def scan_services():
    try:
        out,_,_=run(["systemctl","list-units","--type=service","--state=running","--no-legend","--no-pager"])
        services=[]
        for line in out.splitlines():
            p=line.split(None,3)
            if len(p)>=2: services.append({"name":p[0].replace(".service",""),"status":p[1]})
        # Deteksi services custom yang dikenal
        known=[]
        for s in ["resinflow","pulsa-h2h","dashboard","ssh","ufw","cron"]:
            out2,_,_=run(["systemctl","is-active",s])
            known.append({"name":s,"status":"active" if "active" in out2 else "inactive"})
        return {"services":services,"known":known}
    except: return {"services":[],"known":[]}

_net_prev={}
def scan_network():
    try:
        ifaces,result=[],{"connections":{"established":0,"time_wait":0,"listen":0,"total":0}}
        for iface in os.listdir("/sys/class/net"):
            if iface=="lo": continue
            try:
                rx=int(open(f"/sys/class/net/{iface}/statistics/rx_bytes").read())
                tx=int(open(f"/sys/class/net/{iface}/statistics/tx_bytes").read())
                now=time.time()
                key=f"net_{iface}"
                rx_speed=tx_speed=0
                if key in _net_prev:
                    dt=now-_net_prev[key]["time"]
                    if dt>0:
                        rx_speed=int((rx-_net_prev[key]["rx"])/dt)
                        tx_speed=int((tx-_net_prev[key]["tx"])/dt)
                _net_prev[key]={"rx":rx,"tx":tx,"time":now}
                ifaces.append({"name":iface,"rx":rx,"tx":tx,"rx_speed":rx_speed,"tx_speed":tx_speed})
            except: pass
        out,_,_=run(["ss","-tpn"])
        states={"ESTAB":0,"TIME-WAIT":0,"LISTEN":0,"total":0}
        for line in out.splitlines():
            s=line.split()[1] if len(line.split())>1 else ""
            if s in states: states[s]+=1
            states["total"]+=1
        result["interfaces"]=ifaces
        result["connections"]=states
        return result
    except: return {"interfaces":[],"connections":{"established":0,"time_wait":0,"listen":0,"total":0}}

def clear_memory():
    run(["sync"])
    run(["sudo","-n","tee","/proc/sys/vm/drop_caches"],timeout=5)
    return {"status":"ok"}

def service_action(name,action):
    out,err,code=run(["sudo","-n","systemctl",action,name])
    return {"status":"ok" if code==0 else "error","output":(out+err).strip()}

def scan_folder_sizes():
    result={"folders":[],"mounts":[]}
    try:
        out,_,_=run(["du","-sh",os.path.expanduser("~/*"),os.path.expanduser("~/.*")],timeout=15)
        folders=[]
        for line in out.splitlines():
            p=line.split(None,1)
            if len(p)==2:
                sz=p[0]
                try:
                    if sz.endswith("K"): size_val=float(sz[:-1])
                    elif sz.endswith("M"): size_val=float(sz[:-1])*1024
                    elif sz.endswith("G"): size_val=float(sz[:-1])*1024*1024
                    else: size_val=0
                    if size_val>10240: folders.append({"path":p[1],"size":sz})
                except: pass
        result["folders"]=sorted(folders,key=lambda x: float(x["size"].rstrip("KMG")),reverse=True)[:25]
        out2,_,_=run(["df","-h"])
        for line in out2.splitlines()[1:]:
            p=line.split(None,5)
            if len(p)>=6: result["mounts"].append({"filesystem":p[0],"size":p[1],"used":p[2],"avail":p[3],"use_pct":p[4],"mounted":p[5]})
    except: pass
    return result

# ─── Scanner Loop ──────────────────────────────────
def scanner_loop():
    global _port_cache,_fw_cache,_sys_cache,_cpu_hogs_cache,_mem_cache,_services_cache,_network_cache,_disk_analyzer_cache
    counter=0
    while True:
        try:
            _port_cache=scan_ports()
            _sys_cache=scan_system()
            _cpu_hogs_cache=scan_cpu_hogs()
            _mem_cache=scan_top_mem()
            _services_cache=scan_services()
            _network_cache=scan_network()
            if counter%10==0: _fw_cache=scan_firewall()
            if counter%6==0: _disk_analyzer_cache=scan_folder_sizes()
            payload=json.dumps({"ports":_port_cache,"firewall":_fw_cache,"system":_sys_cache,"cpu_hogs":_cpu_hogs_cache,"memory":_mem_cache,"services":_services_cache,"network":_network_cache})
            with _sub_lock:
                dead=[q for q in _subscribers if not q.full()]
                for q in _subscribers:
                    try: q.put_nowait(payload)
                    except: pass
        except: pass
        time.sleep(5); counter+=1

t=threading.Thread(target=scanner_loop,daemon=True); t.start()

# ─── Routes ────────────────────────────────────────
@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/all")
def api_all():
    with _cache_lock: return jsonify({"ports":_port_cache,"firewall":_fw_cache,"system":_sys_cache,"cpu_hogs":_cpu_hogs_cache,"memory":_mem_cache,"services":_services_cache,"network":_network_cache,"disk_analyzer":_disk_analyzer_cache})

@app.route("/api/stream")
def api_stream():
    q=queue.Queue(maxsize=10)
    with _sub_lock: _subscribers.append(q)
    def gen():
        try:
            with _cache_lock: yield f"data: {json.dumps({'ports':_port_cache,'firewall':_fw_cache,'system':_sys_cache,'cpu_hogs':_cpu_hogs_cache,'memory':_mem_cache,'services':_services_cache,'network':_network_cache})}\n\n"
            while True: yield f"data: {q.get()}\n\n"
        except GeneratorExit: pass
        finally:
            with _sub_lock:
                if q in _subscribers: _subscribers.remove(q)
    return Response(stream_with_context(gen()),mimetype="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/kill/<int:port>",methods=["POST"])
def api_kill(port):
    try:
        out,err,code=run([PORT_KILL,str(port)])
        return jsonify({"status":"ok" if code==0 else "error","output":(out+err).strip()})
    except Exception as e: return jsonify({"status":"error","output":str(e)})

@app.route("/api/firewall/allow/<path:port>",methods=["POST"])
def fw_allow(port):
    out,err,code=run(["sudo","-n","ufw","allow",str(port)])
    return jsonify({"status":"ok" if code==0 else "error","output":(out+err).strip()})

@app.route("/api/firewall/deny/<path:port>",methods=["POST"])
def fw_deny(port):
    out,err,code=run(["sudo","-n","ufw","deny",str(port)])
    return jsonify({"status":"ok" if code==0 else "error","output":(out+err).strip()})

@app.route("/api/firewall/delete/<int:num>",methods=["POST"])
def fw_delete(num):
    out,err,code=run(["sudo","-n","ufw","--force","delete",str(num)])
    return jsonify({"status":"ok" if code==0 else "error","output":(out+err).strip()})

@app.route("/api/memory/clear",methods=["POST"])
def api_clear_memory(): return jsonify(clear_memory())

@app.route("/api/services/<name>/<action>",methods=["POST"])
def api_service(name,action):
    return jsonify(service_action(name,action))

@app.route("/api/cpu-hogs")
def api_cpu_hogs():
    with _cache_lock: return jsonify(_cpu_hogs_cache)

@app.route("/api/memory")
def api_memory():
    with _cache_lock: return jsonify(_mem_cache)

@app.route("/api/services")
def api_services():
    with _cache_lock: return jsonify(_services_cache)

@app.route("/api/network")
def api_network():
    with _cache_lock: return jsonify(_network_cache)

@app.route("/api/disk-analyzer")
def api_disk_analyzer():
    return jsonify(scan_folder_sizes())

@app.route("/api/specs")
def api_specs():
    specs={"cpu":"-","gpu":"-","ram":"-","os":"-","kernel":"-","disk":"-"}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line: specs["cpu"]=line.split(":",1)[1].strip(); break
        out,_,_=run(["grep","^PRETTY_NAME","/etc/os-release"])
        if out: specs["os"]=out.split("=",1)[1].strip().strip('"')
        out,_,_=run(["uname","-r"]); specs["kernel"]=out.strip()
        out,_,_=run(["lspci"])
        for line in out.splitlines():
            if "VGA" in line or "3D" in line or "Display" in line:
                specs["gpu"]=line.split(":",2)[-1].strip() if ":" in line else line.strip(); break
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"): specs["ram"]=f"{int(line.split()[1])/1024/1024:.1f} GB"; break
        st=os.statvfs("/"); specs["disk"]=f"{st.f_blocks*st.f_frsize/(1024**3):.0f} GB"
    except: pass
    return jsonify(specs)

if __name__=="__main__":
    app.run(host="0.0.0.0",port=${PORT},debug=False,threaded=True)
PYEOF

ok "app.py dibuat"

# ─── Buat template index.html (inline) ─────────────
cat > "$INSTALL_DIR/templates/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<title>Dashboard</title>
<style>
@keyframes fadeSlide{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes spin{to{transform:rotate(360deg)}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0e14;color:#e6e9ef;padding:1rem;min-height:100vh}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:.5rem}
.hl{display:flex;align-items:center;gap:.6rem}
.icon-box{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#da3633,#f0883e);display:flex;align-items:center;justify-content:center;font-size:1rem;box-shadow:0 4px 12px rgba(218,54,51,.2)}
.header h1{font-size:1.1rem;font-weight:600}
.header h1 small{font-weight:400;color:#6c7086;font-size:.8rem}
.status-dot{width:7px;height:7px;border-radius:50%;background:#3fb950;animation:pulse 2s infinite}
.status-badge{display:flex;align-items:center;gap:.35rem;font-size:.72rem;color:#9ca0b0;background:#131720;padding:.3rem .65rem;border-radius:20px;border:1px solid #1e2330}
.tabs{display:flex;gap:.25rem;margin-bottom:1rem;background:#131720;border-radius:10px;padding:3px;border:1px solid #1e2330;overflow-x:auto}
.tab{padding:.45rem 1rem;border-radius:8px;border:none;background:transparent;color:#6c7086;cursor:pointer;font-size:.82rem;font-weight:500;white-space:nowrap;transition:all .15s}
.tab:hover{color:#9ca0b0}
.tab.active{background:#1e2330;color:#e6e9ef}
.tab-content{display:none}
.tab-content.active{display:block;animation:fadeSlide .25s ease}
.card{background:#131720;border:1px solid #1e2330;border-radius:10px;padding:1rem;margin-bottom:.75rem}
.card-title{font-size:.75rem;font-weight:600;color:#6c7086;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.75rem}
.card-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.6rem}
.stat-card{background:#0d1117;border:1px solid #1e2330;border-radius:8px;padding:.6rem .7rem;text-align:center}
.stat-card .val{font-size:1.1rem;font-weight:600;color:#e6e9ef;line-height:1.3;word-break:break-word}
.stat-card .lbl{font-size:.68rem;color:#6c7086;margin-top:2px}
.stat-card .hint{font-size:.62rem;color:#484f58;margin-top:1px}
.pbar-wrap{background:#1e2330;border-radius:6px;height:6px;margin-top:6px;overflow:hidden}
.pbar{height:100%;border-radius:6px;transition:width .5s ease}
.pbar.green{background:#3fb950}.pbar.yellow{background:#d29922}.pbar.red{background:#da3633}.pbar.blue{background:#58a6ff}
.table-wrap{border:1px solid #1e2330;border-radius:10px;overflow-x:auto;background:#0d1117}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:.45rem .6rem;background:#131720;color:#6c7086;font-weight:500;font-size:.65rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #1e2330;white-space:nowrap;position:sticky;top:0}
td{padding:.4rem .6rem;border-bottom:1px solid #161b22}
tr:hover td{background:rgba(56,139,253,.04)}
.port-num{font-family:monospace;font-weight:600;font-size:.85rem;color:#f0883e}
.pid-num{font-family:monospace;font-size:.7rem;color:#6c7086}
.g-badge{display:inline-block;padding:.1rem .35rem;border-radius:10px;font-size:.65rem;font-weight:500}
.g-nodejs{background:#1a3d2e;color:#7ee787}
.g-python{background:#1e2a4a;color:#80a0ff}
.g-unknown{background:#1e2330;color:#9ca0b0}
.cmd-txt{color:#9ca0b0;font-size:.74rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.k-btn{background:rgba(218,54,51,.1);color:#f85149;border:1px solid rgba(218,54,51,.2);padding:.2rem .6rem;border-radius:5px;cursor:pointer;font-size:.7rem;transition:all .15s;white-space:nowrap}
.k-btn:hover{background:rgba(218,54,51,.2);border-color:#f85149}
.k-btn:disabled{opacity:.3}
.fw-badge{display:inline-flex;align-items:center;gap:.35rem;padding:.25rem .65rem;border-radius:12px;font-size:.72rem;font-weight:500}
.fw-badge.active{background:#1a3d2e;color:#7ee787;border:1px solid #238636}
.fw-badge.inactive{background:#3d1a1a;color:#f85149;border:1px solid #da3633}
.rule-row{display:flex;align-items:center;gap:.5rem;padding:.35rem 0;border-bottom:1px solid #161b22;font-size:.8rem}
.rule-row:last-child{border-bottom:none}
.rule-port{font-family:monospace;color:#f0883e;font-weight:600;min-width:100px}
.fw-input-group{display:flex;gap:.4rem;margin-top:.75rem}
.fw-input{background:#0d1117;border:1px solid #1e2330;border-radius:6px;padding:.35rem .6rem;color:#e6e9ef;font-size:.8rem;flex:1;min-width:0}
.fw-input:focus{outline:none;border-color:#58a6ff}
.fw-btn{border:none;border-radius:6px;padding:.25rem .6rem;font-size:.7rem;cursor:pointer;transition:all .12s}
.fw-btn.allow{background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.2)}
.fw-btn.deny{background:rgba(218,54,51,.12);color:#f85149;border:1px solid rgba(218,54,51,.2)}
.sys-grid{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
.metric-row{display:flex;justify-content:space-between;align-items:center;padding:.25rem 0;font-size:.8rem}
.metric-row .ml{color:#9ca0b0}
.metric-row .mv{color:#e6e9ef;font-weight:500}
.load-bar{display:flex;gap:4px;align-items:flex-end;height:24px;margin-top:4px}
.load-col{flex:1;border-radius:3px 3px 0 0;min-height:4px;background:linear-gradient(to top,#58a6ff,#79c0ff)}
.conn-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(80px,1fr));gap:.5rem;margin-bottom:.75rem}
.conn-card{background:#0d1117;border:1px solid #1e2330;border-radius:6px;padding:.5rem;text-align:center}
.conn-card .cc-val{font-size:1rem;font-weight:600}
.conn-card .cc-lbl{font-size:.62rem;color:#6c7086}
.iface-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.6rem}
.empty-state{text-align:center;padding:1.5rem;color:#6c7086;font-size:.82rem}
.btn-primary{background:#238636;color:#fff;border:none;border-radius:6px;padding:.35rem .8rem;font-size:.78rem;cursor:pointer;transition:all .12s}
.btn-primary:hover{background:#2ea043}
.btn-danger{background:#da3633;color:#fff;border:none;border-radius:6px;padding:.35rem .8rem;font-size:.78rem;cursor:pointer;transition:all .12s}
.btn-danger:hover{background:#f85149}
.btn-sm{padding:.15rem .5rem;font-size:.68rem;border-radius:4px}
.toast-container{position:fixed;bottom:1rem;right:1rem;z-index:300}
.toast{background:#131720;border:1px solid #1e2330;padding:.6rem .9rem;border-radius:8px;font-size:.78rem;box-shadow:0 8px 24px rgba(0,0,0,.4);animation:fadeSlide .2s ease;max-width:300px;margin-bottom:.4rem}
.toast.success{border-color:#3fb950}
.toast.error{border-color:#da3633}
@media(max-width:600px){
  body{padding:.6rem}.card-grid,.iface-grid{grid-template-columns:1fr 1fr}.sys-grid{grid-template-columns:1fr}
  .cmd-txt{max-width:80px}.tabs{font-size:.72rem}.tab{padding:.3rem .5rem;font-size:.7rem}
  th:nth-child(2),td:nth-child(2),th:nth-child(6),td:nth-child(6){display:none}
  table{min-width:420px}.port-num{font-size:.78rem}
  .k-btn{padding:.3rem .7rem;font-size:.75rem}
}
</style>
</head>
<body>
<div class="header">
  <div class="hl"><div class="icon-box">⬡</div><div><h1>Dashboard <small id="hostLabel"></small></h1></div></div>
  <div class="status-badge"><span class="status-dot"></span><span id="statusLabel">connected</span></div>
</div>

<div class="tabs" id="tabNav">
  <button class="tab active" data-tab="ports">🔌 Port</button>
  <button class="tab" data-tab="firewall">🛡️ Firewall</button>
  <button class="tab" data-tab="system">📊 System</button>
  <button class="tab" data-tab="performance">⚡ Performance</button>
  <button class="tab" data-tab="network">🌐 Network</button>
</div>

<!-- PORIS -->
<div class="tab-content active" id="tab-ports">
  <div class="card"><div class="card-title">Port Monitor</div>
  <div class="card-grid" id="portSummary">
    <div class="stat-card"><div class="val" id="sTotal">-</div><div class="lbl">Total</div></div>
    <div class="stat-card"><div class="val" id="sNode">-</div><div class="lbl">Node.js</div></div>
    <div class="stat-card"><div class="val" id="sPython">-</div><div class="lbl">Python</div></div>
    <div class="stat-card"><div class="val" id="sOther">-</div><div class="lbl">Lainnya</div></div>
  </div></div>
  <div class="table-wrap"><table><thead><tr><th>Port</th><th>PID</th><th>Proses</th><th>Group</th><th>Aktivitas</th><th>Sejak</th><th></th></tr></thead><tbody id="portList"></tbody></table></div>
</div>

<!-- FIREWALL -->
<div class="tab-content" id="tab-firewall">
  <div class="card">
    <div class="fw-status" style="display:flex;align-items:center;gap:.5rem;margin-bottom:.75rem">
      <span class="fw-badge" id="fwBadge">⏳</span><span style="font-size:.75rem;color:#6c7086" id="fwCount"></span>
    </div>
    <div id="fwRules"></div>
    <div class="fw-input-group">
      <input class="fw-input" id="fwPortInput" placeholder="Port (443 / 3000/tcp)" onkeydown="if(event.key==='Enter')fwAllow()">
      <button class="fw-btn allow" onclick="fwAllow()">Allow</button>
      <button class="fw-btn deny" onclick="fwDeny()">Deny</button>
    </div>
  </div>
</div>

<!-- SYSTEM -->
<div class="tab-content" id="tab-system">
  <div class="card"><div class="card-title">Spesifikasi PC</div>
  <div class="sys-grid" id="specsGrid">
    <div class="stat-card"><div class="val" id="spCPU">-</div><div class="lbl">CPU</div></div>
    <div class="stat-card"><div class="val" id="spGPU">-</div><div class="lbl">GPU</div></div>
    <div class="stat-card"><div class="val" id="spRAM">-</div><div class="lbl">RAM</div></div>
    <div class="stat-card"><div class="val" id="spDisk">-</div><div class="lbl">Disk</div></div>
    <div class="stat-card"><div class="val" id="spOS">-</div><div class="lbl">OS</div></div>
    <div class="stat-card"><div class="val" id="spKernel">-</div><div class="lbl">Kernel</div></div>
  </div></div>
  <div class="card"><div class="card-title">Monitor</div>
  <div class="sys-grid">
    <div class="stat-card"><div class="val" id="sysHost">-</div><div class="lbl">Host</div></div>
    <div class="stat-card"><div class="val" id="sysUptime">-</div><div class="lbl">Uptime</div></div>
    <div class="stat-card"><div class="val" id="cpuUsage">-</div><div class="lbl">CPU</div></div>
    <div class="stat-card"><div class="val" id="ramPct">-</div><div class="lbl">RAM</div></div>
  </div></div>
  <div class="card"><div class="card-title">Disk Analyzer</div><div id="diskContent"></div></div>
</div>

<!-- PERFORMANCE -->
<div class="tab-content" id="tab-performance">
  <div class="card"><div class="card-title">CPU Hogs</div><div id="cpuHogsContent"></div></div>
  <div class="card">
    <div class="card-title">Memory</div>
    <div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.6rem">
      <span style="font-size:.8rem;color:#9ca0b0">Cache: <strong id="memCache" style="color:#58a6ff">-</strong></span>
      <span style="font-size:.8rem;color:#9ca0b0">Available: <strong id="memAvail" style="color:#3fb950">-</strong></span>
      <button class="btn-danger btn-sm" onclick="clearMem()">🧹 Clear Cache</button>
    </div>
    <div id="memProcsContent"></div>
  </div>
  <div class="card">
    <div class="card-title">Services</div>
    <div id="servicesContent"></div>
  </div>
</div>

<!-- NETWORK -->
<div class="tab-content" id="tab-network">
  <div class="card"><div class="card-title">Koneksi</div>
  <div class="conn-grid" id="connGrid">
    <div class="conn-card"><div class="cc-val" id="connEstab">-</div><div class="cc-lbl">ESTAB</div></div>
    <div class="conn-card"><div class="cc-val" id="connTimeWait">-</div><div class="cc-lbl">TIME-WAIT</div></div>
    <div class="conn-card"><div class="cc-val" id="connListen">-</div><div class="cc-lbl">LISTEN</div></div>
    <div class="conn-card"><div class="cc-val" id="connTotal">-</div><div class="cc-lbl">Total</div></div>
  </div></div>
  <div class="card"><div class="card-title">Interface</div><div id="ifaceContent"></div></div>
</div>

<div class="toast-container" id="toastContainer"></div>

<script>
document.getElementById('tabNav').addEventListener('click',e=>{
  const t=e.target.closest('.tab'); if(!t)return;
  document.querySelectorAll('.tab,.tab-content').forEach(el=>el.classList.remove('active'));
  t.classList.add('active');
  document.getElementById('tab-'+t.dataset.tab).classList.add('active');
  if(t.dataset.tab==='system') loadDisk();
});

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function toast(msg,type='success'){
  const c=document.getElementById('toastContainer');
  const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;
  c.appendChild(t);setTimeout(()=>t.remove(),2800);
}

const es=new EventSource('/api/stream');
es.onmessage=e=>{
  try{
    const d=JSON.parse(e.data);
    if(d.ports)renderPorts(d.ports);
    if(d.firewall)renderFW(d.firewall);
    if(d.system)renderSys(d.system);
    if(d.cpu_hogs)renderHogs(d.cpu_hogs);
    if(d.memory)renderMem(d.memory);
    if(d.services)renderServices(d.services);
    if(d.network)renderNet(d.network);
  }catch(_){}
};
es.onerror=()=>document.getElementById('statusLabel').textContent='reconnecting...';

fetch('/api/specs').then(r=>r.json()).then(s=>{
  if(s.cpu!=='-'){document.getElementById('spCPU').textContent=s.cpu.split('@')[0].trim().slice(-25);document.getElementById('spCPU').title=s.cpu}
  document.getElementById('spGPU').textContent=s.gpu!=='-'?s.gpu.split('(')[0].trim().slice(0,30):'-';
  document.getElementById('spRAM').textContent=s.ram;
  document.getElementById('spDisk').textContent=s.disk;
  document.getElementById('spOS').textContent=s.os;
  document.getElementById('spKernel').textContent=s.kernel;
}).catch(()=>{});

function renderPorts(ports){
  const tbody=document.getElementById('portList');
  const g={n:0,p:0,o:0};
  ports.forEach(p=>{const g2=(p.process_group||'').toLowerCase();if(g2.includes('node'))g.n++;else if(g2.includes('python'))g.p++;else g.o++});
  document.getElementById('sTotal').textContent=ports.length;
  document.getElementById('sNode').textContent=g.n;
  document.getElementById('sPython').textContent=g.p;
  document.getElementById('sOther').textContent=g.o;
  const existing=new Map();
  Array.from(tbody.children).forEach(r=>{if(r.id&&r.id.startsWith('pr-'))existing.set(r.id,r)});
  const seen=new Set();
  ports.forEach(p=>{
    const rid='pr-'+p.port;seen.add(rid);
    const gc=(p.process_group||'').toLowerCase().includes('node')?'g-nodejs':'g-python';
    const html=`<td><span class="port-num">${p.port}</span></td><td><span class="pid-num">${p.pid||'-'}</span></td><td>${esc(p.name||p.command||'-')}</td><td><span class="g-badge ${gc}">${esc(p.process_group||'-')}</span></td><td><div class="cmd-txt" title="${esc(p.cmd||'')}">${esc(p.cmd||'—')}</div></td><td style="color:#7ee787;font-size:.72rem">${esc(p.uptime||'—')}</td><td>${p.port===5001?'<span style="color:#31364a;font-size:.65rem">self</span>':`<button class="k-btn" onclick="killP(${p.port})">✕</button>`}</td>`;
    if(existing.has(rid))existing.get(rid).innerHTML=html;
    else{const tr=document.createElement('tr');tr.id=rid;tr.innerHTML=html;tbody.appendChild(tr);requestAnimationFrame(()=>tr.style.animation='')}
  });
  for(const[rid,row]of existing)
    if(!seen.has(rid)){row.style.transition='opacity .2s,transform .2s';row.style.opacity='0';row.style.transform='translateX(-8px)';setTimeout(()=>row.remove(),210)}
}

async function killP(p){if(!confirm('Kill port '+p+'?'))return;try{const r=await fetch('/api/kill/'+p,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Port '+p:'❌ '+(d.output||'gagal'),d.status)}catch(e){toast('❌ '+e.message,'error')}}

function renderFW(fw){
  document.getElementById('fwBadge').className='fw-badge '+(fw.status==='active'?'active':'inactive');
  document.getElementById('fwBadge').innerHTML=fw.status==='active'?'🟢 Active':'🔴 Inactive';
  document.getElementById('fwCount').textContent=fw.rules.length+' rules';
  document.getElementById('fwRules').innerHTML=fw.rules.length===0?'<div style="color:#6c7086;font-size:.8rem">No rules</div>':fw.rules.map(r=>`<div class="rule-row"><span class="rule-port">${esc(r.port)}</span><span style="font-size:.7rem;color:${r.action==='allow'?'#3fb950':'#f85149'}">${r.action.toUpperCase()}</span><span style="flex:1;color:#6c7086;font-size:.7rem">${esc(r.comment)}</span><button class="fw-btn deny" onclick="fwDel(${r.num})">✕</button></div>`).join('');
}

async function fwAllow(){const i=document.getElementById('fwPortInput'),v=i.value.trim();if(!v)return;try{const r=await fetch('/api/firewall/allow/'+v,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Allow '+v:'❌ '+(d.output||'gagal'),d.status);i.value=''}catch(e){toast('❌ '+e.message,'error')}}
async function fwDeny(){const i=document.getElementById('fwPortInput'),v=i.value.trim();if(!v)return;try{const r=await fetch('/api/firewall/deny/'+v,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Deny '+v:'❌ '+(d.output||'gagal'),d.status);i.value=''}catch(e){toast('❌ '+e.message,'error')}}
async function fwDel(n){try{const r=await fetch('/api/firewall/delete/'+n,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Rule #'+n:'❌ '+(d.output||'gagal'),d.status)}catch(e){toast('❌ '+e.message,'error')}}

function renderSys(s){
  if(!s)return;
  document.getElementById('sysHost').textContent=s.hostname||'-';
  document.getElementById('hostLabel').textContent='· '+(s.hostname||'');
  document.getElementById('sysUptime').textContent=s.uptime||'-';
  if(s.cpu)document.getElementById('cpuUsage').textContent=(s.cpu.usage||0)+'%';
  if(s.ram)document.getElementById('ramPct').textContent=(s.ram.pct||0)+'%';
}

let _diskLoaded=false;
async function loadDisk(){
  if(_diskLoaded)return;_diskLoaded=true;
  try{
    const r=await fetch('/api/disk-analyzer');const d=await r.json();
    const el=document.getElementById('diskContent');let h='';
    if(d.mounts&&d.mounts.length){
      h+='<div style="font-size:.7rem;color:#6c7086;margin-bottom:.3rem">Mounts</div><div class="table-wrap" style="margin-bottom:.5rem"><table><thead><tr><th>FS</th><th>Size</th><th>Used</th><th>Avail</th><th>Use%</th><th>Mounted</th></tr></thead><tbody>'+d.mounts.map(m=>'<tr><td style="font-family:monospace;font-size:.7rem">'+esc(m.filesystem)+'</td><td>'+esc(m.size)+'</td><td>'+esc(m.used)+'</td><td>'+esc(m.avail)+'</td><td>'+esc(m.use_pct)+'</td><td>'+esc(m.mounted)+'</td></tr>').join('')+'</tbody></table></div>';
    }
    if(d.folders&&d.folders.length){
      h+='<div style="font-size:.7rem;color:#6c7086;margin-bottom:.3rem">Folder terbesar (home)</div><div class="table-wrap"><table><thead><tr><th>Folder</th><th>Size</th></tr></thead><tbody>'+d.folders.map(f=>'<tr><td style="font-family:monospace;font-size:.72rem;color:#9ca0b0">'+esc(f.path)+'</td><td style="font-weight:600;color:#f0883e">'+esc(f.size)+'</td></tr>').join('')+'</tbody></table></div>';
    }
    el.innerHTML=h||'<div style="color:#6c7086;font-size:.8rem">No data</div>';
  }catch(e){document.getElementById('diskContent').innerHTML='<div style="color:#f85149;font-size:.8rem">Error: '+e.message+'</div>'}
}

function renderHogs(h){
  if(!h||!h.length){document.getElementById('cpuHogsContent').innerHTML='<div style="color:#6c7086;font-size:.8rem">No data</div>';return}
  document.getElementById('cpuHogsContent').innerHTML='<div class="table-wrap"><table><thead><tr><th>PID</th><th>User</th><th>CPU%</th><th>Mem%</th><th>Command</th></tr></thead><tbody>'+h.map(p=>`<tr><td class="pid-num">${p.pid}</td><td style="font-size:.72rem;color:#9ca0b0">${esc(p.user)}</td><td style="color:${p.cpu>50?'#f85149':p.cpu>20?'#d29922':'#7ee787'};font-weight:600">${p.cpu}%</td><td style="color:#58a6ff">${p.mem}%</td><td class="cmd-txt" style="max-width:200px" title="${esc(p.command)}">${esc(p.command)}</td></tr>`).join('')+'</tbody></table></div>';
}

function renderMem(m){
  if(!m||!m.top_procs)return;
  document.getElementById('memCache').textContent=m.cached_pct?m.cached_pct+'%':'0%';
  document.getElementById('memAvail').textContent=m.mem_available?m.mem_available+'MB':'0';
  if(!m.top_procs.length){document.getElementById('memProcsContent').innerHTML='<div style="color:#6c7086;font-size:.8rem">No data</div>';return}
  document.getElementById('memProcsContent').innerHTML='<div class="table-wrap"><table><thead><tr><th>PID</th><th>User</th><th>Mem%</th><th>Command</th></tr></thead><tbody>'+m.top_procs.map(p=>`<tr><td class="pid-num">${p.pid}</td><td style="font-size:.72rem;color:#9ca0b0">${esc(p.user)}</td><td style="color:#58a6ff;font-weight:600">${p.mem}%</td><td class="cmd-txt" title="${esc(p.command)}">${esc(p.command)}</td></tr>`).join('')+'</tbody></table></div>';
}

async function clearMem(){try{const r=await fetch('/api/memory/clear',{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ Cache cleared':'❌ Failed',d.status)}catch(e){toast('❌ '+e.message,'error')}}

function renderServices(s){
  if(!s||!s.known){document.getElementById('servicesContent').innerHTML='<div style="color:#6c7086;font-size:.8rem">No data</div>';return}
  document.getElementById('servicesContent').innerHTML=s.known.map(sv=>`<div class="rule-row"><span style="flex:1">${esc(sv.name)}</span><span style="font-size:.7rem;color:${sv.status==='active'?'#3fb950':'#6c7086'};margin-right:.5rem">● ${sv.status}</span><button class="fw-btn allow btn-sm" onclick="svcAct('${esc(sv.name)}','restart')">↻</button><button class="fw-btn deny btn-sm" onclick="svcAct('${esc(sv.name)}','stop')" ${sv.status!=='active'?'disabled':''}>■</button></div>`).join('');
}

async function svcAct(name,action){try{const r=await fetch('/api/services/'+name+'/'+action,{method:'POST'});const d=await r.json();toast(d.status==='ok'?'✅ '+action+' '+name:'❌ '+(d.output||'gagal'),d.status)}catch(e){toast('❌ '+e.message,'error')}}

function renderNet(n){
  if(!n)return;
  const c=n.connections||{};
  document.getElementById('connEstab').textContent=c.established||0;
  document.getElementById('connTimeWait').textContent=c.time_wait||0;
  document.getElementById('connListen').textContent=c.listen||0;
  document.getElementById('connTotal').textContent=c.total||0;
  const el=document.getElementById('ifaceContent');
  if(!n.interfaces||!n.interfaces.length){el.innerHTML='<div style="color:#6c7086;font-size:.8rem">No interfaces</div>';return}
  el.innerHTML=n.interfaces.map(i=>`<div class="stat-card" style="text-align:left"><div style="font-weight:600;font-size:.85rem;color:#e6e9ef;margin-bottom:.3rem">${esc(i.name)}</div><div style="display:flex;justify-content:space-between;font-size:.72rem"><span style="color:#58a6ff">▼ ${fmtSpeed(i.rx_speed)}</span><span style="color:#f0883e">▲ ${fmtSpeed(i.tx_speed)}</span></div><div style="display:flex;justify-content:space-between;font-size:.65rem;color:#484f58;margin-top:2px"><span>▼ ${fmtSize(i.rx)}</span><span>▲ ${fmtSize(i.tx)}</span></div></div>`).join('');
}

function fmtSpeed(b){if(!b)return'0 B/s';if(b>1e6)return(b/1e6).toFixed(1)+' MB/s';if(b>1e3)return(b/1e3).toFixed(0)+' KB/s';return b+' B/s'}
function fmtSize(b){if(!b)return'0 B';if(b>1e9)return(b/1e9).toFixed(1)+' GB';if(b>1e6)return(b/1e6).toFixed(1)+' MB';if(b>1e3)return(b/1e3).toFixed(0)+' KB';return b+' B'}
</script>
</body>
</html>
HTMLEOF

ok "Template HTML dibuat"

# ─── Setup Python venv ────────────────────────────
info "Membuat Python virtual environment..."
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install flask -q
deactivate
ok "Virtual environment siap"

# ─── Setup sudoers untuk UFW ─────────────────────
if $REQUIRE_SUDO && $HAS_UFW; then
    info "Konfigurasi sudoers untuk UFW..."
    SUDOERS_FILE="/etc/sudoers.d/dashboard"
    if [ ! -f "$SUDOERS_FILE" ]; then
        echo "$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw" | sudo tee "$SUDOERS_FILE" >/dev/null 2>&1
        echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/tee /proc/sys/vm/drop_caches" | sudo tee -a "$SUDOERS_FILE" >/dev/null 2>&1
        echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl" | sudo tee -a "$SUDOERS_FILE" >/dev/null 2>&1
        sudo chmod 440 "$SUDOERS_FILE"
        ok "sudoers dikonfigurasi"
    else
        ok "sudoers sudah ada"
    fi
fi

# ─── Setup UFW rule ──────────────────────────────
if $HAS_UFW && command -v sudo >/dev/null 2>&1; then
    info "Membuka port $PORT di UFW..."
    sudo -n ufw allow from 192.168.0.0/16 to any port "$PORT" 2>/dev/null || true
    sudo -n ufw allow from 10.0.0.0/8 to any port "$PORT" 2>/dev/null || true
    ok "UFW port $PORT diizinkan dari jaringan lokal"
fi

# ─── Setup systemd service ───────────────────────
if $HAS_SYSTEMD; then
    info "Membuat systemd service..."

    mkdir -p "$HOME/.config/systemd/user"

    cat > "$HOME/.config/systemd/user/dashboard.service" << EOF
[Unit]
Description=System Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=on-failure
RestartSec=5
Environment=INSTALL_DIR=$INSTALL_DIR

[Install]
WantedBy=default.target
EOF

    loginctl enable-linger 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable dashboard 2>/dev/null || true
    systemctl --user restart dashboard 2>/dev/null || true

    ok "systemd service dibuat & diaktifkan"
fi

# ─── Selesai ──────────────────────────────────────
IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1)

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Installasi Selesai! 🎉               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard : ${CYAN}http://localhost:$PORT${NC}"
echo -e "  Dari HP   : ${CYAN}http://$IP:$PORT${NC}"
echo ""
echo -e "  ${YELLOW}Manage:${NC}"
echo -e "    systemctl --user status dashboard"
echo -e "    systemctl --user restart dashboard"
echo -e "    journalctl --user -u dashboard -f"
echo ""
echo -e "  ${YELLOW}Uninstall:${NC}"
echo -e "    systemctl --user stop dashboard"
echo -e "    systemctl --user disable dashboard"
echo -e "    rm -rf $INSTALL_DIR"
echo ""
