"""Port scanning & kill"""
import os
import re
import pwd
import time

from modules.helpers import run, PORT_KILL


def get_process_info(pid):
    """Enrich port entry with process details from /proc"""
    info = {"cmd": "-", "cwd": "-", "uptime": "-", "username": "-"}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b"\x00", b" ").strip()
            info["cmd"] = raw.decode("utf-8", errors="replace")[:120]
        cwd = os.readlink(f"/proc/{pid}/cwd")
        home = os.path.expanduser("~")
        if cwd.startswith(home):
            cwd = "~" + cwd[len(home):]
        info["cwd"] = cwd
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
            start_ticks = int(parts[21])
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    boot_time = int(line.split()[1])
                    break
        clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        start_time = boot_time + start_ticks / clk_tck
        elapsed = int(time.time() - start_time)
        if elapsed < 60:
            info["uptime"] = f"{elapsed}d"
        elif elapsed < 3600:
            info["uptime"] = f"{elapsed//60}m"
        elif elapsed < 86400:
            info["uptime"] = f"{elapsed//3600}j {elapsed%3600//60}m"
        else:
            info["uptime"] = f"{elapsed//86400}h {elapsed%86400//3600}j"
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    info["username"] = pwd.getpwuid(uid).pw_name
                    break
    except Exception:
        pass
    return info


def scan_ports():
    """Scan listening ports via ss"""
    try:
        out, _, _ = run(["ss", "-tlnp"])
        ports = []
        for line in out.splitlines():
            if "LISTEN" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            addr = parts[3]
            if ":" not in addr:
                continue
            port_str = addr.rsplit(":", 1)[-1]
            try:
                port = int(port_str)
            except ValueError:
                continue

            proc_info = {"pid": None, "name": None, "group": None}
            proc_col = parts[-1] if parts[-1].startswith("users") else None
            if proc_col:
                m = re.search(r'"([^"]+)".*?pid=(\d+)', proc_col)
                if m:
                    proc_info["name"] = m.group(1)
                    proc_info["pid"] = int(m.group(2))

            entry = {
                "port": port,
                "pid": proc_info["pid"],
                "name": proc_info["name"],
                "command": proc_info["name"],
                "process_group": None
            }

            if proc_info["pid"]:
                extra = get_process_info(proc_info["pid"])
                entry.update(extra)
                name_lower = (proc_info["name"] or "").lower()
                if any(x in name_lower for x in ["node", "npm", "npx"]):
                    entry["process_group"] = "Node.js"
                elif "python" in name_lower:
                    entry["process_group"] = "Python"
                elif any(x in name_lower for x in ["go", "goland"]):
                    entry["process_group"] = "Go"
                else:
                    entry["process_group"] = "Other"

            ports.append(entry)
        return ports
    except Exception:
        return []


def kill_port(port):
    """Kill process on a port"""
    try:
        if os.path.exists(PORT_KILL):
            out, err, code = run([PORT_KILL, str(port)])
            return {"status": "ok" if code == 0 else "error", "output": (out + err).strip()}
        out, err, code = run(["fuser", "-k", f"{port}/tcp"])
        return {"status": "ok" if code == 0 else "error", "output": (out + err).strip()}
    except Exception as e:
        return {"status": "error", "output": str(e)}
