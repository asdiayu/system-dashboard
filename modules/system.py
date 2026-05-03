"""System info — CPU, RAM, Disk, Temperature, CPU delta"""
import os
import socket
import threading

from modules.state import _cpu_prev, _cpu_prev_lock
from modules.helpers import run


def get_cpu_delta():
    """CPU usage berbasis delta sampling — real-time akurat"""
    global _cpu_prev
    try:
        with open("/proc/stat") as f:
            parts = f.readline().strip().split()
        if parts[0] != "cpu" or len(parts) < 5:
            return None
        user, nice, system, idle = int(parts[1]), int(parts[2]), int(parts[3]), int(parts[4])
        total = user + nice + system + idle
        with _cpu_prev_lock:
            if _cpu_prev is None:
                _cpu_prev = (total, idle)
                return None
            prev_total, prev_idle = _cpu_prev
            _cpu_prev = (total, idle)
            delta_total = total - prev_total
            if delta_total == 0:
                return None
            delta_idle = idle - prev_idle
            usage = round((1 - delta_idle / delta_total) * 100, 1)
            return usage
    except Exception:
        return None


def scan_system():
    """Collect system info: hostname, uptime, CPU, RAM, Disk, Temp"""
    info = {"hostname": "-", "uptime": "-", "cpu": {}, "ram": {}, "disk": {}, "load": [], "temp": []}
    try:
        info["hostname"] = socket.gethostname()

        # Uptime
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
        h = int(up // 3600)
        m = int((up % 3600) // 60)
        d = int(up // 86400)
        info["uptime"] = f"{d}h {h}j {m}m" if d else f"{h}j {m}m"

        # Load average
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            info["load"] = [float(parts[0]), float(parts[1]), float(parts[2])]

        # CPU (delta real-time)
        cpu_usage = get_cpu_delta()
        if cpu_usage is not None:
            info["cpu"] = {"usage": cpu_usage, "cores": os.cpu_count() or 1}
        else:
            info["cpu"] = {"usage": 0, "cores": os.cpu_count() or 1}

        # RAM
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                if line.startswith("MemTotal"):
                    mem["total"] = int(line.split()[1])
                elif line.startswith("MemAvailable"):
                    mem["avail"] = int(line.split()[1])
                    break
        if "total" in mem and "avail" in mem:
            total_mb = mem["total"] / 1024
            used_mb = (mem["total"] - mem["avail"]) / 1024
            pct = round(used_mb / total_mb * 100, 1)
            info["ram"] = {
                "total": f"{total_mb:.0f} MB",
                "used": f"{used_mb:.0f} MB",
                "avail": f"{(mem['avail']/1024):.0f} MB",
                "pct": pct
            }

        # Disk
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bfree * st.f_frsize
        used = total - free
        pct = round(used / total * 100, 1) if total > 0 else 0
        info["disk"] = {
            "total": f"{total / (1024**3):.1f} GB",
            "used": f"{used / (1024**3):.1f} GB",
            "free": f"{free / (1024**3):.1f} GB",
            "pct": pct
        }

        # Temperature
        try:
            out, _, _ = run(["sensors"])
            for line in out.splitlines():
                if "Core" in line and "\u00b0C" in line:
                    p2 = line.split(":")
                    if len(p2) >= 2:
                        try:
                            t = float(p2[1].split("(")[0].strip().strip("+").replace("\u00b0C", ""))
                            info["temp"].append({"label": p2[0].strip(), "temp": t})
                        except Exception:
                            pass
            if not info["temp"]:
                for i in range(10):
                    try:
                        tp = f"/sys/class/thermal/thermal_zone{i}/temp"
                        np = f"/sys/class/thermal/thermal_zone{i}/type"
                        if os.path.exists(tp):
                            info["temp"].append({
                                "label": open(np).read().strip(),
                                "temp": float(open(tp).read().strip()) / 1000
                            })
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass
    return info
