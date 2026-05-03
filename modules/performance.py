"""Performance — CPU hogs, Memory top, Services, Memory clear"""
import subprocess

from modules.helpers import run


def scan_cpu_hogs():
    """Get top 5 CPU-hungry processes with details"""
    try:
        out, _, _ = run(["ps", "-e", "-o", "user,pid,%cpu,%mem,rss,etime,args",
                         "--sort=-%cpu", "--no-headers"])
        hogs = []
        for line in out.splitlines():
            parts = line.strip().split(None, 6)
            if len(parts) < 7:
                continue
            user, pid, cpu_pct, mem_pct, rss_kb, etime, command = parts
            try:
                pid = int(pid)
            except ValueError:
                continue
            if command.startswith("[") and command.endswith("]"):
                continue
            if "app.py" in command or "/dashboard/venv" in command:
                continue
            # Parse RSS
            try:
                rss_mb = round(int(rss_kb) / 1024, 1)
            except ValueError:
                rss_mb = 0
            hogs.append({
                "user": user, "pid": pid,
                "cpu": cpu_pct, "mem": mem_pct,
                "rss_mb": rss_mb, "etime": etime,
                "command": command[:80]
            })
            if len(hogs) >= 5:
                break
        return hogs
    except Exception:
        return []


def scan_top_mem():
    """Get top 5 memory-hungry processes + cache info"""
    try:
        out, _, _ = run(["ps", "-e", "-o", "user,pid,%cpu,%mem,rss,etime,args",
                         "--sort=-%mem", "--no-headers"])
        procs = []
        for line in out.splitlines():
            parts = line.strip().split(None, 6)
            if len(parts) < 7:
                continue
            user, pid, cpu_pct, mem_pct, rss_kb, etime, command = parts
            try:
                pid = int(pid)
            except ValueError:
                continue
            try:
                rss_mb = round(int(rss_kb) / 1024, 1)
            except ValueError:
                rss_mb = 0
            procs.append({
                "user": user, "pid": pid,
                "cpu": cpu_pct, "mem": mem_pct,
                "rss_mb": rss_mb, "etime": etime,
                "command": command[:80]
            })
            if len(procs) >= 5:
                break

        cache_info = {"mem_available": "-", "buffers": "-", "cached": "-"}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemAvailable"):
                        cache_info["mem_available"] = line.split()[1]
                    elif line.startswith("Buffers"):
                        cache_info["buffers"] = line.split()[1]
                    elif line.startswith("Cached"):
                        cache_info["cached"] = line.split()[1]
        except Exception:
            pass

        return {"processes": procs, "cache_info": cache_info}
    except Exception:
        return {"processes": [], "cache_info": {}}


def clear_memory():
    """Drop caches: sync + echo 3 > drop_caches"""
    try:
        run(["sync"])
        p = subprocess.run(
            ["sudo", "-n", "tee", "/proc/sys/vm/drop_caches"],
            input="3\n", capture_output=True, text=True, timeout=5
        )
        return {
            "status": "ok" if p.returncode == 0 else "error",
            "output": (p.stdout + p.stderr).strip()
        }
    except Exception as e:
        return {"status": "error", "output": str(e)}


def scan_services():
    """Get running systemd services + known custom services"""
    try:
        out, _, _ = run(["systemctl", "list-units", "--type=service",
                         "--state=running", "--no-legend", "--no-pager"])
        services = []
        for line in out.splitlines():
            parts = line.split(None, 3)
            if len(parts) >= 2:
                name = parts[0]
                if name.endswith(".service"):
                    name = name[:-8]
                status = parts[1] if len(parts) > 1 else "unknown"
                desc = parts[3] if len(parts) > 3 else ""
                services.append({
                    "name": name, "status": status,
                    "description": desc, "type": "system"
                })

        for svc in ["resinflow", "pulsa-h2h"]:
            out2, _, _ = run(["systemctl", "is-active", svc])
            active = out2.strip()
            if active == "active":
                if not any(s["name"] == svc for s in services):
                    services.append({
                        "name": svc, "status": "active",
                        "description": "custom service", "type": "custom"
                    })
            else:
                services.append({
                    "name": svc, "status": active if active else "inactive",
                    "description": "custom service", "type": "custom"
                })

        return services
    except Exception:
        return []


def service_action(name, action):
    """Start/stop/restart a systemd service"""
    try:
        out, err, code = run(["sudo", "-n", "systemctl", action, name])
        return {
            "status": "ok" if code == 0 else "error",
            "output": (out + err).strip()
        }
    except Exception as e:
        return {"status": "error", "output": str(e)}
