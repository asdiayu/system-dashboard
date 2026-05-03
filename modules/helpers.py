"""Helper functions — run(), get_specs(), constants"""
import os
import subprocess
import json

from modules.state import _SPECS

PORT_KILL = "/home/asdi/.local/bin/port-kill"


def run(cmd, timeout=8, env=None):
    """Run shell command, return (stdout, stderr, returncode)"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1


def get_specs():
    """Get hardware/OS specs (cached after first call)"""
    global _SPECS
    if _SPECS is not None:
        return _SPECS
    specs = {"cpu": "-", "gpu": "-", "ram": "-", "os": "-", "kernel": "-", "disk": "-", "cpu_cores": os.cpu_count() or 1}
    try:
        # CPU
        with open("/proc/cpuinfo") as f:
            for line in f:
                if "model name" in line:
                    specs["cpu"] = line.split(":", 1)[1].strip()
                    break
        # OS
        out, _, _ = run(["grep", "^PRETTY_NAME", "/etc/os-release"])
        if out:
            specs["os"] = out.split("=", 1)[1].strip().strip('"')
        # Kernel
        out, _, _ = run(["uname", "-r"])
        specs["kernel"] = out.strip()
        # GPU
        out, _, _ = run(["lspci"])
        for line in out.splitlines():
            if "VGA" in line or "3D" in line or "Display" in line:
                specs["gpu"] = line.split(":", 2)[-1].strip() if ":" in line else line.strip()
                break
        # RAM
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    specs["ram"] = f"{kb / 1024 / 1024:.1f} GB"
                    break
        # Disk (root)
        st = os.statvfs("/")
        total_gb = st.f_blocks * st.f_frsize / (1024**3)
        specs["disk"] = f"{total_gb:.0f} GB"
    except Exception:
        pass
    _SPECS = specs
    return specs
