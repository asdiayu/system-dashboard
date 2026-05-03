"""Network monitor — bandwidth & connections"""
import os
import time

from modules.state import _net_prev, _net_prev_lock
from modules.helpers import run


def _iface_group(name):
    """Kategorikan interface: phy / vpn / docker / other"""
    if name.startswith(("br-", "docker")):
        return "docker"
    if name.startswith(("tailscale", "tun", "tap")):
        return "vpn"
    if name.startswith(("wlan", "eth", "enp", "ens", "enx", "eno")):
        return "phy"
    return "other"

def scan_network():
    """Get bandwidth usage per interface + connection state counts"""
    global _net_prev
    try:
        # Detect active interfaces
        active_ifaces = []
        try:
            for entry in os.listdir("/sys/class/net/"):
                if entry == "lo":
                    continue
                out, _, _ = run(["ip", "-4", "addr", "show", entry])
                if "inet " in out:
                    active_ifaces.append(entry)
        except Exception:
            pass

        if not active_ifaces:
            active_ifaces = ["eth0", "wlan0", "enp0s3", "enp0s8", "enp1s0", "enp2s0"]

        interfaces = []
        now = time.time()

        for iface in active_ifaces:
            rx_path = f"/sys/class/net/{iface}/statistics/rx_bytes"
            tx_path = f"/sys/class/net/{iface}/statistics/tx_bytes"
            rx = tx = 0
            try:
                with open(rx_path) as f:
                    rx = int(f.read().strip())
                with open(tx_path) as f:
                    tx = int(f.read().strip())
            except Exception:
                continue

            rx_speed = 0
            tx_speed = 0

            with _net_prev_lock:
                prev = _net_prev.get(iface)
                if prev:
                    elapsed = now - prev["time"]
                    if elapsed > 0:
                        rx_speed = max(0, int((rx - prev["rx"]) / elapsed))
                        tx_speed = max(0, int((tx - prev["tx"]) / elapsed))
                _net_prev[iface] = {"rx": rx, "tx": tx, "time": now}

            interfaces.append({
                "name": iface,
                "rx": rx,
                "tx": tx,
                "rx_speed": rx_speed,
                "tx_speed": tx_speed,
                "group": _iface_group(iface)
            })

        # Urutin: phy dulu, vpn, docker, other
        group_order = {"phy": 0, "vpn": 1, "docker": 2, "other": 3}
        interfaces.sort(key=lambda i: (group_order.get(i["group"], 9), i["name"]))

        # Connection state counts
        connections = {"established": 0, "time_wait": 0, "listen": 0, "total": 0}
        try:
            out, _, _ = run(["ss", "-tapn"])
            lines = out.splitlines()
            # Skip header row (first line contains "State")
            if lines and lines[0].strip().startswith("State"):
                lines = lines[1:]

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                state = parts[0] if parts else ""
                if state == "LISTEN":
                    connections["listen"] += 1
                elif state == "ESTAB":
                    connections["established"] += 1
                elif state == "TIME-WAIT":
                    connections["time_wait"] += 1
            connections["total"] = len(lines)
        except Exception:
            pass

        return {"interfaces": interfaces, "connections": connections}
    except Exception:
        return {"interfaces": [], "connections": {"established": 0, "time_wait": 0, "listen": 0, "total": 0}}
