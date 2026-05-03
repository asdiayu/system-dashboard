#!/usr/bin/env python3
"""System Dashboard — Port Kill + Firewall + System Monitor (SSE real-time)
   Refactored: entry point only, logic in modules/"""
import json
import os
import threading
import time
import queue

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from modules.state import (
    _port_cache, _fw_cache, _sys_cache,
    _cpu_hogs_cache, _mem_cache, _services_cache,
    _network_cache, _disk_analyzer_cache,
    _cache_lock, _subscribers, _sub_lock, _scan_event,
    _net_prev, _net_prev_lock, _cpu_prev, _cpu_prev_lock
)
from modules.helpers import get_specs
from modules.ports import scan_ports, kill_port
from modules.firewall import scan_firewall, fw_allow, fw_deny, fw_delete
from modules.system import scan_system, get_cpu_delta
from modules.performance import (
    scan_cpu_hogs, scan_top_mem, clear_memory,
    scan_services, service_action
)
from modules.disk import scan_path, scan_df
from modules.network import scan_network

app = Flask(__name__)


# ─── SCANNER LOOP ───────────────────────────────────────

def scanner_loop():
    counter = 0
    get_cpu_delta()  # warmup
    while True:
        _scan_event.wait()  # BLOCK kalo gak ada subscriber
        try:
            ports = scan_ports()
            sysinfo = scan_system()
            cpu_hogs = scan_cpu_hogs()
            mem_info = scan_top_mem()
            services = scan_services()
            net_info = scan_network()

            if counter % 10 == 0:
                fw = scan_firewall()
            else:
                fw = None

            if counter % 6 == 0:
                # Scan home directory (faster than root)
                home_scan = scan_path(os.path.expanduser("~"))
                mounts = scan_df()
                disk_analyzer = {"folders": home_scan["folders"], "total": home_scan.get("total", "-"), "path": home_scan.get("path", "~"), "mounts": mounts}
            else:
                disk_analyzer = None

            with _cache_lock:
                _port_cache[:] = ports
                if fw is not None:
                    _fw_cache.clear()
                    _fw_cache.update(fw)
                _sys_cache.clear()
                _sys_cache.update(sysinfo)
                _cpu_hogs_cache[:] = cpu_hogs
                _mem_cache.clear()
                _mem_cache.update(mem_info)
                _services_cache[:] = services
                _network_cache.clear()
                _network_cache.update(net_info)
                if disk_analyzer is not None:
                    _disk_analyzer_cache.clear()
                    _disk_analyzer_cache.update(disk_analyzer)

            sub_count = len(set(s["ip"] for s in _subscribers)) if _subscribers else 0
            payload = json.dumps({
                "ports": ports,
                "firewall": _fw_cache,
                "system": sysinfo,
                "cpu_hogs": cpu_hogs,
                "memory": mem_info,
                "services": services,
                "network": net_info,
                "disk_analyzer": _disk_analyzer_cache,
                "subscribers": sub_count
            })

            with _sub_lock:
                dead = []
                for s in _subscribers:
                    try:
                        s["queue"].put_nowait(payload)
                    except queue.Full:
                        dead.append(s)
                for s in dead:
                    _subscribers.remove(s)
        except Exception:
            pass
        time.sleep(5)
        counter += 1


# ─── ROUTES ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    with _cache_lock:
        return jsonify({
            "ports": _port_cache, "firewall": _fw_cache,
            "system": _sys_cache, "cpu_hogs": _cpu_hogs_cache,
            "memory": _mem_cache, "services": _services_cache,
            "network": _network_cache, "disk_analyzer": _disk_analyzer_cache
        })


@app.route("/api/all")
def api_all():
    return api_data()


@app.route("/api/specs")
def api_specs():
    return jsonify(get_specs())


@app.route("/api/stream")
def api_stream():
    remote_addr = request.remote_addr or "0.0.0.0"
    q = queue.Queue(maxsize=3)
    with _sub_lock:
        # Bersihin subscriber yg gak responsif (queue numpuk = gak ada yg consume)
        _subscribers[:] = [s for s in _subscribers if s["queue"].qsize() == 0]
        was_empty = not _subscribers
        _subscribers.append({"queue": q, "ip": remote_addr})
        if was_empty:
            _scan_event.set()  # bangunin scanner loop

    def gen():
        try:
            sub_count = len(set(s["ip"] for s in _subscribers)) if _subscribers else 1
            with _cache_lock:
                yield f"data: {json.dumps({'ports': _port_cache, 'firewall': _fw_cache, 'system': _sys_cache, 'cpu_hogs': _cpu_hogs_cache, 'memory': _mem_cache, 'services': _services_cache, 'network': _network_cache, 'disk_analyzer': _disk_analyzer_cache, 'subscribers': sub_count})}\n\n"
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sub_lock:
                _subscribers[:] = [s for s in _subscribers if s["queue"] != q]
                if not _subscribers:
                    _scan_event.clear()  # pause scanner — gak ada yg lihat

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# Actions
@app.route("/api/kill/<int:port>", methods=["POST"])
def api_kill(port):
    return jsonify(kill_port(port))


@app.route("/api/firewall/allow/<path:port>", methods=["POST"])
def api_fw_allow(port):
    return jsonify(fw_allow(port))


@app.route("/api/firewall/deny/<path:port>", methods=["POST"])
def api_fw_deny(port):
    return jsonify(fw_deny(port))


@app.route("/api/firewall/delete/<int:num>", methods=["POST"])
def api_fw_delete(num):
    return jsonify(fw_delete(num))


@app.route("/api/cpu-hogs")
def api_cpu_hogs():
    with _cache_lock:
        return jsonify(_cpu_hogs_cache)


@app.route("/api/memory")
def api_memory():
    with _cache_lock:
        return jsonify(_mem_cache)


@app.route("/api/memory/clear", methods=["POST"])
def api_memory_clear():
    return jsonify(clear_memory())


@app.route("/api/services")
def api_services():
    with _cache_lock:
        return jsonify(_services_cache)


@app.route("/api/services/<name>/<action>", methods=["POST"])
def api_service_action(name, action):
    if action not in ("start", "stop", "restart"):
        return jsonify({"status": "error", "output": "invalid action"})
    return jsonify(service_action(name, action))


@app.route("/api/disk-analyzer")
def api_disk_analyzer():
    with _cache_lock:
        return jsonify(_disk_analyzer_cache)


@app.route("/api/disk-analyzer/scan/")
def api_disk_scan_root():
    return jsonify(scan_path("/"))


@app.route("/api/disk-analyzer/scan/<path:subpath>")
def api_disk_scan(subpath):
    path = "/" + subpath if not subpath.startswith("/") else subpath
    return jsonify(scan_path(path))


@app.route("/api/network")
def api_network():
    with _cache_lock:
        return jsonify(_network_cache)


# ─── MAIN ───────────────────────────────────────────────

if __name__ == "__main__":
    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
