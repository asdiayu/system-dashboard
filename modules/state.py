"""Shared state — caches, locks, subscribers"""
import threading
import queue

# Ports
_port_cache = []

# Firewall
_fw_cache = {}

# System
_sys_cache = {}
_cpu_prev = None
_cpu_prev_lock = threading.Lock()

# Performance
_cpu_hogs_cache = []
_mem_cache = {}
_services_cache = []

# Network
_network_cache = {}
_net_prev = {}
_net_prev_lock = threading.Lock()

# Disk
_disk_analyzer_cache = {"folders": [], "mounts": []}

# Global lock for all caches
_cache_lock = threading.Lock()

# SSE subscribers
_subscribers = []
_sub_lock = threading.Lock()
_scan_event = threading.Event()  # set = ada subscriber, clear = idle

# Specs cache
_SPECS = None
