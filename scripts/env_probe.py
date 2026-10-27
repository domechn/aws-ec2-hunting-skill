#!/usr/bin/env python3
"""Runs ON a test instance (shipped over SSM by hunt.py): prints one JSON object describing the environment the probe runs in,
so a report can state OS, kernel, NIC and tuning, and someone else can line up their setup before comparing numbers."""
import json
import os
import re
import subprocess


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def rd(path):
    try:
        return open(path).read().strip()
    except OSError:
        return ""


iface = sh("ip -o -4 route show to default | awk '{print $5}' | head -1")
sysctl = {k: sh(f"sysctl -n {k} 2>/dev/null") or "n/a" for k in (
    "net.ipv4.tcp_congestion_control", "net.core.default_qdisc", "net.core.busy_poll", "net.core.busy_read",
    "net.core.rmem_max", "net.core.wmem_max", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_low_latency",
    "net.ipv4.tcp_slow_start_after_idle", "net.ipv4.tcp_timestamps", "net.ipv4.tcp_sack", "kernel.numa_balancing")}
os_name = re.search(r'PRETTY_NAME="?([^"\n]+)', rd("/etc/os-release"))
print(json.dumps({
    "os": os_name.group(1) if os_name else "?",
    "kernel": sh("uname -r"),
    "kernel_cmdline": rd("/proc/cmdline"),
    "cpu_model": sh("lscpu | awk -F: '/Model name/{print $2; exit}'").strip(),
    "vcpus": os.cpu_count(),
    "threads_per_core": sh("lscpu | awk -F: '/Thread\\(s\\) per core/{print $2}'").strip(),
    "cpu0_thread_siblings": rd("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list"),
    "cpu_governor": rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") or "n/a (no cpufreq)",
    "thp": rd("/sys/kernel/mm/transparent_hugepage/enabled"),
    "clocksource": rd("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
    "time_sync": sh("chronyc tracking 2>/dev/null | grep -E 'Reference ID|System time' | tr -s ' ' | paste -sd';'") or "n/a",
    "nic": {
        "iface": iface,
        "driver": os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver")) if iface else "?",
        "ena_driver_version": sh("modinfo -F version ena 2>/dev/null") or "n/a",
        "mtu": rd(f"/sys/class/net/{iface}/mtu"),
        "rx_queues": sh(f"ls /sys/class/net/{iface}/queues 2>/dev/null | grep -c '^rx-'"),
        "coalescing": sh(f"ethtool -c {iface} 2>/dev/null | grep -E 'Adaptive RX|rx-usecs:' | tr -s ' ' | paste -sd';'") or "n/a",
    },
    "services": {s: sh(f"systemctl is-active {s} 2>/dev/null") or "n/a" for s in ("irqbalance", "tuned")},
    "sysctl": sysctl,
    "rustc": sh("RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust /opt/rust/bin/rustc --version"),
    "probe_source_sha256": sh("cd /opt/hunt/probe && cat Cargo.toml Cargo.lock src/main.rs | sha256sum | cut -d' ' -f1"),
}))
