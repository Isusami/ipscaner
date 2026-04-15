#!/usr/bin/env python3
"""
IP Range Scanner
  • File mode      : python3 ip_scanner.py ranges.txt  (one range/CIDR per line)
  • Manual ranges  : 192.168.1.0/24  |  10.0.0.0/21  |  192.168.1 1 254  |  192.168.1.1-50
  • ASN / URL mode : paste https://ipinfo.io/AS##### — netblocks extracted automatically
Uses raw ICMP sockets for fast scanning (no subprocess per host), shows live progress.
"""

import os
import random
import re
import socket
import struct
import subprocess
import sys
import ipaddress
import threading
import queue
import time
import platform
import urllib.request
import urllib.error


# ── ANSI colours ──────────────────────────────────────────────────────────────
# Enable ANSI on Windows (needed for color + \033[K to work in cmd/PowerShell)
if platform.system() == "Windows":
    import ctypes
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
CL     = "\r\033[K"


def bar(current, total, width=28):
    filled = int(width * current / total) if total else 0
    return f"[{'█' * filled}{'░' * (width - filled)}] {int(100 * current / total) if total else 0:3d}%"


# ── Ping ──────────────────────────────────────────────────────────────────────
_IS_MAC = platform.system() == "Darwin"
_IS_WIN = platform.system() == "Windows"

def ping(ip: str, count: int = 1) -> bool:
    if _IS_WIN:
        cmd = ["ping", "-n", str(count), "-w", "1000", ip]
    elif _IS_MAC:
        cmd = ["ping", "-c", str(count), "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


# ── URL → netblocks ───────────────────────────────────────────────────────────
def fetch_cidrs(url: str) -> list:
    """
    Fetch a URL and return every unique IPv4 CIDR found in the HTML.
    Skips prefixes shorter than /8 (noise like 0.0.0.0/0).
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*",
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        html = resp.read().decode("utf-8", errors="ignore")

    seen: set  = set()
    result: list = []
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b', html):
        raw = m.group(1)
        if raw in seen:
            continue
        seen.add(raw)
        try:
            net = ipaddress.IPv4Network(raw, strict=False)
        except ValueError:
            continue
        if net.prefixlen < 8:   # skip obviously bogus ranges
            continue
        canon = str(net)
        if canon not in result:
            result.append(canon)
    return result


# ── Range parsing ─────────────────────────────────────────────────────────────
def parse_range(text: str):
    """
    Returns (list[str], description) or (None, None).
    Accepted:  192.168.1.0/24  |  10.0.0.0/21  |  192.168.1 1 254  |  192.168.1.1-50
    """
    text = text.strip()

    # CIDR
    try:
        net   = ipaddress.IPv4Network(text, strict=False)
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
        return hosts, str(net)
    except ValueError:
        pass

    # "base start end"
    parts = text.split()
    if len(parts) == 3:
        base, s, e = parts
        try:
            si, ei = int(s), int(e)
            if 0 <= si <= 255 and 0 <= ei <= 255 and si <= ei:
                hosts = [f"{base}.{i}" for i in range(si, ei + 1)]
                ipaddress.IPv4Address(hosts[0])
                return hosts, f"{base}.{si}–{base}.{ei}"
        except (ValueError, ipaddress.AddressValueError):
            pass

    # "base.lo-hi"
    if "-" in text:
        try:
            prefix, rng = text.rsplit(".", 1)
            lo_s, hi_s  = rng.split("-", 1)
            lo, hi      = int(lo_s), int(hi_s)
            if 0 <= lo <= 255 and 0 <= hi <= 255 and lo <= hi:
                hosts = [f"{prefix}.{i}" for i in range(lo, hi + 1)]
                ipaddress.IPv4Address(hosts[0])
                return hosts, f"{prefix}.{lo}–{prefix}.{hi}"
        except (ValueError, ipaddress.AddressValueError):
            pass

    return None, None


def _add_tokens(tokens: list, ranges: list, seen: set):
    """Parse token strings and append valid ranges; print result per token."""
    for token in tokens:
        hosts, desc = parse_range(token)
        if not hosts:
            print(f"{RED}  '{token}' — unrecognised, skipped.{RESET}")
            continue
        new_hosts = [h for h in hosts if h not in seen]
        seen.update(new_hosts)
        ranges.append((new_hosts, desc))
        dup  = len(hosts) - len(new_hosts)
        note = f"  {YELLOW}({dup} dup{'s' if dup != 1 else ''} skipped){RESET}" if dup else ""
        print(f"  {GREEN}✓{RESET} {desc}  ({len(new_hosts)} hosts){note}")


# ── Built-in presets ─────────────────────────────────────────────────────────
# ── Built-in Cloudflare ranges (no internet needed) ───────────────────────────
# Source: ipv4.txt (user-provided), collapsed — 944 ranges
# covering 1,578,496 IPs.  Last updated: 2026-04.
_PRESETS = {
    "cf": {
        "name": "Cloudflare",
        "cidrs": [
            "1.0.0.0/24",  "1.1.1.0/24",  "5.10.214.0/23",
            "5.10.244.0/22",  "5.175.141.0/24",  "5.226.179.0/24",
            "5.226.181.0/24",  "5.226.183.0/24",  "5.252.81.0/24",
            "8.6.112.0/24",  "8.6.144.0/23",  "8.9.231.0/24",
            "8.10.148.0/24",  "8.14.199.0/24",  "8.14.201.0/24",
            "8.14.202.0/24",  "8.14.204.0/24",  "8.17.205.0/24",
            "8.17.206.0/23",  "8.18.50.0/24",  "8.18.113.0/24",
            "8.18.195.0/24",  "8.18.196.0/24",  "8.19.8.0/24",
            "8.20.100.0/23",  "8.20.103.0/24",  "8.20.122.0/23",
            "8.20.124.0/23",  "8.20.126.0/24",  "8.21.8.0/23",
            "8.21.10.0/24",  "8.21.12.0/23",  "8.21.110.0/23",
            "8.21.239.0/24",  "8.23.139.0/24",  "8.23.240.0/24",
            "8.24.87.0/24",  "8.24.243.0/24",  "8.24.244.0/24",
            "8.25.96.0/23",  "8.25.249.0/24",  "8.26.182.0/24",
            "8.27.64.0/24",  "8.27.66.0/23",  "8.27.68.0/23",
            "8.27.79.0/24",  "8.28.20.0/24",  "8.28.82.0/24",
            "8.28.126.0/23",  "8.28.213.0/24",  "8.29.105.0/24",
            "8.29.109.0/24",  "8.29.228.0/24",  "8.29.230.0/23",
            "8.30.234.0/24",  "8.31.2.0/24",  "8.31.160.0/23",
            "8.34.69.0/24",  "8.34.70.0/23",  "8.34.146.0/24",
            "8.34.201.0/24",  "8.34.202.0/24",  "8.35.57.0/24",
            "8.35.58.0/24",  "8.35.149.0/24",  "8.35.211.0/24",
            "8.36.216.0/22",  "8.36.220.0/24",  "8.37.41.0/24",
            "8.37.43.0/24",  "8.38.147.0/24",  "8.38.148.0/23",
            "8.39.6.0/24",  "8.39.18.0/24",  "8.39.125.0/24",
            "8.39.126.0/24",  "8.39.201.0/24",  "8.39.202.0/23",
            "8.39.204.0/22",  "8.39.213.0/24",  "8.39.214.0/23",
            "8.40.26.0/23",  "8.40.29.0/24",  "8.40.30.0/23",
            "8.40.107.0/24",  "8.40.111.0/24",  "8.40.140.0/24",
            "8.41.5.0/24",  "8.41.6.0/23",  "8.41.36.0/23",
            "8.42.51.0/24",  "8.42.54.0/23",  "8.42.161.0/24",
            "8.42.164.0/24",  "8.42.172.0/24",  "8.43.121.0/24",
            "8.43.122.0/23",  "8.43.224.0/23",  "8.43.226.0/24",
            "8.44.2.0/24",  "8.44.6.0/24",  "8.44.60.0/24",
            "8.44.62.0/23",  "8.45.41.0/24",  "8.45.43.0/24",
            "8.45.44.0/22",  "8.45.97.0/24",  "8.45.100.0/23",
            "8.45.102.0/24",  "8.45.108.0/24",  "8.45.111.0/24",
            "8.45.145.0/24",  "8.45.146.0/23",  "8.46.113.0/24",
            "8.46.115.0/24",  "8.46.117.0/24",  "8.46.118.0/23",
            "8.47.9.0/24",  "8.47.12.0/23",  "8.47.15.0/24",
            "8.47.69.0/24",  "8.47.71.0/24",  "8.48.130.0/23",
            "8.48.132.0/23",  "8.48.134.0/24",  "14.102.228.0/23",
            "23.131.204.0/24",  "23.141.168.0/24",  "23.145.136.0/24",
            "23.145.152.0/24",  "23.145.232.0/24",  "23.145.248.0/24",
            "23.152.4.0/24",  "23.167.152.0/24",  "23.178.112.0/24",
            "23.179.248.0/24",  "23.180.136.0/24",  "23.227.37.0/24",
            "23.227.38.0/23",  "23.227.42.0/23",  "23.227.48.0/23",
            "23.227.60.0/24",  "23.247.163.0/24",  "25.25.25.0/24",
            "25.26.27.0/24",  "25.129.196.0/22",  "27.50.48.0/23",
            "31.12.75.0/24",  "31.43.179.0/24",  "31.185.108.0/24",
            "37.153.171.0/24",  "38.96.28.0/23",  "44.31.142.0/24",
            "45.8.211.0/24",  "45.12.30.0/23",  "45.80.108.0/24",
            "45.80.110.0/23",  "45.81.58.0/24",  "45.85.118.0/23",
            "45.86.46.0/24",  "45.95.241.0/24",  "45.128.76.0/24",
            "45.130.125.0/24",  "45.131.4.0/22",  "45.131.208.0/22",
            "45.135.235.0/24",  "45.142.120.0/24",  "45.146.130.0/24",
            "45.146.201.0/24",  "45.148.100.0/24",  "45.149.12.0/24",
            "45.153.7.0/24",  "45.157.17.0/24",  "45.192.222.0/23",
            "45.192.224.0/24",  "45.194.11.0/24",  "45.194.53.0/24",
            "45.195.14.0/24",  "45.196.29.0/24",  "45.199.183.0/24",
            "45.202.113.0/24",  "45.205.0.0/24",  "45.250.152.0/22",
            "46.202.30.0/24",  "46.254.92.0/23",  "49.238.236.0/22",
            "61.32.240.0/24",  "61.245.108.0/24",  "62.72.166.0/24",
            "62.146.255.0/24",  "62.169.155.0/24",  "64.40.138.0/24",
            "64.40.140.0/24",  "64.69.24.0/23",  "64.239.31.0/24",
            "65.110.63.0/24",  "65.205.150.0/24",  "66.45.118.0/24",
            "66.71.220.0/24",  "66.81.247.0/24",  "66.81.255.0/24",
            "66.84.82.0/24",  "66.92.62.0/24",  "66.93.178.0/24",
            "66.94.32.0/20",  "66.203.249.0/24",  "66.225.252.0/24",
            "66.235.200.0/24",  "68.169.48.0/20",  "68.182.187.0/24",
            "69.48.218.0/24",  "69.89.0.0/20",  "69.90.210.0/24",
            "72.52.113.0/24",  "74.49.214.0/23",  "74.204.59.0/24",
            "74.205.180.0/24",  "77.37.33.0/24",  "77.73.113.0/24",
            "77.74.228.0/24",  "77.75.199.0/24",  "77.105.163.0/24",
            "77.111.106.0/24",  "77.232.140.0/24",  "78.128.122.0/24",
            "80.93.202.0/24",  "82.21.82.0/24",  "82.22.16.0/24",
            "82.26.156.0/24",  "82.118.242.0/24",  "82.139.216.0/23",
            "83.118.224.0/22",  "86.38.214.0/24",  "86.38.251.0/24",
            "87.229.48.0/24",  "88.216.66.0/23",  "88.216.69.0/24",
            "89.47.56.0/23",  "89.106.90.0/24",  "89.116.46.0/24",
            "89.116.161.0/24",  "89.116.180.0/24",  "89.116.250.0/24",
            "89.117.112.0/24",  "89.207.18.0/24",  "89.249.200.0/24",
            "91.124.127.0/24",  "91.192.106.0/23",  "91.193.58.0/23",
            "91.199.81.0/24",  "91.206.71.0/24",  "91.209.253.0/24",
            "92.53.188.0/22",  "92.60.74.0/24",  "92.243.74.0/23",
            "93.114.64.0/23",  "93.115.102.0/24",  "94.140.0.0/24",
            "94.156.10.0/24",  "94.247.142.0/24",  "96.43.100.0/23",
            "102.132.188.0/24",  "102.177.176.0/24",  "102.177.189.0/24",
            "103.11.212.0/24",  "103.11.214.0/24",  "103.15.85.0/24",
            "103.19.144.0/23",  "103.21.244.0/24",  "103.21.246.0/23",
            "103.22.200.0/22",  "103.31.4.0/24",  "103.31.79.0/24",
            "103.79.228.0/23",  "103.81.228.0/24",  "103.112.176.0/24",
            "103.116.7.0/24",  "103.121.59.0/24",  "103.133.1.0/24",
            "103.135.208.0/22",  "103.160.204.0/24",  "103.169.142.0/24",
            "103.172.110.0/23",  "103.186.74.0/24",  "103.198.92.0/24",
            "103.204.13.0/24",  "103.215.22.0/24",  "103.219.64.0/22",
            "104.16.0.0/14",  "104.20.0.0/18",  "104.21.0.0/17",
            "104.21.192.0/19",  "104.21.224.0/20",  "104.22.0.0/22",
            "104.22.5.0/24",  "104.22.6.0/23",  "104.22.8.0/21",
            "104.22.16.0/21",  "104.22.24.0/22",  "104.22.29.0/24",
            "104.22.30.0/23",  "104.22.32.0/24",  "104.22.42.0/23",
            "104.22.44.0/22",  "104.22.48.0/24",  "104.22.51.0/24",
            "104.22.52.0/24",  "104.22.54.0/23",  "104.22.56.0/23",
            "104.22.58.0/24",  "104.22.60.0/24",  "104.22.66.0/23",
            "104.22.240.0/20",  "104.23.0.0/18",  "104.23.64.0/19",
            "104.23.160.0/20",  "104.23.176.0/23",  "104.23.178.0/24",
            "104.23.180.0/22",  "104.23.184.0/21",  "104.23.192.0/21",
            "104.23.200.0/22",  "104.23.204.0/24",  "104.23.206.0/23",
            "104.23.208.0/20",  "104.23.224.0/20",  "104.23.240.0/21",
            "104.23.248.0/24",  "104.23.250.0/23",  "104.23.252.0/22",
            "104.24.0.0/18",  "104.24.64.0/19",  "104.24.128.0/17",
            "104.25.0.0/16",  "104.26.0.0/20",  "104.27.0.0/17",
            "104.27.192.0/20",  "104.28.0.0/16",  "104.29.0.0/21",
            "104.29.8.0/23",  "104.29.11.0/24",  "104.29.12.0/22",
            "104.29.16.0/23",  "104.29.19.0/24",  "104.29.20.0/22",
            "104.29.24.0/21",  "104.29.32.0/24",  "104.29.34.0/23",
            "104.29.36.0/22",  "104.29.41.0/24",  "104.29.42.0/23",
            "104.29.44.0/23",  "104.29.47.0/24",  "104.29.48.0/23",
            "104.29.50.0/24",  "104.29.52.0/22",  "104.29.57.0/24",
            "104.29.59.0/24",  "104.29.61.0/24",  "104.29.62.0/23",
            "104.29.64.0/20",  "104.29.80.0/23",  "104.29.82.0/24",
            "104.29.85.0/24",  "104.29.86.0/24",  "104.29.88.0/21",
            "104.29.96.0/22",  "104.29.100.0/23",  "104.29.102.0/24",
            "104.29.104.0/21",  "104.29.112.0/22",  "104.29.116.0/23",
            "104.29.121.0/24",  "104.29.122.0/23",  "104.29.124.0/22",
            "104.29.128.0/18",  "104.30.0.0/19",  "104.30.32.0/23",
            "104.30.128.0/23",  "104.30.132.0/22",  "104.30.136.0/23",
            "104.30.144.0/21",  "104.30.160.0/19",  "104.31.0.0/21",
            "104.31.16.0/22",  "104.31.20.0/24",  "104.36.195.0/24",
            "104.129.164.0/22",  "104.156.176.0/23",  "104.234.239.0/24",
            "104.239.72.0/24",  "104.254.140.0/24",  "108.162.192.0/20",
            "108.162.209.0/24",  "108.162.210.0/23",  "108.162.212.0/23",
            "108.162.216.0/23",  "108.162.218.0/24",  "108.162.220.0/23",
            "108.162.226.0/23",  "108.162.235.0/24",  "108.162.236.0/22",
            "108.162.240.0/21",  "108.162.248.0/23",  "108.162.250.0/24",
            "108.165.152.0/24",  "108.165.216.0/24",  "109.234.211.0/24",
            "114.129.43.0/24",  "123.108.75.0/24",  "123.253.173.0/24",
            "130.108.73.0/24",  "130.108.104.0/23",  "130.108.121.0/24",
            "130.108.253.0/24",  "131.0.72.0/22",  "131.167.255.0/24",
            "136.143.138.0/24",  "137.66.96.0/24",  "138.5.248.0/24",
            "138.226.234.0/24",  "138.249.21.0/24",  "138.249.126.0/24",
            "139.64.234.0/23",  "140.99.233.0/24",  "141.11.202.0/23",
            "141.101.64.0/21",  "141.101.72.0/22",  "141.101.76.0/23",
            "141.101.82.0/23",  "141.101.84.0/22",  "141.101.88.0/22",
            "141.101.93.0/24",  "141.101.94.0/23",  "141.101.96.0/22",
            "141.101.100.0/24",  "141.101.104.0/23",  "141.101.108.0/23",
            "141.101.110.0/24",  "141.101.112.0/20",  "141.193.213.0/24",
            "143.14.224.0/24",  "143.14.251.0/24",  "144.124.208.0/22",
            "147.78.140.0/24",  "147.185.161.0/24",  "147.189.42.0/23",
            "148.227.167.0/24",  "150.48.128.0/18",  "151.243.128.0/22",
            "151.243.133.0/24",  "151.246.216.0/23",  "152.114.0.0/17",
            "152.114.128.0/18",  "154.51.129.0/24",  "154.51.160.0/24",
            "154.62.129.0/24",  "154.81.141.0/24",  "154.83.2.0/24",
            "154.83.22.0/23",  "154.83.30.0/23",  "154.84.14.0/23",
            "154.84.16.0/21",  "154.84.24.0/22",  "154.90.70.0/24",
            "154.92.9.0/24",  "154.193.133.0/24",  "154.193.184.0/24",
            "154.194.12.0/24",  "154.194.225.0/24",  "154.197.64.0/23",
            "154.197.75.0/24",  "154.197.80.0/24",  "154.197.88.0/24",
            "154.197.108.0/24",  "154.197.121.0/24",  "154.198.173.0/24",
            "154.200.89.0/24",  "154.202.89.0/24",  "154.206.12.0/24",
            "154.207.77.0/24",  "154.207.79.0/24",  "154.207.127.0/24",
            "154.207.189.0/24",  "154.207.252.0/23",  "154.211.8.0/24",
            "154.218.15.0/24",  "154.219.5.0/24",  "154.223.134.0/23",
            "155.46.167.0/24",  "155.46.213.0/24",  "155.103.109.0/24",
            "155.117.208.0/23",  "156.224.73.0/24",  "156.225.72.0/24",
            "156.243.83.0/24",  "156.243.246.0/24",  "156.246.69.0/24",
            "156.246.70.0/24",  "156.252.2.0/23",  "156.255.123.0/24",
            "158.94.212.0/24",  "159.112.235.0/24",  "159.242.242.0/24",
            "159.246.55.0/24",  "160.153.0.0/24",  "161.248.134.0/23",
            "162.44.32.0/22",  "162.44.118.0/23",  "162.44.208.0/23",
            "162.120.94.0/24",  "162.158.0.0/20",  "162.158.16.0/21",
            "162.158.24.0/23",  "162.158.26.0/24",  "162.158.28.0/22",
            "162.158.32.0/21",  "162.158.40.0/22",  "162.158.44.0/23",
            "162.158.46.0/24",  "162.158.48.0/20",  "162.158.64.0/24",
            "162.158.71.0/24",  "162.158.72.0/21",  "162.158.80.0/23",
            "162.158.82.0/24",  "162.158.84.0/22",  "162.158.88.0/21",
            "162.158.96.0/19",  "162.158.128.0/17",  "162.159.0.0/18",
            "162.159.64.0/20",  "162.159.80.0/24",  "162.159.90.0/23",
            "162.159.92.0/22",  "162.159.96.0/19",  "162.159.128.0/19",
            "162.159.160.0/24",  "162.159.192.0/20",  "162.159.208.0/21",
            "162.159.224.0/24",  "162.159.226.0/24",  "162.159.228.0/22",
            "162.159.232.0/22",  "162.159.236.0/23",  "162.159.239.0/24",
            "162.159.240.0/20",  "162.251.82.0/24",  "162.251.205.0/24",
            "164.38.155.0/24",  "164.77.28.0/23",  "165.101.60.0/23",
            "166.88.240.0/24",  "167.1.137.0/24",  "167.1.148.0/23",
            "167.1.150.0/24",  "167.1.181.0/24",  "167.68.4.0/23",
            "167.68.11.0/24",  "167.68.42.0/24",  "167.74.94.0/23",
            "167.74.130.0/24",  "167.74.140.0/22",  "168.151.31.0/24",
            "169.40.133.0/24",  "170.114.45.0/24",  "170.114.46.0/24",
            "170.114.52.0/24",  "170.114.78.0/24",  "170.168.7.0/24",
            "170.176.152.0/24",  "170.176.163.0/24",  "172.64.32.0/19",
            "172.64.66.0/23",  "172.64.68.0/23",  "172.64.72.0/24",
            "172.64.74.0/23",  "172.64.76.0/22",  "172.64.80.0/20",
            "172.64.96.0/22",  "172.64.100.0/23",  "172.64.144.0/20",
            "172.64.176.0/24",  "172.64.178.0/23",  "172.64.184.0/22",
            "172.64.188.0/23",  "172.64.192.0/19",  "172.64.228.0/22",
            "172.64.232.0/22",  "172.64.240.0/20",  "172.65.0.0/16",
            "172.66.0.0/22",  "172.66.40.0/21",  "172.66.128.0/19",
            "172.66.160.0/20",  "172.66.176.0/23",  "172.66.192.0/20",
            "172.66.208.0/21",  "172.66.216.0/23",  "172.67.64.0/18",
            "172.67.128.0/17",  "172.68.0.0/22",  "172.68.4.0/23",
            "172.68.7.0/24",  "172.68.8.0/21",  "172.68.16.0/20",
            "172.68.32.0/19",  "172.68.65.0/24",  "172.68.66.0/23",
            "172.68.68.0/22",  "172.68.72.0/21",  "172.68.81.0/24",
            "172.68.82.0/23",  "172.68.84.0/22",  "172.68.88.0/21",
            "172.68.96.0/20",  "172.68.112.0/21",  "172.68.121.0/24",
            "172.68.123.0/24",  "172.68.124.0/22",  "172.68.128.0/20",
            "172.68.144.0/21",  "172.68.152.0/22",  "172.68.156.0/23",
            "172.68.159.0/24",  "172.68.160.0/24",  "172.68.162.0/23",
            "172.68.164.0/22",  "172.68.168.0/21",  "172.68.176.0/20",
            "172.68.192.0/21",  "172.68.200.0/23",  "172.68.203.0/24",
            "172.68.204.0/22",  "172.68.208.0/20",  "172.68.224.0/19",
            "172.69.0.0/22",  "172.69.5.0/24",  "172.69.6.0/23",
            "172.69.8.0/21",  "172.69.16.0/20",  "172.69.32.0/21",
            "172.69.40.0/22",  "172.69.45.0/24",  "172.69.46.0/23",
            "172.69.48.0/23",  "172.69.50.0/24",  "172.69.52.0/22",
            "172.69.56.0/21",  "172.69.64.0/20",  "172.69.81.0/24",
            "172.69.82.0/23",  "172.69.84.0/22",  "172.69.88.0/21",
            "172.69.96.0/20",  "172.69.112.0/22",  "172.69.117.0/24",
            "172.69.118.0/23",  "172.69.120.0/21",  "172.69.128.0/20",
            "172.69.144.0/23",  "172.69.146.0/24",  "172.69.148.0/22",
            "172.69.152.0/23",  "172.69.156.0/22",  "172.69.161.0/24",
            "172.69.162.0/23",  "172.69.164.0/22",  "172.69.168.0/22",
            "172.69.173.0/24",  "172.69.174.0/23",  "172.69.176.0/21",
            "172.69.184.0/22",  "172.69.188.0/23",  "172.69.191.0/24",
            "172.69.192.0/20",  "172.69.208.0/24",  "172.69.210.0/23",
            "172.69.212.0/22",  "172.69.216.0/21",  "172.69.224.0/19",
            "172.70.0.0/19",  "172.70.32.0/20",  "172.70.48.0/21",
            "172.70.56.0/23",  "172.70.58.0/24",  "172.70.62.0/23",
            "172.70.64.0/21",  "172.70.80.0/21",  "172.70.92.0/22",
            "172.70.100.0/23",  "172.70.103.0/24",  "172.70.104.0/21",
            "172.70.112.0/22",  "172.70.116.0/23",  "172.70.120.0/21",
            "172.70.128.0/20",  "172.70.144.0/22",  "172.70.149.0/24",
            "172.70.152.0/21",  "172.70.160.0/22",  "172.70.172.0/22",
            "172.70.176.0/20",  "172.70.192.0/19",  "172.70.224.0/21",
            "172.70.232.0/23",  "172.70.234.0/24",  "172.70.236.0/22",
            "172.70.240.0/20",  "172.71.0.0/20",  "172.71.16.0/21",
            "172.71.24.0/23",  "172.71.27.0/24",  "172.71.28.0/22",
            "172.71.32.0/19",  "172.71.64.0/19",  "172.71.96.0/21",
            "172.71.108.0/22",  "172.71.112.0/20",  "172.71.128.0/18",
            "172.71.192.0/22",  "172.71.197.0/24",  "172.71.198.0/23",
            "172.71.200.0/22",  "172.71.204.0/24",  "172.71.208.0/20",
            "172.71.224.0/20",  "172.71.240.0/23",  "172.71.242.0/24",
            "172.71.244.0/22",  "172.71.248.0/24",  "172.71.253.0/24",
            "172.71.254.0/23",  "172.83.72.0/23",  "172.83.76.0/24",
            "173.0.92.0/24",  "173.245.49.0/24",  "173.245.54.0/24",
            "173.245.58.0/23",  "173.245.60.0/23",  "173.245.63.0/24",
            "176.103.113.0/24",  "176.124.223.0/24",  "176.126.206.0/23",
            "178.94.249.0/24",  "178.211.142.0/24",  "178.213.76.0/24",
            "181.214.1.0/24",  "181.215.196.0/24",  "182.23.210.0/24",
            "184.174.80.0/24",  "185.7.190.0/23",  "185.7.240.0/24",
            "185.18.184.0/24",  "185.18.250.0/24",  "185.29.76.0/24",
            "185.38.25.0/24",  "185.38.135.0/24",  "185.41.148.0/24",
            "185.60.251.0/24",  "185.122.0.0/24",  "185.126.66.0/24",
            "185.132.85.0/24",  "185.132.86.0/23",  "185.133.172.0/24",
            "185.135.9.0/24",  "185.146.172.0/23",  "185.148.104.0/22",
            "185.149.135.0/24",  "185.156.19.0/24",  "185.158.133.0/24",
            "185.159.247.0/24",  "185.162.228.0/22",  "185.170.166.0/24",
            "185.176.24.0/24",  "185.176.26.0/24",  "185.178.196.0/22",
            "185.193.28.0/22",  "185.207.92.0/24",  "185.207.196.0/22",
            "185.209.154.0/24",  "185.229.206.0/24",  "185.238.228.0/24",
            "185.251.80.0/23",  "188.42.88.0/23",  "188.42.98.0/24",
            "188.42.145.0/24",  "188.95.12.0/24",  "188.114.96.0/22",
            "188.114.100.0/24",  "188.114.102.0/23",  "188.114.106.0/23",
            "188.114.108.0/24",  "188.114.111.0/24",  "188.164.158.0/23",
            "188.164.248.0/24",  "188.244.122.0/24",  "190.93.240.0/20",
            "192.65.217.0/24",  "192.71.82.0/24",  "192.86.150.0/24",
            "192.103.56.0/24",  "192.133.11.0/24",  "192.152.138.0/24",
            "192.236.26.0/24",  "193.8.237.0/24",  "193.9.49.0/24",
            "193.16.63.0/24",  "193.17.206.0/24",  "193.22.229.0/24",
            "193.67.144.0/24",  "193.162.35.0/24",  "193.202.90.0/24",
            "193.202.112.0/24",  "193.227.99.0/24",  "193.233.21.0/24",
            "193.233.132.0/24",  "194.1.194.0/24",  "194.26.68.0/24",
            "194.34.64.0/23",  "194.34.66.0/24",  "194.36.49.0/24",
            "194.36.55.0/24",  "194.39.112.0/21",  "194.41.114.0/24",
            "194.53.53.0/24",  "194.59.5.0/24",  "194.113.223.0/24",
            "194.152.44.0/24",  "194.169.194.0/24",  "195.26.229.0/24",
            "195.28.190.0/23",  "195.85.23.0/24",  "195.85.59.0/24",
            "195.189.177.0/24",  "195.242.122.0/23",  "195.245.221.0/24",
            "195.250.46.0/24",  "196.13.241.0/24",  "196.207.45.0/24",
            "197.234.240.0/22",  "198.41.128.0/24",  "198.41.130.0/24",
            "198.41.132.0/22",  "198.41.136.0/22",  "198.41.143.0/24",
            "198.41.144.0/22",  "198.41.148.0/24",  "198.41.150.0/24",
            "198.41.192.0/20",  "198.41.208.0/23",  "198.41.211.0/24",
            "198.41.214.0/23",  "198.41.216.0/22",  "198.41.222.0/23",
            "198.41.224.0/24",  "198.41.226.0/23",  "198.41.228.0/22",
            "198.41.232.0/23",  "198.41.236.0/24",  "198.41.238.0/23",
            "198.41.240.0/22",  "198.41.245.0/24",  "198.41.246.0/23",
            "198.41.248.0/22",  "198.41.252.0/23",  "198.41.255.0/24",
            "198.177.56.0/23",  "198.202.211.0/24",  "198.217.251.0/24",
            "198.252.206.0/24",  "199.5.242.0/24",  "199.27.128.0/21",
            "199.33.230.0/23",  "199.33.232.0/23",  "199.60.103.0/24",
            "199.181.197.0/24",  "200.73.67.0/24",  "202.27.69.0/24",
            "202.82.250.0/24",  "203.6.66.0/24",  "203.6.74.0/24",
            "203.13.32.0/24",  "203.15.65.0/24",  "203.17.126.0/24",
            "203.19.222.0/24",  "203.22.223.0/24",  "203.22.241.0/24",
            "203.23.103.0/24",  "203.23.104.0/24",  "203.23.106.0/24",
            "203.24.102.0/23",  "203.24.108.0/23",  "203.28.8.0/23",
            "203.29.52.0/22",  "203.30.188.0/22",  "203.32.120.0/23",
            "203.34.28.0/24",  "203.34.80.0/24",  "203.55.107.0/24",
            "203.89.5.0/24",  "203.168.128.0/22",  "203.168.192.0/20",
            "204.62.141.0/24",  "204.68.111.0/24",  "204.69.207.0/24",
            "204.153.16.0/24",  "204.195.192.0/18",  "205.233.181.0/24",
            "207.189.149.0/24",  "208.42.188.0/24",  "208.77.33.0/24",
            "208.77.35.0/24",  "208.88.71.0/24",  "208.100.60.0/24",
            "209.46.30.0/24",  "209.55.226.0/24",  "209.55.232.0/24",
            "209.55.234.0/24",  "209.55.246.0/23",  "209.55.253.0/24",
            "209.55.254.0/24",  "209.222.114.0/23",  "211.188.27.0/24",
            "212.6.39.0/24",  "212.22.76.0/24",  "212.104.128.0/24",
            "212.239.86.0/24",  "213.182.199.0/24",  "213.219.247.0/24",
            "213.241.198.0/24",  "216.19.107.0/24",  "216.74.106.0/24",
            "216.120.131.0/24",  "216.120.180.0/23",  "216.132.75.0/24",
            "216.154.208.0/20",  "216.163.179.0/24",  "216.198.53.0/24",
            "216.198.54.0/24",  "216.205.52.0/24",  "216.224.121.0/24",
            "222.167.32.0/22",  "223.27.176.0/23",
        ],
    },
}


def _load_preset(key: str) -> list:
    """Return the hardcoded CIDR list for a preset — no network required."""
    preset = _PRESETS[key]
    cidrs  = preset["cidrs"]
    print(f"  {GREEN}✓{RESET} Loaded {CYAN}{BOLD}{preset['name']}{RESET} "
          f"— {len(cidrs)} ranges (built-in, no internet needed)")
    return cidrs


# ── Fast ICMP scanner (raw sockets, no per-host subprocess) ──────────────────
_PID = os.getpid() & 0xFFFF


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack_from('!H', data, i)[0] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_icmp_echo(seq: int) -> bytes:
    hdr = struct.pack('!BBHHH', 8, 0, 0, _PID, seq & 0xFFFF)
    payload = b'\x00' * 8
    chk = _icmp_checksum(hdr + payload)
    return struct.pack('!BBHHH', 8, 0, chk, _PID, seq & 0xFFFF) + payload


def fast_scan_icmp(hosts: list, rate: int = 1000, timeout: float = 2.0,
                   out_fh=None):
    """
    Send ICMP Echo Requests at `rate` pps from a single socket.
    macOS : SOCK_DGRAM  — no root required.
    Linux : SOCK_RAW    — needs sudo.
    out_fh: open file handle — each alive IP is written + flushed immediately.
    Returns sorted list of alive IPs, or None if socket creation fails.
    """
    target_set = set(hosts)
    alive:     list = []
    alive_set: set  = set()
    total      = len(hosts)
    t_start    = time.time()
    t_refresh  = [0.0]
    out_lock   = threading.Lock()   # serialize stdout between sender + receiver

    # Try unprivileged datagram socket first (macOS), then raw (Linux/root)
    raw_mode = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            raw_mode = True
        except PermissionError:
            return None   # signal caller to fall back

    sock.settimeout(0.1)   # non-blocking-compatible on all platforms incl. Windows
    stop_recv = threading.Event()

    def _receiver():
        while not stop_recv.is_set():
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                continue
            src_ip = addr[0]
            if src_ip not in target_set or src_ip in alive_set:
                continue
            # SOCK_RAW includes 20-byte IP header; SOCK_DGRAM strips it
            offset = 20 if raw_mode else 0
            if len(data) < offset + 1 or data[offset] != 0:   # 0 = Echo Reply
                continue
            alive_set.add(src_ip)
            alive.append(src_ip)
            with out_lock:
                sys.stdout.write(f"{CL}  {GREEN}●{RESET} {src_ip}\n")
                sys.stdout.flush()          # show immediately, don't buffer
                if out_fh:
                    out_fh.write(f"{src_ip}\n")
                    out_fh.flush()          # persist to disk immediately
            t_refresh[0] = 0               # force progress bar redraw right after

    recv_thread = threading.Thread(target=_receiver, daemon=True)
    recv_thread.start()
    sys.stdout.write("\n")

    interval = 1.0 / rate if rate > 0 else 0

    for i, ip in enumerate(hosts):
        try:
            sock.sendto(_build_icmp_echo(i), (ip, 0))
        except OSError:
            pass

        if interval:
            time.sleep(interval)

        now = time.time()
        if now - t_refresh[0] >= 0.25:
            elapsed = now - t_start
            spd     = (i + 1) / elapsed if elapsed > 0 else 0
            rem     = (total - i - 1) / spd if spd > 0 else 0
            if rem >= 3600:
                eta = f"{int(rem // 3600)}h{int((rem % 3600) // 60):02d}m"
            elif rem >= 60:
                eta = f"{int(rem // 60)}m{int(rem % 60):02d}s"
            else:
                eta = f"{rem:.0f}s"
            with out_lock:
                sys.stdout.write(
                    f"{CL}{CYAN}{bar(i + 1, total)}{RESET}"
                    f"  {i+1:,}/{total:,}"
                    f"  {GREEN}alive:{len(alive)}{RESET}"
                    f"  {spd:.0f}/s"
                    f"  ETA:{eta}"
                )
                sys.stdout.flush()
            t_refresh[0] = now

    with out_lock:
        sys.stdout.write(f"{CL}  Waiting {timeout:.1f}s for late replies…")
        sys.stdout.flush()
    time.sleep(timeout)
    stop_recv.set()
    recv_thread.join(timeout=2)
    try:
        sock.close()
    except OSError:
        pass
    sys.stdout.write(CL)
    sys.stdout.flush()

    alive.sort(key=ipaddress.IPv4Address)
    return alive


# ── Fallback scanner (subprocess ping, used if raw sockets unavailable) ───────
def _worker(ip_q: queue.Queue, out_q: queue.Queue, ping_count: int):
    while True:
        try:
            ip = ip_q.get_nowait()
        except queue.Empty:
            return
        out_q.put((ip, ping(ip, ping_count)))
        ip_q.task_done()


def scan(hosts: list, workers: int = 50, ping_count: int = 1, out_fh=None):
    ip_q: queue.Queue = queue.Queue()
    out_q: queue.Queue = queue.Queue()
    for h in hosts:
        ip_q.put(h)

    for _ in range(min(workers, len(hosts))):
        threading.Thread(target=_worker, args=(ip_q, out_q, ping_count), daemon=True).start()

    total     = len(hosts)
    done      = 0
    alive     = []
    t_start   = time.time()
    t_refresh = 0.0   # last time the progress bar was redrawn

    sys.stdout.write("\n")

    while done < total:
        try:
            ip, is_alive = out_q.get(timeout=0.2)
            done += 1
            if is_alive:
                alive.append(ip)
                sys.stdout.write(f"{CL}  {GREEN}●{RESET} {ip}\n")
                sys.stdout.flush()
                if out_fh:
                    out_fh.write(f"{ip}\n")
                    out_fh.flush()
                t_refresh = 0
        except queue.Empty:
            pass

        now = time.time()
        if now - t_refresh >= 0.25:          # redraw at most ~4× per second
            elapsed = now - t_start
            rate    = done / elapsed if elapsed > 0 else 0
            remain  = (total - done) / rate  if rate  > 0 else 0
            if remain >= 3600:
                eta = f"{int(remain // 3600)}h{int((remain % 3600) // 60):02d}m"
            elif remain >= 60:
                eta = f"{int(remain // 60)}m{int(remain % 60):02d}s"
            else:
                eta = f"{remain:.0f}s"
            sys.stdout.write(
                f"{CL}{CYAN}{bar(done, total)}{RESET}"
                f"  {done:,}/{total:,}"
                f"  {GREEN}alive:{len(alive)}{RESET}"
                f"  {rate:.0f}/s"
                f"  ETA:{eta}"
            )
            sys.stdout.flush()
            t_refresh = now

    sys.stdout.write(CL)
    sys.stdout.flush()

    alive.sort(key=ipaddress.IPv4Address)
    return alive


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{BOLD}{'━' * 52}{RESET}")
    print(f"{BOLD}   IP Range Scanner{RESET}")
    print(f"{BOLD}{'━' * 52}{RESET}")
    print("  Usage: python3 ip_scanner.py [ranges.txt]")
    print(f"  {CYAN}cf{RESET}              → Cloudflare official IP ranges")
    print("  https://…       → auto-extract ranges from URL/ASN page")
    print("  192.168.1.0/24  → manual range (one per line, blank to scan)")
    print(f"{'━' * 52}\n")

    ranges: list = []
    seen:   set  = set()

    # ── File mode: python3 ip_scanner.py ranges.txt ──────────────────────────
    if len(sys.argv) > 1:
        src = sys.argv[1]
        try:
            with open(src) as fh:
                raw_lines = [ln.strip() for ln in fh
                             if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as e:
            print(f"{RED}  Cannot read '{src}': {e}{RESET}")
            return
        tokens = [t.strip() for ln in raw_lines for t in ln.split(",") if t.strip()]
        print(f"  Reading from {BOLD}{src}{RESET} — {len(tokens)} range(s)\n")
        _add_tokens(tokens, ranges, seen)

    else:
        # ── First prompt — preset / URL / range ──────────────────────────────
        try:
            first = input("cf / URL / range : ").strip()
        except EOFError:
            return

        if first.lower() in _PRESETS:
            # ── Preset mode (e.g. "cf") ───────────────────────────────────────
            cidrs = _load_preset(first.lower())
            if not cidrs:
                print(f"{RED}  No ranges loaded.{RESET}")
                return
            print()
            _add_tokens(cidrs, ranges, seen)
            total_ips = sum(len(h) for h, _ in ranges)
            print(f"\n  {BOLD}{total_ips:,}{RESET} hosts across {len(ranges)} range(s)")
            try:
                confirm = input("\n  Proceed? [Y/n] : ").strip().lower()
            except EOFError:
                confirm = "y"
            if confirm == "n":
                print("Aborted.")
                return

        elif first.startswith("http://") or first.startswith("https://"):
            # ── URL mode ─────────────────────────────────────────────────────
            print(f"  Fetching {first} …")
            try:
                cidrs = fetch_cidrs(first)
            except urllib.error.URLError as e:
                print(f"{RED}  Network error: {e}{RESET}")
                return
            except Exception as e:
                print(f"{RED}  Failed to fetch URL: {e}{RESET}")
                return

            if not cidrs:
                print(f"{RED}  No IPv4 netblocks found on that page.{RESET}")
                return

            print(f"  Found {BOLD}{len(cidrs)}{RESET} netblock(s):\n")
            _add_tokens(cidrs, ranges, seen)

            total_ips = sum(len(h) for h, _ in ranges)
            print(f"\n  {BOLD}{total_ips:,}{RESET} hosts total across {len(ranges)} range(s)")
            if total_ips > 5000:
                print(f"  {YELLOW}Warning: large scan — this may take a long time.{RESET}")

            try:
                confirm = input("\n  Proceed? [Y/n] : ").strip().lower()
            except EOFError:
                confirm = "y"
            if confirm == "n":
                print("Aborted.")
                return

        else:
            # ── Manual mode — first line already read ────────────────────────
            if first:
                _add_tokens([t.strip() for t in first.split(",") if t.strip()], ranges, seen)

            while True:
                label = f"Range #{len(ranges) + 1}" if ranges else "IP range  "
                try:
                    line = input(f"{label} : ").strip()
                except EOFError:
                    break
                if not line:
                    if ranges:
                        break
                    continue
                _add_tokens([t.strip() for t in line.split(",") if t.strip()], ranges, seen)

    if not ranges:
        print(f"{RED}No ranges entered. Exiting.{RESET}")
        return

    # ── Build flat host list — shuffle within each subnet, then interleave ───
    # Shuffling avoids sequential-scan detection and spreads load across ranges.
    # The seen set already deduplicates at parse time; this is a safety net.
    shuffled_ranges = []
    for hosts, desc in ranges:
        bucket = list(hosts)
        random.shuffle(bucket)
        shuffled_ranges.append(bucket)

    # Round-robin interleave: take one IP from each range in turn so all
    # subnets are probed early rather than one subnet exhausted first.
    all_hosts: list = []
    seen_ips:  set  = set()
    iters = [iter(b) for b in shuffled_ranges]
    while iters:
        next_iters = []
        for it in iters:
            ip = next(it, None)
            if ip is None:
                continue
            if ip not in seen_ips:
                seen_ips.add(ip)
                all_hosts.append(ip)
            next_iters.append(it)
        iters = next_iters

    ip_to_range = {h: idx for idx, (hosts, _) in enumerate(ranges) for h in hosts}

    try:
        out_file = input("\nOutput file [output.txt] : ").strip() or "output.txt"
    except EOFError:
        out_file = "output.txt"

    print(f"\n  {BOLD}Speed presets:{RESET}")
    print(f"    fast   — 5000/s, 1s wait  (local / fast networks)")
    print(f"    normal — 1000/s, 2s wait  (internet, default)")
    print(f"    slow   —  200/s, 3s wait  (distant / lossy networks)")

    _presets = {
        "fast":   (5000, 1.0),
        "normal": (1000, 2.0),
        "slow":   (200,  3.0),
    }
    try:
        sp_input = input("\nSpeed [fast/normal/slow] : ").strip().lower() or "normal"
    except EOFError:
        sp_input = "normal"

    if sp_input in _presets:
        rate, timeout = _presets[sp_input]
    else:
        # allow raw number as rate too
        try:
            rate    = int(sp_input)
            timeout = 2.0
        except ValueError:
            rate, timeout = _presets["normal"]

    rate    = max(1, min(rate, 50000))
    timeout = max(0.5, min(timeout, 30.0))

    total = len(all_hosts)

    print(f"\n{BOLD}Scanning {total:,} hosts across {len(ranges)} range(s)  "
          f"(raw ICMP, {rate}/s, reply wait {timeout:.1f}s){RESET}")
    print(f"  Live results → {BOLD}{out_file}{RESET}\n")

    # ── Open output file — each alive IP written immediately, one per line ──────
    out_fh = open(out_file, "w")

    t0    = time.time()
    alive = fast_scan_icmp(all_hosts, rate=rate, timeout=timeout, out_fh=out_fh)

    if alive is None:
        print(f"{YELLOW}  Raw socket unavailable. Falling back to subprocess ping "
              f"(try sudo for full speed).{RESET}")
        alive = scan(all_hosts, workers=200, ping_count=1, out_fh=out_fh)

    out_fh.close()
    elapsed = time.time() - t0

    # ── Group alive IPs back to their range ───────────────────────────────────
    range_alive: list = [[] for _ in ranges]
    for ip in alive:
        range_alive[ip_to_range[ip]].append(ip)

    n_alive = len(alive)
    n_dead  = total - n_alive

    # ── Per-range summary ─────────────────────────────────────────────────────
    print(f"\n{BOLD}{'━' * 52}{RESET}")
    print(f"{BOLD}  Scan Results — per range{RESET}")
    print(f"{BOLD}{'━' * 52}{RESET}")

    col = max(len(desc) for _, desc in ranges) + 2
    for i, (hosts, desc) in enumerate(ranges):
        a     = len(range_alive[i])
        color = GREEN if a else RESET
        print(f"  {desc:{col}}  {color}{a:4d}{RESET} / {len(hosts)} alive")

    print(f"  {'─' * 48}")
    print(f"  {'Total':{col}}  {GREEN}{n_alive:4d}{RESET} / {total} alive")
    print(f"  Dead / no reply : {n_dead:,}")
    print(f"  Duration        : {elapsed:.1f}s")
    print(f"{BOLD}{'━' * 52}{RESET}")

    if n_alive:
        print(f"\n  Results saved to {BOLD}{out_file}{RESET}\n")
    else:
        print(f"\n  {YELLOW}No alive hosts found.{RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Scan interrupted — output file contains IPs found so far.{RESET}\n")
        sys.exit(130)
