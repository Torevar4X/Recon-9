"""
Network Tools Module
Handles: Ping, Traceroute, TCP/UDP Port Scan, Subnet Lookup, Banner Grabbing
"""

import socket
import subprocess
import platform
import threading
import time
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import ipaddress
    IPADDRESS_OK = True
except ImportError:
    IPADDRESS_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Ping
# ─────────────────────────────────────────────────────────────────────────────

def test_ping(host: str, count: int = 4) -> Dict[str, Any]:
    """Send ICMP pings via the OS ping command and parse the summary."""
    os_name = platform.system().lower()

    if os_name == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * 5 + 5
        )
        output = proc.stdout + proc.stderr
        success = proc.returncode == 0
        return {
            "host": host,
            "count": count,
            "success": success,
            "output": output.strip(),
            "reachable": success,
        }
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "Ping timed out.", "reachable": False}
    except FileNotFoundError:
        return {"host": host, "error": "'ping' command not found on this system.", "reachable": False}


# ─────────────────────────────────────────────────────────────────────────────
# Traceroute
# ─────────────────────────────────────────────────────────────────────────────

def traceroute(host: str, max_hops: int = 30) -> Dict[str, Any]:
    """Run a traceroute/tracert to the specified host."""
    os_name = platform.system().lower()

    if os_name == "windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-n", host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max_hops * 6 + 10
        )
        output = proc.stdout + proc.stderr
        return {
            "host": host,
            "max_hops": max_hops,
            "output": output.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"host": host, "error": "Traceroute timed out."}
    except FileNotFoundError:
        tool = "tracert" if os_name == "windows" else "traceroute"
        return {"host": host, "error": f"'{tool}' not found. Install it and retry."}


# ─────────────────────────────────────────────────────────────────────────────
# Port scanning helpers
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_MAP: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached",
}


def _parse_ports(port_spec: str) -> List[int]:
    """
    Parse a port specification like '80,443,1000-1024' into a sorted list.
    Caps output at 10 000 ports for safety.
    """
    ports: set = set()
    for part in port_spec.replace(" ", "").split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if hi_i - lo_i > 65535:
                raise ValueError("Port range too large (max 65535 ports per segment).")
            ports.update(range(lo_i, hi_i + 1))
        else:
            ports.add(int(part))
    result = sorted(ports)
    if len(result) > 10_000:
        raise ValueError("Total port count exceeds 10 000. Narrow the range.")
    return result


def _tcp_probe(host: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """Return (port, open_bool, banner_or_empty)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode(errors="replace").strip()
            except Exception:
                banner = ""
            return port, True, banner
    except (ConnectionRefusedError, OSError):
        return port, False, ""


# ─────────────────────────────────────────────────────────────────────────────
# TCP Port Scan
# ─────────────────────────────────────────────────────────────────────────────

def tcp_port_scan(
    host: str,
    port_spec: str = "1-1024",
    timeout: float = 1.0,
    threads: int = 100,
) -> Dict[str, Any]:
    """
    Multi-threaded TCP SYN-style connect scan.
    Returns open ports with service guesses and any captured banners.
    """
    try:
        ports = _parse_ports(port_spec)
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"error": f"Cannot resolve host: {exc}"}

    open_ports: List[Dict[str, Any]] = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as pool:
        futures = {pool.submit(_tcp_probe, resolved_ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "service": SERVICE_MAP.get(port, "unknown"),
                    "banner": banner,
                })

    open_ports.sort(key=lambda x: x["port"])
    elapsed = round(time.time() - start, 2)

    return {
        "host": host,
        "ip": resolved_ip,
        "port_spec": port_spec,
        "total_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "elapsed_seconds": elapsed,
    }


# ─────────────────────────────────────────────────────────────────────────────
# UDP Port Scan
# ─────────────────────────────────────────────────────────────────────────────

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 5353]


def _udp_probe(host: str, port: int, timeout: float) -> Tuple[int, str]:
    """
    Very basic UDP probe. 'open|filtered' is the usual result since UDP is
    connectionless; ICMP port-unreachable = 'closed'.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00" * 16, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            state = "open"
            banner = data.decode(errors="replace").strip()
        except socket.timeout:
            state = "open|filtered"
            banner = ""
        sock.close()
        return port, state, banner
    except ConnectionRefusedError:
        return port, "closed", ""
    except OSError:
        return port, "filtered", ""


def udp_port_scan(
    host: str,
    port_spec: str = "53,67,68,69,123,161,500,514",
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    UDP scan. Requires privileged access on most OS for ICMP replies.
    Results are inherently less certain than TCP scans.
    """
    if port_spec.strip() == "":
        ports = COMMON_UDP_PORTS
    else:
        try:
            ports = _parse_ports(port_spec)
        except ValueError as exc:
            return {"error": str(exc)}

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"error": f"Cannot resolve host: {exc}"}

    results: List[Dict[str, Any]] = []
    for port in ports:
        p, state, banner = _udp_probe(resolved_ip, port, timeout)
        if state != "closed":
            results.append({
                "port": p,
                "protocol": "udp",
                "state": state,
                "service": SERVICE_MAP.get(p, "unknown"),
                "banner": banner,
            })

    return {
        "host": host,
        "ip": resolved_ip,
        "ports_probed": len(ports),
        "results": results,
        "note": "UDP results may show 'open|filtered' due to firewall/no-reply behaviour.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Subnet Lookup
# ─────────────────────────────────────────────────────────────────────────────

def subnet_lookup(cidr: str) -> Dict[str, Any]:
    """Break down a CIDR block into useful network information."""
    if not IPADDRESS_OK:
        return {"error": "ipaddress module unavailable."}
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        return {
            "cidr": cidr,
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address) if net.version == 4 else "N/A (IPv6)",
            "netmask": str(net.netmask) if net.version == 4 else str(net.prefixlen),
            "prefix_length": net.prefixlen,
            "ip_version": net.version,
            "num_addresses": net.num_addresses,
            "num_usable_hosts": len(hosts),
            "first_host": str(hosts[0]) if hosts else "N/A",
            "last_host": str(hosts[-1]) if hosts else "N/A",
            "is_private": net.is_private,
            "is_global": net.is_global,
            "host_sample": [str(h) for h in hosts[:10]],
        }
    except ValueError as exc:
        return {"error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Banner Grabbing
# ─────────────────────────────────────────────────────────────────────────────

def banner_grab(host: str, port_spec: str = "21,22,25,80,443,8080", timeout: float = 3.0) -> Dict[str, Any]:
    """
    Attempt to grab service banners from specified ports.
    Sends a minimal HTTP GET probe for web ports; raw recv otherwise.
    """
    try:
        ports = _parse_ports(port_spec)
    except ValueError as exc:
        return {"error": str(exc)}

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return {"error": str(exc)}

    banners: List[Dict[str, Any]] = []
    HTTP_PORTS = {80, 8080, 8000, 8888, 8443, 443}

    for port in ports:
        entry: Dict[str, Any] = {
            "port": port,
            "service": SERVICE_MAP.get(port, "unknown"),
            "banner": None,
            "error": None,
        }
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if port in HTTP_PORTS:
                    probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                    s.sendall(probe)
                raw = s.recv(2048)
                entry["banner"] = raw.decode(errors="replace").strip()[:500]
        except (ConnectionRefusedError, OSError) as exc:
            entry["error"] = str(exc)
        banners.append(entry)

    return {"host": host, "ip": ip, "results": banners}
