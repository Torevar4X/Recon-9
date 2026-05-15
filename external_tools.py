"""
External Tools Module
Handles: Nmap Port Scanner, Nmap OS Detection, RustScan, UPnP Discovery
All tools use subprocess; gracefully report if binary is not installed.
"""

import re
import shutil
import subprocess
import socket
import time
import os
from typing import Dict, Any, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Availability helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = 300) -> Dict[str, str]:
    """Run a command, return stdout/stderr/returncode as strings."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": str(proc.returncode),
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out.", "returncode": "-1"}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"'{cmd[0]}' not found in PATH.", "returncode": "-1"}


def _run_with_streaming(cmd: List[str], timeout: int = 300, progress_callback: callable = None) -> Dict[str, str]:
    """
    Run a command with live streaming output.
    Reads stdout/stderr line-by-line and calls progress_callback for each line.
    Works with ALL netdiscover modes (active, passive, continuous).
    Filters ANSI escape codes and deduplicates output.
    
    Args:
        cmd: Command and arguments as list
        timeout: Maximum execution time in seconds
        progress_callback: Function to call with each output line
        
    Returns:
        Dict with stdout, stderr, returncode
    """
    import re
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
        )
        
        stdout_lines = []
        stderr_lines = []
        start_time = time.time()
        
<<<<<<< HEAD
        # Set non-blocking I/O (Unix only)
        if os.name != "nt":
            import fcntl
            flags = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
            fcntl.fcntl(proc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            flags = fcntl.fcntl(proc.stderr, fcntl.F_GETFL)
            fcntl.fcntl(proc.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)
=======
        # Set non-blocking I/O
        import fcntl
        flags = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
        fcntl.fcntl(proc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        flags = fcntl.fcntl(proc.stderr, fcntl.F_GETFL)
        fcntl.fcntl(proc.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)
>>>>>>> origin/main
        
        # ANSI escape code pattern (for filtering)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        # Track last unique output to avoid duplicates
        last_unique_line = ""
        duplicate_count = 0
        
        if progress_callback:
            progress_callback(f"   Executing: {' '.join(cmd)}")
            progress_callback("")  # Empty line for spacing
        
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                proc.kill()
                if progress_callback:
                    progress_callback(f"\n⚠️  Command timed out after {timeout}s")
                return {
                    "stdout": "".join(stdout_lines),
                    "stderr": "".join(stderr_lines) + f"\nCommand timed out after {timeout}s",
                    "returncode": "-1",
                }
            
            # Check if process is done
            retcode = proc.poll()
            
            # Read stdout line by line
            try:
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    
                    # Clean ANSI escape codes
                    clean_line = ansi_escape.sub('', line).strip()
                    
                    # Skip empty lines and screen control codes
                    if not clean_line or clean_line.startswith('Currently scanning:'):
                        continue
                    
                    # Skip duplicate lines (netdiscover refreshes the screen)
                    if clean_line == last_unique_line:
                        duplicate_count += 1
                        continue
                    
                    # If we had duplicates, show a summary
                    if duplicate_count > 0:
                        last_unique_line = clean_line
                        duplicate_count = 0
                    
                    stdout_lines.append(clean_line + "\n")
                    last_unique_line = clean_line
                    
                    if progress_callback and clean_line.strip():
                        # Stream every unique line immediately
                        progress_callback(clean_line)
            except (BlockingIOError, IOError):
                pass
            
            # Read stderr line by line
            try:
                while True:
                    line = proc.stderr.readline()
                    if not line:
                        break
                    
                    # Clean ANSI escape codes
                    clean_line = ansi_escape.sub('', line).strip()
                    
                    if clean_line and progress_callback:
                        progress_callback(clean_line)
                        stderr_lines.append(clean_line + "\n")
            except (BlockingIOError, IOError):
                pass
            
            if retcode is not None:
                # Process finished, drain any remaining output
                try:
                    remaining_out, remaining_err = proc.communicate(timeout=5)
                    if remaining_out:
                        # Clean and deduplicate remaining output
                        for line in remaining_out.splitlines():
                            clean_line = ansi_escape.sub('', line).strip()
                            if clean_line and not clean_line.startswith('Currently scanning:'):
                                if clean_line != last_unique_line:
                                    stdout_lines.append(clean_line + "\n")
                                    if progress_callback:
                                        progress_callback(clean_line)
                                    last_unique_line = clean_line
                    if remaining_err:
                        for line in remaining_err.splitlines():
                            clean_line = ansi_escape.sub('', line).strip()
                            if clean_line and progress_callback:
                                progress_callback(clean_line)
                            stderr_lines.append(clean_line + "\n")
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                break
            
            # Small sleep to prevent CPU spinning
            time.sleep(0.05)
        
        if progress_callback:
            progress_callback("")  # Empty line for spacing
            progress_callback(f"   ✓ Scan completed in {time.time() - start_time:.1f}s")
        
        return {
            "stdout": "".join(stdout_lines),
            "stderr": "".join(stderr_lines),
            "returncode": str(proc.returncode),
        }
        
    except Exception as e:
        if progress_callback:
            progress_callback(f"❌ Error: {e}")
        return {
            "stdout": "",
            "stderr": f"Error running command: {e}",
            "returncode": "-1",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Nmap Port Scanner
# ─────────────────────────────────────────────────────────────────────────────

NMAP_SCAN_PRESETS: Dict[str, Dict] = {
    # ── Quick Scans ──────────────────────────────────────────────────────────
    "Quick Scan (-T4 top 100)": {
        "flags": ["-T4", "--top-ports", "100"],
        "description": "Fast scan of top 100 most common ports.",
    },
    "Quick Scan + Version (-sV top 100)": {
        "flags": ["-sV", "-T4", "--top-ports", "100"],
        "description": "Fast scan with service version detection.",
    },
    "Fast Scan (-F)": {
        "flags": ["-F", "-T4"],
        "description": "Scan only 100 most common ports (faster than top-ports).",
    },
    
    # ── Full Scans ───────────────────────────────────────────────────────────
    "Full TCP SYN (-sS all ports)": {
        "flags": ["-sS", "-T4", "-p-"],
        "description": "Stealth SYN scan of all 65535 TCP ports. Requires root/admin.",
    },
    "Full TCP + Version (-sV -p-)": {
        "flags": ["-sS", "-sV", "-T4", "-p-"],
        "description": "Complete SYN scan with version detection on all ports.",
    },
    "Full TCP Connect (-sT all ports)": {
        "flags": ["-sT", "-T4", "-p-"],
        "description": "Full TCP connect scan of all ports (no root needed).",
    },
    
    # ── Service/Version Detection ────────────────────────────────────────────
    "Service Version Detection (-sV)": {
        "flags": ["-sV", "-T4", "--top-ports", "1000"],
        "description": "Detect versions of running services on top 1000 ports.",
    },
    "Version Intensity 5 (--version-intensity 5)": {
        "flags": ["-sV", "--version-intensity", "5", "-T4"],
        "description": "Aggressive version detection (tries all probes).",
    },
    
    # ── Aggressive Scans ─────────────────────────────────────────────────────
    "Aggressive Scan (-A)": {
        "flags": ["-A", "-T4"],
        "description": "OS detection, version, scripts & traceroute. Loud scan.",
    },
    "Aggressive + All Ports (-A -p-)": {
        "flags": ["-A", "-T4", "-p-"],
        "description": "Full aggressive scan on all ports. Very loud.",
    },
    
    # ── UDP Scans ────────────────────────────────────────────────────────────
    "UDP Top Ports (-sU)": {
        "flags": ["-sU", "--top-ports", "200"],
        "description": "Scan top 200 UDP ports. Slow; requires root/admin.",
    },
    "UDP Common Ports": {
        "flags": ["-sU", "-T4", "-p", "53,67,68,123,161,162,500,514,1900"],
        "description": "Scan common UDP services (DNS, DHCP, NTP, SNMP).",
    },
    "UDP Full Scan": {
        "flags": ["-sU", "-T3", "-p-"],
        "description": "Full UDP scan of all ports. VERY SLOW.",
    },
    
    # ── Vulnerability Scans ─────────────────────────────────────────────────
    "Vulnerability Scripts (--script vuln)": {
        "flags": ["-sV", "--script", "vuln", "-T4"],
        "description": "Run Nmap NSE vulnerability scripts.",
    },
    "Vuln + Exploit Scripts": {
        "flags": ["-sV", "--script", "vuln,exploit", "-T4"],
        "description": "Run vulnerability and exploit scripts. VERY LOUD.",
    },
    "Vuln + Auth Scripts": {
        "flags": ["-sV", "--script", "vuln,auth", "-T4"],
        "description": "Vulnerability and authentication checks.",
    },
    "Default Scripts (-sC)": {
        "flags": ["-sC", "-sV", "-T4"],
        "description": "Run default NSE scripts with version detection.",
    },
    
    # ── Targeted Scans ───────────────────────────────────────────────────────
    "Web Server Scan": {
        "flags": ["-sV", "-sC", "--script", "http-enum,http-headers,http-methods", "-p", "80,443,8000,8080,8443"],
        "description": "Scan web servers with HTTP enumeration scripts.",
    },
    "Database Scan": {
        "flags": ["-sV", "-p", "1433,1521,3306,5432,6379,27017"],
        "description": "Scan common database ports (MSSQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB).",
    },
    "SMB Scan": {
        "flags": ["-sV", "-sC", "-p", "139,445", "--script", "smb-enum-shares,smb-os-discovery,smb-security-mode"],
        "description": "Scan SMB/CIFS with enumeration scripts.",
    },
    "Mail Server Scan": {
        "flags": ["-sV", "-p", "25,110,143,465,587,993,995", "--script", "smtp-enum-users,imap-capabilities"],
        "description": "Scan mail services (SMTP, POP3, IMAP).",
    },
    "DNS Scan": {
        "flags": ["-sV", "-p", "53", "--script", "dns-zone-transfer,dns-enum-servers"],
        "description": "Scan DNS servers for zone transfers.",
    },
    "FTP Scan": {
        "flags": ["-sV", "-p", "21", "--script", "ftp-anon,ftp-bounce,ftp-vsftpd-backdoor"],
        "description": "Scan FTP for anonymous access and vulnerabilities.",
    },
    "SSH Scan": {
        "flags": ["-sV", "-p", "22", "--script", "ssh-auth-methods,ssh2-enum-algos"],
        "description": "Scan SSH for authentication methods and algorithms.",
    },
    "RDP Scan": {
        "flags": ["-sV", "-p", "3389", "--script", "rdp-enum-encryption,rdp-vuln-ms12-020"],
        "description": "Scan RDP for security settings and vulnerabilities.",
    },
    
    # ── Safe/Stealth Scans ──────────────────────────────────────────────────
    "Safe Scripts Only": {
        "flags": ["-sV", "--script", "safe", "-T4"],
        "description": "Run only safe, non-intrusive NSE scripts.",
    },
    "Stealth Scan (-sS)": {
        "flags": ["-sS", "-T2"],
        "description": "Slow SYN scan for IDS evasion.",
    },
    "Ping Scan (-sn)": {
        "flags": ["-sn", "-T4"],
        "description": "Ping sweep - no port scan, just host discovery.",
    },
    "Ping Scan (-sn only)": {
        "flags": ["-sn"],
        "description": "Basic ping sweep without timing options. Use for subnet discovery (e.g., 192.168.1.0/24).",
    },
    "List Scan (-sL)": {
        "flags": ["-sL"],
        "description": "List scan - reverse DNS lookup only, no packets sent.",
    },
    "No Ping (-Pn)": {
        "flags": ["-Pn", "-T4"],
        "description": "Skip host discovery, scan all ports (bypasses firewalls).",
    },
    
    # ── Protocol Scans ───────────────────────────────────────────────────────
    "IP Protocol Scan (-sO)": {
        "flags": ["-sO"],
        "description": "Scan for IP protocols (ICMP, TCP, UDP, etc.).",
    },
    
    # ── Timing Options ───────────────────────────────────────────────────────
    "Paranoid Timing (-T0)": {
        "flags": ["-sS", "-T0"],
        "description": "Paranoid timing - IDS evasion, very slow (15min between probes).",
    },
    "Sneaky Timing (-T1)": {
        "flags": ["-sS", "-T1"],
        "description": "Sneaky timing - IDS evasion, slow (15s between probes).",
    },
    "Polite Timing (-T2)": {
        "flags": ["-sS", "-T2"],
        "description": "Polite timing - use if network/machines are slow.",
    },
    "Normal Timing (-T3)": {
        "flags": ["-sS", "-T3"],
        "description": "Normal timing - default setting.",
    },
    "Aggressive Timing (-T4)": {
        "flags": ["-sS", "-T4"],
        "description": "Aggressive timing - fast, assumes fast network.",
    },
    "Insane Timing (-T5)": {
        "flags": ["-sS", "-T5"],
        "description": "Insane timing - very fast, less accurate results.",
    },
    
    # ── Custom ───────────────────────────────────────────────────────────────
    "Custom (use flags below)": {
        "flags": [],
        "description": "Provide your own flags in the custom field.",
    },
}


def nmap_port_scan(
    target: str,
    preset: str = "Quick Scan (-T4 top 100)",
    port_spec: Optional[str] = None,
    custom_flags: str = "",
    timeout: int = 300,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Execute nmap with a preset or custom flags.
    Returns raw nmap output plus a parsed open-ports table.
    
    Args:
        target: Hostname or IP to scan
        preset: Preset scan profile
        port_spec: Custom port specification
        custom_flags: Additional nmap flags
        timeout: Timeout in seconds
        progress_callback: Optional callback for streaming output
    """
    if not _tool_available("nmap"):
        return {
            "error": "nmap is not installed or not in PATH.",
            "install_hint": "https://nmap.org/download.html",
        }

    preset_info = NMAP_SCAN_PRESETS.get(preset, NMAP_SCAN_PRESETS["Quick Scan (-T4 top 100)"])
    flags = list(preset_info["flags"])

    if port_spec and "-p" not in " ".join(flags) and "-p-" not in flags:
        flags += ["-p", port_spec]

    if custom_flags.strip():
        flags += custom_flags.split()

    cmd = ["nmap"] + flags + [target]
    
    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)

    output = raw["stdout"] + ("\n" + raw["stderr"] if raw["stderr"].strip() else "")
    parsed = _parse_nmap_output(raw["stdout"])

    return {
        "target": target,
        "command": " ".join(cmd),
        "preset": preset,
        "raw_output": output.strip(),
        "open_ports": parsed,
        "returncode": raw["returncode"],
    }


def nmap_os_detection(target: str, timeout: int = 300, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Run nmap OS detection (-O). Requires root/admin privileges.
    
    Args:
        target: Hostname or IP to scan
        timeout: Timeout in seconds
        progress_callback: Optional callback for streaming output
    """
    if not _tool_available("nmap"):
        return {
            "error": "nmap is not installed or not in PATH.",
            "install_hint": "https://nmap.org/download.html",
        }

    cmd = ["nmap", "-O", "--osscan-guess", "-T4", target]
    
    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)

    output = (raw["stdout"] + "\n" + raw["stderr"]).strip()
    os_guesses = _parse_os_detection(raw["stdout"])

    return {
        "target": target,
        "command": " ".join(cmd),
        "raw_output": output,
        "os_guesses": os_guesses,
        "note": "OS detection requires root/administrator privileges.",
        "returncode": raw["returncode"],
    }


def _parse_nmap_output(text: str) -> List[Dict[str, str]]:
    """Parse nmap stdout for open port lines → list of dicts."""
    ports = []
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S.*)?$", re.MULTILINE
    )
    for m in port_re.finditer(text):
        ports.append({
            "port": m.group(1),
            "protocol": m.group(2),
            "state": m.group(3),
            "service": (m.group(4) or "").strip(),
        })
    return ports


def _parse_os_detection(text: str) -> List[Dict[str, str]]:
    """Extract OS guess lines from nmap output."""
    guesses = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("OS details:") or line.startswith("Aggressive OS guesses:"):
            # Remove the label prefix and split by comma
            content = line.split(":", 1)[-1].strip()
            for part in content.split(","):
                part = part.strip()
                if part:
                    guesses.append({"description": part})
        elif "Running:" in line or "Running (JUST GUESSING):" in line:
            content = line.split(":", 1)[-1].strip()
            guesses.append({"description": content})
    return guesses


# ─────────────────────────────────────────────────────────────────────────────
# RustScan
# ─────────────────────────────────────────────────────────────────────────────

RUSTSCAN_PRESETS: Dict[str, Dict[str, Any]] = {
    "Fast Scan (1-10000)": {
        "port_spec": "1-10000",
        "batch_size": 4500,
        "timeout_ms": 1500,
        "description": "Quick scan of common ports 1-10000.",
    },
    "Full Scan (1-65535)": {
        "port_spec": "1-65535",
        "batch_size": 4500,
        "timeout_ms": 1500,
        "description": "Complete scan of all TCP ports.",
    },
    "Stealth Scan (Top 1000)": {
        "port_spec": "1-1000",
        "batch_size": 3000,
        "timeout_ms": 1000,
        "description": "Fast scan of most common ports.",
    },
    "Deep Scan (Slow)": {
        "port_spec": "1-65535",
        "batch_size": 3000,
        "timeout_ms": 3000,
        "description": "Thorough scan with longer timeouts for accuracy.",
    },
    "Web Services (80-443 + common)": {
        "port_spec": "80,443,8000,8080,8443,3000,5000",
        "batch_size": 1000,
        "timeout_ms": 1500,
        "description": "Scan common web service ports.",
    },
    "Database Ports": {
        "port_spec": "1433,1521,3306,5432,6379,27017",
        "batch_size": 500,
        "timeout_ms": 2000,
        "description": "Scan common database ports (MSSQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB).",
    },
    "Remote Access": {
        "port_spec": "22,23,3389,5900,5901",
        "batch_size": 500,
        "timeout_ms": 2000,
        "description": "Scan remote access ports (SSH, Telnet, RDP, VNC).",
    },
    "Custom (use settings below)": {
        "port_spec": "1-65535",
        "batch_size": 4500,
        "timeout_ms": 1500,
        "description": "Configure custom port range and timing.",
    },
}


def rustscan(
    target: str,
    preset: str = "Fast Scan (1-10000)",
    port_spec: str = "1-10000",
    batch_size: int = 4500,
    timeout_ms: int = 1500,
    extra_flags: str = "",
    timeout: int = 300,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Run RustScan for ultra-fast TCP port discovery.
    RustScan outputs open ports then can pipe to nmap for service detection.

    Args:
        target: Hostname or IP to scan
        preset: Preset scan profile name
        port_spec: Port range (e.g., "1-1000" or "80,443,8000-9000")
        batch_size: Number of concurrent connections
        timeout_ms: Timeout per port in milliseconds
        extra_flags: Additional flags to pass to RustScan
        timeout: Overall timeout in seconds
        progress_callback: Optional callback for streaming output
    """
    if not _tool_available("rustscan"):
        return {
            "error": "rustscan is not installed or not in PATH.",
            "install_hint": "https://github.com/RustScan/RustScan/releases",
        }

    # Apply preset if specified
    if preset in RUSTSCAN_PRESETS:
        preset_data = RUSTSCAN_PRESETS[preset]
        if preset != "Custom (use settings below)":
            port_spec = preset_data["port_spec"]
            batch_size = preset_data["batch_size"]
            timeout_ms = preset_data["timeout_ms"]

    cmd = [
        "rustscan",
        "-a", target,
        "-r", port_spec,
        "-b", str(batch_size),
        "--timeout", str(timeout_ms),
        "--",  # Separator before nmap-style flags
        "-n",  # Nmap flag: no DNS resolution (faster)
    ]

    if extra_flags.strip():
        cmd += extra_flags.split()

    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)
    
    output = (raw["stdout"] + "\n" + raw["stderr"]).strip()

    # Parse open ports from RustScan output
    # RustScan prints lines like "Open 1.2.3.4:80" or just port numbers
    open_ports: List[int] = []
    for line in output.splitlines():
        line_lower = line.lower()
        # Match "Open <ip>:<port>" format
        if "open" in line_lower:
            m = re.search(r":(\d{1,5})\b", line)
            if m:
                open_ports.append(int(m.group(1)))
        # Match comma-separated port numbers (e.g., "80,443,8080")
        elif re.match(r"^\d+(,\d+)*$", line.strip()):
            for p in line.strip().split(","):
                try:
                    open_ports.append(int(p.strip()))
                except ValueError:
                    pass
        # Match individual port numbers that RustScan outputs
        elif line.strip().isdigit():
            try:
                open_ports.append(int(line.strip()))
            except ValueError:
                pass

    open_ports = sorted(set(open_ports))

    return {
        "target": target,
        "command": " ".join(cmd),
        "preset": preset,
        "port_spec": port_spec,
        "batch_size": batch_size,
        "timeout_ms": timeout_ms,
        "raw_output": output,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "returncode": raw["returncode"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Masscan - Ultra-fast port scanner
# ─────────────────────────────────────────────────────────────────────────────

MASSCAN_PRESETS: Dict[str, Dict[str, Any]] = {
    # ── Fast Scans ──────────────────────────────────────────────────────────
    "Top 10 Ports (Fastest)": {
        "ports": "top10",
        "rate": 100000,
        "description": "Ultra-fast scan of top 10 most common ports. Best for quick recon.",
    },
    "Top 100 Ports": {
        "ports": "top100",
        "rate": 10000,
        "description": "Fast scan of top 100 most common ports.",
    },
    "Top 1000 Ports": {
        "ports": "top1000",
        "rate": 5000,
        "description": "Comprehensive scan of top 1000 ports.",
    },

    # ── Targeted Scans ─────────────────────────────────────────────────────
    "Common Ports (80,443,22,21)": {
        "ports": "80,443,22,21,23,25,53,110,143,3306,3389,8080",
        "rate": 10000,
        "description": "Scan most common service ports (HTTP, HTTPS, SSH, FTP, etc.).",
    },
    "Web Ports": {
        "ports": "80,443,8000,8080,8443,3000,5000",
        "rate": 10000,
        "description": "Scan common web service ports.",
    },
    "Database Ports": {
        "ports": "1433,1521,3306,5432,6379,27017",
        "rate": 10000,
        "description": "Scan common database ports (MSSQL, Oracle, MySQL, PostgreSQL, Redis, MongoDB).",
    },
    "Remote Access": {
        "ports": "22,23,3389,5900,5901",
        "rate": 10000,
        "description": "Scan remote access ports (SSH, Telnet, RDP, VNC).",
    },

    # ── Full Scans ─────────────────────────────────────────────────────────
    "All TCP Ports (1-65535)": {
        "ports": "1-65535",
        "rate": 100000,
        "description": "Full TCP port scan. Fast but may take several minutes.",
    },
    "All TCP Ports (Aggressive)": {
        "ports": "1-65535",
        "rate": 1000000,
        "description": "Full TCP scan at maximum speed. Use on fast networks only.",
    },

    # ── Custom ─────────────────────────────────────────────────────────────
    "Custom (use settings below)": {
        "ports": "1-1000",
        "rate": 1000,
        "description": "Configure custom ports and rate.",
    },
}


def masscan(
    target: str,
    preset: str = "Top 100 Ports",
    ports: str = "top100",
    rate: int = 1000,
    timeout: int = 300,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Run Masscan for ultra-fast port discovery.
    Masscan can scan the entire Internet in under 6 minutes.
    Note: Masscan only accepts IP addresses, not hostnames.

    Args:
        target: Hostname, IP, or subnet (e.g., 192.168.1.0/24)
        preset: Preset scan profile name
        ports: Port specification (e.g., "80,443" or "1-1000" or "top100")
        rate: Packets per second (higher = faster but more noticeable)
        timeout: Overall timeout in seconds
        progress_callback: Optional callback for streaming output

    Returns:
        Dict with scan results and open ports list
    """
    if not _tool_available("masscan"):
        return {
            "error": "masscan is not installed or not in PATH.",
            "install_hint": "https://github.com/robertdavidgraham/masscan",
        }

    # Masscan doesn't support DNS names - resolve hostname to IP
    import socket
    try:
        # Check if it's already an IP or subnet
        if re.match(r"^[\d\./]+$", target):
            resolved_target = target
        else:
            # Try to resolve hostname
            resolved_target = socket.gethostbyname(target)
    except socket.gaierror:
        return {
            "error": f"Cannot resolve hostname: {target}",
            "note": "Masscan only accepts IP addresses or subnets (e.g., 192.168.1.0/24)",
        }

    # Apply preset if specified and not using custom ports
    use_custom_ports = ports not in ["top100", "top10", "top1000"] and ports != "1-1000"

    if preset in MASSCAN_PRESETS and not use_custom_ports:
        preset_data = MASSCAN_PRESETS[preset]
        if preset != "Custom (use settings below)":
            ports = preset_data["ports"]
            rate = preset_data["rate"]

    cmd = [
        "masscan",
        "-p", ports,
        resolved_target,
        "--rate", str(rate),
        "--open",  # Only show open ports
    ]

    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)
    
    output = (raw["stdout"] + "\n" + raw["stderr"]).strip()

    # Parse open ports from masscan output
    # Format: "Discovered open port 80/tcp on 192.168.1.1"
    open_ports: List[Dict[str, str]] = []
    port_re = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([\d\.]+)")
    for match in port_re.finditer(output):
        open_ports.append({
            "port": match.group(1),
            "protocol": match.group(2),
            "ip": match.group(3),
        })

    return {
        "target": target,
        "resolved_target": resolved_target,
        "command": " ".join(cmd),
        "preset": preset,
        "ports": ports,
        "rate": rate,
        "raw_output": output,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "returncode": raw["returncode"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Fping - Fast ICMP ping sweep
# ─────────────────────────────────────────────────────────────────────────────

FPING_PRESETS: Dict[str, Dict[str, Any]] = {
    # ── Standard Scans ──────────────────────────────────────────────────────
    "Subnet Sweep (default)": {
        "timeout_ms": 500,
        "retries": 2,
        "description": "Standard ping sweep. Good balance of speed and reliability.",
    },
    "Fast LAN Scan": {
        "timeout_ms": 100,
        "retries": 1,
        "description": "Very fast scan for local networks with low latency.",
    },

    # ── Special Conditions ─────────────────────────────────────────────────
    "Slow/High Latency Network": {
        "timeout_ms": 1000,
        "retries": 3,
        "description": "Longer timeout for WAN, VPN, or high-latency networks.",
    },
    "Unreliable Network": {
        "timeout_ms": 500,
        "retries": 5,
        "description": "Multiple retries for networks with packet loss.",
    },
    "Stealth (Slow)": {
        "timeout_ms": 2000,
        "retries": 1,
        "description": "Slow scan to avoid triggering IDS/IPS alerts.",
    },

    # ── Custom ─────────────────────────────────────────────────────────────
    "Custom (use settings below)": {
        "timeout_ms": 500,
        "retries": 2,
        "description": "Configure custom timeout and retries.",
    },
}


def fping(
    target: str,
    preset: str = "Subnet Sweep (default)",
    timeout_ms: int = 100,
    retries: int = 1,
    timeout: int = 300,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Run fping for fast ICMP host discovery.
    fping can ping entire subnets quickly.

    Args:
        target: IP, hostname, subnet (e.g., 192.168.1.0/24), or range
        preset: Preset scan profile name
        timeout_ms: Timeout per ping in milliseconds
        retries: Number of retries per target
        timeout: Overall timeout in seconds
        progress_callback: Optional callback for streaming output

    Returns:
        Dict with list of reachable hosts
    """
    if not _tool_available("fping"):
        return {
            "error": "fping is not installed or not in PATH.",
            "install_hint": "https://github.com/schweikert/fping",
        }

    # Apply preset if specified
    if preset in FPING_PRESETS:
        preset_data = FPING_PRESETS[preset]
        if preset != "Custom (use settings below)":
            timeout_ms = preset_data["timeout_ms"]
            retries = preset_data["retries"]

    # Build command - check if target is a subnet/range or single host
    cmd = [
        "fping",
        "-a",  # Show alive hosts
        "-t", str(timeout_ms),  # Timeout per ping
        "-r", str(retries),  # Retries
        "-q",  # Quiet mode
    ]

    # Check if target contains CIDR notation or looks like a range
    if "/" in target or "-" in target:
        # Subnet or range - use -g flag
        cmd.insert(2, "-g")  # Insert -g after -a
        cmd.append(target)
    elif re.match(r"^[\d\.]+$", target):
        # Single IP address - don't use -g, just add as target
        cmd.append(target)
    else:
        # Hostname - don't use -g, just add as target
        cmd.append(target)

    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)
    
    output = (raw["stdout"] + "\n" + raw["stderr"]).strip()

    # Parse alive hosts from fping output
    # fping -a outputs one IP per line for alive hosts
    alive_hosts: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith("fping:"):
            # Extract IP addresses from lines like "192.168.1.1 is alive"
            ip_match = re.search(r"([\d\.]+)\s+is alive", line)
            if ip_match:
                alive_hosts.append(ip_match.group(1))
            elif re.match(r"^[\d\.]+$", line):
                # Some versions just output the IP
                alive_hosts.append(line)

    alive_hosts = sorted(set(alive_hosts))

    return {
        "target": target,
        "command": " ".join(cmd),
        "preset": preset,
        "timeout_ms": timeout_ms,
        "retries": retries,
        "raw_output": output,
        "alive_hosts": alive_hosts,
        "alive_count": len(alive_hosts),
        "returncode": raw["returncode"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Netdiscover - ARP-based network discovery
# ─────────────────────────────────────────────────────────────────────────────

NETDISCOVER_PRESETS: Dict[str, Dict[str, Any]] = {
    # ── Fast Scans (Recommended) ─────────────────────────────────────────────
    "Fast Active Scan": {
        "mode": "active",
        "count": 30,
        "delay": 200,
        "description": "Quick active scan. Best for most cases. (~6 seconds for /24)",
    },
    "Very Fast Scan": {
        "mode": "active",
        "count": 10,
        "delay": 50,
        "description": "Ultra-fast scan. May miss some hosts. (~1 second for /24)",
    },
    "Instant Scan (3 sec timeout)": {
        "mode": "active",
        "count": 5,
        "delay": 10,
        "description": "Fastest possible scan. Use -f flag. (~3 seconds)",
    },

    # ── Standard Scans ───────────────────────────────────────────────────────
    "Active Scan (default)": {
        "mode": "active",
        "count": 50,
        "delay": 500,
        "description": "Standard ARP scan. Good balance of speed and reliability.",
    },
    "Deep Active Scan": {
        "mode": "active",
        "count": 100,
        "delay": 1000,
        "description": "Thorough scan for networks with packet loss. Slower but reliable.",
    },

    # ── Passive/Stealth Scans ────────────────────────────────────────────────
    "Passive Scan (Stealth)": {
        "mode": "passive",
        "count": 0,
        "delay": 0,
        "description": "Listen-only mode. Sniffs ARP traffic. Undetectable but slow.",
    },
    "Continuous Monitor (-L)": {
        "mode": "continuous",
        "count": 30,
        "delay": 500,
        "description": "Quick active scan first, then passive monitoring.",
    },

    # ── Custom ───────────────────────────────────────────────────────────────
    "Custom (use settings below)": {
        "mode": "active",
        "count": 50,
        "delay": 500,
        "description": "Configure custom scan parameters.",
    },
}


def netdiscover(
    target: str,
    preset: str = "Fast Active Scan",
    mode: str = "active",
    count: int = 30,
    delay: int = 200,
    timeout: int = 120,  # Increased default timeout
    progress_callback: callable = None,
) -> Dict[str, Any]:
    """
    Run Netdiscover for ARP-based network discovery.
    Works on local network segments using ARP (Layer 2).
    
    ⚠️ SPEED WARNING: For /24 subnets (254 IPs), netdiscover can be VERY slow.
    Each ARP request takes time. Total time ≈ count × delay × 254 hosts.
    
    Speed tips:
    - Use "Very Fast Scan" or "Instant Scan" presets for quick results
    - Use smaller subnets (/25, /26) for faster scanning
    - For large networks, use Fping instead (much faster ICMP scan)
    - Add -f flag for fast mode

    Args:
        target: Subnet in CIDR notation (e.g., 192.168.1.0/24)
        preset: Preset scan profile name
        mode: "active" (send ARP) or "passive" (listen only) or "continuous"
        count: Number of ARP packets to send (0 for passive)
        delay: Delay between packets in milliseconds
        timeout: Overall timeout in seconds (increased to 120s for /24 subnets)
        progress_callback: Callback for live output streaming

    Returns:
        Dict with discovered hosts, IPs, and MAC addresses
    """
    if not _tool_available("netdiscover"):
        return {
            "error": "netdiscover is not installed or not in PATH.",
            "install_hint": "https://github.com/allanlaird/netdiscover",
        }

    # Apply preset if specified
    if preset in NETDISCOVER_PRESETS:
        preset_data = NETDISCOVER_PRESETS[preset]
        if preset != "Custom (use settings below)":
            mode = preset_data["mode"]
            count = preset_data["count"]
            delay = preset_data["delay"]

    # Build command based on mode
    cmd = ["netdiscover"]

    if mode == "passive":
        cmd += ["-p"]  # Passive mode
        if progress_callback:
            progress_callback("📡 Passive mode - listening for ARP traffic...")
            progress_callback("   Waiting for network traffic... (this may take time)")
    elif mode == "continuous":
        cmd += ["-L"]  # Continuous monitoring (active then passive)
        if progress_callback:
            progress_callback("🔄 Continuous monitoring mode...")
            progress_callback("   Will scan actively first, then monitor passively...")
    else:
        # Active mode - add -f for fast mode on quick scans
        use_fast_mode = (count <= 10 and delay <= 200) or "Instant" in preset
        cmd += [
            "-r", target,  # Range/subnet
            "-c", str(count),  # Packet count (for nets with packet loss)
            "-s", str(delay),  # Sleep time between ARP requests (ms)
        ]
        if use_fast_mode:
            cmd.insert(1, "-f")  # Fast mode flag
        
        if progress_callback:
            progress_callback(f"🔍 Active scan: {target} (count={count}, delay={delay}ms)")
            progress_callback(f"   Scanning {target.split('/')[-1] if '/' in target else target} hosts...")

    # Note: timeout is handled by subprocess wrapper, not netdiscover itself
    # Netdiscover doesn't have a -t option

    # Run with live streaming output for ALL modes
    raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    output = (raw.get("stdout", "") + "\n" + raw.get("stderr", "")).strip()

    # Parse discovered hosts from netdiscover output
    # Format: IP            MAC Address     Requests  S  Vendor
    #         192.168.1.1   aa:bb:cc:dd:ee:ff   2     A  RouterBrand
    discovered_hosts: List[Dict[str, str]] = []
    ip_mac_re = re.compile(r"^\s*([\d\.]+)\s+([a-fA-F0-9:]{17})\s+(\d+)\s+([AP])\s+(.*)$")
    for line in output.splitlines():
        match = ip_mac_re.match(line)
        if match:
            discovered_hosts.append({
                "ip": match.group(1),
                "mac": match.group(2),
                "requests": match.group(3),
                "type": "Active" if match.group(4) == "A" else "Passive",
                "vendor": match.group(5).strip(),
            })

    return {
        "target": target,
        "command": " ".join(cmd),
        "preset": preset,
        "mode": mode,
        "raw_output": output,
        "discovered_hosts": discovered_hosts,
        "host_count": len(discovered_hosts),
        "returncode": raw["returncode"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# UPnP Discovery - Discover devices via Universal Plug and Play
# ─────────────────────────────────────────────────────────────────────────────

UPNP_PRESETS: Dict[str, Dict[str, Any]] = {
    "Standard UPnP Scan (TCP)": {
        "port": 1900,
        "script": "upnp-info",
        "udp": False,
        "description": "TCP connect scan for UPnP. No root required. Fast and safe.",
    },
    "UDP UPnP Scan (requires root)": {
        "port": 1900,
        "script": "upnp-info",
        "udp": True,
        "description": "UDP scan for UPnP. More accurate but requires root/sudo.",
    },
    "Broadcast UPnP (local network)": {
        "port": 1900,
        "script": "broadcast-upnp-info",
        "udp": True,
        "description": "Broadcast discovery on local network. Requires root. Finds all UPnP devices.",
    },
    "All UPnP Ports (TCP)": {
        "port": "1900,5000,8000,8200",
        "script": "upnp-info",
        "udp": False,
        "description": "TCP scan common UPnP/SSDP ports. No root required.",
    },
    "Custom (use settings below)": {
        "port": 1900,
        "script": "upnp-info",
        "udp": False,
        "description": "Configure custom port and scripts.",
    },
}


def upnp_discovery(
    target: str,
    preset: str = "Standard UPnP Scan (TCP)",
    port: str = "1900",
    script: str = "upnp-info",
    udp: bool = False,
    timeout: int = 60,
    progress_callback: Optional[callable] = None,
) -> Dict[str, Any]:
    """
    Discover UPnP devices and extract information about internal network devices.
    UPnP can reveal device type, manufacturer, model, and sometimes internal IPs.

    Note:
    - TCP scans (default) work without root but may miss some devices
    - UDP scans are more accurate but require root privileges
    - Broadcast scans only work on local network and require root

    Args:
        target: IP address or hostname (typically router's private IP like 192.168.1.1)
        preset: Preset scan profile name
        port: Port(s) to scan (default: 1900 for UPnP)
        script: NSE scripts to run (upnp-info, broadcast-upnp-info)
        udp: Use UDP scan (True) or TCP connect scan (False, default)
        timeout: Overall timeout in seconds
        progress_callback: Optional callback for streaming output

    Returns:
        Dict with discovered UPnP devices and their information
    """
    if not _tool_available("nmap"):
        return {
            "error": "nmap is not installed or not in PATH. UPnP discovery requires nmap.",
            "install_hint": "https://nmap.org/download.html",
        }

    # Apply preset if specified
    if preset in UPNP_PRESETS:
        preset_data = UPNP_PRESETS[preset]
        if preset != "Custom (use settings below)":
            port = preset_data["port"]
            script = preset_data["script"]
            udp = preset_data["udp"]

    # Build command - TCP by default (no root required)
    if udp:
        # UDP scan requires root
        cmd = [
            "nmap",
            "-sU",  # UDP scan
            "-p", str(port),
            "--script", script,
            "-T4",
            target,
        ]
    else:
        # TCP connect scan (works without root)
        cmd = [
            "nmap",
            "-sT",  # TCP connect scan
            "-p", str(port),
            "--script", script,
            "-T4",
            target,
        ]

    # Use streaming if callback provided
    if progress_callback:
        raw = _run_with_streaming(cmd, timeout=timeout, progress_callback=progress_callback)
    else:
        raw = _run(cmd, timeout=timeout)
    
    output = (raw["stdout"] + "\n" + raw["stderr"]).strip()

    # Parse UPnP information from output
    upnp_devices = []
    
    # Look for UPnP device information
    upnp_patterns = {
        "device_type": r"Device Type:\s*(.+)",
        "manufacturer": r"Manufacturer:\s*(.+)",
        "model": r"Model:\s*(.+)",
        "model_number": r"Model Number:\s*(.+)",
        "serial": r"Serial:\s*(.+)",
        "friendly_name": r"Friendly Name:\s*(.+)",
        "presentation_url": r"Presentation URL:\s*(.+)",
        "upnp_version": r"UPnP Version:\s*(.+)",
    }
    
    current_device: Dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        
        # Check for new device section
        if "Host:" in line or "PORT" in line:
            if current_device:
                upnp_devices.append(current_device)
            current_device = {"raw_line": line}
        
        # Extract UPnP fields
        for field, pattern in upnp_patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                current_device[field] = match.group(1).strip()
    
    # Add last device
    if current_device:
        upnp_devices.append(current_device)
    
    # Filter out empty devices
    upnp_devices = [d for d in upnp_devices if len(d) > 1]

    # Check for internal IP addresses in UPnP data
    internal_ips = set()
    ip_pattern = r'\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'
    for match in re.finditer(ip_pattern, output):
        internal_ips.add(match.group(1))

    return {
        "target": target,
        "command": " ".join(cmd),
        "preset": preset,
        "port": port,
        "script": script,
        "raw_output": output,
        "upnp_devices": upnp_devices,
        "device_count": len(upnp_devices),
        "internal_ips_found": list(internal_ips),
        "internal_ip_count": len(internal_ips),
        "note": "UPnP must be enabled on the target for discovery to succeed. Many routers disable UPnP by default.",
        "returncode": raw["returncode"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tool availability check (called at startup)
# ─────────────────────────────────────────────────────────────────────────────

def check_external_tools() -> Dict[str, bool]:
    """Return availability of each external tool."""
    return {
        "nmap": _tool_available("nmap"),
        "rustscan": _tool_available("rustscan"),
        "masscan": _tool_available("masscan"),
        "fping": _tool_available("fping"),
        "netdiscover": _tool_available("netdiscover"),
        "upnp": True,  # UPnP uses nmap, which is already checked
        "traceroute": _tool_available("traceroute") or _tool_available("tracert"),
        "ping": _tool_available("ping"),
    }
