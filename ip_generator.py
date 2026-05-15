"""
IP Generator & Bulk Ping Tools
Handles: CIDR IP generation, bulk ping testing, live host discovery
"""

import socket
import subprocess
import re
import platform
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────────────────────────────────────
# CIDR IP Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_ips_from_cidr(cidr: str) -> List[str]:
    """
    Generate all IP addresses from a CIDR notation.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        List of IP addresses
    """
    try:
        # Parse CIDR
        if "/" not in cidr:
            return [cidr]
        
        network_part, prefix = cidr.split("/")
        prefix = int(prefix)
        
        # Validate prefix
        if prefix < 0 or prefix > 32:
            return []
        
        # Calculate number of IPs
        num_ips = 2 ** (32 - prefix)
        
        # Limit to reasonable size (max /16 = 65536 IPs)
        if num_ips > 65536:
            return []
        
        # Parse network address
        octets = network_part.split(".")
        if len(octets) != 4:
            return []
        
        base_ip = [int(o) for o in octets]
        
        # Generate IPs
        ips = []
        for i in range(num_ips):
            # Calculate new IP
            new_ip = base_ip.copy()
            new_ip[3] = (base_ip[3] + i) % 256
            carry = (base_ip[3] + i) // 256
            
            if carry > 0:
                new_ip[2] = (base_ip[2] + carry) % 256
                carry = (base_ip[2] + carry) // 256
                
                if carry > 0:
                    new_ip[1] = (base_ip[1] + carry) % 256
                    carry = (base_ip[1] + carry) // 256
                    
                    if carry > 0:
                        new_ip[0] = (base_ip[0] + carry) % 256
            
            # Skip network and broadcast addresses for /24 and larger
            if prefix <= 24:
                if i == 0:  # Network address
                    continue
                if i == num_ips - 1:  # Broadcast address
                    continue
            
            ips.append(f"{new_ip[0]}.{new_ip[1]}.{new_ip[2]}.{new_ip[3]}")
        
        return ips
    
    except Exception:
        return []


def cidr_info(cidr: str) -> Dict[str, Any]:
    """
    Get information about a CIDR block.
    
    Args:
        cidr: CIDR notation
        
    Returns:
        Dict with CIDR information
    """
    try:
        if "/" not in cidr:
            return {"error": "Invalid CIDR notation. Use format: 192.168.1.0/24"}
        
        network_part, prefix = cidr.split("/")
        prefix = int(prefix)
        
        num_ips = 2 ** (32 - prefix)
        usable_ips = max(0, num_ips - 2) if prefix <= 30 else num_ips
        
        # Calculate network and broadcast
        octets = network_part.split(".")
        base_ip = [int(o) for o in octets]
        
        # Simple calculation for common prefixes
        if prefix == 24:
            network = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.0"
            broadcast = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.255"
            first_host = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.1"
            last_host = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.254"
        elif prefix == 16:
            network = f"{base_ip[0]}.{base_ip[1]}.0.0"
            broadcast = f"{base_ip[0]}.{base_ip[1]}.255.255"
            first_host = f"{base_ip[0]}.{base_ip[1]}.0.1"
            last_host = f"{base_ip[0]}.{base_ip[1]}.255.254"
        elif prefix == 8:
            network = f"{base_ip[0]}.0.0.0"
            broadcast = f"{base_ip[0]}.255.255.255"
            first_host = f"{base_ip[0]}.0.0.1"
            last_host = f"{base_ip[0]}.255.255.254"
        else:
            network = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{base_ip[3]}"
            broadcast = "Calculated"
            first_host = "Calculated"
            last_host = "Calculated"
        
        return {
            "cidr": cidr,
            "prefix": prefix,
            "total_ips": num_ips,
            "usable_hosts": usable_ips,
            "network_address": network,
            "broadcast_address": broadcast,
            "first_host": first_host,
            "last_host": last_host,
            "subnet_mask": _prefix_to_mask(prefix),
        }
    
    except Exception as exc:
        return {"error": str(exc)}


def _prefix_to_mask(prefix: int) -> str:
    """Convert prefix length to subnet mask."""
    mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Ping Tester
# ─────────────────────────────────────────────────────────────────────────────

def bulk_ping_cidr(
    cidr: str,
    timeout: float = 1.0,
    threads: int = 100,
    count: int = 1,
) -> Dict[str, Any]:
    """
    Ping all IPs in a CIDR range to discover live hosts.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        timeout: Timeout per ping in seconds
        threads: Number of concurrent threads
        count: Number of pings per host
        
    Returns:
        Dict with live hosts and statistics
    """
    # Generate IPs from CIDR
    ips = generate_ips_from_cidr(cidr)
    
    if not ips:
        return {"error": "No IPs generated. Check CIDR notation."}
    
    if len(ips) > 1024:
        return {
            "error": f"Too many IPs ({len(ips)}). Maximum is 1024 (/22 or smaller).",
            "hint": "Use a smaller subnet or split into multiple scans."
        }
    
    results = {
        "cidr": cidr,
        "total_ips": len(ips),
        "live_hosts": [],
        "dead_hosts": [],
        "errors": [],
        "start_time": datetime.now().isoformat(),
    }

    # Ping each IP using ThreadPoolExecutor
    def ping_host(ip: str) -> Dict[str, Any]:
        """Ping a single host."""
        try:
            result = test_ping(ip, timeout=timeout, count=count)
            return {"ip": ip, "result": result}
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        
        for future in as_completed(futures):
            try:
                response = future.result()
                ip = response["ip"]
                
                if "error" in response:
                    results["errors"].append({"ip": ip, "error": response["error"]})
                    continue
                
                result = response["result"]
                
                if "error" in result:
                    results["errors"].append({"ip": ip, "error": result["error"]})
                elif result.get("reachable", False) or result.get("packets_received", 0) > 0:
                    results["live_hosts"].append({
                        "ip": ip,
                        "ping_result": result,
                    })
                else:
                    results["dead_hosts"].append({
                        "ip": ip,
                        "ping_result": result,
                    })
            
            except Exception as exc:
                ip = futures[future]
                results["errors"].append({"ip": ip, "error": str(exc)})
    
    # Add summary
    results["end_time"] = datetime.now().isoformat()
    results["live_count"] = len(results["live_hosts"])
    results["dead_count"] = len(results["dead_hosts"])
    results["error_count"] = len(results["errors"])
    results["success_rate"] = round(
        (results["live_count"] / len(ips)) * 100, 2
    ) if len(ips) > 0 else 0
    
    return results


def test_ping(
    host: str,
    count: int = 4,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Send ICMP pings to a host.
    
    Args:
        host: Hostname or IP to ping
        count: Number of pings to send
        timeout: Timeout in seconds
        
    Returns:
        Dict with ping results
    """
    result = {
        "host": host,
        "reachable": False,
        "packets_sent": 0,
        "packets_received": 0,
        "packet_loss": "100%",
        "min_rtt": None,
        "avg_rtt": None,
        "max_rtt": None,
    }
    
    # Build ping command based on OS
    try:
        import platform
        if platform.system() == "Windows":
            cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), host]
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,
        )
        
        output = proc.stdout + proc.stderr
        
        # Parse output
        result["packets_sent"] = count
        
        # Extract packets received
        received_match = re.search(r"(\d+)\s+(?:packets?|replies?)\s+received", output, re.I)
        if received_match:
            result["packets_received"] = int(received_match.group(1))
        else:
            # Alternative pattern
            received_match = re.search(r"Received\s*=\s*(\d+)", output, re.I)
            if received_match:
                result["packets_received"] = int(received_match.group(1))
        
        # Calculate loss
        if result["packets_sent"] > 0:
            loss_pct = ((result["packets_sent"] - result["packets_received"]) / result["packets_sent"]) * 100
            result["packet_loss"] = f"{loss_pct:.0f}%"
        
        # Check if reachable
        result["reachable"] = result["packets_received"] > 0
        
        # Extract RTT statistics
        rtt_match = re.search(
            r"(?:rtt|round-trip)\s*=\s*(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)",
            output,
            re.I
        )
        if rtt_match:
            result["min_rtt"] = float(rtt_match.group(1))
            result["avg_rtt"] = float(rtt_match.group(2))
            result["max_rtt"] = float(rtt_match.group(3))
        else:
            # Alternative pattern for Windows
            rtt_match = re.search(r"Average\s*=\s*(\d+)ms", output, re.I)
            if rtt_match:
                result["avg_rtt"] = int(rtt_match.group(1))
        
        return result
    
    except subprocess.TimeoutExpired:
        result["error"] = "Ping timed out"
        return result
    except FileNotFoundError:
        result["error"] = "Ping command not found"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
