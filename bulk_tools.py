"""
Bulk Tools Module
Handles: Bulk operations for DNS, Ping, WHOIS, Geolocation, HTTP headers, Nmap, and Shodan.
Each function processes multiple targets sequentially with configurable delays.
"""

import time
from typing import List, Dict, Any, Optional

import dns_tools
import network_tools
import ip_tools
import web_tools
import external_tools
import shodan_tools


def bulk_dns_lookup(
    targets: List[str],
    record_types: Optional[List[str]] = None,
    delay: int = 100,
) -> Dict[str, Any]:
    """
    Perform DNS lookups for multiple targets.
    
    Args:
        targets: List of domains/IPs to query
        record_types: DNS record types to query (default: A, AAAA, MX, NS, TXT)
        delay: Delay between queries in milliseconds
        
    Returns:
        Dict with per-target results and summary
    """
    if not targets:
        return {"error": "No targets provided"}
    
    results = {
        "total_targets": len(targets),
        "successful": 0,
        "failed": 0,
        "targets": {},
    }
    
    delay_sec = delay / 1000.0
    
    for i, target in enumerate(targets):
        result = dns_tools.dns_lookup(target, record_types=record_types)
        results["targets"][target] = result
        
        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
        
        # Add delay between queries (except for the last one)
        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    
    return results


def bulk_ping(
    targets: List[str],
    count: int = 4,
    delay: int = 100,
) -> Dict[str, Any]:
    """
    Send ICMP pings to multiple hosts.
    
    Args:
        targets: List of hosts/IPs to ping
        count: Number of pings per host
        delay: Delay between pings in milliseconds
        
    Returns:
        Dict with per-target results and summary
    """
    if not targets:
        return {"error": "No targets provided"}
    
    results = {
        "total_targets": len(targets),
        "reachable": 0,
        "unreachable": 0,
        "targets": {},
    }
    
    delay_sec = delay / 1000.0
    
    for i, target in enumerate(targets):
        result = network_tools.test_ping(target, count=count)
        results["targets"][target] = result
        
        # Check if host is reachable
        if result.get("reachable", False) or result.get("packets_received", 0) > 0:
            results["reachable"] += 1
        else:
            results["unreachable"] += 1
        
        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    
    return results


def bulk_whois(
    targets: List[str],
    delay: int = 200,
) -> Dict[str, Any]:
    """
    Perform WHOIS lookups for multiple domains/IPs.
    
    Args:
        targets: List of domains/IPs to query
        delay: Delay between queries in milliseconds
        
    Returns:
        Dict with per-target results and summary
    """
    if not targets:
        return {"error": "No targets provided"}
    
    results = {
        "total_targets": len(targets),
        "successful": 0,
        "failed": 0,
        "targets": {},
    }
    
    delay_sec = delay / 1000.0
    
    for i, target in enumerate(targets):
        result = ip_tools.whois_lookup(target)
        results["targets"][target] = result
        
        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
        
        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    
    return results


def bulk_geolocation(
    targets: List[str],
    delay: int = 100,
) -> Dict[str, Any]:
    """
    Get geolocation data for multiple IP addresses.

    Args:
        targets: List of IP addresses to geolocate
        delay: Delay between queries in milliseconds

    Returns:
        Dict with per-target results and summary
    """
    if not targets:
        return {"error": "No targets provided"}

    results = {
        "total_targets": len(targets),
        "successful": 0,
        "failed": 0,
        "targets": {},
        "_geo_grouped": True,  # Flag for special formatting
        "countries": {},
        "cities": {},
    }

    delay_sec = delay / 1000.0

    for i, target in enumerate(targets):
        result = ip_tools.ip_geolocation(target)
        results["targets"][target] = result

        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
            # Aggregate by country and city
            country = result.get("country", result.get("countryName", "Unknown"))
            city = result.get("city", result.get("regionName", "Unknown"))
            
            if country not in results["countries"]:
                results["countries"][country] = 0
            results["countries"][country] += 1
            
            city_key = f"{country} / {city}" if city else f"{country} / Unknown"
            if city_key not in results["cities"]:
                results["cities"][city_key] = []
            results["cities"][city_key].append(target)

        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)

    # Add sorted country list for quick overview
    results["country_list"] = sorted(results["countries"].items(), key=lambda x: -x[1])

    return results


def bulk_http_headers(
    targets: List[str],
    follow_redirects: bool = True,
    user_agent: str = "Mozilla/5.0 (OSINT-Suite)",
    delay: int = 200,
) -> Dict[str, Any]:
    """
    Fetch HTTP headers for multiple URLs.
    
    Args:
        targets: List of URLs to query
        follow_redirects: Whether to follow redirects
        user_agent: User-Agent header to send
        delay: Delay between requests in milliseconds
        
    Returns:
        Dict with per-target results and summary
    """
    if not targets:
        return {"error": "No targets provided"}
    
    results = {
        "total_targets": len(targets),
        "successful": 0,
        "failed": 0,
        "targets": {},
    }
    
    delay_sec = delay / 1000.0
    
    for i, url in enumerate(targets):
        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        result = web_tools.http_headers(
            url,
            follow_redirects=follow_redirects,
            user_agent=user_agent,
        )
        results["targets"][url] = result
        
        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
        
        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    
    return results


def bulk_nmap_scan(
    targets: List[str],
    preset: str = "Quick Scan (-T4 top 100)",
    port_spec: Optional[str] = None,
    custom_flags: str = "",
    delay: int = 500,
    timeout_per_scan: int = 600,
) -> Dict[str, Any]:
    """
    Perform Nmap scans for multiple targets.

    Args:
        targets: List of hosts/IPs to scan
        preset: Nmap preset scan type
        port_spec: Port specification (optional)
        custom_flags: Additional Nmap flags
        delay: Delay between scans in milliseconds
        timeout_per_scan: Timeout per target in seconds

    Returns:
        Dict with per-target results, summary, and aggregated data
    """
    if not targets:
        return {"error": "No targets provided"}

    results = {
        "total_targets": len(targets),
        "successful": 0,
        "failed": 0,
        "total_open_ports": 0,
        "targets": {},
        "all_open_ports": [],
        "all_services": {},
        "all_ips": set(),
        "hosts_by_os": {},
        "hosts_by_service": {},
    }

    delay_sec = delay / 1000.0

    for i, target in enumerate(targets):
        result = external_tools.nmap_port_scan(
            target,
            preset=preset,
            port_spec=port_spec,
            custom_flags=custom_flags,
            timeout=timeout_per_scan,
        )
        results["targets"][target] = result

        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
            open_ports = result.get("open_ports", [])
            results["total_open_ports"] += len(open_ports)

            # Aggregate services
            for port_info in open_ports:
                port_num = port_info.get("port") if isinstance(port_info, dict) else port_info
                service = port_info.get("service", "unknown") if isinstance(port_info, dict) else "unknown"

                if port_num:
                    results["all_open_ports"].append({
                        "target": target,
                        "port": port_num,
                        "service": service,
                    })

                    # Count services
                    svc_name = service.split()[0] if service else "unknown"
                    results["all_services"][svc_name] = results["all_services"].get(svc_name, 0) + 1
                    
                    # Track hosts by service
                    if svc_name not in results["hosts_by_service"]:
                        results["hosts_by_service"][svc_name] = []
                    if target not in results["hosts_by_service"][svc_name]:
                        results["hosts_by_service"][svc_name].append(target)

                    # Try to extract IP from target
                    if dns_tools.is_ip_address(target):
                        results["all_ips"].add(target)
                    else:
                        # Try to resolve hostname
                        try:
                            import socket
                            ip = socket.gethostbyname(target)
                            results["all_ips"].add(ip)
                        except:
                            pass

            # Track OS detection
            os_guesses = result.get("os_guesses", [])
            if os_guesses:
                os_desc = os_guesses[0].get("description", "Unknown") if os_guesses else "Unknown"
                # Extract main OS family
                os_family = _extract_os_family(os_desc)
                if os_family not in results["hosts_by_os"]:
                    results["hosts_by_os"][os_family] = []
                if target not in results["hosts_by_os"][os_family]:
                    results["hosts_by_os"][os_family].append(target)

        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)

    # Convert set to list for JSON serialization
    results["all_ips"] = list(results["all_ips"])

    # Get geolocation for discovered IPs
    results["geolocations"] = {}
    for ip in results["all_ips"]:
        geo_result = ip_tools.ip_geolocation(ip)
        if "error" not in geo_result:
            results["geolocations"][ip] = geo_result

    # Add sorted service list
    results["service_list"] = sorted(results["all_services"].items(), key=lambda x: -x[1])
    results["os_list"] = sorted(results["hosts_by_os"].items(), key=lambda x: -len(x[1]))

    return results


def _extract_os_family(os_description: str) -> str:
    """Extract general OS family from OS detection string."""
    os_desc_lower = os_description.lower()
    if "windows" in os_desc_lower:
        return "Windows"
    elif "linux" in os_desc_lower or "ubuntu" in os_desc_lower or "debian" in os_desc_lower:
        return "Linux"
    elif "mac" in os_desc_lower or "os x" in os_desc_lower or "darwin" in os_desc_lower:
        return "macOS"
    elif "freebsd" in os_desc_lower or "openbsd" in os_desc_lower:
        return "BSD"
    elif "router" in os_desc_lower or "switch" in os_desc_lower:
        return "Network Device"
    else:
        return "Other"


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Shodan Search
# ─────────────────────────────────────────────────────────────────────────────

def bulk_shodan_search(
    targets: List[str],
    delay: int = 1000,
    extract_cves: bool = True,
    extract_ports: bool = True,
    cookie: str = None,
) -> Dict[str, Any]:
    """
    Perform Shodan lookups for multiple IP addresses.
    Scrapes public Shodan.io host pages for Country, City, CVEs, and more.
    
    Args:
        targets: List of IP addresses to lookup
        delay: Delay between queries in milliseconds (default 1000ms to avoid rate limiting)
        extract_cves: Whether to extract CVE information
        extract_ports: Whether to extract open ports
        cookie: Optional Shodan session cookie for authenticated access
        
    Returns:
        Dict with per-target results and summary
    """
    return shodan_tools.bulk_shodan_search(
        targets=targets,
        delay=delay,
        extract_cves=extract_cves,
        extract_ports=extract_ports,
        cookie=cookie,
    )
