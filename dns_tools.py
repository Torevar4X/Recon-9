"""
DNS Tools Module
Handles: DNS Lookup, Reverse DNS, Subdomain Discovery, Shared DNS
"""

import socket
import re
import requests
from typing import List, Dict, Any, Optional

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Import API configuration
try:
    import api_config
    API_CONFIG_OK = True
except ImportError:
    API_CONFIG_OK = False


def is_ip_address(value: str) -> bool:
    """Check if string is a valid IPv4 address."""
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, value):
        return False
    # Validate each octet
    try:
        parts = value.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def dns_lookup(target: str, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Perform DNS lookup for one or more record types.
    Falls back to socket for basic A lookups if dnspython is absent.
    """
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    results: Dict[str, Any] = {"domain": target, "records": {}}

    if not DNS_AVAILABLE:
        # Minimal fallback
        try:
            ip = socket.gethostbyname(target)
            results["records"]["A"] = [ip]
            results["warning"] = "dnspython not installed — only A record available via socket."
        except socket.gaierror as exc:
            results["error"] = str(exc)
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            results["records"][rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            results["error"] = f"Domain '{target}' does not exist (NXDOMAIN)."
            return results
        except dns.exception.DNSException as exc:
            results["records"][rtype] = [f"Error: {exc}"]

    return results


def reverse_dns(ip: str) -> Dict[str, Any]:
    """Perform reverse DNS (PTR) lookup for an IP address."""
    result: Dict[str, Any] = {"ip": ip}

    if DNS_AVAILABLE:
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(addr, "PTR")
            result["hostnames"] = [str(a).rstrip(".") for a in answers]
            return result
        except Exception:
            pass  # fall through to socket fallback

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["hostnames"] = [hostname]
    except socket.herror as exc:
        result["error"] = str(exc)

    return result


def find_subdomains(domain: str, use_crt: bool = True, use_brute: bool = True) -> Dict[str, Any]:
    """
    Discover subdomains via certificate-transparency logs (crt.sh) and/or
    a built-in common-subdomain brute-force list.
    """
    found: set = set()
    methods_used: List[str] = []
    errors: List[str] = []

    # ── Method 1: crt.sh certificate transparency ──────────────────────────
    if use_crt:
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=20, headers={"User-Agent": "OSINT-Suite/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            found.add(name)
                methods_used.append("Certificate Transparency (crt.sh)")
        except Exception as exc:
            errors.append(f"crt.sh error: {exc}")

    # ── Method 2: Brute-force with common prefixes ──────────────────────────
    if use_brute:
        wordlist = [
            "www", "mail", "ftp", "ssh", "smtp", "pop", "imap", "ns1", "ns2",
            "ns3", "vpn", "admin", "api", "dev", "staging", "test", "blog",
            "shop", "store", "secure", "cdn", "media", "static", "assets",
            "portal", "app", "mobile", "docs", "support", "help", "dashboard",
            "login", "auth", "mx", "email", "webmail", "remote", "files",
            "intranet", "internal", "beta", "demo", "preview", "old", "new",
            "upload", "download", "git", "svn", "jenkins", "ci", "monitor",
            "status", "health", "db", "sql", "mysql", "redis", "elastic",
        ]
        if DNS_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 1.5
            for sub in wordlist:
                fqdn = f"{sub}.{domain}"
                try:
                    resolver.resolve(fqdn, "A")
                    found.add(fqdn)
                except Exception:
                    pass
            methods_used.append("Brute-force (common wordlist)")
        else:
            for sub in wordlist:
                fqdn = f"{sub}.{domain}"
                try:
                    socket.gethostbyname(fqdn)
                    found.add(fqdn)
                except Exception:
                    pass
            methods_used.append("Brute-force via socket (dnspython unavailable)")

    return {
        "domain": domain,
        "subdomains": sorted(found),
        "count": len(found),
        "methods": methods_used,
        "errors": errors,
    }


def find_shared_dns(domain: str) -> Dict[str, Any]:
    """
    Identify the authoritative nameservers for a domain, resolve their IPs,
    and query HackerTarget to find other domains sharing those NS servers.
    """
    result: Dict[str, Any] = {"domain": domain, "nameservers": [], "ns_ips": {}, "shared": {}}

    # Resolve NS records
    ns_list: List[str] = []
    if DNS_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, "NS")
            ns_list = [str(a).rstrip(".") for a in answers]
        except Exception as exc:
            result["error"] = str(exc)
            return result
    else:
        result["error"] = "dnspython not installed; NS resolution unavailable."
        return result

    result["nameservers"] = ns_list

    # Resolve NS IPs
    for ns in ns_list:
        try:
            answers = dns.resolver.resolve(ns, "A")
            result["ns_ips"][ns] = [str(a) for a in answers]
        except Exception:
            result["ns_ips"][ns] = ["Unresolvable"]

    # HackerTarget shared-DNS API (rate-limited; free tier)
    # Check for API key configuration (for potential premium access)
    api_key = api_config.get_api_key("hackertarget") if API_CONFIG_OK else None
    for ns in ns_list[:2]:
        try:
            api_url = f"https://api.hackertarget.com/findshareddns/?q={ns}"
            # Note: HackerTarget free tier doesn't require key, but premium does
            resp = requests.get(api_url, timeout=12, headers={"User-Agent": "OSINT-Suite/1.0"})
            if resp.ok and "error" not in resp.text.lower()[:30]:
                domains = [d.strip() for d in resp.text.strip().splitlines() if d.strip()]
                result["shared"][ns] = domains[:60]
        except Exception as exc:
            result["shared"][ns] = [f"API error: {exc}"]

    return result
