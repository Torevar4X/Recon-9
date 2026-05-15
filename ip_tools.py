"""
WHOIS, ASN & IP Information Module
Handles: WHOIS Lookup, ASN Lookup, IP Geolocation,
         IP Information, Reverse IP Lookup
"""

import socket
import requests
from typing import Dict, Any, Optional

try:
    import whois as pywhois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from ipwhois import IPWhois
    IPWHOIS_OK = True
except ImportError:
    IPWHOIS_OK = False

# Import API configuration
try:
    import api_config
    API_CONFIG_OK = True
except ImportError:
    API_CONFIG_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def whois_lookup(target: str) -> Dict[str, Any]:
    """
    Perform a WHOIS lookup for a domain or IP address.
    Uses python-whois if installed; falls back to a raw socket query.
    """
    if WHOIS_OK:
        try:
            w = pywhois.whois(target)
            # Convert to dict, handle datetime objects
            data = {}
            for key, val in w.items():
                if val is None:
                    continue
                if isinstance(val, list):
                    data[key] = [str(v) for v in val]
                else:
                    data[key] = str(val)
            return {"target": target, "whois": data}
        except Exception as exc:
            return {"target": target, "error": str(exc)}
    else:
        # Manual raw WHOIS
        return _raw_whois(target)


def _raw_whois(target: str) -> Dict[str, Any]:
    """Minimal WHOIS via raw socket to whois.iana.org."""
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=10) as s:
            s.sendall((target + "\r\n").encode())
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        text = response.decode(errors="replace")
        return {"target": target, "raw": text, "source": "whois.iana.org"}
    except Exception as exc:
        return {"target": target, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# ASN Lookup
# ─────────────────────────────────────────────────────────────────────────────

def asn_lookup(ip_or_asn: str) -> Dict[str, Any]:
    """
    Look up ASN information for an IP address or ASN number.
    Uses ipwhois if available; falls back to ip-api.com.
    """
    # Resolve hostname to IP if needed
    ip = ip_or_asn
    if not _is_ip(ip_or_asn) and not ip_or_asn.upper().startswith("AS"):
        try:
            ip = socket.gethostbyname(ip_or_asn)
        except Exception as exc:
            return {"error": f"Cannot resolve '{ip_or_asn}': {exc}"}

    if IPWHOIS_OK and _is_ip(ip):
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            return {
                "ip": ip,
                "asn": rdap.get("asn"),
                "asn_cidr": rdap.get("asn_cidr"),
                "asn_country_code": rdap.get("asn_country_code"),
                "asn_date": rdap.get("asn_date"),
                "asn_registry": rdap.get("asn_registry"),
                "asn_description": rdap.get("asn_description"),
                "network_name": rdap.get("network", {}).get("name"),
                "network_cidr": rdap.get("network", {}).get("cidr"),
                "source": "ipwhois/RDAP",
            }
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}
    else:
        # ip-api.com fallback
        return _ip_api_info(ip)


# ─────────────────────────────────────────────────────────────────────────────
# IP Geolocation
# ─────────────────────────────────────────────────────────────────────────────

def ip_geolocation(ip_or_host: str) -> Dict[str, Any]:
    """
    Geolocate an IP or hostname using ipinfo.io (free tier, no key required).
    Returns country, region, city, lat/lon, timezone, ISP, org and AS.
    """
    ip = ip_or_host
    if not _is_ip(ip_or_host):
        try:
            ip = socket.gethostbyname(ip_or_host)
        except Exception as exc:
            return {"error": f"Cannot resolve '{ip_or_host}': {exc}"}

    try:
        # Build URL with optional API key
        api_key = api_config.get_api_key("ipinfo") if API_CONFIG_OK else None
        if api_key:
            url = f"https://ipinfo.io/{ip}/json?token={api_key}"
        else:
            url = f"https://ipinfo.io/{ip}/json"
        
        resp = requests.get(url, timeout=10, headers={"User-Agent": "OSINT-Suite/1.0"})
        resp.raise_for_status()
        data = resp.json()

        # Parse loc field (format: "lat,lon")
        loc = data.pop("loc", None)
        if loc:
            lat, lon = loc.split(",")
            data["lat"] = lat
            data["lon"] = lon

        # Rename fields to match expected output
        rename_map = {
            "country": "country",
            "country_name": "countryName",
            "region": "regionName",
            "city": "city",
            "postal": "zip",
            "timezone": "timezone",
            "org": "org",
            "asn": "asn",
        }
        result = {}
        for key, val in data.items():
            result[key] = val

        return {"ip": ip, "source": "ipinfo.io", **result}
    except requests.exceptions.HTTPError as exc:
        if exc.response.status_code == 429:
            return {"ip": ip, "error": "Rate limit exceeded. Try again later."}
        return {"ip": ip, "error": f"HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# IP Information (comprehensive)
# ─────────────────────────────────────────────────────────────────────────────

def ip_information(ip_or_host: str) -> Dict[str, Any]:
    """
    Aggregate IP information: geolocation + ASN/RDAP data + reverse DNS.
    """
    ip = ip_or_host
    if not _is_ip(ip_or_host):
        try:
            ip = socket.gethostbyname(ip_or_host)
        except Exception as exc:
            return {"error": str(exc)}

    result: Dict[str, Any] = {"queried": ip_or_host, "ip": ip}

    # Geolocation
    geo = ip_geolocation(ip)
    geo.pop("ip", None)
    geo.pop("source", None)
    result["geolocation"] = geo

    # ASN
    if IPWHOIS_OK:
        asn = asn_lookup(ip)
        result["asn"] = {
            k: v for k, v in asn.items()
            if k not in ("ip", "source")
        }

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = hostname
    except Exception:
        result["reverse_dns"] = None

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Reverse IP Lookup
# ─────────────────────────────────────────────────────────────────────────────

def reverse_ip_lookup(ip_or_host: str) -> Dict[str, Any]:
    """
    Find all domains hosted on the same IP using HackerTarget's free API.
    """
    ip = ip_or_host
    if not _is_ip(ip_or_host):
        try:
            ip = socket.gethostbyname(ip_or_host)
        except Exception as exc:
            return {"error": str(exc)}

    try:
        # HackerTarget API doesn't require a key for basic usage,
        # but we check for configuration in case premium API becomes available
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "OSINT-Suite/1.0"})
        if resp.ok:
            text = resp.text.strip()
            if "error" in text.lower()[:20]:
                return {"ip": ip, "error": text}
            domains = [d.strip() for d in text.splitlines() if d.strip()]
            return {"ip": ip, "domains": domains, "count": len(domains)}
        return {"ip": ip, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_ip(value: str) -> bool:
    """Return True if *value* looks like an IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            pass
    return False


def _ip_api_info(ip: str) -> Dict[str, Any]:
    """Lightweight ipinfo.io fallback for ASN info."""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        resp = requests.get(url, timeout=8, headers={"User-Agent": "OSINT-Suite/1.0"})
        resp.raise_for_status()
        data = resp.json()
        return {"ip": ip, "org": data.get("org"), "asn": data.get("asn"), 
                "country": data.get("country"), "source": "ipinfo.io (fallback)"}
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}
