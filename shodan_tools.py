"""
Shodan Tools Module
Handles: Shodan IP lookup, bulk search, CVE detection
Scrapes public Shodan.io host pages for information.
"""

import re
import socket
import time
import requests
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

# Import API configuration
try:
    import api_config
    API_CONFIG_OK = True
except ImportError:
    API_CONFIG_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Shodan IP Lookup (Web Scraping)
# ─────────────────────────────────────────────────────────────────────────────

def shodan_ip_lookup(ip_or_host: str, cookie: str = None) -> Dict[str, Any]:
    """
    Scrape Shodan host page for IP information.
    Extracts: Country, City, Organization, Open Ports, CVEs, Hostnames.
    
    Args:
        ip_or_host: IP address or hostname to lookup
        cookie: Optional Shodan session cookie for authenticated access
        
    Returns:
        Dict with scraped Shodan data or error
    """
    # Resolve hostname to IP if needed
    ip = ip_or_host
    if not _is_ip(ip_or_host):
        try:
            ip = socket.gethostbyname(ip_or_host)
        except Exception as exc:
            return {"error": f"Cannot resolve '{ip_or_host}': {exc}"}
    
    # Try API first if key is available
    if API_CONFIG_OK:
        api_key = api_config.get_api_key("shodan")
        if api_key:
            return _shodan_api_lookup(ip, api_key)
    
    # Fall back to web scraping
    shodan_url = f"https://www.shodan.io/host/{ip}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
    }
    
    # Add cookie if provided
    cookies = {}
    if cookie:
        cookies["session"] = cookie
        headers["Cookie"] = f"session={cookie}"
    
    try:
        resp = requests.get(shodan_url, headers=headers, cookies=cookies, timeout=15, allow_redirects=True)
        
        if resp.status_code == 404:
            return {"error": "No information found for this IP", "ip": ip}
        elif resp.status_code == 429:
            return {"error": "Rate limited by Shodan. Please wait and try again.", "ip": ip}
        elif resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}", "ip": ip, "url": shodan_url}
        
        # Check if redirected to login page
        if "login" in resp.url.lower() or "sign in" in resp.text.lower():
            return {
                "error": "Shodan requires login for detailed information. Add your API key or session cookie in Settings.",
                "ip": ip,
                "url": shodan_url,
                "hint": "Get a free API key at https://account.shodan.io/"
            }
        
        return _parse_shodan_html(resp.text, ip, resp.url)
        
    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            resp = requests.get(shodan_url, headers=headers, cookies=cookies, timeout=15, verify=False, allow_redirects=True)
            return _parse_shodan_html(resp.text, ip, resp.url)
        except Exception as exc:
            return {"error": f"Request failed: {exc}", "ip": ip}
    except Exception as exc:
        return {"error": f"Request failed: {exc}", "ip": ip}


def _shodan_api_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Lookup IP using Shodan API (more reliable than scraping).
    
    Args:
        ip: IP address to lookup
        api_key: Shodan API key
        
    Returns:
        Dict with API response data
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    
    try:
        resp = requests.get(url, timeout=15)
        
        if resp.status_code == 404:
            return {"error": "No information found for this IP", "ip": ip, "source": "Shodan API"}
        elif resp.status_code == 401:
            return {"error": "Invalid Shodan API key", "ip": ip}
        elif resp.status_code == 429:
            return {"error": "Shodan API rate limit exceeded", "ip": ip}
        elif resp.status_code != 200:
            return {"error": f"API HTTP {resp.status_code}", "ip": ip}
        
        data = resp.json()
        
        # Parse API response
        result = {
            "ip": ip,
            "source": "Shodan API",
            "url": f"https://www.shodan.io/host/{ip}",
            "city": data.get("city", "Unknown"),
            "country": data.get("country_name", data.get("country", "Unknown")),
            "country_code": data.get("country_code", ""),
            "region": data.get("region", ""),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "organization": data.get("org", data.get("isp", "")),
            "asn": data.get("asn", ""),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "os": data.get("os", ""),
            "last_update": data.get("last_update", ""),
            "tags": data.get("tags", []),
        }
        
        # Extract ports and services
        if "data" in data:
            ports = set()
            cves = []
            services = []
            
            for service in data["data"]:
                port = service.get("port")
                transport = service.get("transport", "tcp")
                if port:
                    ports.add(f"{port}/{transport}")
                
                # Extract CVEs
                if "vulns" in service:
                    for cve_id in service["vulns"]:
                        if cve_id.startswith("CVE-"):
                            cves.append({
                                "cve_id": cve_id,
                                "url": f"https://www.shodan.io/vulnerabilities/{cve_id}",
                            })
                
                # Extract service info
                if "product" in service or "version" in service:
                    product = service.get("product", "")
                    version = service.get("version", "")
                    if product:
                        services.append(f"{product} {version}".strip())
            
            result["open_ports"] = sorted(list(ports))
            result["cves"] = cves
            result["services"] = services[:10]
        
        return result
        
    except requests.exceptions.JSONDecodeError:
        return {"error": "Invalid API response", "ip": ip}
    except Exception as exc:
        return {"error": f"API request failed: {exc}", "ip": ip}


def _parse_shodan_html(html: str, ip: str, url: str = None) -> Dict[str, Any]:
    """Parse Shodan HTML response and extract relevant information."""
    result = {
        "ip": ip,
        "source": "shodan.io",
        "url": url or f"https://www.shodan.io/host/{ip}",
    }

    try:
        soup = BeautifulSoup(html, 'html.parser')
    except Exception:
        return {"error": "Failed to parse HTML response", "ip": ip}

    # Get page text once for regex searches
    page_text = soup.get_text()

    # ─────────────────────────────────────────────────────────────────────────
    # Strategy 1: Parse grid-table structure (primary method)
    # ─────────────────────────────────────────────────────────────────────────

    grid_table = soup.find('div', class_='grid-table')
    if grid_table:
        # Parse label-value pairs from grid-table
        labels = grid_table.find_all('label')
        for label in labels:
            label_text = label.get_text(strip=True).lower()
            # Get the next sibling div with the value
            value_div = label.find_next_sibling('div')
            if value_div:
                value_text = value_div.get_text(strip=True)
                strong_tag = value_div.find('strong')
                if strong_tag:
                    value_text = strong_tag.get_text(strip=True)

                if 'country' in label_text:
                    result["country"] = value_text
                elif 'city' in label_text:
                    result["city"] = value_text
                elif 'organization' in label_text:
                    result["organization"] = value_text
                elif 'isp' in label_text:
                    result["isp"] = value_text
                elif 'asn' in label_text:
                    result["asn"] = value_text
    
    # ─────────────────────────────────────────────────────────────────────────
    # Strategy 2: Look for location in main-info or similar containers
    # ─────────────────────────────────────────────────────────────────────────
    
    if "city" not in result or "country" not in result:
        for container in soup.find_all(['div', 'section'], class_=re.compile(r'main|info|location|host', re.I)):
            text = container.get_text(separator=' ', strip=True)
            # Look for "City, Country" pattern
            match = re.search(r'([\w\s\-\'\.]+),\s*([\w\s\-\'\.]+)', text)
            if match:
                potential_city = match.group(1).strip()
                potential_country = match.group(2).strip()
                # Validate - city should be reasonable length
                if 2 < len(potential_city) < 50 and 2 < len(potential_country) < 50:
                    # Avoid false positives
                    if not any(word in potential_city.lower() for word in ['ports', 'organization', 'asn', 'isp']):
                        if "city" not in result:
                            result["city"] = potential_city
                        if "country" not in result:
                            result["country"] = potential_country
                        break
    
    # ─────────────────────────────────────────────────────────────────────────
    # Strategy 3: Look for specific location-related classes or data attributes
    # ─────────────────────────────────────────────────────────────────────────
    
    if "city" not in result:
        # Search for elements with location-related data attributes
        for tag in soup.find_all(attrs={'data-name': True}):
            attr_name = tag.get('data-name', '').lower()
            if 'city' in attr_name or 'country' in attr_name:
                value = tag.get_text(strip=True)
                if 'city' in attr_name:
                    result["city"] = value
                elif 'country' in attr_name:
                    result["country"] = value
        
        # Look for location in meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            if 'city' in name and content:
                result["city"] = content
            elif 'country' in name and content:
                result["country"] = content
    
    # ─────────────────────────────────────────────────────────────────────────
    # Strategy 4: Search for location patterns in script tags (JSON data)
    # ─────────────────────────────────────────────────────────────────────────
    
    if "city" not in result:
        for script in soup.find_all('script'):
            script_text = script.string or ""
            # Look for JSON-like structures
            city_match = re.search(r'"city"\s*:\s*"([^"]+)"', script_text)
            country_match = re.search(r'"country_name"\s*:\s*"([^"]+)"', script_text)
            if city_match:
                result["city"] = city_match.group(1)
            if country_match:
                result["country"] = country_match.group(1)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Strategy 5: Look for address-like structures
    # ─────────────────────────────────────────────────────────────────────────
    
    if "city" not in result or "country" not in result:
        # Search for spans/divs that might contain location
        for tag in soup.find_all(['span', 'div', 'li']):
            text = tag.get_text(strip=True)
            # Common location format: "City, Country"
            if ',' in text and 5 < len(text) < 60:
                parts = text.split(',')
                if len(parts) >= 2:
                    part1 = parts[0].strip()
                    part2 = parts[-1].strip()
                    # Check if it looks like a location
                    if (part1[0].isupper() and part2[0].isupper() and 
                        len(part1) > 2 and len(part2) > 2 and
                        len(part1) < 40 and len(part2) < 40):
                        if not result.get("city"):
                            result["city"] = part1
                        if not result.get("country"):
                            result["country"] = part2
    
    # Fallback: Set Unknown if not found
    if "city" not in result:
        result["city"] = "Unknown"
    if "country" not in result:
        result["country"] = "Unknown"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Organization / ISP (if not already found)
    # ─────────────────────────────────────────────────────────────────────────

    if "organization" not in result:
        org_patterns = [
            (r'Organization[:\s]+([^\n,]+)', re.I),
            (r'Org[:\s]+([^\n,]+)', re.I),
            (r'ISP[:\s]+([^\n,]+)', re.I),
            (r'Company[:\s]+([^\n,]+)', re.I),
        ]

        for pattern, flags in org_patterns:
            match = re.search(pattern, page_text, flags)
            if match:
                result["organization"] = match.group(1).strip()
                break

    if "asn" not in result:
        asn_match = re.search(r'AS(\d+)\s*|ASN[:\s]*(\d+)', page_text, re.I)
        if asn_match:
            result["asn"] = f"AS{asn_match.group(1) or asn_match.group(2)}"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Hostnames
    # ─────────────────────────────────────────────────────────────────────────
    
    # Look for hostname section
    hostname_section = soup.find('div', string=re.compile(r'Hostnames?|Domain', re.I))
    if hostname_section:
        parent = hostname_section.find_parent(['div', 'ul', 'li'])
        if parent:
            hostname_tags = parent.find_all(['a', 'span'], class_=re.compile(r'tag|label|hostname', re.I))
            if hostname_tags:
                result["hostnames"] = [tag.get_text(strip=True) for tag in hostname_tags if tag.get_text(strip=True)]
    
    # Alternative: search for hostname patterns
    if "hostnames" not in result:
        hostname_pattern = re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+')
        found_hostnames = set()
        # Look in specific containers first
        for container in soup.find_all(['div', 'section'], class_=re.compile(r'host|info', re.I)):
            text = container.get_text()
            matches = hostname_pattern.findall(text)
            for match in matches:
                # Filter out common false positives
                if (match != ip and 
                    not match.startswith('www.') and 
                    not match.endswith('.css') and
                    len(match) < 100):
                    found_hostnames.add(match)
        
        if found_hostnames:
            result["hostnames"] = list(found_hostnames)[:10]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Open Ports
    # ─────────────────────────────────────────────────────────────────────────
    
    # Look for port section
    ports_section = soup.find('div', string=re.compile(r'Open Ports|Ports', re.I))
    if ports_section:
        parent = ports_section.find_parent(['div', 'ul'])
        if parent:
            port_tags = parent.find_all(['span', 'li', 'a'], string=re.compile(r'^\d+/[a-z]+', re.I))
            if port_tags:
                result["open_ports"] = [tag.get_text(strip=True) for tag in port_tags]
    
    # Alternative: search for port patterns
    if "open_ports" not in result:
        port_pattern = re.compile(r'\b(\d+)/(tcp|udp)\b')
        found_ports = set()
        for tag in soup.find_all(['span', 'div', 'li']):
            text = tag.get_text(strip=True)
            matches = port_pattern.findall(text)
            for port, proto in matches:
                port_entry = f"{port}/{proto}"
                if port_entry not in found_ports:
                    found_ports.add(port_entry)
        
        if found_ports:
            result["open_ports"] = sorted(list(found_ports))
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract CVEs
    # ─────────────────────────────────────────────────────────────────────────
    
    # Look for CVE section
    cve_section = soup.find('div', string=re.compile(r'CVE|Vulnerabilit', re.I))
    if cve_section:
        parent = cve_section.find_parent(['div', 'ul'])
        if parent:
            cve_tags = parent.find_all(['a', 'span'], string=re.compile(r'CVE-\d{4}-\d+', re.I))
            if cve_tags:
                result["cves"] = []
                for tag in cve_tags:
                    cve_text = tag.get_text(strip=True)
                    if cve_text.startswith("CVE-"):
                        result["cves"].append({
                            "cve_id": cve_text,
                            "url": f"https://www.shodan.io/vulnerabilities/{cve_text}",
                        })
    
    # Alternative: search entire page for CVE patterns
    if "cves" not in result:
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.I)
        found_cves = set()
        for tag in soup.find_all(['a', 'span', 'div']):
            text = tag.get_text(strip=True)
            matches = cve_pattern.findall(text)
            for cve in matches:
                if cve.upper() not in found_cves:
                    found_cves.add(cve.upper())
                    if "cves" not in result:
                        result["cves"] = []
                    result["cves"].append({
                        "cve_id": cve.upper(),
                        "url": f"https://www.shodan.io/vulnerabilities/{cve.upper()}",
                    })
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Services/Banners
    # ─────────────────────────────────────────────────────────────────────────
    
    services = []
    service_sections = soup.find_all('div', class_=re.compile(r'service|banner|product', re.I))
    for section in service_sections[:20]:
        service_text = section.get_text(separator=' ', strip=True)
        if service_text and len(service_text) < 200:
            services.append(service_text)
    
    if services:
        result["services"] = services[:10]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Operating System
    # ─────────────────────────────────────────────────────────────────────────
    
    os_patterns = [
        re.compile(r'Operating System[:\s]+([^\n]+)', re.I),
        re.compile(r'OS[:\s]+([^\n,]+)', re.I),
    ]
    
    for pattern in os_patterns:
        match = pattern.search(page_text)
        if match:
            result["os"] = match.group(1).strip()
            break
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract Last Update
    # ─────────────────────────────────────────────────────────────────────────
    
    update_patterns = [
        re.compile(r'Last Update[:\s]+([^\n]+)', re.I),
        re.compile(r'Updated[:\s]+([^\n]+)', re.I),
        re.compile(r'Scanned[:\s]+([^\n]+)', re.I),
    ]
    
    for pattern in update_patterns:
        match = pattern.search(page_text)
        if match:
            result["last_update"] = match.group(1).strip()
            break
    
    return result


def _is_ip(value: str) -> bool:
    """Check if string is a valid IPv4 address."""
    import re
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, value):
        return False
    try:
        parts = value.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


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
    Scrapes public Shodan.io host pages.

    Args:
        targets: List of IP addresses to lookup
        delay: Delay between queries in milliseconds (default 1000ms to avoid rate limiting)
        extract_cves: Whether to extract CVE information
        extract_ports: Whether to extract open ports
        cookie: Optional Shodan session cookie for authenticated access

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
        "_shodan_grouped": True,  # Flag for special formatting
        "countries": {},
        "cities": {},
        "cves_found": [],
        "all_ports": set(),
    }

    delay_sec = delay / 1000.0

    for i, target in enumerate(targets):
        result = shodan_ip_lookup(target, cookie=cookie)
        results["targets"][target] = result
        
        if "error" in result:
            results["failed"] += 1
        else:
            results["successful"] += 1
            
            # Aggregate by country and city
            country = result.get("country", "Unknown")
            city = result.get("city", "Unknown")
            
            if country not in results["countries"]:
                results["countries"][country] = 0
            results["countries"][country] += 1
            
            city_key = f"{country} / {city}" if city else f"{country} / Unknown"
            if city_key not in results["cities"]:
                results["cities"][city_key] = []
            results["cities"][city_key].append(target)
            
            # Collect CVEs
            if extract_cves and "cves" in result:
                for cve in result["cves"]:
                    if cve not in results["cves_found"]:
                        results["cves_found"].append(cve)
            
            # Collect ports
            if extract_ports and "open_ports" in result:
                for port in result["open_ports"]:
                    results["all_ports"].add(port)
        
        # Add delay between queries to avoid rate limiting
        if i < len(targets) - 1 and delay_sec > 0:
            time.sleep(delay_sec)
    
    # Convert sets to lists
    results["all_ports"] = sorted(list(results["all_ports"]))
    
    # Add sorted country list
    results["country_list"] = sorted(results["countries"].items(), key=lambda x: -x[1])
    
    # Add CVE count
    results["cve_count"] = len(results["cves_found"])

    return results
