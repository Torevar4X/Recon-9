"""
Graph Extractor
Handles: Converting OSINT tool results into graph nodes and edges for visualization
"""

from typing import Dict, Any, List, Tuple


class GraphExtractor:
    """Extract graph nodes and edges from OSINT tool results."""

    @classmethod
    def extract(
        cls, tool_name: str, result: Dict[str, Any], target: str = ""
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Extract nodes and edges from tool results.

        Args:
            tool_name: Name of the OSINT tool (e.g., "DNS Lookup", "TCP Port Scan")
            result: Tool result dictionary
            target: Original target of the scan

        Returns:
            Tuple of (nodes list, edges list)
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # Add target node
        target_id = cls._make_id(target)
        nodes.append({
            "id": target_id,
            "label": target,
            "type": "target",
            "tooltip": f"Scan target: {target}",
        })

        # Dispatch to specific extractor based on tool name
        # Note: Bulk and Shodan must be checked FIRST to override generic DNS/Port/IP match
        if "Bulk" in tool_name or "bulk" in tool_name.lower():
            nodes, edges = cls._extract_bulk(result, target_id, nodes, edges)
        elif "Shodan" in tool_name or "shodan" in tool_name.lower():
            nodes, edges = cls._extract_shodan(result, target_id, nodes, edges)
        elif "DNS" in tool_name or "dns" in tool_name.lower():
            nodes, edges = cls._extract_dns(result, target_id, nodes, edges)
        elif "Subdomain" in tool_name or "subdomain" in tool_name.lower():
            nodes, edges = cls._extract_subdomains(result, target_id, nodes, edges)
        elif "Port Scan" in tool_name or "port" in tool_name.lower():
            nodes, edges = cls._extract_ports(result, target_id, nodes, edges)
        elif "Geolocation" in tool_name or "geo" in tool_name.lower():
            nodes, edges = cls._extract_geolocation(result, target_id, nodes, edges)
        elif "WHOIS" in tool_name or "whois" in tool_name.lower():
            nodes, edges = cls._extract_whois(result, target_id, nodes, edges)
        elif "Traceroute" in tool_name or "trace" in tool_name.lower():
            nodes, edges = cls._extract_traceroute(result, target_id, nodes, edges)
        elif "ASN" in tool_name or "asn" in tool_name.lower():
            nodes, edges = cls._extract_asn(result, target_id, nodes, edges)
        elif "Link" in tool_name or "link" in tool_name.lower():
            nodes, edges = cls._extract_links(result, target_id, nodes, edges)
        elif "Social" in tool_name or "social" in tool_name.lower():
            nodes, edges = cls._extract_social(result, target_id, nodes, edges)
        elif "Analytics" in tool_name or "analytics" in tool_name.lower():
            nodes, edges = cls._extract_analytics(result, target_id, nodes, edges)
        elif "Banner" in tool_name or "banner" in tool_name.lower():
            nodes, edges = cls._extract_banners(result, target_id, nodes, edges)
        elif "Reverse" in tool_name or "reverse" in tool_name.lower():
            nodes, edges = cls._extract_reverse(result, target_id, nodes, edges)
        elif "Shared" in tool_name or "shared" in tool_name.lower():
            nodes, edges = cls._extract_shared(result, target_id, nodes, edges)
        elif "Ping" in tool_name or "ping" in tool_name.lower():
            nodes, edges = cls._extract_ping(result, target_id, nodes, edges)
        elif "Subnet" in tool_name or "subnet" in tool_name.lower():
            nodes, edges = cls._extract_subnet(result, target_id, nodes, edges)
        elif "Nmap" in tool_name or "nmap" in tool_name.lower():
            nodes, edges = cls._extract_nmap(result, target_id, nodes, edges)
        elif "RustScan" in tool_name or "rustscan" in tool_name.lower():
            nodes, edges = cls._extract_rustscan(result, target_id, nodes, edges)
        elif "HTTP" in tool_name or "http" in tool_name.lower():
            nodes, edges = cls._extract_http(result, target_id, nodes, edges)
        elif "IP" in tool_name or "ip" in tool_name.lower():
            nodes, edges = cls._extract_ip(result, target_id, nodes, edges)
        else:
            # Generic fallback - just add a result node
            nodes.append({
                "id": cls._make_id(f"{tool_name}_{target}"),
                "label": f"{tool_name} Result",
                "type": "default",
                "tooltip": f"Result from {tool_name}",
            })
            edges.append({
                "src": target_id,
                "dst": cls._make_id(f"{tool_name}_{target}"),
                "label": tool_name,
            })

        return nodes, edges

    @classmethod
    def _extract_dns(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract DNS records into graph nodes and edges."""
        records = result.get("records", {})

        # A records (IP addresses)
        for ip in records.get("A", []):
            ip_id = cls._make_id(f"ip_{ip}")
            nodes.append({
                "id": ip_id,
                "label": ip,
                "type": "ip",
                "tooltip": f"IP Address: {ip}",
            })
            edges.append({
                "src": target_id,
                "dst": ip_id,
                "label": "A",
            })

        # AAAA records (IPv6)
        for ip in records.get("AAAA", []):
            ip_id = cls._make_id(f"ip6_{ip}")
            nodes.append({
                "id": ip_id,
                "label": ip,
                "type": "ip",
                "tooltip": f"IPv6 Address: {ip}",
            })
            edges.append({
                "src": target_id,
                "dst": ip_id,
                "label": "AAAA",
            })

        # MX records (Mail servers)
        for mx in records.get("MX", []):
            mx_clean = mx.rstrip(".")
            mx_id = cls._make_id(f"mx_{mx_clean}")
            nodes.append({
                "id": mx_id,
                "label": mx_clean,
                "type": "mx",
                "tooltip": f"Mail Server: {mx_clean}",
            })
            edges.append({
                "src": target_id,
                "dst": mx_id,
                "label": "MX",
            })

        # NS records (Name servers)
        for ns in records.get("NS", []):
            ns_clean = ns.rstrip(".")
            ns_id = cls._make_id(f"ns_{ns_clean}")
            nodes.append({
                "id": ns_id,
                "label": ns_clean,
                "type": "ns",
                "tooltip": f"Name Server: {ns_clean}",
            })
            edges.append({
                "src": target_id,
                "dst": ns_id,
                "label": "NS",
            })

        # TXT records
        for txt in records.get("TXT", []):
            txt_str = str(txt) if txt else ""
            txt_id = cls._make_id(f"txt_{txt_str[:30]}")
            nodes.append({
                "id": txt_id,
                "label": txt_str[:50] + "..." if len(txt_str) > 50 else txt_str,
                "type": "txt",
                "tooltip": f"TXT Record: {txt_str}",
            })
            edges.append({
                "src": target_id,
                "dst": txt_id,
                "label": "TXT",
            })

        # CNAME records
        for cname in records.get("CNAME", []):
            cname_clean = cname.rstrip(".")
            cname_id = cls._make_id(f"cname_{cname_clean}")
            nodes.append({
                "id": cname_id,
                "label": cname_clean,
                "type": "cname",
                "tooltip": f"CNAME: {cname_clean}",
            })
            edges.append({
                "src": target_id,
                "dst": cname_id,
                "label": "CNAME",
            })

        return nodes, edges

    @classmethod
    def _extract_subdomains(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract subdomain discovery results."""
        subdomains = result.get("subdomains", [])

        for sub in subdomains:
            # Handle both dict and string subdomain formats
            if isinstance(sub, str):
                subdomain = sub
                ips = []
            elif isinstance(sub, dict):
                subdomain = sub.get("subdomain", "")
                ips = sub.get("ips", [])
            else:
                continue  # Skip invalid entries

            sub_id = cls._make_id(f"sub_{subdomain}")
            nodes.append({
                "id": sub_id,
                "label": subdomain,
                "type": "subdomain",
                "tooltip": f"Subdomain: {subdomain}",
            })
            edges.append({
                "src": target_id,
                "dst": sub_id,
                "label": "subdomain",
            })

            # Link to IPs
            for ip in ips:
                ip_id = cls._make_id(f"ip_{ip}")
                nodes.append({
                    "id": ip_id,
                    "label": ip,
                    "type": "ip",
                    "tooltip": f"IP: {ip}",
                })
                edges.append({
                    "src": sub_id,
                    "dst": ip_id,
                    "label": "resolves to",
                })

        return nodes, edges

    @classmethod
    def _extract_ports(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract port scan results."""
        open_ports = result.get("open_ports", [])

        for port_info in open_ports:
            # Handle both dict and integer port formats
            if isinstance(port_info, int):
                port = port_info
                service = "unknown"
                state = "open"
                banner = ""
            elif isinstance(port_info, dict):
                port = port_info.get("port", 0)
                service = port_info.get("service", "unknown")
                state = port_info.get("state", "unknown")
                banner = port_info.get("banner", "")
            else:
                continue  # Skip invalid entries

            port_id = cls._make_id(f"port_{port}")
            port_label = f"{port}/{service}"
            nodes.append({
                "id": port_id,
                "label": port_label,
                "type": "port",
                "tooltip": f"Port {port} ({service}) - {state}",
            })
            edges.append({
                "src": target_id,
                "dst": port_id,
                "label": "open",
            })

            # Add service node if banner exists
            if banner:
                service_id = cls._make_id(f"service_{port}_{service}")
                nodes.append({
                    "id": service_id,
                    "label": banner,
                    "type": "service",
                    "tooltip": f"Service: {banner}",
                })
                edges.append({
                    "src": port_id,
                    "dst": service_id,
                    "label": "runs",
                })

        return nodes, edges

    @classmethod
    def _extract_geolocation(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract geolocation data."""
        country = result.get("country", "")
        city = result.get("city", "")
        org = result.get("org", "")
        asn = result.get("asn", "")
        lat = result.get("lat")
        lon = result.get("lon")

        if country or city:
            location = f"{city}, {country}" if city and country else city or country
            loc_id = cls._make_id(f"geo_{location}")
            nodes.append({
                "id": loc_id,
                "label": location,
                "type": "geo",
                "tooltip": f"Location: {location}",
            })
            edges.append({
                "src": target_id,
                "dst": loc_id,
                "label": "located in",
            })

        if org or asn:
            org_id = cls._make_id(f"org_{org or asn}")
            nodes.append({
                "id": org_id,
                "label": org or asn,
                "type": "asn",
                "tooltip": f"Organization: {org or asn}",
            })
            edges.append({
                "src": target_id,
                "dst": org_id,
                "label": "owned by",
            })

        return nodes, edges

    @classmethod
    def _extract_whois(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract WHOIS data."""
        registrar = result.get("registrar", "")
        registrant = result.get("registrant", "")
        name_servers = result.get("name_servers", [])
        creation_date = result.get("creation_date", "")

        if registrar:
            reg_id = cls._make_id(f"reg_{registrar}")
            nodes.append({
                "id": reg_id,
                "label": registrar,
                "type": "whois",
                "tooltip": f"Registrar: {registrar}",
            })
            edges.append({
                "src": target_id,
                "dst": reg_id,
                "label": "registered via",
            })

        if registrant:
            reg_id = cls._make_id(f"registrant_{registrant}")
            nodes.append({
                "id": reg_id,
                "label": registrant,
                "type": "whois",
                "tooltip": f"Registrant: {registrant}",
            })
            edges.append({
                "src": target_id,
                "dst": reg_id,
                "label": "owned by",
            })

        for ns in name_servers:
            ns_clean = ns.rstrip(".") if isinstance(ns, str) else str(ns)
            ns_id = cls._make_id(f"whois_ns_{ns_clean}")
            nodes.append({
                "id": ns_id,
                "label": ns_clean,
                "type": "ns",
                "tooltip": f"WHOIS NS: {ns_clean}",
            })
            edges.append({
                "src": target_id,
                "dst": ns_id,
                "label": "uses NS",
            })

        return nodes, edges

    @classmethod
    def _extract_traceroute(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract traceroute hops with path visualization."""
        import re
        
        hops = result.get("hops", [])
        
        # If no hops field, try to parse from raw output
        if not hops and result.get("output"):
            output = result.get("output", "")
            # Parse traceroute output format: "1  192.168.1.1  1.234 ms"
            hop_pattern = re.compile(r'^\s*(\d+)\s+(.+?)\s+(\d+\.?\d*)\s*ms', re.MULTILINE)
            
            prev_id = None
            prev_ip = None
            for match in hop_pattern.finditer(output):
                hop_num = int(match.group(1))
                hop_info = match.group(2)
                hop_time = match.group(3)
                
                # Extract IP or hostname
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', hop_info)
                hostname_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', hop_info)
                
                ip = ip_match.group(1) if ip_match else (hostname_match.group(1) if hostname_match else hop_info.strip())
                
                hop_id = cls._make_id(f"hop_{hop_num}_{ip}")
                nodes.append({
                    "id": hop_id,
                    "label": ip,
                    "type": "hop",
                    "tooltip": f"Hop {hop_num}: {ip} ({hop_time}ms)",
                    "hop_number": hop_num,
                    "response_time": hop_time,
                })
                
                # Connect to previous hop or target
                if prev_id:
                    edges.append({
                        "src": prev_id,
                        "dst": hop_id,
                        "label": f"hop {hop_num}",
                    })
                else:
                    edges.append({
                        "src": target_id,
                        "dst": hop_id,
                        "label": f"hop {hop_num}",
                    })
                
                prev_id = hop_id
                prev_ip = ip
        else:
            # Use hops field if available (legacy format)
            prev_id = None
            for hop in hops:
                # Handle both dict and string IP formats
                if isinstance(hop, str):
                    ttl = 0
                    ip = hop
                elif isinstance(hop, dict):
                    ttl = hop.get("ttl", 0)
                    ip = hop.get("ip", "")
                else:
                    continue  # Skip invalid entries

                hop_id = cls._make_id(f"hop_{ttl}_{ip}")
                nodes.append({
                    "id": hop_id,
                    "label": ip,
                    "type": "hop",
                    "tooltip": f"Hop {ttl}: {ip}",
                    "hop_number": ttl,
                })

                if prev_id:
                    edges.append({
                        "src": prev_id,
                        "dst": hop_id,
                        "label": f"hop {ttl}",
                    })
                else:
                    edges.append({
                        "src": target_id,
                        "dst": hop_id,
                        "label": f"hop {ttl}",
                    })

                prev_id = hop_id

        return nodes, edges

    @classmethod
    def _extract_asn(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract ASN information."""
        asn = result.get("asn", "")
        cidr = result.get("cidr", "")
        country = result.get("country", "")

        if asn:
            asn_id = cls._make_id(f"asn_{asn}")
            nodes.append({
                "id": asn_id,
                "label": str(asn),
                "type": "asn",
                "tooltip": f"ASN: {asn}",
            })
            edges.append({
                "src": target_id,
                "dst": asn_id,
                "label": "belongs to",
            })

        if cidr:
            cidr_id = cls._make_id(f"cidr_{cidr}")
            nodes.append({
                "id": cidr_id,
                "label": cidr,
                "type": "ip",
                "tooltip": f"CIDR: {cidr}",
            })
            edges.append({
                "src": target_id,
                "dst": cidr_id,
                "label": "in range",
            })

        return nodes, edges

    @classmethod
    def _extract_links(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract web links."""
        links = result.get("links", [])

        for link in links:
            url = link if isinstance(link, str) else link.get("url", "")
            link_id = cls._make_id(f"url_{url}")
            nodes.append({
                "id": link_id,
                "label": url[:60] + "..." if len(url) > 60 else url,
                "type": "url",
                "tooltip": f"URL: {url}",
            })
            edges.append({
                "src": target_id,
                "dst": link_id,
                "label": "links to",
            })

        return nodes, edges

    @classmethod
    def _extract_social(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract social media profiles."""
        # Handle web_tools.py format: social_profiles is a dict {platform: [urls]}
        social_profiles = result.get("social_profiles", {})
        
        if isinstance(social_profiles, dict):
            # Format from web_tools.py: {"Facebook": ["https://facebook.com/..."], ...}
            for platform, urls in social_profiles.items():
                if isinstance(urls, list):
                    for url in urls:
                        profile_id = cls._make_id(f"social_{platform}_{url}")
                        label = f"{platform}: {url.split('/')[-1] if '/' in url else url}"
                        nodes.append({
                            "id": profile_id,
                            "label": label,
                            "type": "social",
                            "tooltip": f"Social: {platform} - {url}",
                        })
                        edges.append({
                            "src": target_id,
                            "dst": profile_id,
                            "label": f"on {platform}",
                        })
        elif isinstance(social_profiles, list):
            # Legacy format: list of profile dicts
            for profile in social_profiles:
                platform = profile.get("platform", "")
                url = profile.get("url", "")
                username = profile.get("username", "")

                profile_id = cls._make_id(f"social_{platform}_{username or url}")
                label = f"{platform}: {username or url}"
                nodes.append({
                    "id": profile_id,
                    "label": label,
                    "type": "social",
                    "tooltip": f"Social: {label}",
                })
                edges.append({
                    "src": target_id,
                    "dst": profile_id,
                    "label": "has profile",
                })

        return nodes, edges

    @classmethod
    def _extract_analytics(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract analytics/tracking services."""
        trackers = result.get("trackers", [])

        for tracker in trackers:
            name = tracker if isinstance(tracker, str) else tracker.get("name", "")
            tracker_id = cls._make_id(f"tracker_{name}")
            nodes.append({
                "id": tracker_id,
                "label": name,
                "type": "tracker",
                "tooltip": f"Tracker: {name}",
            })
            edges.append({
                "src": target_id,
                "dst": tracker_id,
                "label": "uses",
            })

        return nodes, edges

    @classmethod
    def _extract_banners(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract service banners."""
        banners = result.get("banners", [])

        for banner in banners:
            port = banner.get("port", "")
            text = banner.get("banner", "") or ""
            text_str = str(text)
            banner_id = cls._make_id(f"banner_{port}_{text_str[:30]}")
            nodes.append({
                "id": banner_id,
                "label": text_str[:50],
                "type": "banner",
                "tooltip": f"Banner on port {port}: {text_str}",
            })
            edges.append({
                "src": target_id,
                "dst": banner_id,
                "label": f"port {port}",
            })

        return nodes, edges

    @classmethod
    def _extract_reverse(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract reverse lookup results."""
        domains = result.get("domains", [])

        for domain in domains:
            domain_id = cls._make_id(f"rev_domain_{domain}")
            nodes.append({
                "id": domain_id,
                "label": domain,
                "type": "domain",
                "tooltip": f"Reverse domain: {domain}",
            })
            edges.append({
                "src": target_id,
                "dst": domain_id,
                "label": "resolves to",
            })

        return nodes, edges

    @classmethod
    def _extract_shared(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract shared DNS/hosting information."""
        domains = result.get("shared_domains", [])

        for domain in domains:
            domain_id = cls._make_id(f"shared_{domain}")
            nodes.append({
                "id": domain_id,
                "label": domain,
                "type": "domain",
                "tooltip": f"Shared hosting: {domain}",
            })
            edges.append({
                "src": target_id,
                "dst": domain_id,
                "label": "shares IP",
            })

        return nodes, edges

    @classmethod
    def _extract_ping(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract ping results (simple reachability)."""
        # Just confirm the target is reachable
        nodes.append({
            "id": target_id,
            "label": target_id.split("_")[-1] if "_" in target_id else target_id,
            "type": "target",
            "tooltip": f"Ping target: {target_id}",
        })
        # No additional edges needed - target is already the main node

        return nodes, edges

    @classmethod
    def _extract_subnet(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract subnet/CIDR information."""
        cidr = result.get("cidr", "")
        hosts = result.get("hosts", [])

        if cidr:
            cidr_id = cls._make_id(f"subnet_{cidr}")
            nodes.append({
                "id": cidr_id,
                "label": cidr,
                "type": "ip",
                "tooltip": f"Subnet: {cidr}",
            })
            edges.append({
                "src": target_id,
                "dst": cidr_id,
                "label": "in subnet",
            })

        for host in hosts[:20]:  # Limit to 20 hosts
            host_id = cls._make_id(f"host_{host}")
            nodes.append({
                "id": host_id,
                "label": host,
                "type": "ip",
                "tooltip": f"Host: {host}",
            })
            edges.append({
                "src": cidr_id,
                "dst": host_id,
                "label": "contains",
            })

        return nodes, edges

    @classmethod
    def _extract_nmap(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract Nmap scan results (reuse port extraction)."""
        return cls._extract_ports(result, target_id, nodes, edges)

    @classmethod
    def _extract_rustscan(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract RustScan results (reuse port extraction)."""
        return cls._extract_ports(result, target_id, nodes, edges)

    @classmethod
    def _extract_http(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract HTTP headers and security info."""
        headers = result.get("headers", {})
        security = result.get("security", {})

        # Server header
        server = headers.get("Server", "")
        if server:
            server_id = cls._make_id(f"http_server_{server}")
            nodes.append({
                "id": server_id,
                "label": server,
                "type": "service",
                "tooltip": f"HTTP Server: {server}",
            })
            edges.append({
                "src": target_id,
                "dst": server_id,
                "label": "runs",
            })

        # Security features
        for feature, present in security.items():
            if present:
                feature_id = cls._make_id(f"http_sec_{feature}")
                nodes.append({
                    "id": feature_id,
                    "label": feature,
                    "type": "tracker",
                    "tooltip": f"Security: {feature}",
                })
                edges.append({
                    "src": target_id,
                    "dst": feature_id,
                    "label": "has",
                })

        return nodes, edges

    @classmethod
    def _extract_ip(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract general IP information."""
        # Combine with geolocation extraction
        return cls._extract_geolocation(result, target_id, nodes, edges)

    @classmethod
    def _extract_bulk(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract bulk scan results - processes all targets in the bulk result."""
        targets = result.get("targets", {})
        
        for target, target_result in targets.items():
            if not isinstance(target_result, dict):
                continue
                
            # Create target node
            t_id = cls._make_id(f"bulk_{target}")
            nodes.append({
                "id": t_id,
                "label": target,
                "type": "target",
                "tooltip": f"Bulk scan target: {target}",
            })
            edges.append({
                "src": target_id,
                "dst": t_id,
                "label": "bulk target",
            })
            
            # Extract DNS records
            records = target_result.get("records", {})
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                for val in records.get(rtype, []):
                    val_str = str(val) if val else ""
                    n_id = cls._make_id(f"{rtype.lower()}_{val_str}_{target}")
                    nodes.append({
                        "id": n_id,
                        "label": val_str[:40],
                        "type": rtype.lower(),
                        "tooltip": f"{rtype}: {val_str} ({target})",
                    })
                    edges.append({
                        "src": t_id,
                        "dst": n_id,
                        "label": rtype,
                    })
            
            # Extract ping results
            if target_result.get("reachable") or target_result.get("success"):
                nodes.append({
                    "id": cls._make_id(f"ping_ok_{target}"),
                    "label": f"✓ {target}",
                    "type": "target",
                    "tooltip": f"Ping reachable: {target}",
                })
                edges.append({
                    "src": t_id,
                    "dst": cls._make_id(f"ping_ok_{target}"),
                    "label": "reachable",
                })
            
            # Extract geolocation
            if target_result.get("country") or target_result.get("city"):
                country = target_result.get("country", "")
                city = target_result.get("city", "")
                loc = f"{city}, {country}" if city and country else city or country
                loc_id = cls._make_id(f"geo_{loc}_{target}")
                nodes.append({
                    "id": loc_id,
                    "label": loc[:40],
                    "type": "geo",
                    "tooltip": f"Location: {loc}",
                })
                edges.append({
                    "src": t_id,
                    "dst": loc_id,
                    "label": "located in",
                })
            
            # Extract open ports
            open_ports = target_result.get("open_ports", [])
            for port_info in open_ports:
                if isinstance(port_info, int):
                    port, service = port_info, "unknown"
                elif isinstance(port_info, dict):
                    port = port_info.get("port", 0)
                    service = port_info.get("service", "unknown")
                else:
                    continue
                p_id = cls._make_id(f"port_{port}_{target}")
                nodes.append({
                    "id": p_id,
                    "label": f"{port}/{service}",
                    "type": "port",
                    "tooltip": f"Port {port} ({service}) on {target}",
                })
                edges.append({
                    "src": t_id,
                    "dst": p_id,
                    "label": "open",
                })
            
            # Extract WHOIS data
            registrar = target_result.get("registrar", "")
            if registrar:
                reg_id = cls._make_id(f"reg_{registrar}_{target}")
                nodes.append({
                    "id": reg_id,
                    "label": registrar[:40],
                    "type": "whois",
                    "tooltip": f"Registrar: {registrar} ({target})",
                })
                edges.append({
                    "src": t_id,
                    "dst": reg_id,
                    "label": "registered via",
                })
            
            # Extract HTTP headers
            headers = target_result.get("headers", {})
            server = headers.get("Server", "")
            if server:
                srv_id = cls._make_id(f"http_srv_{server}_{target}")
                nodes.append({
                    "id": srv_id,
                    "label": server[:40],
                    "type": "service",
                    "tooltip": f"HTTP Server: {server} ({target})",
                })
                edges.append({
                    "src": t_id,
                    "dst": srv_id,
                    "label": "runs",
                })
            
            # Extract Shodan CVEs
            cves = target_result.get("cves", [])
            for cve in cves:
                cve_id = cls._make_id(f"cve_{cve}")
                nodes.append({
                    "id": cve_id,
                    "label": cve,
                    "type": "tracker",
                    "tooltip": f"CVE: {cve} ({target})",
                })
                edges.append({
                    "src": t_id,
                    "dst": cve_id,
                    "label": "has CVE",
                })
            
            # Extract Shodan ports
            shodan_ports = target_result.get("ports", [])
            for p in shodan_ports:
                p_id = cls._make_id(f"shodan_port_{p}_{target}")
                nodes.append({
                    "id": p_id,
                    "label": str(p),
                    "type": "port",
                    "tooltip": f"Shodan port: {p} ({target})",
                })
                edges.append({
                    "src": t_id,
                    "dst": p_id,
                    "label": "Shodan",
                })

        return nodes, edges

    @classmethod
    def _extract_shodan(
        cls,
        result: Dict[str, Any],
        target_id: str,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Extract Shodan scan results including CVEs, ports, and services."""
        # Extract ports/services
        ports = result.get("ports", [])
        for port in ports:
            if isinstance(port, int):
                p_id = cls._make_id(f"shodan_p_{port}")
                nodes.append({
                    "id": p_id,
                    "label": str(port),
                    "type": "port",
                    "tooltip": f"Shodan port: {port}",
                })
                edges.append({
                    "src": target_id,
                    "dst": p_id,
                    "label": "Shodan",
                })
        
        # Extract CVEs
        cves = result.get("cves", [])
        for cve in cves:
            cve_id = cls._make_id(f"cve_{cve}")
            nodes.append({
                "id": cve_id,
                "label": cve,
                "type": "tracker",
                "tooltip": f"CVE: {cve}",
            })
            edges.append({
                "src": target_id,
                "dst": cve_id,
                "label": "has CVE",
            })
        
        # Extract location
        city = result.get("city", "")
        country = result.get("country", "")
        if city or country:
            loc = f"{city}, {country}" if city and country else city or country
            loc_id = cls._make_id(f"shodan_geo_{loc}")
            nodes.append({
                "id": loc_id,
                "label": loc[:40],
                "type": "geo",
                "tooltip": f"Shodan location: {loc}",
            })
            edges.append({
                "src": target_id,
                "dst": loc_id,
                "label": "located in",
            })
        
        # Extract organization/ISP
        org = result.get("org", "")
        isp = result.get("isp", "")
        if org or isp:
            org_id = cls._make_id(f"shodan_org_{org or isp}")
            nodes.append({
                "id": org_id,
                "label": (org or isp)[:40],
                "type": "asn",
                "tooltip": f"Shodan org: {org or isp}",
            })
            edges.append({
                "src": target_id,
                "dst": org_id,
                "label": "owned by",
            })
        
        # Extract hostnames
        hostnames = result.get("hostnames", [])
        for hn in hostnames:
            hn_str = str(hn) if hn else ""
            hn_id = cls._make_id(f"shodan_hn_{hn_str}")
            nodes.append({
                "id": hn_id,
                "label": hn_str[:40],
                "type": "domain",
                "tooltip": f"Shodan hostname: {hn_str}",
            })
            edges.append({
                "src": target_id,
                "dst": hn_id,
                "label": "hostname",
            })
        
        # Extract OS
        os_info = result.get("os", "")
        if os_info:
            os_id = cls._make_id(f"shodan_os_{os_info}")
            nodes.append({
                "id": os_id,
                "label": os_info[:40],
                "type": "service",
                "tooltip": f"Shodan OS: {os_info}",
            })
            edges.append({
                "src": target_id,
                "dst": os_id,
                "label": "runs",
            })

        return nodes, edges

    @staticmethod
    def _make_id(text: str) -> str:
        """
        Create a safe node ID from text.

        Args:
            text: Input text to convert to ID

        Returns:
            Sanitized ID string (lowercase, safe characters only)
        """
        import re

        # Lowercase and replace unsafe chars
        safe = text.lower().strip()
        safe = re.sub(r"[^a-z0-9._-]", "_", safe)
        # Collapse multiple underscores
        safe = re.sub(r"_+", "_", safe)
        # Remove leading/trailing underscores
        safe = safe.strip("_")
        return safe or "unknown"
