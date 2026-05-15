"""
Report Generator Module
Handles: Modern HTML report generation with charts and visualizations
"""

import json
import html
import re
from datetime import datetime
from typing import Dict, Any, List, Optional


class HTMLReportGenerator:
    """
    Generate professional HTML reports from OSINT scan results.
    Features:
    - Modern dark theme with glassmorphism effects
    - Interactive charts (Chart.js)
    - Summary statistics with animations
    - Organized sections by tool category
    - IP/port visualization with maps
    - Vulnerability indicators with risk scores
    - Traceroute path visualization
    - Timeline of scans
    """

    # Tool categories for organization
    CATEGORIES = {
        "dns_tools": "🌐 DNS Analysis",
        "network_tools": "🔌 Network Scanning",
        "ip_tools": "📍 IP Intelligence",
        "web_tools": "🌍 Web Analysis",
        "external_tools": "🛠️ External Tools",
    }

    # Category color mapping
    CATEGORY_COLORS = {
        "dns_tools": "#79c0ff",
        "network_tools": "#3fb950",
        "ip_tools": "#d2a8ff",
        "web_tools": "#ff7b72",
        "external_tools": "#ffa657",
    }

    # Icon mapping for tools
    TOOL_ICONS = {
        "dns": "🔍",
        "reverse": "🔄",
        "subdomain": "🔗",
        "shared": "🏢",
        "ping": "📡",
        "traceroute": "🗺️",
        "tcp": "🚪",
        "udp": "📦",
        "subnet": "🌐",
        "banner": "🚩",
        "whois": "📋",
        "asn": "🏷️",
        "geolocation": "📍",
        "ip": "💻",
        "reverse_ip": "🔙",
        "http": "🌐",
        "headers": "📑",
        "link": "🔗",
        "analytics": "📊",
        "social": "📱",
        "nmap": "🔬",
        "rustscan": "⚡",
        "masscan": "🚀",
        "fping": "📶",
        "netdiscover": "🔎",
        "upnp": "🔌",
    }

    @classmethod
    def generate_report(cls, results: List[Dict], title: str = "Recon 9 Report") -> str:
        """
        Generate a complete HTML report from scan results.

        Args:
            results: List of scan results with keys: tool, target, result, timestamp
            title: Report title

        Returns:
            Complete HTML document string
        """
        report_data = cls._process_results(results)

        # Build graph data
        graph_nodes, graph_edges = cls._build_graph_data(results)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(title)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        {cls._get_css()}
        {cls._get_graph_css()}
    </style>
</head>
<body>
    <div class="container">
        {cls._generate_header(report_data)}
        {cls._generate_summary(report_data)}
        {cls._generate_graph_section(graph_nodes, graph_edges)}
        {cls._generate_charts_section(report_data)}
        {cls._generate_timeline(report_data)}
        {cls._generate_vulnerabilities(report_data)}
        {cls._generate_network_map(report_data)}
        {cls._generate_traceroute_visualization(report_data)}
        {cls._generate_geolocation_section(report_data)}
        {cls._generate_detailed_results(report_data)}
        {cls._generate_footer()}
    </div>
    <script>
        {cls._get_javascript(report_data)}
        {cls._get_graph_javascript(graph_nodes, graph_edges)}
    </script>
</body>
</html>"""

        return html_doc

    @classmethod
    def generate_graph_only(cls, results: List[Dict], title: str = "Recon 9 - Interactive Graph") -> str:
        """
        Generate standalone interactive graph HTML (no report sections).

        Args:
            results: List of scan results
            title: Page title

        Returns:
            Complete HTML document with graph only
        """
        graph_nodes, graph_edges = cls._build_graph_data(results)

        # Build JSON data for module loader
        import json
        results_json = json.dumps(results)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(title)}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <style>
        {cls._get_graph_css()}
        body {{ margin: 0; padding: 0; overflow: hidden; }}
        body.graph-only-mode .graph-section {{ margin: 0; border-radius: 0; border: none; height: 100vh; }}
        body.graph-only-mode .graph-body {{ height: calc(100vh - 78px); }}
    </style>
</head>
<body class="graph-only-mode">
    <div class="container" style="max-width:100vw;height:100vh;">
    {cls._generate_graph_section(graph_nodes, graph_edges)}
    </div>
    <script>
        const ALL_SCAN_RESULTS = {results_json};
        {cls._get_graph_javascript(graph_nodes, graph_edges)}
    </script>
</body>
</html>"""

        return html_doc

    @classmethod
    def _process_results(cls, results: List[Dict]) -> Dict[str, Any]:
        """Process raw results into structured report data."""
        processed = {
            "total_scans": len(results),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "categories": {},
            "targets": set(),
            "ips_found": set(),
            "ports_found": set(),
            "open_ports": [],
            "closed_ports": [],
            "vulnerabilities": [],
            "errors": 0,
            "success": 0,
            "traceroutes": [],
            "dns_records": [],
            "geolocations": [],
            "web_data": [],
        }
        
        for entry in results:
            tool = entry.get("tool", "Unknown")
            target = entry.get("target", "")
            result = entry.get("result", {})
            timestamp = entry.get("timestamp", "")
            
            if target:
                processed["targets"].add(target)
            
            # Categorize
            category = cls._get_tool_category(tool)
            if category not in processed["categories"]:
                processed["categories"][category] = []
            processed["categories"][category].append(entry)
            
            # Extract data based on tool type
            if isinstance(result, dict):
                if "error" in result:
                    processed["errors"] += 1
                else:
                    processed["success"] += 1
                    
                # Extract IP addresses
                for key in ["ip", "query", "host", "target"]:
                    if key in result and result[key]:
                        val = result[key]
                        if cls._is_ip_address(str(val)):
                            processed["ips_found"].add(val)
                
                # Extract ports
                if "open_ports" in result:
                    ports = result["open_ports"]
                    if isinstance(ports, list):
                        for port in ports:
                            if isinstance(port, dict):
                                port_num = port.get("port")
                                service = port.get("service", "unknown")
                                state = port.get("state", "open")
                            else:
                                port_num = port
                                service = "unknown"
                                state = "open"
                            
                            if port_num:
                                processed["ports_found"].add(port_num)
                                port_info = {
                                    "port": port_num,
                                    "service": service,
                                    "target": target,
                                    "state": state
                                }
                                if state == "open":
                                    processed["open_ports"].append(port_info)
                                else:
                                    processed["closed_ports"].append(port_info)
                
                # Extract traceroute data
                if "hops" in result or "path" in result or "output" in result:
                    processed["traceroutes"].append({
                        "target": target,
                        "result": result,
                        "timestamp": timestamp
                    })
                
                # Extract DNS records
                if "records" in result or "a_records" in result or "mx_records" in result:
                    processed["dns_records"].append({
                        "target": target,
                        "result": result,
                        "timestamp": timestamp
                    })
                
                # Extract geolocation data
                if any(k in result for k in ["lat", "latitude", "country", "city", "regionName"]):
                    processed["geolocations"].append({
                        "target": target,
                        "ip": result.get("ip", result.get("query", target)),
                        "country": result.get("country", result.get("countryName", "Unknown")),
                        "city": result.get("city", result.get("regionName", "Unknown")),
                        "lat": result.get("lat", result.get("latitude")),
                        "lon": result.get("lon", result.get("longitude")),
                        "result": result,
                        "timestamp": timestamp
                    })
                
                # Extract web data
                if any(k in result for k in ["status_code", "headers", "links", "analytics", "server"]):
                    processed["web_data"].append({
                        "target": target,
                        "result": result,
                        "timestamp": timestamp
                    })
                
                # Check for potential vulnerabilities
                vulns = cls._check_vulnerabilities(result, target, tool)
                processed["vulnerabilities"].extend(vulns)
                
                # Handle bulk scan results (nested targets)
                if "targets" in result and isinstance(result["targets"], dict):
                    # This is a bulk scan result
                    for sub_target, sub_result in result["targets"].items():
                        if isinstance(sub_result, dict):
                            # Extract IPs from bulk results
                            for key in ["ip", "query", "host", "target"]:
                                if key in sub_result and sub_result[key]:
                                    val = sub_result[key]
                                    if cls._is_ip_address(str(val)):
                                        processed["ips_found"].add(val)
                            
                            # Extract ports from bulk nmap
                            if "open_ports" in sub_result:
                                ports = sub_result["open_ports"]
                                if isinstance(ports, list):
                                    for port in ports:
                                        if isinstance(port, dict):
                                            port_num = port.get("port")
                                            service = port.get("service", "unknown")
                                        else:
                                            port_num = port
                                            service = "unknown"
                                        if port_num:
                                            processed["ports_found"].add(port_num)
                                            processed["open_ports"].append({
                                                "port": port_num,
                                                "service": service,
                                                "target": sub_target,
                                                "state": "open"
                                            })
                            
                            # Extract geolocation from bulk results
                            if any(k in sub_result for k in ["lat", "latitude", "country", "city", "regionName"]):
                                processed["geolocations"].append({
                                    "target": sub_target,
                                    "ip": sub_result.get("ip", sub_result.get("query", sub_target)),
                                    "country": sub_result.get("country", sub_result.get("countryName", "Unknown")),
                                    "city": sub_result.get("city", sub_result.get("regionName", "Unknown")),
                                    "lat": sub_result.get("lat", sub_result.get("latitude")),
                                    "lon": sub_result.get("lon", sub_result.get("longitude")),
                                    "result": sub_result,
                                })
                    
                    # Handle aggregated geolocations from bulk_nmap_scan
                    if "geolocations" in result and isinstance(result["geolocations"], dict):
                        for ip, geo_result in result["geolocations"].items():
                            if isinstance(geo_result, dict) and "country" in geo_result:
                                processed["geolocations"].append({
                                    "target": ip,
                                    "ip": ip,
                                    "country": geo_result.get("country", geo_result.get("countryName", "Unknown")),
                                    "city": geo_result.get("city", geo_result.get("regionName", "Unknown")),
                                    "lat": geo_result.get("lat", geo_result.get("latitude")),
                                    "lon": geo_result.get("lon", geo_result.get("longitude")),
                                    "isp": geo_result.get("isp", geo_result.get("org", "")),
                                    "result": geo_result,
                                })

        processed["targets"] = list(processed["targets"])
        processed["ips_found"] = list(processed["ips_found"])
        # Convert ports to integers for proper sorting (handles mixed int/str)
        port_set = set()
        for p in processed["ports_found"]:
            try:
                port_set.add(int(p))
            except (ValueError, TypeError):
                pass
        processed["ports_found"] = sorted(list(port_set))

        return processed

    @classmethod
    def _get_tool_category(cls, tool_name: str) -> str:
        """Determine category from tool name."""
        tool_lower = tool_name.lower()
        if any(x in tool_lower for x in ["dns", "subdomain", "reverse dns", "shared dns"]):
            return "dns_tools"
        elif any(x in tool_lower for x in ["ping", "traceroute", "scan", "port", "subnet", "banner", "fping", "netdiscover"]):
            return "network_tools"
        elif any(x in tool_lower for x in ["whois", "geolocate", "ip", "asn", "reverse ip"]):
            return "ip_tools"
        elif any(x in tool_lower for x in ["http", "web", "link", "analytics", "social", "header"]):
            return "web_tools"
        elif any(x in tool_lower for x in ["nmap", "rustscan", "masscan", "upnp"]):
            return "external_tools"
        return "network_tools"

    @classmethod
    def _is_ip_address(cls, value: str) -> bool:
        """Check if string looks like an IP address."""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))

    @classmethod
    def _check_vulnerabilities(cls, result: Dict, target: str, tool: str = "") -> List[Dict]:
        """Check for potential security issues."""
        vulns = []
        
        # Check for open dangerous ports
        dangerous_ports = {
            21: ("FTP", "high", "Unencrypted file transfer protocol"),
            23: ("Telnet", "critical", "Unencrypted remote access - credentials sent in plaintext"),
            25: ("SMTP", "medium", "Mail server - potential relay or spam source"),
            53: ("DNS", "low", "DNS server - check for zone transfer vulnerabilities"),
            110: ("POP3", "medium", "Unencrypted email retrieval"),
            135: ("RPC", "high", "Windows RPC - common attack vector"),
            139: ("NetBIOS", "high", "Windows file sharing - information disclosure"),
            143: ("IMAP", "medium", "Unencrypted email access"),
            445: ("SMB", "critical", "Windows file sharing - ransomware vector"),
            1433: ("MSSQL", "high", "Microsoft SQL Server - database exposure"),
            1521: ("Oracle", "high", "Oracle Database - database exposure"),
            3306: ("MySQL", "high", "MySQL Database - database exposure"),
            3389: ("RDP", "critical", "Remote Desktop - brute force target"),
            5432: ("PostgreSQL", "high", "PostgreSQL Database - database exposure"),
            5900: ("VNC", "high", "VNC Remote Desktop - often weak authentication"),
            6379: ("Redis", "critical", "Redis - often exposed without authentication"),
            27017: ("MongoDB", "critical", "MongoDB - often exposed without authentication"),
        }
        
        open_ports = result.get("open_ports", [])
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port_num = port_info.get("port")
                service = port_info.get("service", "unknown")
            else:
                port_num = port_info
                service = "unknown"
            
            if port_num in dangerous_ports:
                svc_name, severity, desc = dangerous_ports[port_num]
                vulns.append({
                    "severity": severity,
                    "type": "Open Port",
                    "port": port_num,
                    "service": service or svc_name,
                    "description": f"Port {port_num} ({service or svc_name}) is open - {desc}",
                    "target": target,
                    "recommendation": f"Review if {service or svc_name} service needs to be exposed"
                })
        
        # Check for missing security headers
        if "security_headers" in result or "headers" in result:
            headers = result.get("security_headers", result.get("headers", {}))
            missing = []
            critical_headers = {
                "Content-Security-Policy": "XSS and injection protection",
                "X-Frame-Options": "Clickjacking protection",
                "Strict-Transport-Security": "Forces HTTPS connections",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
            }
            for header, reason in critical_headers.items():
                if header not in headers or not headers.get(header):
                    missing.append((header, reason))
            
            if missing:
                vulns.append({
                    "severity": "medium",
                    "type": "Missing Security Headers",
                    "description": f"Missing: {', '.join(h[0] for h in missing)}",
                    "target": target,
                    "details": missing,
                    "recommendation": "Add missing security headers to reduce attack surface"
                })
        
        # Check for server information disclosure
        if "server" in result and result["server"]:
            server = result["server"]
            if any(v in server.lower() for v in ["apache", "nginx", "iis", "tomcat"]):
                vulns.append({
                    "severity": "low",
                    "type": "Information Disclosure",
                    "description": f"Server version disclosed: {server}",
                    "target": target,
                    "recommendation": "Configure server to hide version information"
                })
        
        # Check for technology disclosure
        if "technologies" in result and result["technologies"]:
            techs = result["technologies"]
            if isinstance(techs, list) and len(techs) > 0:
                vulns.append({
                    "severity": "info",
                    "type": "Technology Stack Detected",
                    "description": f"Technologies: {', '.join(str(t) for t in techs[:5])}",
                    "target": target,
                    "recommendation": "Review detected technologies for known vulnerabilities"
                })
        
        # Check for analytics/tracking
        if "analytics" in result and result["analytics"]:
            analytics = result["analytics"]
            if isinstance(analytics, list) and len(analytics) > 0:
                vulns.append({
                    "severity": "info",
                    "type": "Analytics/Tracking Detected",
                    "description": f"Tracking: {', '.join(str(a) for a in analytics)}",
                    "target": target,
                    "recommendation": "Review privacy implications of tracking scripts"
                })
        
        return vulns

    @classmethod
    def _get_css(cls) -> str:
        """Return embedded CSS styles."""
        return """
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-tertiary: #1f2937;
            --bg-card: rgba(31, 41, 55, 0.6);
            --border: #374151;
            --border-light: #4b5563;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-blue: #3b82f6;
            --accent-blue-glow: rgba(59, 130, 246, 0.3);
            --accent-green: #10b981;
            --accent-green-glow: rgba(16, 185, 129, 0.3);
            --accent-red: #ef4444;
            --accent-red-glow: rgba(239, 68, 68, 0.3);
            --accent-yellow: #f59e0b;
            --accent-yellow-glow: rgba(245, 158, 11, 0.3);
            --accent-purple: #8b5cf6;
            --accent-purple-glow: rgba(139, 92, 246, 0.3);
            --accent-orange: #f97316;
            --accent-pink: #ec4899;
            --accent-cyan: #06b6d4;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.7;
            padding: 20px;
            min-height: 100vh;
            background-image: 
                radial-gradient(ellipse at top, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
                radial-gradient(ellipse at bottom, rgba(139, 92, 246, 0.05) 0%, transparent 50%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 100%;
            margin: 0;
            padding: 0;
        }

        body.graph-only-mode {
            padding: 0;
            overflow: hidden;
        }

        body.graph-only-mode .container {
            max-width: 100vw;
            height: 100vh;
        }

        body.graph-only-mode .graph-section {
            border-radius: 0;
            margin-bottom: 0;
            border: none;
            height: 100vh;
        }

        body.graph-only-mode .graph-body {
            height: calc(100vh - 78px);
        }
        
        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, rgba(31, 41, 55, 0.8) 0%, rgba(17, 24, 39, 0.9) 100%);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            animation: fadeIn 0.6s ease-out;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple), var(--accent-pink));
        }
        
        .header h1 {
            color: var(--text-primary);
            font-size: 2.8em;
            font-weight: 700;
            margin-bottom: 15px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 40px var(--accent-blue-glow);
            letter-spacing: -0.5px;
        }
        
        .header .meta {
            color: var(--text-secondary);
            font-size: 1em;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        .header .meta span {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border-radius: 20px;
            border: 1px solid var(--border);
        }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s ease;
            animation: fadeIn 0.6s ease-out;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--accent-blue), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
            border-color: var(--border-light);
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-card .icon {
            font-size: 2.5em;
            margin-bottom: 10px;
            display: block;
        }
        
        .stat-card .value {
            font-size: 2.8em;
            font-weight: 700;
            color: var(--accent-blue);
            line-height: 1;
            margin-bottom: 5px;
        }
        
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-card.success .value { color: var(--accent-green); }
        .stat-card.success .icon { filter: drop-shadow(0 0 10px var(--accent-green-glow)); }
        
        .stat-card.error .value { color: var(--accent-red); }
        .stat-card.error .icon { filter: drop-shadow(0 0 10px var(--accent-red-glow)); }
        
        .stat-card.warning .value { color: var(--accent-yellow); }
        .stat-card.warning .icon { filter: drop-shadow(0 0 10px var(--accent-yellow-glow)); }
        
        .stat-card.info .value { color: var(--accent-purple); }
        .stat-card.info .icon { filter: drop-shadow(0 0 10px var(--accent-purple-glow)); }
        
        /* Charts Section */
        .charts-section {
            margin-bottom: 30px;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 20px;
        }
        
        .chart-container {
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            animation: fadeIn 0.6s ease-out;
        }
        
        .chart-container h3 {
            color: var(--text-primary);
            margin-bottom: 20px;
            font-size: 1.2em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .chart-container h3::before {
            content: '';
            width: 4px;
            height: 20px;
            background: linear-gradient(180deg, var(--accent-blue), var(--accent-purple));
            border-radius: 2px;
        }
        
        .chart-wrapper {
            position: relative;
            height: 320px;
        }
        
        /* Sections */
        .section {
            background: var(--bg-card);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 25px;
            overflow: hidden;
            animation: fadeIn 0.6s ease-out;
        }
        
        .section-header {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(31, 41, 55, 0.5) 100%);
            padding: 20px 25px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-header h2 {
            font-size: 1.4em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .section-header .count {
            background: var(--accent-blue);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .section-content {
            padding: 25px;
        }
        
        /* Vulnerability Cards */
        .vuln-list {
            list-style: none;
        }
        
        .vuln-item {
            background: var(--bg-tertiary);
            border-left: 4px solid var(--accent-yellow);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 12px 12px 0;
            transition: all 0.3s ease;
            animation: slideIn 0.4s ease-out;
        }
        
        .vuln-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
        }
        
        .vuln-item.severity-critical {
            border-left-color: #dc2626;
            background: linear-gradient(90deg, rgba(220, 38, 38, 0.1), var(--bg-tertiary));
        }
        
        .vuln-item.severity-high {
            border-left-color: var(--accent-red);
            background: linear-gradient(90deg, rgba(239, 68, 68, 0.08), var(--bg-tertiary));
        }
        
        .vuln-item.severity-medium {
            border-left-color: var(--accent-yellow);
        }
        
        .vuln-item.severity-low {
            border-left-color: var(--accent-green);
        }
        
        .vuln-item.severity-info {
            border-left-color: var(--accent-blue);
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .vuln-type {
            font-weight: 600;
            color: var(--text-primary);
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .vuln-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        
        .vuln-severity.critical {
            background: #dc2626;
            color: white;
            box-shadow: 0 0 15px var(--accent-red-glow);
        }
        
        .vuln-severity.high {
            background: var(--accent-red);
            color: white;
        }
        
        .vuln-severity.medium {
            background: var(--accent-yellow);
            color: var(--bg-primary);
        }
        
        .vuln-severity.low {
            background: var(--accent-green);
            color: white;
        }
        
        .vuln-severity.info {
            background: var(--accent-blue);
            color: white;
        }
        
        .vuln-description {
            color: var(--text-secondary);
            margin-bottom: 10px;
            line-height: 1.6;
        }
        
        .vuln-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9em;
            color: var(--text-muted);
        }
        
        .vuln-meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .vuln-recommendation {
            margin-top: 12px;
            padding: 12px;
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 8px;
            color: var(--accent-blue);
            font-size: 0.9em;
        }
        
        /* Results Table */
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        .results-table th,
        .results-table td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        .results-table th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 0.5px;
        }
        
        .results-table tr {
            transition: background 0.2s;
        }
        
        .results-table tr:hover {
            background: var(--bg-tertiary);
        }
        
        .results-table .tool-name {
            color: var(--accent-purple);
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .results-table .target {
            color: var(--text-primary);
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 0.95em;
        }
        
        .results-table .status {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            display: inline-block;
        }
        
        .status.success {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .status.error {
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        /* IP Tags */
        .ip-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        
        .ip-tag {
            background: linear-gradient(135deg, var(--bg-tertiary), rgba(59, 130, 246, 0.1));
            color: var(--accent-blue);
            padding: 8px 14px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 0.9em;
            border: 1px solid var(--border);
            transition: all 0.2s;
        }
        
        .ip-tag:hover {
            border-color: var(--accent-blue);
            box-shadow: 0 0 15px var(--accent-blue-glow);
            transform: translateY(-2px);
        }
        
        /* Port Tags */
        .port-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-green);
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: 500;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .port-tag.danger {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-red);
            border-color: rgba(239, 68, 68, 0.3);
        }
        
        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 30px;
            margin: 20px 0;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 8px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: linear-gradient(180deg, var(--accent-blue), var(--accent-purple));
            border-radius: 2px;
        }
        
        .timeline-item {
            position: relative;
            padding-bottom: 25px;
            animation: slideIn 0.4s ease-out;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -26px;
            top: 5px;
            width: 12px;
            height: 12px;
            background: var(--accent-blue);
            border-radius: 50%;
            border: 3px solid var(--bg-secondary);
            box-shadow: 0 0 10px var(--accent-blue-glow);
        }
        
        .timeline-item:last-child {
            padding-bottom: 0;
        }
        
        .timeline-time {
            font-size: 0.85em;
            color: var(--text-muted);
            margin-bottom: 5px;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .timeline-content {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }
        
        /* Traceroute Visualization */
        .traceroute-viz {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
            padding: 20px;
            overflow-x: auto;
        }
        
        .hop-node {
            background: linear-gradient(135deg, var(--bg-tertiary), rgba(59, 130, 246, 0.1));
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 12px 18px;
            min-width: 140px;
            text-align: center;
            position: relative;
            transition: all 0.3s;
        }
        
        .hop-node:hover {
            border-color: var(--accent-blue);
            box-shadow: 0 5px 20px var(--accent-blue-glow);
            transform: translateY(-3px);
        }
        
        .hop-number {
            font-size: 0.75em;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        
        .hop-ip {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-blue);
            font-size: 0.95em;
            margin-bottom: 5px;
        }
        
        .hop-time {
            font-size: 0.85em;
            color: var(--text-secondary);
        }
        
        .hop-arrow {
            color: var(--accent-blue);
            font-size: 1.5em;
            opacity: 0.5;
        }
        
        /* Network Map */
        .network-map {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .network-node {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            transition: all 0.3s;
        }
        
        .network-node:hover {
            border-color: var(--accent-blue);
            box-shadow: 0 5px 25px rgba(59, 130, 246, 0.2);
            transform: translateY(-3px);
        }
        
        .network-node-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .network-node-icon {
            font-size: 2em;
        }
        
        .network-node-type {
            font-size: 0.75em;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .network-node-ip {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-blue);
            font-size: 1em;
            margin-bottom: 8px;
            word-break: break-all;
        }
        
        .network-node-details {
            font-size: 0.85em;
            color: var(--text-secondary);
        }
        
        .network-node-details span {
            display: block;
            margin-bottom: 4px;
        }

        /* Scan Detail Cards */
        .scan-detail-card {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .scan-detail-card:hover {
            border-color: var(--border-light);
            box-shadow: 0 5px 25px rgba(0, 0, 0, 0.3);
        }

        .scan-detail-header {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), var(--bg-tertiary));
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .scan-detail-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.05em;
        }

        .scan-detail-icon {
            font-size: 1.3em;
        }

        .scan-detail-target {
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            margin-left: 8px;
        }

        .scan-detail-meta {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .scan-detail-content {
            padding: 20px;
        }

        /* Result Details */
        .result-details {
            font-size: 0.95em;
            line-height: 1.7;
        }

        .detail-section {
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }

        .detail-section:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }

        .detail-subtitle {
            color: var(--accent-blue);
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .detail-row {
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid rgba(55, 65, 81, 0.3);
            gap: 15px;
        }

        .detail-row:last-child {
            border-bottom: none;
        }

        .detail-key {
            color: var(--text-secondary);
            font-weight: 500;
            min-width: 180px;
            font-size: 0.9em;
        }

        .detail-value {
            color: var(--text-primary);
            flex: 1;
            word-break: break-word;
        }

        .detail-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 12px 15px;
            margin-bottom: 15px;
            color: var(--accent-red);
        }

        .detail-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .detail-tag {
            background: var(--bg-secondary);
            color: var(--accent-blue);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            border: 1px solid var(--border);
            font-family: 'JetBrains Mono', monospace;
        }

        .detail-list-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }

        .detail-list-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
        }

        .detail-nested {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
        }

        .detail-raw-output {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 0.85em;
            color: var(--text-secondary);
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }
        
        .footer p {
            margin-bottom: 10px;
        }
        
        .footer-warning {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 20px;
            font-size: 0.9em;
            color: var(--accent-yellow);
            margin-top: 15px;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--border-light);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }
        
        /* Responsive */
        @media (max-width: 1024px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 640px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .header .meta {
                flex-direction: column;
                gap: 10px;
            }
            
            .section-header {
                flex-direction: column;
                gap: 10px;
                text-align: left;
            }
        }
        
        /* Utility */
        .text-gradient {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-blue { background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); }
        .badge-green { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); }
        .badge-red { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); }
        .badge-yellow { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); }
        .badge-purple { background: rgba(139, 92, 246, 0.2); color: var(--accent-purple); }
        """

    @classmethod
    def _generate_header(cls, data: Dict) -> str:
        """Generate report header."""
        return f"""
        <div class="header">
            <h1>🎯 Recon 9 Intelligence Report</h1>
            <div class="meta">
                <span>📅 {data['timestamp']}</span>
                <span>📊 {data['total_scans']} Scans</span>
                <span>🎯 {len(data['targets'])} Targets</span>
                <span>💻 {len(data['ips_found'])} IPs</span>
                <span>🚪 {len(data['ports_found'])} Ports</span>
            </div>
        </div>
        """

    @classmethod
    def _generate_summary(cls, data: Dict) -> str:
        """Generate summary statistics cards."""
        vuln_count = len(data["vulnerabilities"])
        critical_vulns = sum(1 for v in data["vulnerabilities"] if v["severity"] == "critical")
        high_vulns = sum(1 for v in data["vulnerabilities"] if v["severity"] == "high")
        
        return f"""
        <div class="summary-grid">
            <div class="stat-card success">
                <span class="icon">✓</span>
                <div class="value">{data['success']}</div>
                <div class="label">Successful</div>
            </div>
            <div class="stat-card error">
                <span class="icon">✗</span>
                <div class="value">{data['errors']}</div>
                <div class="label">Errors</div>
            </div>
            <div class="stat-card warning">
                <span class="icon">⚠</span>
                <div class="value">{vuln_count}</div>
                <div class="label">Findings</div>
            </div>
            <div class="stat-card {'error' if critical_vulns > 0 else 'info'}">
                <span class="icon">🔴</span>
                <div class="value">{critical_vulns}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card {'warning' if high_vulns > 0 else 'info'}">
                <span class="icon">🟠</span>
                <div class="value">{high_vulns}</div>
                <div class="label">High Risk</div>
            </div>
            <div class="stat-card info">
                <span class="icon">🌐</span>
                <div class="value">{len(data['ips_found'])}</div>
                <div class="label">IPs Found</div>
            </div>
            <div class="stat-card info">
                <span class="icon">🔓</span>
                <div class="value">{len(data['open_ports'])}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card info">
                <span class="icon">📍</span>
                <div class="value">{len(data['geolocations'])}</div>
                <div class="label">Geo Located</div>
            </div>
        </div>
        """

    @classmethod
    def _generate_charts_section(cls, data: Dict) -> str:
        """Generate chart containers."""
        # Generate IP tags HTML
        if data['ips_found']:
            ip_tags_html = ''.join(f'<span class="ip-tag">{html.escape(ip)}</span>' for ip in data['ips_found'])
        else:
            ip_tags_html = '<span style="color: var(--text-muted);">No IPs discovered</span>'
        
        return f"""
        <div class="charts-section">
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Scans by Category</h3>
                    <div class="chart-wrapper">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>
                <div class="chart-container">
                    <h3>Security Findings</h3>
                    <div class="chart-wrapper">
                        <canvas id="vulnChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="charts-grid" style="margin-top: 20px;">
                <div class="chart-container" style="grid-column: 1 / -1;">
                    <h3>Discovered IP Addresses</h3>
                    <div class="ip-tags">
                        {ip_tags_html}
                    </div>
                </div>
            </div>
            
            {cls._generate_open_ports_section(data) if data['open_ports'] else ''}
        </div>
        """

    @classmethod
    def _generate_open_ports_section(cls, data: Dict) -> str:
        """Generate open ports table."""
        dangerous_ports = {21, 23, 25, 110, 135, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
        
        rows = ""
        for port_info in data["open_ports"]:
            port = port_info.get("port", "N/A")
            service = port_info.get("service", "unknown")
            target = port_info.get("target", "N/A")
            is_dangerous = port in dangerous_ports
            danger_class = "danger" if is_dangerous else ""
            danger_icon = "⚠️ " if is_dangerous else ""
            
            rows += f"""
            <tr>
                <td class="target">{html.escape(str(target))}</td>
                <td><span class="port-tag {danger_class}">{danger_icon}{port}</span></td>
                <td>{html.escape(service)}</td>
            </tr>
            """
        
        return f"""
        <div class="section" style="margin-top: 20px;">
            <div class="section-header">
                <h2>🔓 Open Ports Discovered</h2>
                <span class="count">{len(data['open_ports'])} ports</span>
            </div>
            <div class="section-content">
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Port</th>
                            <th>Service</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """

    @classmethod
    def _generate_timeline(cls, data: Dict) -> str:
        """Generate scan timeline."""
        if not data.get("categories"):
            return ""
        
        # Flatten all scans and sort by timestamp
        all_scans = []
        for category, items in data["categories"].items():
            for item in items:
                all_scans.append(item)
        
        all_scans.sort(key=lambda x: x.get("timestamp", ""))
        
        items_html = ""
        for scan in all_scans[:20]:  # Limit to 20 items
            tool = scan.get("tool", "Unknown")
            target = scan.get("target", "N/A")
            timestamp = scan.get("timestamp", "")
            result = scan.get("result", {})
            has_error = "error" in result if isinstance(result, dict) else False
            status = "❌ Error" if has_error else "✓ Success"
            status_class = "error" if has_error else "success"
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime("%H:%M:%S")
            except:
                time_str = timestamp[:19] if timestamp else "N/A"
            
            items_html += f"""
            <div class="timeline-item">
                <div class="timeline-time">{time_str}</div>
                <div class="timeline-content">
                    <strong>{html.escape(tool)}</strong> → {html.escape(str(target))}
                    <span class="badge badge-{'red' if has_error else 'green'}" style="margin-left: 10px;">{status}</span>
                </div>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>⏱️ Scan Timeline</h2>
                <span class="count">{len(all_scans)} scans</span>
            </div>
            <div class="section-content">
                <div class="timeline">
                    {items_html}
                </div>
            </div>
        </div>
        """

    @classmethod
    def _generate_vulnerabilities(cls, data: Dict) -> str:
        """Generate vulnerabilities section."""
        if not data["vulnerabilities"]:
            return ""
        
        vuln_items = ""
        for vuln in sorted(data["vulnerabilities"], key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5)):
            severity = vuln['severity']
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
            
            vuln_items += f"""
            <li class="vuln-item severity-{severity}">
                <div class="vuln-header">
                    <span class="vuln-type">{icon} {html.escape(vuln['type'])}</span>
                    <span class="vuln-severity {severity}">{severity.upper()}</span>
                </div>
                <div class="vuln-description">{html.escape(vuln['description'])}</div>
                <div class="vuln-meta">
                    <span>🎯 Target: {html.escape(vuln['target'])}</span>
                    {f"<span>🚪 Port: {vuln.get('port', 'N/A')}</span>" if vuln.get('port') else ''}
                    {f"<span>🔧 Service: {html.escape(vuln.get('service', 'N/A'))}</span>" if vuln.get('service') else ''}
                </div>
                {f"<div class=\"vuln-recommendation\">💡 {html.escape(vuln.get('recommendation', 'Review this finding'))}</div>" if vuln.get('recommendation') else ''}
            </li>
            """
        
        return f"""
        <div class="section">
            <div class="section-header" style="border-left: 4px solid #dc2626;">
                <h2>⚠️ Security Findings</h2>
                <span class="count">{len(data['vulnerabilities'])} findings</span>
            </div>
            <div class="section-content">
                <ul class="vuln-list">
                    {vuln_items}
                </ul>
            </div>
        </div>
        """

    @classmethod
    def _generate_network_map(cls, data: Dict) -> str:
        """Generate network topology visualization."""
        if not data["ips_found"] and not data["targets"]:
            return ""

        nodes_html = ""

        # Add targets
        for target in data["targets"][:10]:
            nodes_html += f"""
            <div class="network-node">
                <div class="network-node-header">
                    <span class="network-node-icon">🎯</span>
                    <span class="network-node-type">Target</span>
                </div>
                <div class="network-node-ip">{html.escape(target)}</div>
            </div>
            """

        # Add discovered IPs
        for ip in data["ips_found"][:10]:
            nodes_html += f"""
            <div class="network-node">
                <div class="network-node-header">
                    <span class="network-node-icon">💻</span>
                    <span class="network-node-type">Discovered IP</span>
                </div>
                <div class="network-node-ip">{html.escape(ip)}</div>
            </div>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <h2>🕸️ Network Topology</h2>
                <span class="count">{len(data['targets']) + len(data['ips_found'])} nodes</span>
            </div>
            <div class="section-content">
                <div class="network-map">
                    {nodes_html}
                </div>
            </div>
        </div>
        """

    @classmethod
    def _generate_geolocation_section(cls, data: Dict) -> str:
        """Generate geolocation visualization with country/city/coordinates."""
        if not data.get("geolocations"):
            return ""
        
        # Also check for geolocations in bulk nmap results
        geolocations = data.get("geolocations", [])
        
        # Build geolocation cards
        geo_cards = ""
        for geo in geolocations:
            ip = geo.get("ip", geo.get("query", "Unknown"))
            country = geo.get("country", geo.get("countryName", "Unknown"))
            city = geo.get("city", geo.get("regionName", "Unknown"))
            lat = geo.get("lat", geo.get("latitude"))
            lon = geo.get("lon", geo.get("longitude"))
            isp = geo.get("isp", geo.get("org", ""))
            timezone = geo.get("timezone", "")
            
            coords = f"{lat}, {lon}" if lat and lon else "Unknown"
            
            # Country flag emoji (simple mapping)
            flag = geo.get("country_code", "")
            if flag:
                flag_emoji = f"🇹{flag.upper()}" if len(flag) == 2 else "🌍"
            else:
                flag_emoji = "🌍"
            
            geo_cards += f"""
            <div class="scan-detail-card">
                <div class="scan-detail-header">
                    <div class="scan-detail-title">
                        <span class="scan-detail-icon">📍</span>
                        <strong>{html.escape(str(ip))}</strong>
                    </div>
                </div>
                <div class="scan-detail-content">
                    <div class="detail-section">
                        <div class="detail-row">
                            <span class="detail-key">🌍 Location</span>
                            <span class="detail-value">{flag_emoji} {html.escape(str(city))}, {html.escape(str(country))}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-key">📐 Coordinates</span>
                            <span class="detail-value" style="font-family: 'JetBrains Mono', monospace;">{coords}</span>
                        </div>
                        {f'<div class="detail-row"><span class="detail-key">🏢 ISP</span><span class="detail-value">{html.escape(str(isp))}</span></div>' if isp else ''}
                        {f'<div class="detail-row"><span class="detail-key">🕐 Timezone</span><span class="detail-value">{html.escape(str(timezone))}</span></div>' if timezone else ''}
                    </div>
                    <div class="detail-tags">
                        <span class="detail-tag">🎯 {html.escape(str(ip))}</span>
                        <span class="detail-tag">🌐 {html.escape(str(country))}</span>
                    </div>
                </div>
            </div>
            """
        
        # Generate map placeholder with coordinates for potential map integration
        coord_list = []
        for geo in geolocations:
            lat = geo.get("lat", geo.get("latitude"))
            lon = geo.get("lon", geo.get("longitude"))
            if lat and lon:
                coord_list.append((lat, lon, geo.get("city", ""), geo.get("country", "")))
        
        # Create chart data for geographic distribution
        country_counts = {}
        for geo in geolocations:
            country = geo.get("country", geo.get("countryName", "Unknown"))
            country_counts[country] = country_counts.get(country, 0) + 1
        
        country_chart_data = json.dumps({
            "labels": list(country_counts.keys()),
            "data": list(country_counts.values())
        })
        
        return f"""
        <div class="section">
            <div class="section-header" style="border-left: 4px solid var(--accent-green);">
                <h2>🌍 Geolocation Intelligence</h2>
                <span class="count">{len(geolocations)} locations</span>
            </div>
            <div class="section-content">
                <div class="charts-grid" style="margin-bottom: 20px;">
                    <div class="chart-container" style="grid-column: 1 / -1;">
                        <h3>Geographic Distribution by Country</h3>
                        <div class="chart-wrapper" style="height: 250px;">
                            <canvas id="geoChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <h3 style="color: var(--text-primary); margin: 20px 0 15px; font-size: 1.2em; display: flex; align-items: center; gap: 10px;">
                    <span>📍</span> Detailed Location Data
                </h3>
                {geo_cards}
            </div>
        </div>
        """

    @classmethod
    def _generate_traceroute_visualization(cls, data: Dict) -> str:
        """Generate traceroute path visualization."""
        if not data["traceroutes"]:
            return ""
        
        viz_html = ""
        for trace in data["traceroutes"]:
            target = trace.get("target", "Unknown")
            result = trace.get("result", {})
            
            # Try to parse traceroute output
            hops_html = ""
            output = result.get("output", "")
            
            if output:
                # Parse hops from traceroute output
                hop_lines = output.split('\n')[:15]  # Limit to 15 hops
                hop_nodes = []
                
                for line in hop_lines:
                    # Try to extract hop info
                    if 'ms' in line.lower():
                        # Extract IP if present
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        time_match = re.search(r'(\d+\.?\d*)\s*ms', line)
                        
                        if ip_match:
                            hop_nodes.append({
                                "ip": ip_match.group(),
                                "time": time_match.group(1) if time_match else "N/A"
                            })
                
                # Build hop visualization
                for i, hop in enumerate(hop_nodes[:10], 1):
                    if i > 1:
                        hops_html += '<span class="hop-arrow">→</span>'
                    hops_html += f"""
                    <div class="hop-node">
                        <div class="hop-number">Hop {i}</div>
                        <div class="hop-ip">{html.escape(hop['ip'])}</div>
                        <div class="hop-time">{hop['time']} ms</div>
                    </div>
                    """
            
            if hops_html:
                viz_html += f"""
                <div class="section" style="margin-bottom: 20px;">
                    <div class="section-header">
                        <h2>🗺️ Traceroute to {html.escape(target)}</h2>
                    </div>
                    <div class="section-content">
                        <div class="traceroute-viz">
                            {hops_html}
                        </div>
                    </div>
                </div>
                """
        
        return f"""
        <div class="section">
            <div class="section-header">
                <h2>🗺️ Network Paths (Traceroute)</h2>
                <span class="count">{len(data['traceroutes'])} traces</span>
            </div>
            <div class="section-content">
                {viz_html or '<p style="color: var(--text-muted);">No traceroute data available</p>'}
            </div>
        </div>
        """

    @classmethod
    def _generate_detailed_results(cls, data: Dict) -> str:
        """Generate detailed results sections by category with full scan details."""
        sections = ""

        # Results by category
        for category, items in data["categories"].items():
            category_name = cls.CATEGORIES.get(category, category.replace("_", " ").title())
            category_color = cls.CATEGORY_COLORS.get(category, "#79c0ff")

            # First show summary table
            summary_rows = ""
            for entry in items:
                tool = entry.get("tool", "Unknown")
                target = entry.get("target", "N/A")
                result = entry.get("result", {})
                timestamp = entry.get("timestamp", "")

                has_error = "error" in result if isinstance(result, dict) else False
                status_class = "error" if has_error else "success"
                status_text = "❌ Error" if has_error else "✓ Success"

                # Get icon for tool
                icon = "🔧"
                for key, tool_icon in cls.TOOL_ICONS.items():
                    if key in tool.lower():
                        icon = tool_icon
                        break

                # Format timestamp
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    time_str = timestamp[:10] if timestamp else "N/A"

                summary_rows += f"""
                <tr>
                    <td class="tool-name">{icon} {html.escape(tool)}</td>
                    <td class="target">{html.escape(str(target))}</td>
                    <td><span class="status {status_class}">{status_text}</span></td>
                    <td style="color: var(--text-secondary); font-size: 0.9em;">{time_str}</td>
                </tr>
                """

            # Now generate detailed cards for each scan
            detail_cards = ""
            for i, entry in enumerate(items, 1):
                tool = entry.get("tool", "Unknown")
                target = entry.get("target", "N/A")
                result = entry.get("result", {})
                timestamp = entry.get("timestamp", "")
                
                has_error = "error" in result if isinstance(result, dict) else False
                
                # Get icon for tool
                icon = "🔧"
                for key, tool_icon in cls.TOOL_ICONS.items():
                    if key in tool.lower():
                        icon = tool_icon
                        break
                
                # Format timestamp
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    time_str = timestamp
                
                # Generate detailed result content
                result_details = cls._format_result_details(result)
                
                detail_cards += f"""
                <div class="scan-detail-card">
                    <div class="scan-detail-header">
                        <div class="scan-detail-title">
                            <span class="scan-detail-icon">{icon}</span>
                            <strong>{html.escape(tool)}</strong>
                            <span class="scan-detail-target">→ {html.escape(str(target))}</span>
                        </div>
                        <div class="scan-detail-meta">
                            <span class="status {status_class}">{"❌ Error" if has_error else "✓ Success"}</span>
                            <span style="color: var(--text-muted); font-size: 0.85em;">{time_str}</span>
                        </div>
                    </div>
                    <div class="scan-detail-content">
                        {result_details}
                    </div>
                </div>
                """

            sections += f"""
            <div class="section">
                <div class="section-header" style="border-left: 4px solid {category_color};">
                    <h2>{category_name}</h2>
                    <span class="count">{len(items)} scans</span>
                </div>
                <div class="section-content">
                    <details open>
                        <summary style="cursor: pointer; padding: 10px 0; color: var(--accent-blue); font-weight: 500;">
                            📋 Summary Table (click to toggle)
                        </summary>
                        <table class="results-table">
                            <thead>
                                <tr>
                                    <th>Tool</th>
                                    <th>Target</th>
                                    <th>Status</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {summary_rows}
                            </tbody>
                        </table>
                    </details>
                    
                    <div style="margin-top: 25px;">
                        <h3 style="color: var(--text-secondary); font-size: 1.1em; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 10px;">
                            📝 Detailed Results
                        </h3>
                        {detail_cards}
                    </div>
                </div>
            </div>
            """

        return sections

    @classmethod
    def _format_result_details(cls, result: Dict) -> str:
        """Format detailed result data into readable HTML."""
        if not result:
            return '<p style="color: var(--text-muted);">No data</p>'
        
        if isinstance(result, dict):
            details_html = '<div class="result-details">'
            
            # Check for error first
            if "error" in result:
                details_html += f"""
                <div class="detail-error">
                    <span style="color: var(--accent-red); font-weight: 600;">⚠️ Error:</span>
                    {html.escape(str(result["error"]))}
                </div>
                """
            
            # Group data by type
            simple_fields = []
            list_fields = []
            dict_fields = []
            
            for key, value in result.items():
                if key in ("error", "target", "command", "preset", "port_spec", "batch_size", "timeout_ms", "returncode", "raw_output"):
                    continue  # Skip metadata fields
                
                if isinstance(value, list):
                    if value:
                        list_fields.append((key, value))
                elif isinstance(value, dict):
                    if value:
                        dict_fields.append((key, value))
                elif value is not None and str(value).strip():
                    simple_fields.append((key, value))
            
            # Show simple fields
            if simple_fields:
                details_html += '<div class="detail-section">'
                for key, value in simple_fields:
                    formatted_value = cls._format_value(value)
                    details_html += f"""
                    <div class="detail-row">
                        <span class="detail-key">{html.escape(str(key).replace("_", " ").title())}:</span>
                        <span class="detail-value">{formatted_value}</span>
                    </div>
                    """
                details_html += '</div>'
            
            # Show lists
            if list_fields:
                for key, items in list_fields:
                    details_html += f'<div class="detail-section"><div class="detail-subtitle">{html.escape(str(key).replace("_", " ").title())}</div>'
                    if isinstance(items[0], dict) if items else False:
                        # List of dicts (like open_ports)
                        details_html += '<div class="detail-list-grid">'
                        for item in items:
                            details_html += '<div class="detail-list-item">'
                            for k, v in item.items():
                                details_html += f"""
                                <div class="detail-row">
                                    <span class="detail-key">{html.escape(str(k).replace("_", " ").title())}:</span>
                                    <span class="detail-value">{cls._format_value(v)}</span>
                                </div>
                                """
                            details_html += '</div>'
                        details_html += '</div>'
                    else:
                        # Simple list
                        details_html += '<div class="detail-tags">'
                        for item in items:
                            details_html += f'<span class="detail-tag">{cls._format_value(item)}</span>'
                        details_html += '</div>'
                    details_html += '</div>'
            
            # Show nested dicts
            if dict_fields:
                for key, subdict in dict_fields:
                    details_html += f'<div class="detail-section"><div class="detail-subtitle">{html.escape(str(key).replace("_", " ").title())}</div>'
                    details_html += '<div class="detail-nested">'
                    for k, v in subdict.items():
                        if v is not None and str(v).strip():
                            details_html += f"""
                            <div class="detail-row">
                                <span class="detail-key">{html.escape(str(k).replace("_", " ").title())}:</span>
                                <span class="detail-value">{cls._format_value(v)}</span>
                            </div>
                            """
                    details_html += '</div></div>'
            
            # Show raw output if available
            if result.get("raw_output"):
                details_html += f"""
                <div class="detail-section">
                    <div class="detail-subtitle">📄 Raw Output</div>
                    <pre class="detail-raw-output">{html.escape(result["raw_output"])}</pre>
                </div>
                """
            
            details_html += '</div>'
            return details_html
        
        return f'<p>{html.escape(str(result))}</p>'

    @classmethod
    def _format_value(cls, value: Any) -> str:
        """Format a value for display."""
        if value is None:
            return '<span style="color: var(--text-muted);">null</span>'
        if isinstance(value, bool):
            color = "var(--accent-green)" if value else "var(--accent-red)"
            return f'<span style="color: {color}; font-weight: 600;">{str(value).lower()}</span>'
        if isinstance(value, (int, float)):
            return f'<span style="color: var(--accent-yellow);">{value}</span>'
        if isinstance(value, str):
            if len(value) > 500:
                return f'<span style="color: var(--text-primary);">{html.escape(value[:500])}...</span>'
            return f'<span style="color: var(--text-primary);">{html.escape(value)}</span>'
        return f'<span style="color: var(--text-primary);">{html.escape(str(value))}</span>'

    @classmethod
    def _build_graph_data(cls, results: List[Dict]) -> tuple:
        """Build graph nodes and edges from scan results."""
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph"))
        from graph_extractor import GraphExtractor
        
        all_nodes = []
        all_edges = []
        
        for entry in results:
            tool = entry.get("tool", "Unknown")
            target = entry.get("target", "")
            result = entry.get("result", {})
            
            nodes, edges = GraphExtractor.extract(tool, result, target)
            all_nodes.extend(nodes)
            all_edges.extend(edges)
        
        return all_nodes, all_edges

    @classmethod
    def _get_graph_css(cls) -> str:
        """Return CSS for interactive graph section — matches demo_web.py design."""
        return """
        /* ── Graph Section: demo_web.py design ── */
        .graph-section {
            border-radius: 12px;
            margin-bottom: 30px;
            overflow: hidden;
            border: 1px solid #30363d;
            animation: fadeIn 0.6s ease-out;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }

        /* Header bar */
        .graph-header {
            display: flex; align-items: center; gap: 16px;
            padding: 0 20px; height: 52px; flex-shrink: 0;
            background: #161b22; border-bottom: 1px solid #30363d;
        }
        .graph-logo { color: #58a6ff; font-size: 14px; font-weight: 700; letter-spacing: 0.5px; white-space: nowrap; }
        .graph-logo span { color: #8b949e; font-weight: 400; }
        .graph-hdr-sep { width: 1px; height: 24px; background: #30363d; flex-shrink: 0; }
        .graph-spacer { flex: 1; }
        .graph-legend { display: flex; align-items: center; gap: 10px; }
        .graph-legend-item { display: flex; align-items: center; gap: 4px; font-size: 11px; color: #8b949e; }
        .graph-legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

        /* Load Module button - Modern gradient style */
        .graph-btn-load {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            color: #fff;
            border-radius: 8px;
            padding: 8px 18px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
            position: relative;
            overflow: hidden;
        }
        .graph-btn-load::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }
        .graph-btn-load:hover::before {
            left: 100%;
        }
        .graph-btn-load:hover {
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
            transform: translateY(-2px);
        }
        .graph-btn-load:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
        }

        /* Module loader panel - Glass morphism style */
        .graph-module-loader {
            background: rgba(13, 17, 23, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 2px solid #58a6ff;
            max-height: 550px;
            overflow: hidden;
            animation: graphSlideDown 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            flex-direction: column;
            box-shadow: 0 8px 32px rgba(88, 166, 255, 0.15);
        }
        @keyframes graphSlideDown { from { max-height: 0; opacity: 0; transform: translateY(-20px); } to { max-height: 550px; opacity: 1; transform: translateY(0); }}
        .graph-loader-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 24px;
            border-bottom: 1px solid #30363d;
            background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
            flex-shrink: 0;
        }
        .graph-loader-header h4 {
            font-size: 15px;
            color: #58a6ff;
            margin: 0;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .graph-loader-header h4::before { content: "⚡"; font-size: 16px; }
        .graph-loader-actions {
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .graph-loader-close {
            background: #21262d;
            border: 1px solid #30363d;
            color: #8b949e;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            padding: 6px 12px;
            line-height: 1;
            transition: all 0.2s;
            font-weight: 600;
        }
        .graph-loader-close:hover {
            color: #f85149;
            border-color: #f85149;
            background: rgba(248, 81, 73, 0.1);
            transform: rotate(90deg);
        }
        .graph-btn-select-all, .graph-btn-deselect-all {
            background: transparent;
            border: 1px solid #30363d;
            color: #8b949e;
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .graph-btn-select-all:hover {
            background: #238636;
            border-color: #3fb950;
            color: #fff;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(35, 134, 54, 0.3);
        }
        .graph-btn-deselect-all:hover {
            background: #da3633;
            border-color: #f85149;
            color: #fff;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(218, 54, 51, 0.3);
        }

        .graph-loader-body {
            flex: 1;
            overflow-y: auto;
            padding: 16px 20px;
            background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
        }
        .graph-loader-body::-webkit-scrollbar { width: 8px; }
        .graph-loader-body::-webkit-scrollbar-track {
            background: #0d1117;
            border-radius: 4px;
        }
        .graph-loader-body::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, #30363d 0%, #21262d 100%);
            border-radius: 4px;
            border: 2px solid #0d1117;
        }
        .graph-loader-body::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(180deg, #484f58 0%, #30363d 100%);
        }

        /* Module filter bar - Enhanced style */
        .graph-module-filter {
            display: flex;
            gap: 8px;
            padding: 0 0 12px 0;
        }
        .graph-module-filter input {
            flex: 1;
            background: #0d1117;
            border: 2px solid #30363d;
            color: #c9d1d9;
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 13px;
            outline: none;
            transition: all 0.2s;
            font-weight: 500;
        }
        .graph-module-filter input:focus {
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.1);
            background: #161b22;
        }
        .graph-module-filter input::placeholder { color: #484f58; }

        /* Module item - Tree style with categories */
        .graph-module-category {
            margin-bottom: 8px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #30363d;
            background: #161b22;
        }
        .graph-module-category-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px;
            cursor: pointer;
            background: linear-gradient(135deg, #1c2128 0%, #21262d 100%);
            border-bottom: 1px solid #30363d;
            transition: all 0.2s;
            user-select: none;
        }
        .graph-module-category-header:hover {
            background: linear-gradient(135deg, #21262d 0%, #30363d 100%);
        }
        .graph-module-category-arrow {
            font-size: 12px;
            transition: transform 0.2s;
            color: #8b949e;
        }
        .graph-module-category-arrow.expanded {
            transform: rotate(90deg);
        }
        .graph-module-category-icon {
            font-size: 16px;
        }
        .graph-module-category-title {
            flex: 1;
            font-size: 12px;
            font-weight: 600;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .graph-module-category-count {
            font-size: 11px;
            color: #484f58;
            background: #0d1117;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 600;
        }
        .graph-module-category-checkbox {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .graph-module-category-checkbox:hover {
            background: rgba(88, 166, 255, 0.1);
        }
        .graph-module-category-checkbox input[type="checkbox"] {
            width: 14px;
            height: 14px;
            cursor: pointer;
            accent-color: #3fb950;
        }
        .graph-module-category-checkbox label {
            font-size: 11px;
            color: #c9d1d9;
            cursor: pointer;
            font-weight: 500;
        }
        .graph-module-category-body {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: #0d1117;
        }
        .graph-module-category-body.expanded {
            max-height: 1000px;
            overflow-y: auto;
        }
        .graph-module-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 14px 10px 24px;
            cursor: pointer;
            transition: all 0.2s;
            border-bottom: 1px solid #21262d;
            position: relative;
        }
        .graph-module-item:last-child {
            border-bottom: none;
        }
        .graph-module-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: transparent;
            transition: all 0.2s;
        }
        .graph-module-item:hover {
            background: #161b22;
        }
        .graph-module-item:hover::before {
            background: #58a6ff;
        }
        .graph-module-item.selected {
            background: rgba(63, 185, 80, 0.08);
        }
        .graph-module-item.selected::before {
            background: #3fb950;
        }
        .graph-module-item.selected::after {
            background: linear-gradient(135deg, rgba(63, 185, 80, 0.08) 0%, rgba(35, 134, 54, 0.08) 100%);
            opacity: 1;
        }
        .graph-module-icon {
            width: 48px;
            height: 48px;
            border-radius: 10px;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            flex-shrink: 0;
            border: 2px solid #30363d;
            transition: all 0.3s;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
        }
        .graph-module-item:hover .graph-module-icon {
            border-color: #58a6ff;
            transform: scale(1.05);
        }
        .graph-module-item.selected .graph-module-icon {
            border-color: #3fb950;
            background: linear-gradient(135deg, #0d2818 0%, #161b22 100%);
        }
        .graph-module-info { flex: 1; min-width: 0; position: relative; z-index: 1; }
        .graph-module-tool {
            font-size: 14px;
            font-weight: 700;
            color: #c9d1d9;
            margin-bottom: 4px;
            transition: color 0.3s;
        }
        .graph-module-item.selected .graph-module-tool { color: #3fb950; }
        .graph-module-target {
            font-size: 12px;
            color: #8b949e;
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            background: rgba(13, 17, 23, 0.6);
            padding: 3px 8px;
            border-radius: 4px;
            display: inline-block;
        }
        .graph-module-check {
            width: 26px;
            height: 26px;
            border-radius: 8px;
            border: 2px solid #30363d;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            flex-shrink: 0;
            font-size: 14px;
            color: transparent;
            background: #0d1117;
            position: relative;
            z-index: 1;
        }
        .graph-module-item:hover .graph-module-check {
            border-color: #58a6ff;
            background: rgba(88, 166, 255, 0.1);
        }
        .graph-module-item.selected .graph-module-check {
            background: linear-gradient(135deg, #3fb950 0%, #2ea043 100%);
            border-color: #3fb950;
            color: #fff;
            transform: scale(1.1);
            box-shadow: 0 2px 8px rgba(63, 185, 80, 0.4);
        }

        /* Load selected button bar - Modern style */
        .graph-loader-footer {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 20px;
            border-top: 2px solid #30363d;
            background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
            flex-shrink: 0;
            box-shadow: 0 -4px 12px rgba(0, 0, 0, 0.2);
        }
        .graph-selected-count {
            font-size: 13px;
            color: #8b949e;
            font-weight: 600;
        }
        .graph-selected-count b {
            color: #3fb950;
            font-weight: 700;
            font-size: 16px;
        }
        .graph-btn-load-selected {
            background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
            border: none;
            color: #fff;
            border-radius: 10px;
            padding: 10px 24px;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 12px rgba(35, 134, 54, 0.3);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            position: relative;
            overflow: hidden;
        }
        .graph-btn-load-selected::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
            transition: left 0.5s;
        }
        .graph-btn-load-selected:hover::before {
            left: 100%;
        }
        .graph-btn-load-selected:hover {
            background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%);
            box-shadow: 0 6px 20px rgba(35, 134, 54, 0.5);
            transform: translateY(-2px);
        }
        .graph-btn-load-selected:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(35, 134, 54, 0.3);
        }
        .graph-btn-load-selected:disabled {
            background: #21262d;
            border: 2px solid #30363d;
            color: #484f58;
            box-shadow: none;
            cursor: not-allowed;
            transform: none;
        }
        .graph-btn-load-selected:disabled::before {
            display: none;
        }

        /* Body row */
        .graph-body { display: flex; height: 580px; position: relative; overflow: hidden; }

        /* Sidebar */
        .graph-sidebar {
            width: 236px; flex-shrink: 0;
            background: #161b22; border-right: 1px solid #30363d;
            display: flex; flex-direction: column; overflow: hidden;
        }
        .graph-sidebar-header {
            padding: 10px 12px 8px; border-bottom: 1px solid #30363d;
            display: flex; align-items: center; justify-content: space-between;
        }
        .graph-sidebar-header h3 {
            font-size: 11px; color: #8b949e; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.5px; margin: 0;
        }
        .graph-btn-copy-all {
            background: transparent; border: 1px solid #30363d; color: #8b949e;
            border-radius: 4px; padding: 3px 8px; font-size: 10px; cursor: pointer;
            display: flex; align-items: center; gap: 4px; transition: all .15s;
        }
        .graph-btn-copy-all:hover { border-color: #58a6ff; color: #58a6ff; }
        .graph-sidebar-body { flex: 1; overflow-y: auto; padding: 6px; }
        .graph-sidebar-body::-webkit-scrollbar { width: 4px; }
        .graph-sidebar-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }

        /* Node cards */
        .graph-node-card {
            background: #21262d; border: 1px solid #30363d;
            border-radius: 6px; padding: 7px 9px; margin-bottom: 5px;
            cursor: pointer; transition: border-color .15s; position: relative;
        }
        .graph-node-card:hover { border-color: #58a6ff; }
        .graph-node-card:hover .graph-nc-copy { opacity: 1; }
        .graph-node-card.selected { border-color: #58a6ff; background: #1a2a3f; }
        .graph-nc-header { display: flex; align-items: center; gap: 7px; margin-bottom: 2px; }
        .graph-nc-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .graph-nc-label { font-size: 12px; font-weight: 600; color: #c9d1d9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
        .graph-nc-copy {
            opacity: 0; background: #21262d; border: 1px solid #30363d;
            color: #8b949e; border-radius: 3px; padding: 1px 5px; font-size: 10px;
            cursor: pointer; transition: all .15s; flex-shrink: 0;
        }
        .graph-nc-copy:hover { border-color: #3fb950; color: #3fb950; }
        .graph-nc-copy.copied { color: #3fb950; border-color: #3fb950; }
        .graph-nc-type { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .3px; }
        .graph-nc-tip { font-size: 10px; color: #484f58; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Stats row */
        .graph-stats-row { display: flex; gap: 8px; padding: 8px 12px; border-top: 1px solid #30363d; }
        .graph-stat { flex: 1; text-align: center; }
        .graph-stat-val { font-size: 17px; font-weight: 700; color: #58a6ff; }
        .graph-stat-lbl { font-size: 10px; color: #8b949e; }

        /* Canvas */
        .graph-canvas {
            flex: 1; position: relative;
            background: #0d1117;
            background-image: radial-gradient(circle, #2a2d33 1px, transparent 1px);
            background-size: 30px 30px;
        }
        #graph-cy { width: 100%; height: 100%; }

        /* Loading overlay */
        .graph-loading {
            position: absolute; inset: 0; display: flex; align-items: center;
            justify-content: center; background: rgba(13,17,23,.85);
            z-index: 100; gap: 12px; font-size: 14px; color: #8b949e;
        }
        .graph-spinner {
            width: 22px; height: 22px; border: 2px solid #30363d;
            border-top-color: #58a6ff; border-radius: 50%;
            animation: graphSpin .7s linear infinite;
        }
        @keyframes graphSpin { to { transform: rotate(360deg); } }

        /* Detail panel */
        .graph-detail-panel {
            width: 260px; flex-shrink: 0;
            background: #161b22; border-left: 1px solid #30363d;
            display: flex; flex-direction: column; overflow: hidden;
            transform: translateX(100%); transition: transform .25s ease;
        }
        .graph-detail-panel.open { transform: translateX(0); }
        .graph-detail-header {
            padding: 10px 12px 8px; border-bottom: 1px solid #30363d;
            display: flex; align-items: center; justify-content: space-between;
        }
        .graph-detail-header h3 {
            font-size: 11px; color: #8b949e; font-weight: 600;
            text-transform: uppercase; letter-spacing: .5px; margin: 0;
        }
        .graph-detail-close { background: none; border: none; color: #8b949e; font-size: 16px; cursor: pointer; padding: 0 2px; line-height: 1; }
        .graph-detail-close:hover { color: #c9d1d9; }
        .graph-detail-body { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 10px; }
        .graph-detail-body::-webkit-scrollbar { width: 4px; }
        .graph-detail-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
        .graph-dp-badge {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600;
            border: 1px solid; width: fit-content;
        }
        .graph-dp-field { display: flex; flex-direction: column; gap: 4px; }
        .graph-dp-field label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .4px; }
        .graph-dp-value {
            background: #21262d; border: 1px solid #30363d; border-radius: 5px;
            padding: 7px 10px; font-size: 12px; color: #c9d1d9;
            word-break: break-all; line-height: 1.5; font-family: monospace;
        }
        .graph-dp-copy-row { display: flex; gap: 6px; flex-wrap: wrap; }
        .graph-dp-btn {
            display: flex; align-items: center; gap: 5px;
            background: #21262d; border: 1px solid #30363d;
            color: #8b949e; border-radius: 5px; padding: 5px 10px;
            font-size: 11px; cursor: pointer; transition: all .15s;
        }
        .graph-dp-btn:hover { border-color: #58a6ff; color: #58a6ff; }
        .graph-dp-btn.copied { border-color: #3fb950 !important; color: #3fb950 !important; }
        .graph-dp-divider { height: 1px; background: #30363d; margin: 2px 0; }
        .graph-dp-connections { display: flex; flex-direction: column; gap: 4px; }
        .graph-dp-conn-item {
            display: flex; align-items: center; gap: 7px;
            padding: 5px 8px; border-radius: 5px; background: #21262d;
            font-size: 11px; cursor: pointer; border: 1px solid transparent; transition: border-color .12s;
        }
        .graph-dp-conn-item:hover { border-color: #30363d; }
        .graph-dp-conn-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
        .graph-dp-conn-lbl { color: #c9d1d9; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .graph-dp-conn-type { font-size: 9px; color: #484f58; text-transform: uppercase; }

        /* Footer bar */
        .graph-footer {
            height: 26px; flex-shrink: 0; display: flex; align-items: center;
            padding: 0 14px; gap: 20px;
            background: #161b22; border-top: 1px solid #30363d;
            font-size: 10px; color: #484f58; font-family: 'Segoe UI', system-ui, sans-serif;
        }
        .graph-status-dot { width: 7px; height: 7px; border-radius: 50%; background: #3fb950; flex-shrink: 0; }
        .graph-status-text { color: #8b949e; }
        .graph-node-info { color: #58a6ff; margin-left: auto; }

        /* Tooltip */
        .graph-tooltip {
            position: fixed; display: none; z-index: 9999;
            background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 10px 13px;
            font-size: 12px; max-width: 280px; pointer-events: none;
            box-shadow: 0 8px 24px rgba(0,0,0,.5);
            font-family: 'Segoe UI', system-ui, sans-serif;
        }
        .graph-tt-type { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: .4px; margin-bottom: 4px; }
        .graph-tt-label { font-size: 13px; font-weight: 600; color: #c9d1d9; margin-bottom: 4px; }
        .graph-tt-tip { font-size: 11px; color: #8b949e; }

        /* Toast */
        .graph-toast {
            position: fixed; bottom: 40px; left: 50%; transform: translateX(-50%) translateY(20px);
            background: #238636; color: #fff; padding: 7px 18px; border-radius: 6px;
            font-size: 12px; font-weight: 600; pointer-events: none;
            opacity: 0; transition: opacity .2s, transform .2s; z-index: 10000;
        }
        .graph-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
        """

    @classmethod
    def _generate_graph_section(cls, nodes: List[Dict], edges: List[Dict]) -> str:
        """Generate interactive graph section HTML — matches demo_web.py design."""
        node_count = len(nodes)
        edge_count = len(edges)

        return f'''
        <div class="graph-section">
            <!-- Header bar -->
            <div class="graph-header">
                <div class="graph-logo">◈ Recon 9 <span>· Graph View</span></div>
                <div class="graph-hdr-sep"></div>
                <span style="font-size:12px;color:#8b949e;">{node_count} nodes · {edge_count} edges</span>
                <div class="graph-spacer"></div>
                <button class="graph-btn-load" onclick="graphShowModuleLoader()" title="Load tool/module results">⚡ Load Module</button>
                <div class="graph-legend">
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#58a6ff"></div>Target/Domain</div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#f0883e"></div>IP</div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#3fb950"></div>Subdomain</div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#f85149"></div>Port</div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#ffd60a"></div>Geo</div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#d2a8ff"></div>MX/NS/ASN</div>
                </div>
            </div>

            <!-- Module Loader (hidden by default) -->
            <div class="graph-module-loader" id="graph-module-loader" style="display:none;">
                <div class="graph-loader-header">
                    <h4>Load Tool Results</h4>
                    <div class="graph-loader-actions">
                        <button class="graph-btn-select-all" onclick="graphSelectAllModules()" title="Select all modules">☑ Select All</button>
                        <button class="graph-btn-deselect-all" onclick="graphDeselectAllModules()" title="Deselect all modules">☐ Deselect All</button>
                        <button class="graph-loader-close" onclick="graphHideModuleLoader()" title="Close">✕</button>
                    </div>
                </div>
                <div class="graph-loader-body">
                    <div class="graph-module-filter">
                        <input type="text" id="graph-module-search" placeholder="🔍 Filter by tool name or target..." oninput="graphFilterModules(this.value)">
                    </div>
                    <div id="graph-module-list">
                        <p style="color:#8b949e;font-size:12px;">Select tool results to load into the graph:</p>
                    </div>
                </div>
                <div class="graph-loader-footer">
                    <div class="graph-selected-count"><b id="graph-selected-count">0</b> / <span id="graph-total-count">0</span> selected</div>
                    <button class="graph-btn-load-selected" id="graph-btn-load" onclick="graphLoadSelectedModules()" disabled>⚡ Load Selected</button>
                </div>
            </div>

            <!-- Body -->
            <div class="graph-body">
                <!-- Left sidebar -->
                <aside class="graph-sidebar">
                    <div class="graph-sidebar-header">
                        <h3>Nodes</h3>
                        <button class="graph-btn-copy-all" onclick="graphCopyAll('text')" title="Copy all node values">⎘ Copy All</button>
                    </div>
                    <div class="graph-sidebar-body" id="graph-node-list"></div>
                    <div class="graph-stats-row">
                        <div class="graph-stat">
                            <div class="graph-stat-val" id="graph-node-count">{node_count}</div>
                            <div class="graph-stat-lbl">Nodes</div>
                        </div>
                        <div class="graph-stat">
                            <div class="graph-stat-val" id="graph-edge-count">{edge_count}</div>
                            <div class="graph-stat-lbl">Edges</div>
                        </div>
                        <div class="graph-stat">
                            <div class="graph-stat-val" style="font-size:13px;">
                                <button class="graph-dp-btn" style="padding:3px 7px;font-size:10px;" onclick="graphCopyAll('json')">JSON</button>
                            </div>
                            <div class="graph-stat-lbl">Export</div>
                        </div>
                    </div>
                </aside>

                <!-- Graph canvas -->
                <div class="graph-canvas">
                    <div class="graph-loading" id="graph-loading">
                        <div class="graph-spinner"></div> Loading graph…
                    </div>
                    <div id="graph-cy"></div>
                    <!-- Tooltip -->
                    <div class="graph-tooltip" id="graph-tooltip">
                        <div class="graph-tt-type" id="graph-tt-type"></div>
                        <div class="graph-tt-label" id="graph-tt-label"></div>
                        <div class="graph-tt-tip" id="graph-tt-tip"></div>
                    </div>
                </div>

                <!-- Right detail panel -->
                <div class="graph-detail-panel" id="graph-detail-panel">
                    <div class="graph-detail-header">
                        <h3>Node Detail</h3>
                        <button class="graph-detail-close" onclick="closeGraphDetail()" title="Close">✕</button>
                    </div>
                    <div class="graph-detail-body" id="graph-detail-body">
                        <p style="color:#484f58;font-size:12px;">Click a node in the graph to inspect it here.</p>
                    </div>
                </div>
            </div>

            <!-- Footer bar -->
            <div class="graph-footer">
                <div class="graph-status-dot"></div>
                <span class="graph-status-text" id="graph-status-text">Ready</span>
                <span>Scroll = zoom &nbsp;·&nbsp; Drag = pan &nbsp;·&nbsp; Click node = inspect</span>
                <span class="graph-node-info" id="graph-node-info"></span>
            </div>
        </div>

        <!-- Toast notification -->
        <div class="graph-toast" id="graph-toast">Copied!</div>
        '''

    @classmethod
    def _get_node_color(cls, ntype: str) -> str:
        """Get border/accent color for node type (used for dots in sidebar)."""
        colors = {
            "target":    "#58a6ff",
            "domain":    "#79c0ff",
            "ip":        "#f0883e",
            "subdomain": "#3fb950",
            "port":      "#f85149",
            "mx":        "#d2a8ff",
            "ns":        "#ffa657",
            "txt":       "#8b949e",
            "asn":       "#b08eff",
            "geo":       "#ffd60a",
            "whois":     "#a8dadc",
            "service":   "#c9d1d9",
            "tracker":   "#e3b341",
            "social":    "#ff7b72",
            "cname":     "#56d364",
            "banner":    "#79c0ff",
            "default":   "#8b949e",
        }
        return colors.get(ntype, "#8b949e")

    @classmethod
    def _generate_footer(cls) -> str:
        """Generate report footer."""
        return f"""
        <div class="footer">
            <p><strong>Recon 9</strong> - Advanced Reconnaissance Platform</p>
            <p style="font-size: 0.9em; color: var(--text-muted);">Report generated on {datetime.now().strftime("%Y-%m-%d at %H:%M:%S")}</p>
            <div class="footer-warning">
                ⚠️ This report contains sensitive information. Handle with care and only share with authorized personnel.
            </div>
        </div>
        """

    @classmethod
    def _get_javascript(cls, data: Dict) -> str:
        """Generate Chart.js initialization script."""
        # Category distribution
        category_labels = []
        category_data = []
        category_colors = []

        for category, items in data["categories"].items():
            category_labels.append(cls.CATEGORIES.get(category, category))
            category_data.append(len(items))
            category_colors.append(cls.CATEGORY_COLORS.get(category, "#79c0ff"))

        # Vulnerability chart data
        vuln_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in data["vulnerabilities"]:
            severity = vuln["severity"]
            vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1

        # Geographic distribution - count countries from geolocations
        country_counts = {}
        for g in data.get("geolocations", []):
            c = g.get("country", "Unknown")
            country_counts[c] = country_counts.get(c, 0) + 1

        return f"""
        // Chart.js default config
        Chart.defaults.color = '#9ca3af';
        Chart.defaults.font.family = 'Inter';

        // Category Distribution Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(category_labels)},
                datasets: [{{
                    data: {json.dumps(category_data)},
                    backgroundColor: {json.dumps(category_colors)},
                    borderWidth: 0,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            padding: 15,
                            font: {{ size: 11, weight: 500 }},
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }}
                    }},
                    tooltip: {{
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f9fafb',
                        bodyColor: '#9ca3af',
                        borderColor: '#374151',
                        borderWidth: 1,
                        padding: 12,
                        displayColors: true,
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ': ' + context.parsed + ' scans';
                            }}
                        }}
                    }}
                }},
                animation: {{
                    animateScale: true,
                    animateRotate: true
                }}
            }}
        }});

        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnChart').getContext('2d');
        new Chart(vulnCtx, {{
            type: 'bar',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    label: 'Findings',
                    data: {json.dumps([vuln_by_severity['critical'], vuln_by_severity['high'], vuln_by_severity['medium'], vuln_by_severity['low'], vuln_by_severity['info']])},
                    backgroundColor: [
                        'rgba(220, 38, 38, 0.8)',
                        'rgba(239, 68, 68, 0.8)',
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(16, 185, 129, 0.8)',
                        'rgba(59, 130, 246, 0.8)'
                    ],
                    borderColor: [
                        '#dc2626',
                        '#ef4444',
                        '#f59e0b',
                        '#10b981',
                        '#3b82f6'
                    ],
                    borderWidth: 2,
                    borderRadius: 8,
                    borderSkipped: false
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            color: '#9ca3af',
                            stepSize: 1,
                            font: {{ size: 11 }}
                        }},
                        grid: {{
                            color: 'rgba(55, 65, 81, 0.5)',
                            drawBorder: false
                        }}
                    }},
                    x: {{
                        ticks: {{
                            color: '#9ca3af',
                            font: {{ size: 11, weight: 500 }}
                        }},
                        grid: {{ display: false }}
                    }}
                }},
                plugins: {{
                    legend: {{ display: false }},
                    tooltip: {{
                        backgroundColor: 'rgba(17, 24, 39, 0.95)',
                        titleColor: '#f9fafb',
                        bodyColor: '#9ca3af',
                        borderColor: '#374151',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        displayColors: false
                    }}
                }},
                animation: {{
                    delay: 200,
                    duration: 800,
                    easing: 'easeOutQuart'
                }}
            }}
        }});

        // Geographic Distribution Chart
        const geoCtx = document.getElementById('geoChart');
        if (geoCtx && {len(country_counts)} > 0) {{
            new Chart(geoCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(list(country_counts.keys()))},
                    datasets: [{{
                        label: 'Locations',
                        data: {json.dumps(list(country_counts.values()))},
                        backgroundColor: 'rgba(16, 185, 129, 0.7)',
                        borderColor: '#10b981',
                        borderWidth: 2,
                        borderRadius: 8,
                        borderSkipped: false
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            ticks: {{
                                color: '#9ca3af',
                                stepSize: 1,
                                font: {{ size: 11 }}
                            }},
                            grid: {{
                                color: 'rgba(55, 65, 81, 0.5)',
                                drawBorder: false
                            }}
                        }},
                        y: {{
                            ticks: {{
                                color: '#f9fafb',
                                font: {{ size: 12, weight: 500 }}
                            }},
                            grid: {{ display: false }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }},
                        tooltip: {{
                            backgroundColor: 'rgba(17, 24, 39, 0.95)',
                            titleColor: '#f9fafb',
                            bodyColor: '#9ca3af',
                            borderColor: '#374151',
                            borderWidth: 1,
                            padding: 12,
                            cornerRadius: 8,
                            displayColors: false
                        }}
                    }},
                    animation: {{
                        delay: 300,
                        duration: 800,
                        easing: 'easeOutQuart'
                    }}
                }}
            }});
        }}
        """

    @classmethod
    def _get_graph_javascript(cls, nodes: List[Dict], edges: List[Dict]) -> str:
        """Generate JavaScript for interactive graph - matches demo_web.py design."""
        import json

        # Build Cytoscape elements with full demo_web.py data attributes
        NODE_COLORS = {
            "target":    {"bg": "#1f6feb", "border": "#58a6ff", "text": "#ffffff"},
            "domain":    {"bg": "#1a3a5c", "border": "#79c0ff", "text": "#79c0ff"},
            "ip":        {"bg": "#4a2000", "border": "#f0883e", "text": "#f0883e"},
            "subdomain": {"bg": "#0d3320", "border": "#3fb950", "text": "#3fb950"},
            "port":      {"bg": "#3d0c0a", "border": "#f85149", "text": "#f85149"},
            "mx":        {"bg": "#2d1b4e", "border": "#d2a8ff", "text": "#d2a8ff"},
            "ns":        {"bg": "#3a2a00", "border": "#ffa657", "text": "#ffa657"},
            "txt":       {"bg": "#21262d", "border": "#8b949e", "text": "#8b949e"},
            "asn":       {"bg": "#1e1040", "border": "#b08eff", "text": "#b08eff"},
            "geo":       {"bg": "#3a2e00", "border": "#ffd60a", "text": "#ffd60a"},
            "whois":     {"bg": "#0f2a2c", "border": "#a8dadc", "text": "#a8dadc"},
            "service":   {"bg": "#21262d", "border": "#c9d1d9", "text": "#c9d1d9"},
            "tracker":   {"bg": "#2e2200", "border": "#e3b341", "text": "#e3b341"},
            "social":    {"bg": "#3d1010", "border": "#ff7b72", "text": "#ff7b72"},
            "cname":     {"bg": "#0d2a14", "border": "#56d364", "text": "#56d364"},
            "banner":    {"bg": "#0d1f3c", "border": "#79c0ff", "text": "#79c0ff"},
            "hop":       {"bg": "#2d1b4e", "border": "#d2a8ff", "text": "#d2a8ff"},
            "default":   {"bg": "#21262d", "border": "#8b949e", "text": "#8b949e"},
        }
        NODE_ICONS = {
            "target":    "◉", "domain":    "◎", "ip":        "●", "subdomain": "○",
            "port":      "▪", "mx":        "✉", "ns":        "◇", "txt":       "▤",
            "asn":       "⬡", "geo":       "◈", "whois":     "▤", "service":   "⚙",
            "tracker":   "◉", "social":    "◆", "cname":     "↗", "banner":    "▤",
            "hop":       "◉",
            "default":   "●",
        }
        NODE_SHAPES = {
            "target": "ellipse", "domain": "hexagon", "ip": "diamond",
            "subdomain": "ellipse", "port": "rectangle", "mx": "ellipse",
            "ns": "ellipse", "txt": "rectangle", "asn": "hexagon",
            "geo": "ellipse", "whois": "rectangle", "service": "ellipse",
            "tracker": "diamond", "social": "ellipse", "cname": "ellipse",
            "banner": "rectangle", "hop": "ellipse", "default": "ellipse",
        }
        NODE_SIZES = {
            "target": 54, "domain": 46, "ip": 42, "subdomain": 36,
            "port": 32, "mx": 32, "ns": 32, "txt": 28, "asn": 38,
            "geo": 32, "whois": 32, "service": 28, "tracker": 32,
            "social": 32, "cname": 28, "banner": 28, "hop": 36, "default": 28,
        }

        elements = []
        for n in nodes:
            ntype = n.get("type", "default")
            colors = NODE_COLORS.get(ntype, NODE_COLORS["default"])
            label = n.get("label") or ""
            elements.append({
                "data": {
                    "id": n["id"],
                    "label": str(label)[:30],
                    "type": ntype,
                    "tooltip": n.get("tooltip") or n.get("label") or "",
                    "bg":        colors["bg"],
                    "border":    colors["border"],
                    "textColor": colors["text"],
                    "icon":      NODE_ICONS.get(ntype, "●"),
                    "size":      NODE_SIZES.get(ntype, 28),
                    "shape":     NODE_SHAPES.get(ntype, "ellipse"),
                }
            })
        for e in edges:
            elements.append({
                "data": {
                    "id": f"e_{e['src']}_{e['dst']}",
                    "source": e["src"],
                    "target": e["dst"],
                    "label": e.get("label", ""),
                }
            })

        elements_json = json.dumps(elements)
        nodes_json    = json.dumps(nodes)

        return f'''
        // Graph: demo_web.py design
        let graphCy = null;
        let graphCurrentElements = {elements_json};
        let graphRawNodes = {nodes_json};

        const GRAPH_COLOR_MAP = {{
            target:    {{bg:'#1f6feb', border:'#58a6ff'}},
            domain:    {{bg:'#1a3a5c', border:'#79c0ff'}},
            ip:        {{bg:'#4a2000', border:'#f0883e'}},
            subdomain: {{bg:'#0d3320', border:'#3fb950'}},
            port:      {{bg:'#3d0c0a', border:'#f85149'}},
            mx:        {{bg:'#2d1b4e', border:'#d2a8ff'}},
            ns:        {{bg:'#3a2a00', border:'#ffa657'}},
            txt:       {{bg:'#21262d', border:'#8b949e'}},
            asn:       {{bg:'#1e1040', border:'#b08eff'}},
            geo:       {{bg:'#3a2e00', border:'#ffd60a'}},
            whois:     {{bg:'#0f2a2c', border:'#a8dadc'}},
            service:   {{bg:'#21262d', border:'#c9d1d9'}},
            tracker:   {{bg:'#2e2200', border:'#e3b341'}},
            social:    {{bg:'#3d1010', border:'#ff7b72'}},
            cname:     {{bg:'#0d2a14', border:'#56d364'}},
            banner:    {{bg:'#0d1f3c', border:'#79c0ff'}},
            hop:       {{bg:'#2d1b4e', border:'#d2a8ff'}},
            default:   {{bg:'#21262d', border:'#8b949e'}},
        }};

        // Copy helpers
        function graphCopyText(text, btnEl) {{
            navigator.clipboard.writeText(text).then(() => {{
                graphShowToast('Copied!');
                if (btnEl) {{
                    const orig = btnEl.textContent;
                    btnEl.textContent = '✓ Copied';
                    btnEl.classList.add('copied');
                    setTimeout(() => {{ btnEl.textContent = orig; btnEl.classList.remove('copied'); }}, 1800);
                }}
            }}).catch(() => {{
                const ta = document.createElement('textarea');
                ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
                document.body.appendChild(ta); ta.select();
                document.execCommand('copy'); document.body.removeChild(ta);
                graphShowToast('Copied!');
            }});
        }}

        function graphShowToast(msg) {{
            const t = document.getElementById('graph-toast');
            if (!t) return;
            t.textContent = msg; t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 1800);
        }}

        function graphCopyAll(format) {{
            const nodeEls = graphCurrentElements.filter(e => !e.data.source);
            if (format === 'json') {{
                const out = nodeEls.map(n => ({{ type: n.data.type, label: n.data.label, detail: n.data.tooltip }}));
                graphCopyText(JSON.stringify(out, null, 2));
                graphShowToast('JSON copied — ' + nodeEls.length + ' nodes');
            }} else {{
                const lines = nodeEls.map(n => '[' + n.data.type.toUpperCase() + ']  ' + (n.data.tooltip || n.data.label));
                graphCopyText(lines.join('\\n'));
                graphShowToast('Copied — ' + nodeEls.length + ' nodes');
            }}
        }}

        // Sidebar
        function graphBuildSidebar(elements) {{
            const nodeEls = elements.filter(e => !e.data.source);
            const list = document.getElementById('graph-node-list');
            if (!list) return;
            list.innerHTML = '';
            const nc = document.getElementById('graph-node-count');
            const ec = document.getElementById('graph-edge-count');
            if (nc) nc.textContent = nodeEls.length;
            if (ec) ec.textContent = elements.filter(e => e.data.source).length;

            nodeEls.forEach(n => {{
                const d = n.data;
                const c = GRAPH_COLOR_MAP[d.type] || GRAPH_COLOR_MAP.default;
                const copyVal = d.tooltip || d.label;
                const tipHtml = (d.tooltip && d.tooltip !== d.label)
                    ? '<div class="graph-nc-tip" title="' + graphEsc(d.tooltip) + '">' + graphEsc(d.tooltip) + '</div>'
                    : '';

                const card = document.createElement('div');
                card.className = 'graph-node-card';
                card.id = 'graph-card-' + d.id;
                card.setAttribute('data-copy', graphEsc(copyVal));
                card.innerHTML =
                    '<div class="graph-nc-header">' +
                        '<div class="graph-nc-dot" style="background:' + c.border + '"></div>' +
                        '<div class="graph-nc-label" title="' + graphEsc(d.tooltip || d.label) + '">' + graphEsc(d.label) + '</div>' +
                        '<button class="graph-nc-copy" title="Copy value" onclick="event.stopPropagation();graphCardCopy(this)">⎘</button>' +
                    '</div>' +
                    '<div class="graph-nc-type">' + d.type + '</div>' +
                    tipHtml;

                card.onclick = () => {{
                    if (!graphCy) return;
                    const node = graphCy.getElementById(d.id);
                    if (node.length) {{
                        graphCy.animate({{
                            fit: {{ eles: node.closedNeighborhood(), padding: 80 }},
                            duration: 500,
                            easing: 'ease-in-out'
                        }});
                        node.emit('tap');
                    }}
                }};
                list.appendChild(card);
            }});
        }}

        function graphCardCopy(btn) {{
            const card = btn.closest('.graph-node-card');
            const text = card ? card.getAttribute('data-copy') : '';
            graphCopyText(text, btn);
            btn.textContent = '✓';
            setTimeout(() => {{ btn.textContent = '⎘'; }}, 1800);
        }}

        // Detail panel
        function graphOpenDetail(nodeData) {{
            const panel = document.getElementById('graph-detail-panel');
            const body  = document.getElementById('graph-detail-body');
            if (!panel || !body) return;
            const c = GRAPH_COLOR_MAP[nodeData.type] || GRAPH_COLOR_MAP.default;
            const conns = graphGetConnections(nodeData.id);

            // Try to find full scan result for this node
            let fullResultHtml = '';
            if (typeof ALL_SCAN_RESULTS !== 'undefined') {{
                const scanResult = graphFindScanResult(nodeData);
                if (scanResult) {{
                    fullResultHtml = graphRenderScanResult(scanResult.result || {{}});
                }}
            }}

            let connHtml = '';
            if (conns.length) {{
                connHtml = '<div class="graph-dp-field"><label>Connected nodes (' + conns.length + ')</label>' +
                    '<div class="graph-dp-connections">' +
                    conns.map(n => {{
                        const cc = GRAPH_COLOR_MAP[n.type] || GRAPH_COLOR_MAP.default;
                        const escId = graphEsc(n.id);
                        return '<div class="graph-dp-conn-item" data-target-id="' + escId + '" onclick="graphFocusNodeConn(this)">' +
                            '<div class="graph-dp-conn-dot" style="background:' + cc.border + '"></div>' +
                            '<span class="graph-dp-conn-lbl" title="' + graphEsc(n.tooltip || n.label) + '">' + graphEsc(n.label) + '</span>' +
                            '<span class="graph-dp-conn-type">' + n.type + '</span>' +
                            '</div>';
                    }}).join('') +
                    '</div></div>';
            }}

            body.innerHTML =
                '<div class="graph-dp-badge" style="color:' + c.border + ';border-color:' + c.border + ';background:' + c.bg + '33;">' +
                    (nodeData.icon || '●') + ' &nbsp; ' + nodeData.type.toUpperCase() +
                '</div>' +

                '<div class="graph-dp-field"><label>Label / Value</label>' +
                '<div class="graph-dp-value">' + graphEsc(nodeData.label) + '</div></div>' +

                '<div class="graph-dp-copy-row">' +
                    '<button class="graph-dp-btn" data-copy-label onclick="graphCopyDPLabel(this)">⎘ Copy Value</button>' +
                    (nodeData.tooltip && nodeData.tooltip !== nodeData.label
                        ? '<button class="graph-dp-btn" data-copy-detail onclick="graphCopyDPDetail(this)">⎘ Copy Detail</button>'
                        : '') +
                    '<button class="graph-dp-btn" data-copy-json onclick="graphCopyDPJSON(this)">⎘ Copy JSON</button>' +
                '</div>' +

                (nodeData.tooltip && nodeData.tooltip !== nodeData.label
                    ? '<div class="graph-dp-field"><label>Full Detail</label><div class="graph-dp-value" style="font-size:11px;">' + graphEsc(nodeData.tooltip) + '</div></div>'
                    : '') +

                (fullResultHtml ? '<div class="graph-dp-divider"></div>' + fullResultHtml : '') +

                (connHtml ? '<div class="graph-dp-divider"></div>' + connHtml : '');

            panel.classList.add('open');
        }}

        function graphFindScanResult(nodeData) {{
            if (!ALL_SCAN_RESULTS || !ALL_SCAN_RESULTS.length) return null;
            const nodeId = nodeData.id.toLowerCase();
            const nodeLabel = (nodeData.label || '').toLowerCase();
            const nodeTooltip = (nodeData.tooltip || '').toLowerCase();

            // Search through all scan results
            for (const entry of ALL_SCAN_RESULTS) {{
                const result = entry.result || {{}};
                const target = (entry.target || '').toLowerCase();

                // Check if node matches target
                if (nodeLabel.includes(target) || nodeTooltip.includes(target) || nodeId.includes(target)) {{
                    return entry;
                }}

                // Check DNS records
                if (result.records) {{
                    for (const rtype of ['A','AAAA','MX','NS','TXT','CNAME']) {{
                        for (const val of (result.records[rtype] || [])) {{
                            if (nodeLabel.includes(val.toLowerCase()) || nodeId.includes(val.toLowerCase().replace(/[^a-z0-9]/g,'_'))) {{
                                return entry;
                            }}
                        }}
                    }}
                }}

                // Check open ports
                if (result.open_ports) {{
                    for (const p of result.open_ports) {{
                        const port = typeof p === 'object' ? p.port : p;
                        if (nodeLabel.includes(String(port)) || nodeId.includes('port_' + port)) {{
                            return entry;
                        }}
                    }}
                }}

                // Check bulk targets
                if (result.targets) {{
                    for (const [t, tr] of Object.entries(result.targets)) {{
                        if (nodeLabel.includes(t.toLowerCase()) || nodeTooltip.includes(t.toLowerCase())) {{
                            return {{ ...entry, result: tr, target: t }};
                        }}
                    }}
                }}

                // Check Shodan CVEs
                if (result.cves) {{
                    for (const cve of result.cves) {{
                        if (nodeLabel.includes(cve.toLowerCase()) || nodeId.includes(cve.toLowerCase())) {{
                            return entry;
                        }}
                    }}
                }}

                // Check Shodan ports
                if (result.ports) {{
                    for (const p of result.ports) {{
                        if (nodeLabel.includes(String(p)) || nodeId.includes('shodan_p_' + p)) {{
                            return entry;
                        }}
                    }}
                }}

                // Check geolocation
                if (result.country || result.city) {{
                    const loc = ((result.city || '') + ', ' + (result.country || '')).toLowerCase();
                    if (nodeLabel.includes(loc) || nodeTooltip.includes(loc)) {{
                        return entry;
                    }}
                }}
            }}
            return null;
        }}

        function graphRenderScanResult(result) {{
            if (!result || typeof result !== 'object') return '';
            let html = '<div class="graph-dp-field"><label>Scan Result Data</label><div class="graph-dp-value" style="max-height:250px;overflow-y:auto;font-size:10px;line-height:1.6;">';

            // ── DNS Records (DNS Lookup) ──────────────────────────────────────
            if (result.records && typeof result.records === 'object') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🌐 DNS Records</div>';
                for (const [rtype, vals] of Object.entries(result.records)) {{
                    if (Array.isArray(vals) && vals.length > 0) {{
                        html += '<div style="color:#8b949e;font-size:9px;text-transform:uppercase;margin-top:4px;">' + rtype + ' Records (' + vals.length + ')</div>';
                        for (const v of vals.slice(0, 15)) {{
                            html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(String(v)) + '</div>';
                        }}
                        if (vals.length > 15) {{
                            html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (vals.length - 15) + ' more</div>';
                        }}
                    }} else if (Array.isArray(vals) && vals.length === 0) {{
                        html += '<div style="color:#8b949e;font-size:9px;margin-top:2px;">• ' + rtype + ': No records found</div>';
                    }}
                }}
            }}

            // ── Subdomains (Subdomain Discovery) ──────────────────────────────
            if (result.subdomains && result.subdomains.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🌲 Subdomains (' + result.subdomains.length + ')</div>';
                for (const sub of result.subdomains.slice(0, 20)) {{
                    html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• ' + graphEsc(sub) + '</div>';
                }}
                if (result.subdomains.length > 20) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.subdomains.length - 20) + ' more</div>';
                }}
            }}

            // ── Shared DNS / Nameservers ──────────────────────────────────────
            if (result.nameservers && result.nameservers.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔗 Nameservers (' + result.nameservers.length + ')</div>';
                for (const ns of result.nameservers.slice(0, 10)) {{
                    const ips = result.ns_ips && result.ns_ips[ns];
                    const ipStr = Array.isArray(ips) ? ips.join(', ') : '';
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#79c0ff;">' + graphEsc(ns) + '</span>' + (ipStr ? ' → ' + graphEsc(ipStr) : '') + '</div>';
                }}
            }}
            if (result.shared && typeof result.shared === 'object') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔗 Shared Domains per NS</div>';
                for (const [ns, domains] of Object.entries(result.shared)) {{
                    if (Array.isArray(domains) && domains.length > 0) {{
                        html += '<div style="color:#8b949e;font-size:9px;margin-top:4px;">' + graphEsc(ns) + ' (' + domains.length + ' domains)</div>';
                        for (const d of domains.slice(0, 10)) {{
                            html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(d) + '</div>';
                        }}
                        if (domains.length > 10) {{
                            html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (domains.length - 10) + ' more</div>';
                        }}
                    }}
                }}
            }}

            // ── Reverse DNS hostnames ─────────────────────────────────────────
            if (result.hostnames && result.hostnames.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">↩️ Reverse DNS Hostnames</div>';
                for (const hn of result.hostnames) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(hn) + '</div>';
                }}
            }}

            // ── Open Ports (TCP Scan, UDP Scan, Nmap, RustScan, Masscan) ──────
            if (result.open_ports && Array.isArray(result.open_ports) && result.open_ports.length) {{
                const portType = result.port_spec ? '🚪' : (result.command && result.command.includes('masscan') ? '⚡' : '🚪');
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">' + portType + ' Open Ports (' + result.open_ports.length + ')</div>';
                for (const p of result.open_ports.slice(0, 30)) {{
                    if (typeof p === 'object') {{
                        const port = p.port || '?';
                        const svc = p.service || '';
                        const banner = p.banner || '';
                        const state = p.state || 'open';
                        const ip = p.ip || '';
                        html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#f0883e;font-weight:600;">' + port + '</span>' + (svc ? '/' + svc : '') + (state && state !== 'open' ? ' [<span style="color:#d29922;">' + state + '</span>]' : '') + (banner ? ' <span style="color:#8b949e;font-size:8px;">(' + graphEsc(banner).substring(0, 50) + ')</span>' : '') + (ip ? ' <span style="color:#79c0ff;font-size:8px;">[' + graphEsc(ip) + ']</span>' : '') + '</div>';
                    }} else {{
                        html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#f0883e;">' + p + '</span></div>';
                    }}
                }}
                if (result.open_ports.length > 30) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.open_ports.length - 30) + ' more ports</div>';
                }}
                if (result.open_count !== undefined) {{
                    html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;margin-top:3px;">✓ ' + result.open_count + ' open port' + (result.open_count !== 1 ? 's' : '') + ' found</div>';
                }}
            }}

            // ── UDP Scan Results ──────────────────────────────────────────────
            if (result.results && Array.isArray(result.results) && result.results.length && !result.open_ports) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📭 UDP Scan Results (' + result.results.length + ' ports)</div>';
                for (const r of result.results.slice(0, 20)) {{
                    const port = r.port || '?';
                    const state = r.state || 'unknown';
                    const svc = r.service || '';
                    const banner = r.banner || '';
                    const stateColor = state === 'open' ? '#3fb950' : state === 'open|filtered' ? '#d29922' : '#f85149';
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Port <span style="color:#f0883e;">' + port + '</span> [<span style="color:' + stateColor + ';">' + state + '</span>]' + (svc ? '/' + svc : '') + (banner ? ' <span style="color:#8b949e;font-size:8px;">(' + graphEsc(banner).substring(0, 40) + ')</span>' : '') + '</div>';
                }}
            }}

            // ── CVEs (Shodan/Nmap Vuln Scripts) ──────────────────────────────
            if (result.cves && result.cves.length) {{
                html += '<div style="color:#f85149;font-weight:600;margin:6px 0 3px;">⚠️ CVEs (' + result.cves.length + ')</div>';
                for (const cve of result.cves.slice(0, 15)) {{
                    const cveId = typeof cve === 'object' ? (cve.cve_id || cve.id || 'Unknown') : cve;
                    html += '<div style="color:#f85149;margin-left:8px;font-size:9px;">• ' + graphEsc(String(cveId)) + '</div>';
                }}
                if (result.cves.length > 15) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.cves.length - 15) + ' more CVEs</div>';
                }}
            }}

            // ── Services (Bulk Nmap) ─────────────────────────────────────────
            if (result.services && result.services.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔧 Services (' + result.services.length + ')</div>';
                for (const svc of result.services.slice(0, 20)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(String(svc)) + '</div>';
                }}
            }}

            // ── Geolocation (IP Geolocation, IP Info) ─────────────────────────
            if (result.country || result.city || result.lat || result.latitude) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📍 Location</div>';
                if (result.city) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• City: ' + graphEsc(result.city) + '</div>';
                if (result.region || result.regionName) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Region: ' + graphEsc(result.region || result.regionName) + '</div>';
                if (result.country || result.countryName) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Country: ' + graphEsc(result.country || result.countryName) + '</div>';
                if (result.postal) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Postal: ' + graphEsc(result.postal) + '</div>';
                const lat = result.lat || result.latitude;
                const lon = result.lon || result.longitude;
                if (lat && lon) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Coordinates: <span style="color:#f0883e;">' + lat + ', ' + lon + '</span></div>';
                if (result.isp || result.org) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ISP: ' + graphEsc(result.isp || result.org) + '</div>';
                if (result.timezone) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Timezone: ' + graphEsc(result.timezone) + '</div>';
                if (result.asn && !result.asn_description) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ASN: ' + graphEsc(result.asn) + '</div>';
            }}

            // ── WHOIS Lookup ──────────────────────────────────────────────────
            if (result.registrar || result.creation_date || result.whois || result.raw) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📋 WHOIS</div>';
                if (result.whois && typeof result.whois === 'object') {{
                    const whoisFields = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'updated_date', 'status', 'name_servers', 'emails', 'org', 'state', 'country'];
                    for (const field of whoisFields) {{
                        const val = result.whois[field];
                        if (val) {{
                            const displayVal = Array.isArray(val) ? val.join(', ') : String(val);
                            html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(field.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())) + ': ' + graphEsc(displayVal).substring(0, 100) + '</div>';
                        }}
                    }}
                }} else {{
                    if (result.registrar) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Registrar: ' + graphEsc(result.registrar) + '</div>';
                    if (result.creation_date) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Created: ' + graphEsc(String(result.creation_date)) + '</div>';
                    if (result.expiration_date) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Expires: ' + graphEsc(String(result.expiration_date)) + '</div>';
                }}
                // Show raw WHOIS only if no structured data
                if (result.raw && !result.whois && !result.registrar && !result.creation_date) {{
                    html += '<div style="color:#8b949e;font-size:9px;margin-left:8px;margin-top:4px;">Raw WHOIS (first 300 chars):</div>';
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:8px;white-space:pre-wrap;font-family:monospace;">' + graphEsc(result.raw).substring(0, 300) + '</div>';
                }}
            }}

            // ── HTTP Headers ──────────────────────────────────────────────────
            if (result.headers && typeof result.headers === 'object') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔗 HTTP Headers</div>';
                if (result.status_code) {{
                    const statusColor = result.status_code >= 200 && result.status_code < 300 ? '#3fb950' : result.status_code >= 300 && result.status_code < 400 ? '#d29922' : '#f85149';
                    html += '<div style="color:' + statusColor + ';margin-left:8px;font-size:9px;font-weight:600;">• Status: ' + result.status_code + '</div>';
                }}
                if (result.server) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Server: ' + graphEsc(result.server) + '</div>';
                if (result.content_type) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Content-Type: ' + graphEsc(result.content_type) + '</div>';
                if (result.powered_by) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• X-Powered-By: ' + graphEsc(result.powered_by) + '</div>';
                const importantHeaders = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy', 'X-XSS-Protection'];
                for (const h of importantHeaders) {{
                    if (result.headers[h]) {{
                        html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• ✓ <span style="color:#79c0ff;">' + graphEsc(h) + '</span>: ' + graphEsc(String(result.headers[h])).substring(0, 80) + '</div>';
                    }}
                }}
            }}

            // ── Security Analysis ─────────────────────────────────────────────
            if (result.security_analysis && typeof result.security_analysis === 'object') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔒 Security Analysis</div>';
                const sec = result.security_analysis;
                if (sec.score_pct !== undefined) {{
                    const scoreColor = sec.score_pct >= 80 ? '#3fb950' : sec.score_pct >= 50 ? '#d29922' : '#f85149';
                    html += '<div style="color:' + scoreColor + ';margin-left:8px;font-size:9px;font-weight:600;">• Security Score: ' + sec.score_pct + '%</div>';
                }}
                if (sec.present && Object.keys(sec.present).length > 0) {{
                    html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• ✓ ' + Object.keys(sec.present).length + ' security headers present</div>';
                }}
                if (sec.missing && sec.missing.length > 0) {{
                    html += '<div style="color:#f85149;margin-left:8px;font-size:9px;">• ✗ ' + sec.missing.length + ' security headers missing</div>';
                }}
            }}

            // ── Link Extraction ───────────────────────────────────────────────
            if (result.links && Array.isArray(result.links) && result.links.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔗 Extracted Links (' + result.links.length + ')</div>';
                html += '<div style="color:#8b949e;font-size:9px;margin-left:8px;">• Internal: ' + (result.internal_count || 0) + ' | External: ' + (result.external_count || 0) + '</div>';
                for (const link of result.links.slice(0, 15)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(link).substring(0, 80) + '</div>';
                }}
                if (result.links.length > 15) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.links.length - 15) + ' more links</div>';
                }}
            }}

            // ── Analytics & Trackers ──────────────────────────────────────────
            if (result.analytics_ids && typeof result.analytics_ids === 'object') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📊 Analytics & Trackers (' + (result.total_trackers || 0) + ')</div>';
                for (const [trackerType, ids] of Object.entries(result.analytics_ids)) {{
                    if (Array.isArray(ids) && ids.length > 0) {{
                        html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#79c0ff;">' + graphEsc(trackerType) + '</span>: ' + ids.slice(0, 3).map(id => graphEsc(id)).join(', ') + '</div>';
                    }}
                }}
            }}
            if (result.technology_hints && result.technology_hints.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">⚙️ Technology Stack</div>';
                for (const tech of result.technology_hints.slice(0, 10)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(tech) + '</div>';
                }}
            }}

            // ── Social Media Profiles ─────────────────────────────────────────
            if (result.social_profiles && typeof result.social_profiles === 'object' && Object.keys(result.social_profiles).length > 0) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📱 Social Profiles (' + (result.platform_count || 0) + ' platforms)</div>';
                for (const [platform, urls] of Object.entries(result.social_profiles)) {{
                    if (Array.isArray(urls) && urls.length > 0) {{
                        html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#79c0ff;">' + graphEsc(platform) + '</span>: ' + urls.slice(0, 2).map(u => graphEsc(u).substring(0, 50)).join(', ') + '</div>';
                    }}
                }}
            }}
            if (result.email_addresses && result.email_addresses.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📧 Email Addresses (' + result.email_addresses.length + ')</div>';
                for (const email of result.email_addresses.slice(0, 10)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(email) + '</div>';
                }}
            }}

            // ── Open Graph / Twitter Meta ─────────────────────────────────────
            if (result.og_meta_tags && Object.keys(result.og_meta_tags).length > 0) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔖 Open Graph Meta</div>';
                for (const [key, val] of Object.entries(result.og_meta_tags)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(key) + ': ' + graphEsc(String(val)).substring(0, 80) + '</div>';
                }}
            }}

            // ── OS Detection (Nmap) ───────────────────────────────────────────
            if (result.os_guesses && result.os_guesses.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">💻 OS Detection Guesses</div>';
                for (const guess of result.os_guesses.slice(0, 5)) {{
                    const desc = typeof guess === 'object' ? (guess.description || guess.os || 'Unknown') : guess;
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(String(desc)).substring(0, 100) + '</div>';
                }}
            }}

            // ── ASN Information ───────────────────────────────────────────────
            if (result.asn || result.asn_cidr || result.asn_description) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🏢 ASN Information</div>';
                if (result.asn) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ASN: <span style="color:#f0883e;">' + graphEsc(result.asn) + '</span></div>';
                if (result.asn_description) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Description: ' + graphEsc(result.asn_description) + '</div>';
                if (result.asn_cidr) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• CIDR: ' + graphEsc(result.asn_cidr) + '</div>';
                if (result.asn_country_code) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Country: ' + graphEsc(result.asn_country_code) + '</div>';
                if (result.asn_registry) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Registry: ' + graphEsc(result.asn_registry) + '</div>';
                if (result.network_name) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Network: ' + graphEsc(result.network_name) + '</div>';
            }}

            // ── Subnet Information ────────────────────────────────────────────
            if (result.network_address || result.cidr) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📐 Subnet Information</div>';
                if (result.network_address) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Network: <span style="color:#f0883e;">' + graphEsc(result.network_address) + '</span></div>';
                if (result.broadcast_address) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Broadcast: ' + graphEsc(result.broadcast_address) + '</div>';
                if (result.netmask) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Netmask: ' + graphEsc(result.netmask) + '</div>';
                if (result.prefix_length !== undefined) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Prefix Length: /' + result.prefix_length + '</div>';
                if (result.num_addresses) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Total addresses: ' + result.num_addresses + '</div>';
                if (result.num_usable_hosts !== undefined) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Usable hosts: ' + result.num_usable_hosts + '</div>';
                if (result.first_host) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• First host: ' + graphEsc(result.first_host) + '</div>';
                if (result.last_host) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Last host: ' + graphEsc(result.last_host) + '</div>';
            }}

            // ── Banner Grabbing ───────────────────────────────────────────────
            if (result.results && Array.isArray(result.results) && result.results.length && result.results[0].banner !== undefined) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🏷️ Service Banners</div>';
                for (const banner of result.results.slice(0, 15)) {{
                    const port = banner.port || '?';
                    const svc = banner.service || '';
                    const text = banner.banner || banner.error || 'No response';
                    const color = banner.banner ? '#3fb950' : '#f85149';
                    html += '<div style="color:' + color + ';margin-left:8px;font-size:9px;">• Port <span style="color:#f0883e;">' + port + '</span>' + (svc ? '/' + svc : '') + ': ' + graphEsc(String(text)).substring(0, 100) + '</div>';
                }}
            }}

            // ── Alive Hosts (Fping) ───────────────────────────────────────────
            if (result.alive_hosts && result.alive_hosts.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📡 Alive Hosts (' + result.alive_count + ')</div>';
                for (const host of result.alive_hosts.slice(0, 20)) {{
                    html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• ' + graphEsc(host) + '</div>';
                }}
                if (result.alive_hosts.length > 20) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.alive_hosts.length - 20) + ' more</div>';
                }}
            }}

            // ── Discovered Hosts (Netdiscover) ────────────────────────────────
            if (result.discovered_hosts && result.discovered_hosts.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔎 Discovered Hosts (' + result.host_count + ')</div>';
                for (const host of result.discovered_hosts.slice(0, 15)) {{
                    const ip = host.ip || '?';
                    const mac = host.mac || '';
                    const vendor = host.vendor || '';
                    const reqCount = host.requests || '';
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• <span style="color:#f0883e;">' + ip + '</span>' + (mac ? ' / ' + mac : '') + (vendor ? ' <span style="color:#8b949e;font-size:8px;">(' + graphEsc(vendor).substring(0, 40) + ')</span>' : '') + (reqCount ? ' <span style="color:#79c0ff;font-size:8px;">[' + reqCount + ' pkts]</span>' : '') + '</div>';
                }}
                if (result.discovered_hosts.length > 15) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.discovered_hosts.length - 15) + ' more hosts</div>';
                }}
            }}

            // ── UPnP Devices ──────────────────────────────────────────────────
            if (result.upnp_devices && result.device_count) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔌 UPnP Devices (' + result.device_count + ')</div>';
                for (const device of result.upnp_devices.slice(0, 10)) {{
                    const type = device.device_type || device.DeviceType || 'Unknown';
                    const manufacturer = device.manufacturer || device.Manufacturer || '';
                    const model = device.model || device.Model || '';
                    const modelNum = device.model_number || device.ModelNumber || '';
                    const friendly = device.friendly_name || device.FriendlyName || '';
                    const label = friendly || (manufacturer ? manufacturer + ' ' + model : type);
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(label) + (modelNum ? ' <span style="color:#8b949e;font-size:8px;">[' + graphEsc(modelNum) + ']</span>' : '') + '</div>';
                }}
                if (result.internal_ips_found && result.internal_ips_found.length) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• Internal IPs: ' + result.internal_ips_found.slice(0, 5).map(ip => '<span style="color:#f0883e;">' + graphEsc(ip) + '</span>').join(', ') + '</div>';
                }}
            }}

            // ── Reverse IP Domains ────────────────────────────────────────────
            if (result.domains && Array.isArray(result.domains) && result.domains.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔄 Domains on IP (' + result.count + ')</div>';
                for (const domain of result.domains.slice(0, 20)) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(domain) + '</div>';
                }}
                if (result.domains.length > 20) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.domains.length - 20) + ' more</div>';
                }}
            }}

            // ── Traceroute (Parse raw output) ─────────────────────────────────
            if (result.output && (result.host || result.max_hops !== undefined) && !result.reachable && !result.success) {{
                const output = result.output;
                const isTraceroute = output.includes('traceroute') || output.includes('tracert') ||
                                     result.max_hops !== undefined ||
                                     (output.match(/^\s*\d+\s+/m) && output.includes('ms'));

                if (isTraceroute) {{
                    html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🗺️ Traceroute</div>';
                    html += '<div style="color:#8b949e;font-size:9px;margin-left:8px;">Target: <span style="color:#c9d1d9;">' + graphEsc(result.host || 'Unknown') + '</span> (max hops: ' + (result.max_hops || 30) + ')</div>';

                    const lines = output.split('\\n');
                    let hopsFound = 0;
                    for (const line of lines) {{
                        if (/^\s*\d+/.test(line) && line.includes('ms')) {{
                            hopsFound++;
                            if (hopsFound <= 15) {{
                                const hopMatch = line.match(/^\s*(\d+)\s+(.+?)\s+(\d+\.?\d*)\s*ms/);
                                if (hopMatch) {{
                                    const hopNum = hopMatch[1];
                                    const hopInfo = hopMatch[2];
                                    const hopTime = hopMatch[3];
                                    const ipMatch = hopInfo.match(/(\d+\.\d+\.\d+\.\d+)/);
                                    const hostnameMatch = hopInfo.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}})/);

                                    if (ipMatch) {{
                                        html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Hop <span style="color:#f0883e;">' + hopNum + '</span>: <span style="color:#79c0ff;">' + ipMatch[1] + '</span>' + (hostnameMatch ? ' <span style="color:#8b949e;font-size:8px;">(' + graphEsc(hostnameMatch[1]) + ')</span>' : '') + ' (' + hopTime + 'ms)</div>';
                                    }} else if (hostnameMatch) {{
                                        html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• Hop ' + hopNum + ': ' + graphEsc(hostnameMatch[1]) + ' (' + hopTime + 'ms)</div>';
                                    }} else {{
                                        html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• Hop ' + hopNum + ': ' + graphEsc(hopInfo.trim().substring(0, 50)) + ' (' + hopTime + 'ms)</div>';
                                    }}
                                }}
                            }}
                        }}
                    }}
                    if (hopsFound === 0) {{
                        html += '<div style="color:#f85149;margin-left:8px;font-size:9px;">✗ No hops found in output</div>';
                    }} else {{
                        html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;margin-top:4px;">✓ Total hops: ' + hopsFound + '</div>';
                        if (hopsFound > 15) {{
                            html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (hopsFound - 15) + ' more hops</div>';
                        }}
                    }}
                }}
            }}

            // ── Ping Results (Parse raw output) ───────────────────────────────
            if (result.output && result.count !== undefined && (result.reachable !== undefined || result.success !== undefined)) {{
                const output = result.output;
                const isPing = output.includes('ping') || output.includes('icmp') ||
                              (result.reachable !== undefined && result.count !== undefined);

                if (isPing) {{
                    const isReachable = result.reachable !== undefined ? result.reachable : (result.success || false);
                    html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📡 Ping Results</div>';
                    html += '<div style="color:#8b949e;font-size:9px;margin-left:8px;">Target: <span style="color:#c9d1d9;">' + graphEsc(result.host || 'Unknown') + '</span></div>';
                    html += '<div style="color:' + (isReachable ? '#3fb950' : '#f85149') + ';margin-left:8px;font-size:9px;font-weight:600;">• Status: ' + (isReachable ? '✓ Reachable' : '✗ Unreachable') + '</div>';
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Packets sent: ' + result.count + '</div>';

                    // Try to extract packet statistics
                    const sentMatch = output.match(/(\d+)\s+packets?\s+transmitted/i);
                    const receivedMatch = output.match(/(\d+)\s+(received|received,)/i);
                    const lossMatch = output.match(/([\d.]+)%\s+packet\s+loss/i);

                    if (sentMatch) html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Transmitted: ' + sentMatch[1] + '</div>';
                    if (receivedMatch) html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• Received: ' + receivedMatch[1] + '</div>';
                    if (lossMatch) {{
                        const loss = parseFloat(lossMatch[1]);
                        const lossColor = loss === 0 ? '#3fb950' : loss < 50 ? '#d29922' : '#f85149';
                        html += '<div style="color:' + lossColor + ';margin-left:8px;font-size:9px;">• Packet loss: ' + lossMatch[1] + '%</div>';
                    }}

                    // Extract RTT statistics
                    const avgMatch = output.match(/avg[=\/ ]\s*(\d+\.?\d*)/i);
                    const minMatch = output.match(/min[=\/ ]\s*(\d+\.?\d*)/i);
                    const maxMatch = output.match(/max[=\/ ]\s*(\d+\.?\d*)/i);
                    const mdevMatch = output.match(/mdev[=\/ ]\s*(\d+\.?\d*)/i);

                    if (avgMatch) html += '<div style="color:#f0883e;margin-left:8px;font-size:9px;">• Avg RTT: ' + avgMatch[1] + 'ms</div>';
                    if (minMatch) html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">• Min RTT: ' + minMatch[1] + 'ms</div>';
                    if (maxMatch) html += '<div style="color:#f85149;margin-left:8px;font-size:9px;">• Max RTT: ' + maxMatch[1] + 'ms</div>';
                    if (mdevMatch) html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• Std Dev: ' + mdevMatch[1] + 'ms</div>';
                }}
            }}

            // ── Ports (Shodan string format) ──────────────────────────────────
            if (result.ports && Array.isArray(result.ports) && result.ports.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🔎 Shodan Ports (' + result.ports.length + ')</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">' + result.ports.slice(0, 20).map(p => '<span style="color:#f0883e;">' + p + '</span>').join(', ') + '</div>';
                if (result.ports.length > 20) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.ports.length - 20) + ' more</div>';
                }}
            }}

            // ── Tags (Shodan) ─────────────────────────────────────────────────
            if (result.tags && result.tags.length) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">🏷️ Tags</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + result.tags.map(t => graphEsc(t)).join(', ') + '</div>';
            }}

            // ── OS (Shodan string format) ─────────────────────────────────────
            if (result.os && typeof result.os === 'string') {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">⚙️ Operating System</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(result.os) + '</div>';
            }}

            // ── Bulk Scan Summary ─────────────────────────────────────────────
            if (result.total_targets !== undefined && result.targets) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📦 Bulk Scan Summary</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Total targets: ' + result.total_targets + '</div>';
                if (result.successful !== undefined) html += '<div style="color:#3fb950;margin-left:8px;font-size:9px;">✓ Success: ' + result.successful + '</div>';
                if (result.failed !== undefined) html += '<div style="color:#f85149;margin-left:8px;font-size:9px;">✗ Failed: ' + result.failed + '</div>';
                if (result.total_open_ports !== undefined) html += '<div style="color:#f0883e;margin-left:8px;font-size:9px;">🚪 Total open ports: ' + result.total_open_ports + '</div>';
                if (result.all_services && Object.keys(result.all_services).length) {{
                    html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• Top services: ' + Object.entries(result.all_services).slice(0, 5).map(([s, c]) => s + ' (' + c + ')').join(', ') + '</div>';
                }}
                if (result.all_ips && result.all_ips.length) {{
                    html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• Discovered IPs: ' + result.all_ips.slice(0, 10).map(ip => '<span style="color:#f0883e;">' + graphEsc(ip) + '</span>').join(', ') + '</div>';
                    if (result.all_ips.length > 10) {{
                        html += '<div style="color:#8b949e;margin-left:8px;font-size:9px;">• ... and ' + (result.all_ips.length - 10) + ' more IPs</div>';
                    }}
                }}
            }}

            // ── Generic scalar fields (only if not already shown) ─────────────
            const shownKeys = ['records','subdomains','nameservers','shared','hostnames','open_ports','results','cves','services','country','city','region','regionName','lat','lon','latitude','longitude','postal','timezone','isp','org','registrar','creation_date','expiration_date','whois','raw','headers','security_analysis','links','internal_count','external_count','analytics_ids','total_trackers','technology_hints','social_profiles','platform_count','email_addresses','og_meta_tags','twitter_meta_tags','ports','os','os_guesses','asn','asn_cidr','asn_description','asn_country_code','asn_registry','network_name','network_cidr','network_address','cidr','broadcast_address','netmask','num_addresses','num_usable_hosts','first_host','last_host','banners','alive_hosts','alive_count','discovered_hosts','host_count','upnp_devices','device_count','internal_ips_found','internal_ip_count','domains','count','output','max_hops','success','reachable','targets','error','host','preset','command','returncode','total_targets','successful','failed','total_open_ports','all_services','all_open_ports','all_ips','geolocations','service_list','os_list','hosts_by_os','hosts_by_service','ip','url','source','final_url','status_code','http_version','redirect_chain','server','content_type','powered_by','base_domain','total','filter_applied','total_trackers','tracker_type','last_update','tags','domain','methods','errors','ns_ips','port_spec','total_scanned','open_count','elapsed_seconds','ports_probed','note','prefix_length','ip_version','is_private','is_global','host_sample','queried','geolocation','reverse_dns','methods_used','count','retries','timeout_ms','rate','batch_size','resolved_target','target','os','description','preset','command','returncode','reachable','success'];
            for (const [k, v] of Object.entries(result)) {{
                if (shownKeys.includes(k)) continue;
                if (typeof v === 'object' && v !== null) continue;
                if (v === null || v === undefined) continue;
                const keyLabel = String(k).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:9px;">• ' + graphEsc(keyLabel) + ': <span style="color:#79c0ff;">' + graphEsc(String(v)) + '</span></div>';
            }}

            // ── Fallback: Show raw output ONLY if no structured data found ───
            const hasStructuredData = result.records || result.subdomains || result.open_ports || result.whois || result.headers || result.alive_hosts || result.discovered_hosts || result.upnp_devices || result.domains || result.links || result.analytics_ids || result.social_profiles || result.os_guesses || result.banners || result.cves || result.results;
            if (result.raw_output && !hasStructuredData) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📄 Raw Output (first 300 chars)</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:8px;white-space:pre-wrap;font-family:monospace;">' + graphEsc(result.raw_output).substring(0, 300) + '</div>';
            }}
            if (result.raw && !hasStructuredData && !result.whois) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📄 Raw Output (first 300 chars)</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:8px;white-space:pre-wrap;font-family:monospace;">' + graphEsc(result.raw).substring(0, 300) + '</div>';
            }}
            if (result.output && !hasStructuredData && !result.reachable && !result.success) {{
                html += '<div style="color:#58a6ff;font-weight:600;margin:6px 0 3px;">📄 Raw Output (first 300 chars)</div>';
                html += '<div style="color:#c9d1d9;margin-left:8px;font-size:8px;white-space:pre-wrap;font-family:monospace;">' + graphEsc(result.output).substring(0, 300) + '</div>';
            }}

            html += '</div></div>';
            return html;
        }}

        function graphRenderTracerouteBubbles() {{
            // Find all hop nodes and render them as a visual path
            if (!graphCy) return;
            
            const hopNodes = graphCy.nodes().filter(n => n.data('type') === 'hop');
            if (hopNodes.length === 0) return;
            
            // Sort hops by hop_number
            const sortedHops = hopNodes.sort((a, b) => {{
                return (a.data('hop_number') || 0) - (b.data('hop_number') || 0);
            }});
            
            // Add visual path markers to edges between hops
            const hopEdges = graphCy.edges().filter(e => {{
                const src = e.source().data('type');
                const tgt = e.target().data('type');
                return (src === 'hop' || src === 'target') && tgt === 'hop';
            }});
            
            // Style hop edges with dashed lines and arrows
            hopEdges.style({{
                'line-color': '#d2a8ff',
                'width': 3,
                'line-style': 'dashed',
                'target-arrow-color': '#d2a8ff',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
            }});
            
            // Add hop number labels to edges
            hopEdges.forEach(edge => {{
                const label = edge.data('label') || '';
                if (label.includes('hop')) {{
                    edge.style({{
                        'label': label,
                        'color': '#d2a8ff',
                        'font-size': '10px',
                        'text-opacity': 0.8,
                        'text-background-color': '#161b22',
                        'text-background-opacity': 0.7,
                        'text-background-padding': '2px',
                        'text-background-shape': 'roundrectangle',
                    }});
                }}
            }});
            
            // Style hop nodes as glowing bubbles
            sortedHops.forEach((node, index) => {{
                const responseTime = node.data('response_time');
                let glowColor = '#d2a8ff';
                let glowSize = 20;
                
                // Color based on response time
                if (responseTime) {{
                    const ms = parseFloat(responseTime);
                    if (ms < 10) {{
                        glowColor = '#3fb950'; // Fast - green
                        glowSize = 15;
                    }} else if (ms < 50) {{
                        glowColor = '#d2a8ff'; // Medium - purple
                        glowSize = 20;
                    }} else if (ms < 100) {{
                        glowColor = '#ffa657'; // Slow - orange
                        glowSize = 25;
                    }} else {{
                        glowColor = '#f85149'; // Very slow - red
                        glowSize = 30;
                    }}
                }}
                
                node.style({{
                    'background-color': glowColor,
                    'border-color': glowColor,
                    'border-width': 3,
                    'background-opacity': 0.9,
                    'label': node.data('label'),
                    'color': '#ffffff',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '11px',
                    'font-weight': 'bold',
                    'text-outline-color': '#000000',
                    'text-outline-width': 2,
                    'text-outline-opacity': 0.8,
                    'width': 40 + (index * 2),  // Slightly increase size for each hop
                    'height': 40 + (index * 2),
                }});
            }});
            
            // Style the target node differently
            const targetNode = graphCy.nodes().filter(n => n.data('type') === 'target');
            if (targetNode.length > 0) {{
                targetNode.style({{
                    'background-color': '#1f6feb',
                    'border-color': '#58a6ff',
                    'border-width': 4,
                    'width': 50,
                    'height': 50,
                }});
            }}
        }}

        function closeGraphDetail() {{
            const panel = document.getElementById('graph-detail-panel');
            if (panel) panel.classList.remove('open');
        }}

        function graphGetConnections(nodeId) {{
            if (!graphCy) return [];
            return graphCy.getElementById(nodeId).neighborhood('node').map(n => n.data());
        }}

        function graphFocusNode(nodeId) {{
            if (!graphCy) return;
            const node = graphCy.getElementById(nodeId);
            graphCy.animate({{
                fit: {{ eles: node.closedNeighborhood(), padding: 80 }},
                duration: 500,
                easing: 'ease-in-out'
            }});
            node.emit('tap');
        }}

        function graphFocusNodeConn(el) {{
            const nodeId = el.getAttribute('data-target-id');
            if (nodeId) graphFocusNode(nodeId);
        }}

        function graphEsc(s) {{
            return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }}

        // Detail panel copy helpers
        function graphCopyDPLabel(btn) {{
            if (!graphCy || !graphCy.nodes().length) return;
            const node = graphCy.nodes().filter(n => n.selected())[0];
            if (node) {{
                graphCopyText(node.data('label'), btn);
            }}
            btn.textContent = '✓';
            setTimeout(() => {{ btn.textContent = '⎘ Copy Value'; }}, 1800);
        }}

        function graphCopyDPDetail(btn) {{
            if (!graphCy || !graphCy.nodes().length) return;
            const node = graphCy.nodes().filter(n => n.selected())[0];
            if (node) {{
                graphCopyText(node.data('tooltip'), btn);
            }}
            btn.textContent = '✓';
            setTimeout(() => {{ btn.textContent = '⎘ Copy Detail'; }}, 1800);
        }}

        function graphCopyDPJSON(btn) {{
            if (!graphCy || !graphCy.nodes().length) return;
            const node = graphCy.nodes().filter(n => n.selected())[0];
            if (node) {{
                const d = node.data();
                const json = JSON.stringify({{type:d.type, label:d.label, detail:d.tooltip}}, null, 2);
                graphCopyText(json, btn);
            }}
            btn.textContent = '✓';
            setTimeout(() => {{ btn.textContent = '⎘ Copy JSON'; }}, 1800);
        }}

        function graphSetStatus(msg) {{
            const el = document.getElementById('graph-status-text');
            if (el) el.textContent = msg;
        }}

        // Cytoscape init
        function initGraph() {{
            const elements = graphCurrentElements;
            const loadEl = document.getElementById('graph-loading');

            graphCy = cytoscape({{
                container: document.getElementById('graph-cy'),
                elements: elements,
                style: [
                    {{
                        selector: 'node',
                        style: {{
                            'background-color':        'data(bg)',
                            'border-color':            'data(border)',
                            'border-width':            2,
                            'width':                   'data(size)',
                            'height':                  'data(size)',
                            'shape':                   'data(shape)',
                            'label':                   'data(label)',
                            'color':                   'data(textColor)',
                            'font-size':               10,
                            'font-family':             'Segoe UI, sans-serif',
                            'text-valign':             'bottom',
                            'text-halign':             'center',
                            'text-margin-y':           4,
                            'text-max-width':          90,
                            'text-wrap':               'ellipsis',
                            'text-background-color':   '#0d1117',
                            'text-background-opacity': 0.75,
                            'text-background-padding': '2px',
                            'text-background-shape':   'roundrectangle',
                            'overlay-opacity':         0,
                            'transition-property':     'background-color, border-color, border-width, width, height',
                            'transition-duration':     '0.25s',
                            'transition-timing-function': 'ease-in-out',
                        }}
                    }},
                    {{
                        selector: 'node:selected',
                        style: {{
                            'border-width':    3,
                            'border-color':    '#ffffff',
                            'overlay-opacity': 0.08,
                            'overlay-color':   '#58a6ff',
                        }}
                    }},
                    {{
                        selector: 'node:active',
                        style: {{ 'overlay-opacity': 0.12 }}
                    }},
                    {{
                        selector: 'edge',
                        style: {{
                            'width':              1.5,
                            'line-color':         '#30363d',
                            'target-arrow-color': '#30363d',
                            'target-arrow-shape': 'triangle',
                            'arrow-scale':        0.8,
                            'curve-style':        'bezier',
                            'label':              'data(label)',
                            'font-size':          9,
                            'color':              '#484f58',
                            'text-background-color':   '#0d1117',
                            'text-background-opacity': 0.8,
                            'text-background-padding': '2px',
                            'opacity':            0.7,
                        }}
                    }},
                    {{
                        selector: 'edge:selected',
                        style: {{ 'line-color':'#58a6ff', 'target-arrow-color':'#58a6ff', 'opacity':1 }}
                    }},
                    {{
                        selector: '.highlighted',
                        style: {{ 'border-color':'#ffffff', 'border-width':3, 'opacity':1 }}
                    }},
                    {{
                        selector: '.faded',
                        style: {{ 'opacity': 0.15 }}
                    }}
                ],
                layout: {{
                    name: 'cose',
                    animate: true,
                    animationDuration: 1200,
                    animationEasing: function(pos) {{
                        // Custom easing for ultra-smooth animation
                        return pos < 0.5
                            ? 4 * pos * pos * pos
                            : 1 - Math.pow(-2 * pos + 2, 3) / 2;
                    }},
                    randomize: true,
                    nodeRepulsion: 14000,
                    idealEdgeLength: 140,
                    edgeElasticity: 250,
                    gravity: 0.2,
                    numIter: 800,
                    nodeDimensionsIncludeLabels: true,
                    fit: true,
                    padding: 80,
                    tile: true,
                    avoidOverlap: true,
                }},
                minZoom: 0.1,
                maxZoom: 4,
                wheelSensitivity: 0.3,
            }});

            graphCy.one('layoutstop', () => {{
                if (loadEl) loadEl.style.display = 'none';
                graphSetStatus('Graph loaded — ' + graphCy.nodes().length + ' nodes, ' + graphCy.edges().length + ' edges');
                
                // Render traceroute bubbles if hop nodes exist
                graphRenderTracerouteBubbles();
            }});

            // Tooltip
            const tooltip = document.getElementById('graph-tooltip');
            graphCy.on('mouseover', 'node', function(e) {{
                const d = e.target.data();
                const c = GRAPH_COLOR_MAP[d.type] || GRAPH_COLOR_MAP.default;
                document.getElementById('graph-tt-type').textContent  = d.type.toUpperCase();
                document.getElementById('graph-tt-type').style.color  = c.border;
                document.getElementById('graph-tt-label').textContent = d.label;
                document.getElementById('graph-tt-tip').textContent   = d.tooltip || '';
                if (tooltip) tooltip.style.display = 'block';
            }});
            graphCy.on('mouseout', 'node', () => {{ if (tooltip) tooltip.style.display = 'none'; }});
            graphCy.on('mousemove', function(e) {{
                if (tooltip) {{
                    tooltip.style.left = (e.originalEvent.clientX + 14) + 'px';
                    tooltip.style.top  = (e.originalEvent.clientY - 10) + 'px';
                }}
            }});

            // Click: highlight neighbourhood + open detail panel
            graphCy.on('tap', 'node', function(e) {{
                const node = e.target;
                const d = node.data();
                graphCy.elements().removeClass('highlighted faded');
                const connected = node.closedNeighborhood();
                graphCy.elements().not(connected).addClass('faded');
                connected.addClass('highlighted');
                node.removeClass('faded');

                const infoEl = document.getElementById('graph-node-info');
                if (infoEl) infoEl.textContent = (d.icon || '●') + '  ' + d.label + '  [' + d.type + ']';

                document.querySelectorAll('.graph-node-card').forEach(c => c.classList.remove('selected'));
                const card = document.getElementById('graph-card-' + d.id);
                if (card) {{ card.classList.add('selected'); card.scrollIntoView({{block:'nearest'}}); }}

                graphOpenDetail(d);
            }});

            graphCy.on('tap', function(e) {{
                if (e.target === graphCy) {{
                    graphCy.elements().removeClass('highlighted faded');
                    const infoEl = document.getElementById('graph-node-info');
                    if (infoEl) infoEl.textContent = '';
                    document.querySelectorAll('.graph-node-card').forEach(c => c.classList.remove('selected'));
                    closeGraphDetail();
                }}
            }});

            document.addEventListener('keydown', function(ev) {{
                if (!graphCy) return;
                if (ev.key === 'f' || ev.key === 'F') graphCy.fit(60);
                if (ev.key === '+') graphCy.zoom(graphCy.zoom() * 1.2);
                if (ev.key === '-') graphCy.zoom(graphCy.zoom() / 1.2);
            }});
        }}

        document.addEventListener('DOMContentLoaded', function() {{
            graphBuildSidebar(graphCurrentElements);
            initGraph();
            graphBuildModuleList();
        }});

        // ── Module Loader Functions ──
        let graphSelectedModules = new Set();
        let graphAllResults = [];

        function graphBuildModuleList() {{
            if (typeof ALL_SCAN_RESULTS === 'undefined' || !ALL_SCAN_RESULTS.length) {{
                const list = document.getElementById('graph-module-list');
                if (list) list.innerHTML = '<p style="color:#8b949e;font-size:12px;text-align:center;padding:20px;">No scan results available to load.</p>';
                return;
            }}

            graphAllResults = ALL_SCAN_RESULTS.map((entry, idx) => ({{ ...entry, _orig_idx: idx }}));
            const totalCount = document.getElementById('graph-total-count');
            if (totalCount) totalCount.textContent = graphAllResults.length;

            graphRenderModuleList(graphAllResults);
            graphUpdateSelectedCount();
        }}

        function graphRenderModuleList(results) {{
            const list = document.getElementById('graph-module-list');
            if (!list) return;

            // Group results by tool category
            const categories = {{}};
            results.forEach((entry, idx) => {{
                const tool = entry.tool || 'Unknown';
                const category = graphGetToolCategory(tool);
                if (!categories[category]) {{
                    categories[category] = {{
                        icon: graphGetCategoryIcon(category),
                        items: []
                    }};
                }}
                entry._orig_idx = entry._orig_idx !== undefined ? entry._orig_idx : idx;
                categories[category].items.push(entry);
            }});

            let html = '';
            const categoryKeys = Object.keys(categories);
            
            if (categoryKeys.length === 0) {{
                html = '<p style="color:#8b949e;font-size:12px;text-align:center;padding:20px;">No matching results.</p>';
            }} else {{
                categoryKeys.forEach((catName, catIdx) => {{
                    const cat = categories[catName];
                    const catId = 'graph-cat-' + catIdx;
                    const isSelected = cat.items.every(entry => graphSelectedModules.has(entry._orig_idx));
                    const isPartial = cat.items.some(entry => graphSelectedModules.has(entry._orig_idx)) && !isSelected;
                    
                    html += '<div class="graph-module-category">';
                    html += '<div class="graph-module-category-header" onclick="graphToggleCategory(\\'' + catId + '\\')">';
                    html += '<span class="graph-module-category-arrow" id="' + catId + '-arrow">▶</span>';
                    html += '<span class="graph-module-category-icon">' + cat.icon + '</span>';
                    html += '<span class="graph-module-category-title">' + catName + '</span>';
                    html += '<span class="graph-module-category-count">' + cat.items.length + '</span>';
                    html += '<div class="graph-module-category-checkbox" onclick="event.stopPropagation();">';
                    html += '<input type="checkbox" id="' + catId + '-checkbox" ' + (isSelected ? 'checked' : '') + 
                            ' onclick="graphToggleCategoryCheck(\\'' + catId + '\\', this.checked)"' +
                            (isPartial ? ' style="opacity:0.5"' : '') + '>';
                    html += '</div></div>';
                    
                    html += '<div class="graph-module-category-body" id="' + catId + '-body">';
                    cat.items.forEach((entry) => {{
                        const origIdx = entry._orig_idx;
                        const tool = entry.tool || 'Unknown';
                        const target = entry.target || 'N/A';
                        const isSelected = graphSelectedModules.has(origIdx);

                        html += '<div class="graph-module-item' + (isSelected ? ' selected' : '') + '" data-idx="' + origIdx + '" onclick="graphToggleModule(' + origIdx + ', this)">' +
                            '<div style="flex:1;min-width:0;">' +
                                '<div style="font-size:13px;font-weight:600;color:#c9d1d9;">' + graphEsc(tool) + '</div>' +
                                '<div style="font-size:11px;color:#8b949e;margin-top:2px;">' + graphEsc(target) + '</div>' +
                            '</div>' +
                            '<div style="color:' + (isSelected ? '#3fb950' : '#484f58') + ';font-size:16px;font-weight:bold;">' + (isSelected ? '✓' : '☐') + '</div>' +
                            '</div>';
                    }});
                    html += '</div></div>';
                }});
            }}
            list.innerHTML = html;
        }}

        function graphGetToolCategory(toolName) {{
            const tool = toolName.toLowerCase();
            if (tool.includes('dns') && !tool.includes('bulk')) return 'DNS Tools';
            if (tool.includes('subdomain')) return 'DNS Tools';
            if (tool.includes('ping') && !tool.includes('bulk')) return 'Network Tools';
            if (tool.includes('traceroute') || tool.includes('trace')) return 'Network Tools';
            if (tool.includes('port') || tool.includes('scan')) return 'Network Tools';
            if (tool.includes('banner')) return 'Network Tools';
            if (tool.includes('whois')) return 'WHOIS & ASN';
            if (tool.includes('asn')) return 'WHOIS & ASN';
            if (tool.includes('geo') || tool.includes('ip')) return 'IP Information';
            if (tool.includes('http') || tool.includes('link') || tool.includes('analytics') || tool.includes('social')) return 'Web Tools';
            if (tool.includes('nmap') || tool.includes('rustscan') || tool.includes('masscan') || tool.includes('upnp')) return 'External Tools';
            if (tool.includes('fping') || tool.includes('netdiscover')) return 'External Tools';
            if (tool.includes('bulk') || tool.includes('generator')) return 'Bulk Tools';
            return 'Other Tools';
        }}

        function graphGetCategoryIcon(category) {{
            const icons = {{
                'DNS Tools': '🌐',
                'Network Tools': '🔌',
                'WHOIS & ASN': '📋',
                'IP Information': '🌍',
                'Web Tools': '🕸️',
                'External Tools': '🛠️',
                'Bulk Tools': '📦',
                'Other Tools': '🔧'
            }};
            return icons[category] || '🔧';
        }}

        function graphToggleCategory(catId) {{
            const body = document.getElementById(catId + '-body');
            const arrow = document.getElementById(catId + '-arrow');
            if (body.classList.contains('expanded')) {{
                body.classList.remove('expanded');
                arrow.classList.remove('expanded');
            }} else {{
                body.classList.add('expanded');
                arrow.classList.add('expanded');
            }}
        }}

        function graphToggleCategoryCheck(catId, checked) {{
            const body = document.getElementById(catId + '-body');
            const items = body.querySelectorAll('.graph-module-item');
            items.forEach(item => {{
                const idx = parseInt(item.getAttribute('data-idx'));
                if (checked) {{
                    graphSelectedModules.add(idx);
                    item.classList.add('selected');
                    item.querySelector('div:last-child').textContent = '✓';
                    item.querySelector('div:last-child').style.color = '#3fb950';
                }} else {{
                    graphSelectedModules.delete(idx);
                    item.classList.remove('selected');
                    item.querySelector('div:last-child').textContent = '☐';
                    item.querySelector('div:last-child').style.color = '#484f58';
                }}
            }});
            graphUpdateSelectedCount();
        }}

        function graphToggleModule(idx, el) {{
            if (graphSelectedModules.has(idx)) {{
                graphSelectedModules.delete(idx);
                el.classList.remove('selected');
            }} else {{
                graphSelectedModules.add(idx);
                el.classList.add('selected');
            }}
            graphUpdateSelectedCount();
        }}

        function graphUpdateSelectedCount() {{
            const countEl = document.getElementById('graph-selected-count');
            const btn = document.getElementById('graph-btn-load');
            if (countEl) countEl.textContent = graphSelectedModules.size;
            if (btn) btn.disabled = graphSelectedModules.size === 0;
        }}

        function graphSelectAllModules() {{
            graphAllResults.forEach(entry => {{
                graphSelectedModules.add(entry._orig_idx);
            }});
            graphRenderModuleList(graphAllResults);
            // Expand all categories when selecting all
            document.querySelectorAll('.graph-module-category-body').forEach(body => {{
                body.classList.add('expanded');
            }});
            document.querySelectorAll('.graph-module-category-arrow').forEach(arrow => {{
                arrow.classList.add('expanded');
            }});
            graphUpdateSelectedCount();
        }}

        function graphDeselectAllModules() {{
            graphSelectedModules.clear();
            graphRenderModuleList(graphAllResults);
            graphUpdateSelectedCount();
        }}

        function graphFilterModules(query) {{
            const q = (query || '').toLowerCase().trim();
            if (!q) {{
                graphRenderModuleList(graphAllResults);
                return;
            }}
            const filtered = graphAllResults.filter(entry =>
                (entry.tool || '').toLowerCase().includes(q) ||
                (entry.target || '').toLowerCase().includes(q)
            );
            graphRenderModuleList(filtered);
        }}

        function graphLoadSelectedModules() {{
            if (graphSelectedModules.size === 0) {{
                graphShowToast('No modules selected');
                return;
            }}

            const selected = Array.from(graphSelectedModules).map(idx => ALL_SCAN_RESULTS[idx]);
            let allNodes = [], allEdges = [];

            selected.forEach(entry => {{
                const tool = entry.tool || 'Unknown';
                const target = entry.target || '';
                const result = entry.result || {{}};

                // Extract using GraphExtractor logic (simplified inline)
                const targetId = graphMakeId(target);
                if (!allNodes.find(n => n.id === targetId)) {{
                    allNodes.push({{ id: targetId, label: target, type: 'target', tooltip: 'Scan target: ' + target }});
                }}

                if (typeof result.records !== 'undefined') {{
                    ['A','AAAA','MX','NS','TXT','CNAME'].forEach(rtype => {{
                        (result.records[rtype] || []).forEach(val => {{
                            const nodeId = graphMakeId(rtype + '_' + val);
                            allNodes.push({{ id: nodeId, label: val, type: rtype.toLowerCase(), tooltip: rtype + ': ' + val }});
                            allEdges.push({{ src: targetId, dst: nodeId, label: rtype }});
                        }});
                    }});
                }}

                // Handle bulk scan targets
                if (result.targets) {{
                    Object.entries(result.targets).forEach(([t, tr]) => {{
                        const tId = graphMakeId('bulk_' + t);
                        allNodes.push({{ id: tId, label: t, type: 'target', tooltip: 'Bulk: ' + t }});
                        allEdges.push({{ src: targetId, dst: tId, label: 'target' }});
                        if (tr.records) {{
                            ['A','AAAA','MX','NS','TXT'].forEach(rtype => {{
                                (tr.records[rtype] || []).forEach(val => {{
                                    const nId = graphMakeId(rtype + '_' + val);
                                    allNodes.push({{ id: nId, label: val, type: rtype.toLowerCase(), tooltip: rtype + ': ' + val }});
                                    allEdges.push({{ src: tId, dst: nId, label: rtype }});
                                }});
                            }});
                        }}
                        if (tr.open_ports) {{
                            tr.open_ports.forEach(p => {{
                                const port = typeof p === 'object' ? p.port : p;
                                const pId = graphMakeId('port_' + port);
                                allNodes.push({{ id: pId, label: 'Port ' + port, type: 'port', tooltip: 'Port ' + port }});
                                allEdges.push({{ src: tId, dst: pId, label: 'open' }});
                            }});
                        }}
                    }});
                }}

                if (result.open_ports) {{
                    result.open_ports.forEach(p => {{
                        const port = typeof p === 'object' ? p.port : p;
                        const service = typeof p === 'object' ? (p.service || 'unknown') : 'unknown';
                        const portId = graphMakeId('port_' + port);
                        allNodes.push({{ id: portId, label: port + '/' + service, type: 'port', tooltip: 'Port ' + port }});
                        allEdges.push({{ src: targetId, dst: portId, label: 'open' }});
                    }});
                }}

                if (result.country || result.city) {{
                    const loc = (result.city || '') + (result.city && result.country ? ', ' : '') + (result.country || '');
                    const locId = graphMakeId('geo_' + loc);
                    allNodes.push({{ id: locId, label: loc, type: 'geo', tooltip: 'Location: ' + loc }});
                    allEdges.push({{ src: targetId, dst: locId, label: 'located in' }});
                }}

                // Shodan CVEs
                if (result.cves) {{
                    result.cves.forEach(cve => {{
                        const cId = graphMakeId('cve_' + cve);
                        allNodes.push({{ id: cId, label: cve, type: 'tracker', tooltip: 'CVE: ' + cve }});
                        allEdges.push({{ src: targetId, dst: cId, label: 'CVE' }});
                    }});
                }}

                // Shodan ports
                if (result.ports) {{
                    result.ports.forEach(p => {{
                        const pId = graphMakeId('shodan_p_' + p);
                        allNodes.push({{ id: pId, label: 'Port ' + p, type: 'port', tooltip: 'Shodan port: ' + p }});
                        allEdges.push({{ src: targetId, dst: pId, label: 'Shodan' }});
                    }});
                }}
            }});

            // Update graph
            graphCurrentElements = [];
            allNodes.forEach(n => {{
                const colors = GRAPH_COLOR_MAP[n.type] || GRAPH_COLOR_MAP.default;
                graphCurrentElements.push({{
                    data: {{
                        id: n.id, label: n.label, type: n.type, tooltip: n.tooltip,
                        bg: colors.bg, border: colors.border, textColor: colors.border,
                        size: n.type === 'target' ? 54 : (n.type === 'port' ? 32 : 28),
                        shape: 'ellipse', icon: '●'
                    }}
                }});
            }});
            allEdges.forEach(e => {{
                graphCurrentElements.push({{
                    data: {{ id: 'e_' + e.src + '_' + e.dst, source: e.src, target: e.dst, label: e.label }}
                }});
            }});

            // Reload cytoscape
            if (graphCy) {{
                graphCy.destroy();
                initGraph();
            }}

            graphBuildSidebar(graphCurrentElements);
            graphShowToast('Loaded ' + graphSelectedModules.size + ' module(s)');
            graphSelectedModules.clear();
            graphBuildModuleList();
            graphHideModuleLoader();
        }}

        function graphShowModuleLoader() {{
            const loader = document.getElementById('graph-module-loader');
            if (loader) loader.style.display = 'block';
        }}

        function graphHideModuleLoader() {{
            const loader = document.getElementById('graph-module-loader');
            if (loader) loader.style.display = 'none';
        }}

        function graphMakeId(text) {{
            return String(text || '').toLowerCase().replace(/[^a-z0-9._-]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '') || 'unknown';
        }}
        '''

