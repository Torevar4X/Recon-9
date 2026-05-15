"""
Workers Module
QThread-based workers that run OSINT scans in the background,
keeping the PyQt6 GUI responsive at all times.
"""

import traceback
from typing import Any, Callable, Dict

from PyQt6.QtCore import QThread, pyqtSignal


# ─────────────────────────────────────────────────────────────────────────────
# Generic scan worker
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    """
    Runs any callable in a background thread and emits signals for the result,
    progress messages, errors, and completion.

    Usage::

        worker = ScanWorker("DNS Lookup", dns_tools.dns_lookup, "example.com",
                            record_types=["A", "MX"])
        worker.result_ready.connect(on_result)
        worker.error_occurred.connect(on_error)
        worker.finished_scan.connect(on_done)
        worker.start()
    """

    result_ready   = pyqtSignal(str, object)   # (tool_name, result_dict)
    progress_msg   = pyqtSignal(str)            # intermediate status line
    live_output    = pyqtSignal(str, str)       # (tool_name, html_output) for live streaming
    error_occurred = pyqtSignal(str)            # error message
    finished_scan  = pyqtSignal()               # always emitted when done

    def __init__(
        self,
        tool_name: str,
        scan_func: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.tool_name  = tool_name
        self.scan_func  = scan_func
        self.args       = args
        self.kwargs     = kwargs
        self._cancelled = False

    # ------------------------------------------------------------------
    def run(self) -> None:  # executed in the new thread
        try:
            self.progress_msg.emit(f"[{self.tool_name}] Starting …")

            # Pass progress callback for tools that support streaming
            def stream_output(text: str):
                if not self._cancelled:
                    self.live_output.emit(self.tool_name, text)

            # Check if the function accepts progress_callback before adding it
            import inspect
            sig = inspect.signature(self.scan_func)
            accepts_progress = 'progress_callback' in sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )

            if accepts_progress and 'progress_callback' not in self.kwargs:
                self.kwargs['progress_callback'] = stream_output

            result = self.scan_func(*self.args, **self.kwargs)
            if not self._cancelled:
                self.result_ready.emit(self.tool_name, result)
        except Exception:
            tb = traceback.format_exc()
            self.error_occurred.emit(f"[{self.tool_name}] Unhandled exception:\n{tb}")
        finally:
            self.finished_scan.emit()

    def cancel(self) -> None:
        """Request cancellation (best-effort; blocking calls cannot be interrupted)."""
        self._cancelled = True
        self.terminate()   # forcefully stop the thread if still running
        self.wait(2000)


# ─────────────────────────────────────────────────────────────────────────────
# Result formatter
# ─────────────────────────────────────────────────────────────────────────────

class ResultFormatter:
    """
    Convert raw dict/list results from scan modules into rich HTML
    suitable for display in a QTextEdit widget.
    """

    # Colour palette (GitHub dark-inspired)
    C = {
        "bg":       "#0d1117",
        "key":      "#79c0ff",   # blue  – key names
        "val":      "#a5d6ff",   # light – values
        "str_val":  "#a8ff78",   # green – string values
        "num_val":  "#f2cc60",   # amber – numbers
        "bool_t":   "#3fb950",   # green – True
        "bool_f":   "#f85149",   # red   – False
        "error":    "#f85149",   # red
        "warn":     "#d29922",   # orange
        "header":   "#58a6ff",   # bright blue
        "muted":    "#8b949e",   # grey
        "border":   "#30363d",
        "success":  "#3fb950",
        "port_open":"#3fb950",
        "section":  "#e3b341",   # gold section titles
    }

    @classmethod
    def format(cls, tool_name: str, data: Any, target: str = "") -> str:
        """Return an HTML string ready for setHtml()."""
        c = cls.C
        
        # Handle bulk scan results with special formatting
        if isinstance(data, dict) and "targets" in data and "total_targets" in data:
            return cls._format_bulk_result(tool_name, data, target)
        
        header = (
            f"<div style='background:{c['bg']};padding:0;'>"
            f"<span style='color:{c['header']};font-size:14px;font-weight:bold;'>"
            f"⬡ {tool_name}</span>"
        )
        if target:
            header += (
                f" &nbsp;<span style='color:{c['muted']};font-size:12px;'>"
                f"→ {target}</span>"
            )
        header += "</div><hr style='border-color:#30363d;margin:6px 0;'>"

        body = cls._render_value(data, indent=0)
        footer = (
            f"<div style='color:{c['muted']};font-size:11px;margin-top:10px;'>"
            f"─── end of result ───</div>"
        )

        return (
            f"<html><body style='background:{c['bg']};color:#c9d1d9;"
            f"font-family:Consolas,\"Courier New\",monospace;font-size:12px;"
            f"padding:10px;'>"
            f"{header}{body}{footer}</body></html>"
        )

    @classmethod
    def _format_bulk_result(cls, tool_name: str, data: Dict, target: str = "") -> str:
        """Format bulk scan results with per-target sections."""
        c = cls.C

        # Header
        total = data.get("total_targets", 0)
        successful = data.get("successful", 0)
        failed = data.get("failed", 0)

        header_html = (
            f"<html><body style='background:{c['bg']};color:#c9d1d9;"
            f"font-family:Consolas,\"Courier New\",monospace;font-size:12px;"
            f"padding:10px;'>"
            f"<div style='background:{c['bg']};padding:0;'>"
            f"<span style='color:{c['header']};font-size:14px;font-weight:bold;'>"
            f"⬡ {tool_name}</span>"
            f" &nbsp;<span style='color:{c['muted']};font-size:12px;'>→ {target}</span>"
            f"</div>"
            f"<hr style='border-color:#30363d;margin:6px 0;'>"
        )

        # Summary
        summary_color = c["success"] if failed == 0 else c["warn"] if failed < total else c["error"]
        summary_html = (
            f"<div style='margin:10px 0;padding:10px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
            f"<span style='color:{c['header']};font-weight:bold;'>📊 Summary:</span><br>"
            f"<span style='color:{c['str_val']};'>Total Targets:</span> <span style='color:{c['num_val']};'>{total}</span><br>"
            f"<span style='color:{c['str_val']};'>Successful:</span> <span style='color:{c['success']};'>{successful}</span><br>"
            f"<span style='color:{c['str_val']};'>Failed:</span> <span style='color:{summary_color};'>{failed}</span>"
        )

        # Add bulk-specific summaries
        if "total_open_ports" in data:
            summary_html += f"<br><span style='color:{c['str_val']};'>Total Open Ports:</span> <span style='color:{c['port_open']};'>{data.get('total_open_ports', 0)}</span>"
        if "all_ips" in data and data["all_ips"]:
            summary_html += f"<br><span style='color:{c['str_val']};'>IPs Discovered:</span> <span style='color:{c['num_val']};'>{len(data.get('all_ips', []))}</span>"
        if "geolocations" in data and data["geolocations"]:
            summary_html += f"<br><span style='color:{c['str_val']};'>Geolocations:</span> <span style='color:{c['num_val']};'>{len(data.get('geolocations', {}))}</span>"

        summary_html += "</div><hr style='border-color:#30363d;margin:6px 0;'>"

        # Special formatting for bulk geolocation - group by country/city
        if "bulk_geolocation" in tool_name.lower() or data.get("_geo_grouped"):
            targets_html = cls._format_geo_grouped(data, c)
        # Special formatting for bulk nmap - group by host with ports
        elif "bulk_nmap" in tool_name.lower() or "bulk_rustscan" in tool_name.lower():
            targets_html = cls._format_nmap_grouped(data, c)
        # Special formatting for bulk shodan - show CVEs and location
        elif "bulk_shodan" in tool_name.lower() or data.get("_shodan_grouped"):
            targets_html = cls._format_shodan_grouped(data, c)
        else:
            # Default per-target format
            targets_html = cls._format_bulk_default(data, c)

        footer = (
            f"<div style='color:{c['muted']};font-size:11px;margin-top:10px;'>"
            f"─── end of bulk scan results ───</div>"
            f"</body></html>"
        )

        return header_html + summary_html + targets_html + footer

    @classmethod
    def _format_geo_grouped(cls, data: Dict, c: Dict) -> str:
        """Format geolocation results grouped by country and city."""
        targets_data = data.get("targets", {})
        
        # Group by country → city
        geo_groups: Dict[str, Dict[str, List[tuple]]] = {}
        errors = []
        
        for tgt, result in targets_data.items():
            if isinstance(result, dict):
                if "error" in result:
                    errors.append((tgt, result["error"]))
                    continue
                
                country = result.get("country", result.get("countryName", "Unknown"))
                city = result.get("city", result.get("regionName", "Unknown"))
                lat = result.get("lat", result.get("latitude"))
                lon = result.get("lon", result.get("longitude"))
                isp = result.get("isp", result.get("org", ""))
                
                if country not in geo_groups:
                    geo_groups[country] = {}
                if city not in geo_groups[country]:
                    geo_groups[country][city] = []
                
                geo_groups[country][city].append((tgt, lat, lon, isp))
        
        # Build HTML with collapsible country sections
        html = ""
        
        # Summary by country
        if geo_groups:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;margin-bottom:8px;'>🌍 Countries Overview</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:6px;'>"
            )
            for country, cities in sorted(geo_groups.items()):
                total_ips = sum(len(ips) for ips in cities.values())
                html += (
                    f"<span style='color:{c['port_open']};background:rgba(63,185,80,0.1);"
                    f"padding:6px 12px;border-radius:4px;font-size:12px;border:1px solid {c['success']};'>"
                    f"📍 {cls._esc(country)} ({total_ips})</span>"
                )
            html += "</div></div>"
        
        # Detailed view by country → city
        for country, cities in sorted(geo_groups.items()):
            country_id = country.replace(" ", "_").replace("-", "_")
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;font-size:13px;margin-bottom:8px;'>"
                f"🇺🇳 {cls._esc(country)} ({len(cities)} cities, {sum(len(ips) for ips in cities.values())} IPs)</div>"
            )
            
            for city, ips in sorted(cities.items()):
                city_display = city if city else "Unknown"
                html += (
                    f"<div style='margin:8px 0;padding:8px;background:{c['bg']};border-left:3px solid {c['port_open']};padding-left:10px;'>"
                    f"<div style='color:{c['str_val']};font-weight:bold;margin-bottom:6px;'>📍 {cls._esc(city_display)} ({len(ips)} IPs)</div>"
                    f"<div style='margin-left:10px;'>"
                )
                
                for ip, lat, lon, isp in ips:
                    coords = f"{lat}, {lon}" if lat and lon else "Coordinates: N/A"
                    html += (
                        f"<div style='margin:4px 0;padding:6px;background:rgba(48,54,61,0.3);border-radius:4px;'>"
                        f"<div style='color:{c['port_open']};font-weight:bold;'>{cls._esc(ip)}</div>"
                        f"<div style='color:{c['muted']};font-size:11px;'>{cls._esc(coords)}</div>"
                    )
                    if isp:
                        html += f"<div style='color:{c['muted']};font-size:11px;'>ISP: {cls._esc(str(isp))}</div>"
                    html += "</div>"
                
                html += "</div></div>"
            
            html += "</div>"
        
        # Show errors separately
        if errors:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['error']};border-radius:6px;'>"
                f"<div style='color:{c['error']};font-weight:bold;margin-bottom:8px;'>❌ Failed Lookups ({len(errors)})</div>"
            )
            for tgt, error in errors[:10]:  # Limit to 10
                html += (
                    f"<div style='color:{c['muted']};font-size:11px;margin:4px 0;'>"
                    f"• {cls._esc(tgt)}: {cls._esc(str(error))}</div>"
                )
            if len(errors) > 10:
                html += f"<div style='color:{c['warn']};font-size:11px;'>... and {len(errors) - 10} more</div>"
            html += "</div>"
        
        return html

    @classmethod
    def _format_shodan_grouped(cls, data: Dict, c: Dict) -> str:
        """Format Shodan bulk results grouped by country/city with CVE highlights."""
        targets_data = data.get("targets", {})
        
        # Group by country → city
        geo_groups: Dict[str, Dict[str, List[tuple]]] = {}
        errors = []
        all_cves = []
        
        for tgt, result in targets_data.items():
            if isinstance(result, dict):
                if "error" in result:
                    errors.append((tgt, result["error"]))
                    continue
                
                country = result.get("country", "Unknown")
                city = result.get("city", "Unknown")
                org = result.get("organization", result.get("isp", ""))
                cves = result.get("cves", [])
                ports = result.get("open_ports", [])
                url = result.get("url", f"https://www.shodan.io/host/{tgt}")
                
                if country not in geo_groups:
                    geo_groups[country] = {}
                if city not in geo_groups[country]:
                    geo_groups[country][city] = []
                
                geo_groups[country][city].append((tgt, org, cves, ports, url))
                
                # Collect CVEs
                for cve in cves:
                    if cve not in all_cves:
                        all_cves.append(cve)
        
        html = ""
        
        # CVE Alert Section
        if all_cves:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:rgba(248,81,73,0.1);"
                f"border:2px solid {c['error']};border-radius:6px;'>"
                f"<div style='color:{c['error']};font-weight:bold;font-size:14px;margin-bottom:8px;'>"
                f"⚠️ VULNERABILITIES DETECTED ({len(all_cves)} CVEs)</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:6px;'>"
            )
            for cve_info in all_cves[:20]:  # Show first 20
                cve_id = cve_info.get("cve_id", "Unknown")
                cve_url = cve_info.get("url", "#")
                html += (
                    f"<a href='{cve_url}' style='color:{c['error']};background:rgba(248,81,73,0.2);"
                    f"padding:6px 12px;border-radius:4px;font-size:12px;border:1px solid {c['error']};text-decoration:none;'>"
                    f"🔴 {cve_id}</a>"
                )
            if len(all_cves) > 20:
                html += (
                    f"<span style='color:{c['muted']};padding:6px 12px;font-size:12px;'>"
                    f"... and {len(all_cves) - 20} more</span>"
                )
            html += "</div></div>"
        
        # Countries Overview
        if geo_groups:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;margin-bottom:8px;'>🌍 Geographic Distribution</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:6px;'>"
            )
            for country, cities in sorted(geo_groups.items()):
                total_ips = sum(len(ips) for ips in cities.values())
                # Count CVEs in this country
                country_cves = 0
                for city_ips in cities.values():
                    for ip_data in city_ips:
                        country_cves += len(ip_data[2])  # cves is at index 2
                
                cve_indicator = f" <span style='color:{c['error']};'>(⚠️ {country_cves})</span>" if country_cves > 0 else ""
                html += (
                    f"<span style='color:{c['port_open']};background:rgba(63,185,80,0.1);"
                    f"padding:6px 12px;border-radius:4px;font-size:12px;border:1px solid {c['success']};'>"
                    f"📍 {cls._esc(country)} ({total_ips}{cve_indicator})</span>"
                )
            html += "</div></div>"
        
        # Detailed view by country → city
        for country, cities in sorted(geo_groups.items()):
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;font-size:13px;margin-bottom:8px;'>"
                f"🇺🇳 {cls._esc(country)} ({len(cities)} cities, {sum(len(ips) for ips in cities.values())} IPs)</div>"
            )
            
            for city, ips in sorted(cities.items()):
                city_display = city if city else "Unknown"
                html += (
                    f"<div style='margin:8px 0;padding:8px;background:{c['bg']};border-left:3px solid {c['port_open']};padding-left:10px;'>"
                    f"<div style='color:{c['str_val']};font-weight:bold;margin-bottom:6px;'>📍 {cls._esc(city_display)} ({len(ips)} IPs)</div>"
                )
                
                for ip, org, cves, ports, url in ips:
                    has_cves = len(cves) > 0
                    border_color = c["error"] if has_cves else c["port_open"]
                    bg_color = "rgba(248,81,73,0.05)" if has_cves else "rgba(48,54,61,0.3)"
                    
                    html += (
                        f"<div style='margin:6px 0;padding:8px;background:{bg_color};"
                        f"border:1px solid {border_color};border-radius:4px;'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;'>"
                        f"<a href='{url}' target='_blank' style='color:{c['port_open']};font-weight:bold;text-decoration:none;'>"
                        f"🔗 {cls._esc(ip)}</a>"
                    )
                    
                    if has_cves:
                        html += (
                            f"<span style='color:{c['error']};background:rgba(248,81,73,0.2);"
                            f"padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;'>"
                            f"⚠️ {len(cves)} CVEs</span>"
                        )
                    
                    html += "</div>"  # Close flex container
                    
                    if org:
                        html += f"<div style='color:{c['muted']};font-size:11px;margin:4px 0;'>🏢 {cls._esc(str(org))}</div>"
                    
                    if ports:
                        html += (
                            f"<div style='color:{c['str_val']};font-size:11px;margin:4px 0;'>"
                            f"🔓 Ports: <span style='color:{c['val']};'>{cls._esc(', '.join(ports[:10]))}"
                            f"{('...' if len(ports) > 10 else '')}</span></div>"
                        )
                    
                    if has_cves:
                        html += f"<div style='color:{c['error']};font-size:11px;margin:4px 0;'>🔴 CVEs:</div>"
                        html += "<div style='margin-left:10px;'>"
                        for cve_info in cves[:5]:  # Show first 5 CVEs
                            cve_id = cve_info.get("cve_id", "Unknown")
                            cve_url = cve_info.get("url", "#")
                            html += (
                                f"<div style='margin:2px 0;'>"
                                f"<a href='{cve_url}' target='_blank' style='color:{c['error']};text-decoration:none;'>"
                                f"• {cls._esc(cve_id)}</a></div>"
                            )
                        if len(cves) > 5:
                            html += f"<div style='color:{c['muted']};font-size:11px;'>... and {len(cves) - 5} more</div>"
                        html += "</div>"
                    
                    html += "</div>"  # Close IP card
                
                html += "</div>"  # Close city section
            
            html += "</div>"  # Close country section
        
        # Show errors separately
        if errors:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['error']};border-radius:6px;'>"
                f"<div style='color:{c['error']};font-weight:bold;margin-bottom:8px;'>❌ Failed Lookups ({len(errors)})</div>"
            )
            for tgt, error in errors[:10]:
                html += (
                    f"<div style='color:{c['muted']};font-size:11px;margin:4px 0;'>"
                    f"• {cls._esc(tgt)}: {cls._esc(str(error))}</div>"
                )
            if len(errors) > 10:
                html += f"<div style='color:{c['warn']};font-size:11px;'>... and {len(errors) - 10} more</div>"
            html += "</div>"
        
        return html

    @classmethod
    def _format_nmap_grouped(cls, data: Dict, c: Dict) -> str:
        """Format Nmap/RustScan results grouped by host with port tables."""
        targets_data = data.get("targets", {})
        
        # Aggregate data
        all_open_ports = data.get("all_open_ports", [])
        all_services = data.get("all_services", {})
        geolocations = data.get("geolocations", {})
        
        html = ""
        
        # Quick stats bar
        html += (
            f"<div style='margin:12px 0;padding:10px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;"
            f"display:flex;gap:16px;flex-wrap:wrap;'>"
            f"<div><span style='color:{c['muted']};'>Hosts:</span> <span style='color:{c['num_val']};font-weight:bold;'>{data.get('successful', 0)}</span></div>"
            f"<div><span style='color:{c['muted']};'>Open Ports:</span> <span style='color:{c['port_open']};font-weight:bold;'>{data.get('total_open_ports', 0)}</span></div>"
            f"<div><span style='color:{c['muted']};'>Services:</span> <span style='color:{c['header']};font-weight:bold;'>{len(all_services)}</span></div>"
            f"</div>"
        )
        
        # Services word cloud
        if all_services:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;margin-bottom:8px;'>🔧 Services Detected</div>"
                f"<div style='display:flex;flex-wrap:wrap;gap:6px;'>"
            )
            for svc, count in sorted(all_services.items(), key=lambda x: -x[1])[:30]:
                intensity = min(1.0, count / 10.0)
                bg_alpha = 0.1 + (intensity * 0.3)
                html += (
                    f"<span style='color:{c['port_open']};background:rgba(63,185,80,{bg_alpha});"
                    f"padding:6px 12px;border-radius:4px;font-size:12px;border:1px solid {c['success']};'>"
                    f"{cls._esc(svc)} <span style='opacity:0.7;'>({count})</span></span>"
                )
            html += "</div></div>"
        
        # Per-host detailed results
        html += (
            f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
            f"<div style='color:{c['header']};font-weight:bold;margin-bottom:12px;font-size:13px;'>🎯 Host Details</div>"
        )
        
        for tgt, result in targets_data.items():
            html += f"<div style='margin:10px 0;padding:10px;background:rgba(22,27,34,0.5);border:1px solid {c['border']};border-radius:6px;'>"
            
            # Host header
            is_error = isinstance(result, dict) and "error" in result
            header_color = c["error"] if is_error else c["port_open"]
            html += f"<div style='color:{header_color};font-weight:bold;font-size:12px;margin-bottom:8px;'>🖥 {cls._esc(tgt)}</div>"
            
            if is_error:
                html += (
                    f"<div style='color:{c['error']};padding:8px;background:rgba(248,81,73,0.1);border-radius:4px;font-size:11px;'>"
                    f"❌ {cls._esc(result.get('error', 'Unknown error'))}</div>"
                )
            else:
                # Port table
                open_ports = result.get("open_ports", []) if isinstance(result, dict) else []
                if open_ports:
                    html += (
                        f"<div style='color:{c['str_val']};font-size:11px;margin-bottom:6px;'>🔓 Open Ports ({len(open_ports)})</div>"
                        f"<div style='background:{c['bg']};border:1px solid {c['border']};border-radius:4px;overflow:hidden;'>"
                        f"<table style='width:100%;border-collapse:collapse;font-size:11px;'>"
                        f"<thead style='background:rgba(48,54,61,0.5);'>"
                        f"<tr>"
                        f"<th style='padding:8px;text-align:left;border-bottom:1px solid {c['border']};color:{c['header']};'>Port</th>"
                        f"<th style='padding:8px;text-align:left;border-bottom:1px solid {c['border']};color:{c['header']};'>Protocol</th>"
                        f"<th style='padding:8px;text-align:left;border-bottom:1px solid {c['border']};color:{c['header']};'>State</th>"
                        f"<th style='padding:8px;text-align:left;border-bottom:1px solid {c['border']};color:{c['header']};'>Service</th>"
                        f"</tr>"
                        f"</thead>"
                        f"<tbody>"
                    )
                    
                    for i, port_info in enumerate(open_ports[:50]):  # Limit to 50 ports per host
                        if isinstance(port_info, dict):
                            port_num = port_info.get("port", "?")
                            protocol = port_info.get("protocol", "tcp")
                            state = port_info.get("state", "open")
                            service = port_info.get("service", "unknown")
                        else:
                            port_num = str(port_info)
                            protocol = "tcp"
                            state = "open"
                            service = "unknown"
                        
                        row_bg = "rgba(22,27,34,0.3)" if i % 2 == 0 else "transparent"
                        html += (
                            f"<tr style='background:{row_bg};'>"
                            f"<td style='padding:6px 8px;color:{c['port_open']};font-weight:bold;'>{port_num}</td>"
                            f"<td style='padding:6px 8px;color:{c['val']};'>{protocol.upper()}</td>"
                            f"<td style='padding:6px 8px;color:{c['success']};'>{state}</td>"
                            f"<td style='padding:6px 8px;color:{c['str_val']};'>{cls._esc(service)}</td>"
                            f"</tr>"
                        )
                    
                    if len(open_ports) > 50:
                        html += (
                            f"<tr><td colspan='4' style='padding:8px;text-align:center;color:{c['warn']};'>"
                            f"... and {len(open_ports) - 50} more ports (use export for full data)</td></tr>"
                        )
                    
                    html += "</tbody></table></div>"
                else:
                    html += f"<div style='color:{c['muted']};font-size:11px;'>No open ports detected</div>"
                
                # OS detection
                os_guesses = result.get("os_guesses", []) if isinstance(result, dict) else []
                if os_guesses:
                    html += f"<div style='color:{c['str_val']};font-size:11px;margin:8px 0 4px;'>💻 OS Detection:</div>"
                    for os in os_guesses[:5]:
                        html += f"<div style='color:{c['num_val']};font-size:11px;margin-left:10px;'>• {cls._esc(os.get('description', 'Unknown'))}</div>"
                
                # Command used
                command = result.get("command", "")
                if command:
                    html += (
                        f"<div style='color:{c['muted']};font-size:10px;margin-top:8px;padding:6px;"
                        f"background:rgba(48,54,61,0.3);border-radius:4px;font-family:monospace;'>"
                        f"$ {cls._esc(command)}</div>"
                    )
            
            # Add geolocation if available
            if geolocations and tgt in geolocations:
                geo = geolocations[tgt]
                country = geo.get("country", geo.get("countryName", "Unknown"))
                city = geo.get("city", geo.get("regionName", "Unknown"))
                html += (
                    f"<div style='margin-top:8px;padding:6px;background:rgba(88,166,255,0.1);border-radius:4px;"
                    f"font-size:11px;color:{c['str_val']};'>📍 {cls._esc(city)}, {cls._esc(country)}</div>"
                )
            
            html += "</div>"
        
        html += "</div>"
        
        # Geolocation map summary
        if geolocations:
            html += (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;margin-bottom:8px;'>🌍 Geographic Distribution</div>"
                f"<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;'>"
            )
            
            # Group by country
            country_ips: Dict[str, List[str]] = {}
            for ip, geo in geolocations.items():
                country = geo.get("country", geo.get("countryName", "Unknown"))
                if country not in country_ips:
                    country_ips[country] = []
                country_ips[country].append(ip)
            
            for country, ips in sorted(country_ips.items()):
                html += (
                    f"<div style='padding:8px;background:rgba(48,54,61,0.3);border-radius:4px;"
                    f"border-left:3px solid {c['port_open']};'>"
                    f"<div style='color:{c['header']};font-size:11px;'>📍 {cls._esc(country)}</div>"
                    f"<div style='color:{c['muted']};font-size:10px;margin-top:4px;'>{len(ips)} IPs</div>"
                    f"<div style='color:{c['val']};font-size:10px;margin-top:2px;max-height:60px;overflow:hidden;'>"
                    f"{', '.join(cls._esc(ip) for ip in ips[:5])}"
                    f"{('...' if len(ips) > 5 else '')}</div>"
                    f"</div>"
                )
            
            html += "</div></div>"
        
        return html

    @classmethod
    def _format_bulk_default(cls, data: Dict, c: Dict) -> str:
        """Default per-target formatting for bulk results."""
        targets_data = data.get("targets", {})
        targets_html = ""
        
        for tgt, result in targets_data.items():
            target_section = (
                f"<div style='margin:12px 0;padding:12px;background:{c['bg']};border:1px solid {c['border']};border-radius:6px;'>"
                f"<div style='color:{c['header']};font-weight:bold;margin-bottom:8px;'>🎯 {tgt}</div>"
            )

            if isinstance(result, dict):
                if "error" in result:
                    target_section += (
                        f"<div style='color:{c['error']};padding:8px;background:rgba(248,81,73,0.1);border-radius:4px;'>"
                        f"❌ Error: {cls._esc(result.get('error', 'Unknown error'))}</div>"
                    )
                else:
                    # Format based on tool type
                    if "open_ports" in result:
                        # Nmap result
                        open_ports = result.get("open_ports", [])
                        if open_ports:
                            target_section += f"<div style='color:{c['str_val']};margin-bottom:6px;'>🔓 Open Ports:</div>"
                            target_section += "<div style='margin-left:10px;'>"
                            for port_info in open_ports:
                                if isinstance(port_info, dict):
                                    port_num = port_info.get("port", "?")
                                    service = port_info.get("service", "unknown")
                                    state = port_info.get("state", "open")
                                else:
                                    port_num = port_info
                                    service = "unknown"
                                    state = "open"
                                target_section += (
                                    f"<div style='color:{c['port_open']};margin:4px 0;'>"
                                    f"  Port {port_num}/{service} - {state}"
                                    f"</div>"
                                )
                            target_section += "</div>"
                        else:
                            target_section += f"<div style='color:{c['muted']};'>No open ports found</div>"

                        # OS detection
                        if "os_guesses" in result and result["os_guesses"]:
                            target_section += f"<div style='color:{c['str_val']};margin:8px 0 4px;'>💻 OS Detection:</div>"
                            for os in result.get("os_guesses", []):
                                target_section += f"<div style='color:{c['num_val']};margin-left:10px;'>• {cls._esc(os.get('description', 'Unknown'))}</div>"

                    # DNS records
                    elif "records" in result:
                        records = result.get("records", {})
                        for rtype, rdata in records.items():
                            if rdata:
                                target_section += f"<div style='color:{c['str_val']};margin:4px 0;'>{rtype}: "
                                target_section += f"<span style='color:{c['val']};'>{cls._esc(str(rdata))}</span></div>"

                    # Geolocation
                    elif any(k in result for k in ["country", "city", "lat", "latitude"]):
                        country = result.get("country", result.get("countryName", "Unknown"))
                        city = result.get("city", result.get("regionName", "Unknown"))
                        lat = result.get("lat", result.get("latitude"))
                        lon = result.get("lon", result.get("longitude"))
                        coords = f"{lat}, {lon}" if lat and lon else "Unknown"
                        target_section += (
                            f"<div style='color:{c['str_val']};margin:4px 0;'>"
                            f"📍 {city}, {country}</div>"
                            f"<div style='color:{c['muted']};margin-left:10px;font-size:11px;'>Coordinates: {coords}</div>"
                        )

                    # WHOIS
                    elif "registrar" in result or "domain_name" in result:
                        domain = result.get("domain_name", result.get("domain", tgt))
                        registrar = result.get("registrar", "Unknown")
                        target_section += (
                            f"<div style='color:{c['str_val']};margin:4px 0;'>Domain: {cls._esc(str(domain))}</div>"
                            f"<div style='color:{c['str_val']};margin:4px 0;'>Registrar: {cls._esc(str(registrar))}</div>"
                        )

                    # Ping
                    elif "avg_rtt" in result or "packets_sent" in result:
                        avg_rtt = result.get("avg_rtt", result.get("average", "N/A"))
                        packets_sent = result.get("packets_sent", 0)
                        packets_recv = result.get("packets_received", 0)
                        target_section += (
                            f"<div style='color:{c['str_val']};margin:4px 0;'>"
                            f"📡 Packets: {packets_sent} sent, {packets_recv} received</div>"
                            f"<div style='color:{c['num_val']};margin:4px 0;'>Average RTT: {avg_rtt}ms</div>"
                        )

                    # HTTP headers
                    elif "status_code" in result or "headers" in result:
                        status = result.get("status_code", "N/A")
                        server = result.get("server", "Unknown")
                        target_section += (
                            f"<div style='color:{c['str_val']};margin:4px 0;'>Status: {status}</div>"
                            f"<div style='color:{c['str_val']};margin:4px 0;'>Server: {cls._esc(str(server))}</div>"
                        )

                    # Generic
                    else:
                        for key, value in list(result.items())[:10]:  # Limit displayed keys
                            if key not in ("target", "command", "raw_output", "preset"):
                                target_section += (
                                    f"<div style='color:{c['str_val']};margin:4px 0;'>"
                                    f"{key}: {cls._esc(str(value))}</div>"
                                )

            target_section += "</div>"
            targets_html += target_section
        
        return targets_html

    @classmethod
    def _render_value(cls, value: Any, indent: int = 0) -> str:
        c = cls.C
        pad = "&nbsp;" * (indent * 4)

        if isinstance(value, dict):
            if not value:
                return f"{pad}<span style='color:{c['muted']}'>{{}}</span><br>"
            lines = []
            for k, v in value.items():
                key_str = f"<span style='color:{c['key']}'>{k}</span>"
                if isinstance(v, (dict, list)):
                    inner = cls._render_value(v, indent + 1)
                    lines.append(f"{pad}{key_str}:<br>{inner}")
                else:
                    val_html = cls._render_scalar(k, v)
                    lines.append(f"{pad}{key_str}: {val_html}<br>")
            return "".join(lines)

        elif isinstance(value, list):
            if not value:
                return f"{pad}<span style='color:{c['muted']}'>>(empty)</span><br>"
            lines = []
            for i, item in enumerate(value):
                if isinstance(item, (dict, list)):
                    lines.append(f"{pad}<span style='color:{c['muted']}'>#{i+1}</span><br>")
                    lines.append(cls._render_value(item, indent + 1))
                else:
                    lines.append(f"{pad}<span style='color:{c['str_val']}'>• {cls._esc(str(item))}</span><br>")
            return "".join(lines)

        else:
            return f"{pad}{cls._render_scalar('', value)}<br>"

    @classmethod
    def _render_scalar(cls, key: str, value: Any) -> str:
        c = cls.C
        s = str(value) if value is not None else "null"

        if isinstance(value, bool):
            colour = c["bool_t"] if value else c["bool_f"]
            return f"<span style='color:{colour}'>{s}</span>"

        if isinstance(value, (int, float)):
            return f"<span style='color:{c['num_val']}'>{s}</span>"

        if key in ("error",) or s.lower().startswith("error"):
            return f"<span style='color:{c['error']}'>{cls._esc(s)}</span>"

        if key in ("open_ports", "port") or "open" in s.lower():
            return f"<span style='color:{c['port_open']}'>{cls._esc(s)}</span>"

        return f"<span style='color:{c['str_val']}'>{cls._esc(s)}</span>"

    @staticmethod
    def _esc(text: str) -> str:
        """HTML-escape a string but preserve newlines as <br>."""
        return (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>")
        )

    @classmethod
    def format_plain_text(cls, tool_name: str, data: Any, target: str = "") -> str:
        """Plain-text version for export / clipboard."""
        import json
        try:
            body = json.dumps(data, indent=2, default=str)
        except Exception:
            body = str(data)
        return f"=== {tool_name} : {target} ===\n\n{body}\n"

    @classmethod
    def export_to_csv(cls, tool_name: str, data: Dict) -> str:
        """Export bulk results to CSV format."""
        import csv
        import io
        
        output = io.StringIO()
        targets_data = data.get("targets", {})
        
        if not targets_data:
            return "No data to export"
        
        # Determine columns based on tool type
        if "shodan" in tool_name.lower() or "geolocation" in tool_name.lower():
            # Geolocation/Shodan columns
            fieldnames = ["IP", "Country", "City", "Organization", "ISP", "ASN", "Status", "CVEs", "Ports"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for ip, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "IP": ip,
                            "Country": "",
                            "City": "",
                            "Organization": "",
                            "ISP": "",
                            "ASN": "",
                            "Status": f"Error: {result.get('error', 'Unknown')}",
                            "CVEs": "",
                            "Ports": ""
                        })
                    else:
                        cves = result.get("cves", [])
                        ports = result.get("open_ports", [])
                        writer.writerow({
                            "IP": ip,
                            "Country": result.get("country", ""),
                            "City": result.get("city", ""),
                            "Organization": result.get("organization", ""),
                            "ISP": result.get("isp", ""),
                            "ASN": result.get("asn", ""),
                            "Status": "Success",
                            "CVEs": "; ".join([c.get("cve_id", "") for c in cves]) if cves else "",
                            "Ports": "; ".join(ports) if ports else ""
                        })
        
        elif "ping" in tool_name.lower():
            # Ping columns
            fieldnames = ["Host", "Status", "Packets Sent", "Packets Received", "Loss %", "Avg RTT (ms)", "Min RTT (ms)", "Max RTT (ms)"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for host, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "Host": host,
                            "Status": "Error",
                            "Packets Sent": "",
                            "Packets Received": "",
                            "Loss %": "",
                            "Avg RTT (ms)": "",
                            "Min RTT (ms)": "",
                            "Max RTT (ms)": ""
                        })
                    else:
                        loss = result.get("packet_loss", "0")
                        if isinstance(loss, str) and "%" in loss:
                            loss = loss.replace("%", "")
                        writer.writerow({
                            "Host": host,
                            "Status": "Up" if result.get("reachable", False) or result.get("packets_received", 0) > 0 else "Down",
                            "Packets Sent": result.get("packets_sent", 0),
                            "Packets Received": result.get("packets_received", 0),
                            "Loss %": loss,
                            "Avg RTT (ms)": result.get("avg_rtt", result.get("average", "N/A")),
                            "Min RTT (ms)": result.get("min_rtt", "N/A"),
                            "Max RTT (ms)": result.get("max_rtt", "N/A")
                        })
        
        elif "nmap" in tool_name.lower() or "rustscan" in tool_name.lower() or "masscan" in tool_name.lower():
            # Port scanner columns - one row per port
            fieldnames = ["Host", "Port", "Protocol", "State", "Service", "Status"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for host, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "Host": host,
                            "Port": "",
                            "Protocol": "",
                            "State": "",
                            "Service": "",
                            "Status": f"Error: {result.get('error', 'Unknown')}"
                        })
                    else:
                        open_ports = result.get("open_ports", [])
                        if open_ports:
                            for port_info in open_ports:
                                if isinstance(port_info, dict):
                                    writer.writerow({
                                        "Host": host,
                                        "Port": port_info.get("port", ""),
                                        "Protocol": port_info.get("protocol", "tcp"),
                                        "State": port_info.get("state", "open"),
                                        "Service": port_info.get("service", ""),
                                        "Status": "Success"
                                    })
                                else:
                                    writer.writerow({
                                        "Host": host,
                                        "Port": port_info,
                                        "Protocol": "tcp",
                                        "State": "open",
                                        "Service": "",
                                        "Status": "Success"
                                    })
                        else:
                            writer.writerow({
                                "Host": host,
                                "Port": "",
                                "Protocol": "",
                                "State": "",
                                "Service": "",
                                "Status": "No open ports"
                            })

        elif "fping" in tool_name.lower():
            # Fping columns
            fieldnames = ["Host", "Status", "Alive", "Status"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for host, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "Host": host,
                            "Status": "Error",
                            "Alive": "",
                            "Details": result.get('error', 'Unknown')
                        })
                    else:
                        alive_hosts = result.get("alive_hosts", [])
                        if alive_hosts:
                            for alive_host in alive_hosts:
                                writer.writerow({
                                    "Host": host,
                                    "Status": "Alive",
                                    "Alive": alive_host,
                                    "Details": ""
                                })
                        else:
                            writer.writerow({
                                "Host": host,
                                "Status": "No hosts found",
                                "Alive": "",
                                "Details": ""
                            })

        elif "netdiscover" in tool_name.lower():
            # Netdiscover columns
            fieldnames = ["Target", "Discovered IP", "MAC Address", "Vendor", "Type", "Status"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for target, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "Target": target,
                            "Discovered IP": "",
                            "MAC Address": "",
                            "Vendor": "",
                            "Type": "",
                            "Status": f"Error: {result.get('error', 'Unknown')}"
                        })
                    else:
                        discovered_hosts = result.get("discovered_hosts", [])
                        if discovered_hosts:
                            for host_info in discovered_hosts:
                                writer.writerow({
                                    "Target": target,
                                    "Discovered IP": host_info.get("ip", ""),
                                    "MAC Address": host_info.get("mac", ""),
                                    "Vendor": host_info.get("vendor", ""),
                                    "Type": host_info.get("type", "Active"),
                                    "Status": "Success"
                                })
                        else:
                            writer.writerow({
                                "Target": target,
                                "Discovered IP": "",
                                "MAC Address": "",
                                "Vendor": "",
                                "Type": "",
                                "Status": "No hosts discovered"
                            })

        elif "upnp" in tool_name.lower():
            # UPnP Discovery columns
            fieldnames = ["Target", "Device Type", "Manufacturer", "Model", "Friendly Name", "Internal IP", "Status"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for target, result in targets_data.items():
                if isinstance(result, dict):
                    if "error" in result:
                        writer.writerow({
                            "Target": target,
                            "Device Type": "",
                            "Manufacturer": "",
                            "Model": "",
                            "Friendly Name": "",
                            "Internal IP": "",
                            "Status": f"Error: {result.get('error', 'Unknown')}"
                        })
                    else:
                        upnp_devices = result.get("upnp_devices", [])
                        internal_ips = result.get("internal_ips_found", [])
                        if upnp_devices:
                            for device in upnp_devices:
                                writer.writerow({
                                    "Target": target,
                                    "Device Type": device.get("device_type", ""),
                                    "Manufacturer": device.get("manufacturer", ""),
                                    "Model": device.get("model", ""),
                                    "Friendly Name": device.get("friendly_name", ""),
                                    "Internal IP": "; ".join(internal_ips) if internal_ips else "",
                                    "Status": "Success"
                                })
                        elif internal_ips:
                            # Found IPs but no device details
                            for ip in internal_ips:
                                writer.writerow({
                                    "Target": target,
                                    "Device Type": "",
                                    "Manufacturer": "",
                                    "Model": "",
                                    "Friendly Name": "",
                                    "Internal IP": ip,
                                    "Status": "IP Found"
                                })
                        else:
                            writer.writerow({
                                "Target": target,
                                "Device Type": "",
                                "Manufacturer": "",
                                "Model": "",
                                "Friendly Name": "",
                                "Internal IP": "",
                                "Status": "No UPnP devices found"
                            })

        else:
            # Generic export
            fieldnames = ["Target", "Status", "Data"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for target, result in targets_data.items():
                writer.writerow({
                    "Target": target,
                    "Status": "Error" if isinstance(result, dict) and "error" in result else "Success",
                    "Data": str(result)
                })
        
        return output.getvalue()
