# Recon 9 by TOREVAR

A modular, dark-themed desktop OSINT (Open Source Intelligence) application
built with **Python 3.10+** and **PyQt6**.

---

## ✦ Features

| Category | Tools |
|---|---|
| 🌐 DNS Tools | DNS Lookup (A/AAAA/MX/NS/TXT/CNAME/SOA), Reverse DNS, Subdomain Discovery, Shared DNS Finder |
| 🔌 Network | Ping, Traceroute, TCP Port Scan, UDP Port Scan, Subnet Lookup, Banner Grabbing |
| 📋 WHOIS | WHOIS Lookup, ASN Lookup |
| 🌍 IP Information | IP Geolocation, Full IP Info, Reverse IP Lookup |
| 🌐 Web Tools | HTTP Headers + Security Analysis, Extract Page Links, Reverse Analytics / Tracker Detection, Social Media Extractor |
| 🛠 External | Nmap Port Scanner (presets + custom), Nmap OS Detection, RustScan, Masscan, Fping, Netdiscover |

---

## ⚙ Installation

```bash
# 1.git clone https://github.com/Torevar4X/Recon-9.git
cd recon-9

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Install external tools
#    Nmap:       https://nmap.org/download.html
#    RustScan:   https://github.com/RustScan/RustScan/releases
#    Masscan:    sudo apt install masscan       (Debian/Ubuntu)
#                sudo pacman -S masscan         (Arch)
#    Fping:      sudo apt install fping         (Debian/Ubuntu)
#                sudo pacman -S fping           (Arch)
#    Netdiscover:sudo apt install netdiscover   (Debian/Ubuntu)

# 5. Run
python main.py
```

---

## 🖥 Architecture

```
osint_app/
├── main.py              ← Entry point; QApplication + dark palette
├── main_window.py       ← MainWindow, ToolPanel base, all 22 panel subclasses
├── workers.py           ← ScanWorker (QThread), ResultFormatter (HTML output)
├── modules/
│   ├── dns_tools.py     ← dns_lookup, reverse_dns, find_subdomains, find_shared_dns
│   ├── network_tools.py ← test_ping, traceroute, tcp_port_scan, udp_port_scan,
│   │                        subnet_lookup, banner_grab
│   ├── ip_tools.py      ← whois_lookup, asn_lookup, ip_geolocation,
│   │                        ip_information, reverse_ip_lookup
│   ├── web_tools.py     ← http_headers, extract_links, reverse_analytics,
│   │                        extract_social_media
│   └── external_tools.py← nmap_port_scan, nmap_os_detection, rustscan,
│                           check_external_tools
└── requirements.txt
```

### Design Principles

- **Non-blocking UI** — every scan runs in a `QThread` (`ScanWorker`).
  Signals (`result_ready`, `error_occurred`, `finished_scan`) safely marshal
  data back to the main thread.
- **Module isolation** — each module file has zero Qt dependency; it can be
  imported and tested independently in a REPL or unit-test suite.
- **Graceful degradation** — optional libraries (`dnspython`, `ipwhois`,
  `beautifulsoup4`) are detected at call-time; socket-based fallbacks are used
  when they are absent.
- **Extensibility** — add a new tool by:
  1. Writing a function in the appropriate `modules/` file.
  2. Subclassing `ToolPanel` in `main_window.py` (typically ~15 lines).
  3. Adding an entry to `TOOL_CATALOGUE` and `PANEL_MAP`.

---

## 🔑 Key Bindings

| Shortcut | Action |
|---|---|
| `Ctrl+Enter` | Run current tool |
| Click sidebar item | Switch tool panel |

---

## 📤 Export

Click **↓ Export** in the toolbar to save all accumulated results as:
- **JSON** (structured, full data)
- **TXT** (human-readable plain text)

---

## ⚖ Legal & Ethical Use

> **You are responsible for how you use this tool.**
> Only scan systems and domains you own or have **explicit written permission**
> to test. Unauthorised port scanning or data collection may be illegal in
> your jurisdiction. The WHOIS, IP geolocation, and CT-log features use public
> third-party APIs; respect their terms of service and rate limits.

---

## 🔒 Security Recommendations

- Run in a dedicated virtual environment.
- Never store credentials or sensitive results in shared directories.
- Treat all retrieved data as potentially sensitive PII.
- Use a VPN or isolated VM for active scanning tasks.
- Rotate source IPs or add delays when making many API calls to avoid
  being rate-limited or blocked.

---

## 🔭 Extending the Application

### Add a new tool in 3 steps

```python
# 1. modules/my_tools.py
def my_new_scan(target: str, option: int = 10) -> dict:
    ...
    return {"target": target, "data": ...}

# 2. main_window.py – new panel class (~15 lines)
class MyNewPanel(ToolPanel):
    def __init__(self):
        super().__init__("My New Scan", "Short description.", my_tools.my_new_scan)
        self._text("target", "Target", "example.com")
        self._spin("option", "Option", 1, 100, 10)
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "option": self._val("option", 10)}

# 3. Register in TOOL_CATALOGUE and PANEL_MAP
TOOL_CATALOGUE → ("🔍  My Category", [("my_new_scan", "My New Scan", "🔬")])
PANEL_MAP      → {"my_new_scan": MyNewPanel}
```

That's it — the sidebar, stacked widget, and worker system handle everything else automatically.

---

## 📦 Dependencies

| Library | Purpose |
|---|---|
| `PyQt6` | GUI framework |
| `dnspython` | DNS resolution & reverse lookups |
| `python-whois` | WHOIS data parsing |
| `ipwhois` | RDAP / ASN lookups |
| `requests` | HTTP requests |
| `beautifulsoup4` | HTML parsing for web tools |
| `netaddr` | CIDR / subnet arithmetic |
| **`nmap`** (system) | Port scanning, OS detection |
| **`rustscan`** (system) | Ultra-fast port discovery |
| **`masscan`** (system) | Blazing fast port scanner |
| **`fping`** (system) | Fast ICMP ping sweep |
| **`netdiscover`** (system) | ARP-based network discovery |
