# OSINT Suite - Project Context

## Project Overview

A modular, dark-themed desktop **OSINT (Open Source Intelligence)** application built with **Python 3.10+** and **PyQt6**. The tool provides 22+ security and reconnaissance utilities for DNS analysis, network scanning, IP/WHOIS lookups, web analysis, and external tool integration (Nmap, RustScan).

### Key Features by Category

| Category | Tools |
|----------|-------|
| **DNS Tools** | DNS Lookup, Reverse DNS, Subdomain Discovery, Shared DNS Finder |
| **Network** | Ping, Traceroute, TCP/UDP Port Scan, Subnet Lookup, Banner Grabbing |
| **WHOIS** | WHOIS Lookup, ASN Lookup |
| **IP Information** | IP Geolocation, Full IP Info, Reverse IP Lookup |
| **Web Tools** | HTTP Headers + Security Analysis, Link Extraction, Analytics Detection, Social Media Extractor |
| **External Tools** | Nmap Port Scanner (presets + custom), Nmap OS Detection, RustScan |

---

## Architecture

```
files/
├── main.py              # Entry point; QApplication + dark palette setup
├── main_window.py       # MainWindow, ToolPanel base class, 22 panel subclasses
├── workers.py           # ScanWorker (QThread), ResultFormatter (HTML output)
├── dns_tools.py         # DNS resolution, subdomain discovery, shared DNS
├── network_tools.py     # Ping, traceroute, port scanning, subnet analysis
├── ip_tools.py          # WHOIS, ASN, geolocation, reverse IP
├── web_tools.py         # HTTP headers, link extraction, analytics detection
├── external_tools.py    # Nmap, RustScan subprocess wrappers
├── requirements.txt     # Python dependencies
└── README.md            # User documentation
```

### Design Principles

1. **Non-blocking UI** — All scans run in `ScanWorker` (QThread). Signals (`result_ready`, `error_occurred`, `finished_scan`) marshal data safely to the main thread.

2. **Module Isolation** — Tool modules (`*_tools.py`) have zero Qt dependency; they can be imported and tested independently in a REPL.

3. **Graceful Degradation** — Optional libraries (`dnspython`, `ipwhois`, `beautifulsoup4`) are detected at call-time; socket-based fallbacks are used when absent.

4. **Extensibility** — Add a new tool by:
   - Writing a function in the appropriate `*_tools.py` file
   - Subclassing `ToolPanel` in `main_window.py` (~15 lines)
   - Adding an entry to `TOOL_CATALOGUE` and `PANEL_MAP`

---

## Building and Running

### Prerequisites

- **Python 3.10+**
- **System tools (optional):** `nmap`, `rustscan`, `traceroute`/`tracert`, `ping`

### Installation

```bash
# 1. Navigate to project directory
cd /mnt/sda1/TOOLS/files

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate      # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run the application
python main.py
```

### External Tools Installation (Optional)

- **Nmap:** https://nmap.org/download.html
- **RustScan:** https://github.com/RustScan/RustScan/releases

---

## Development Conventions

### Code Style

- **Type hints:** All functions use Python type annotations
- **Docstrings:** Google-style docstrings explaining purpose, parameters, and return values
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes
- **Constants:** `UPPER_CASE` for module-level constants (e.g., `SERVICE_MAP`, `ANALYTICS_PATTERNS`)

### Module Structure

Each tool module follows a consistent pattern:

```python
"""
Module Name
Handles: Feature1, Feature2, Feature3
"""

import ...
from typing import Dict, Any, List, Optional

# Optional library detection
try:
    import optional_lib
    LIB_OK = True
except ImportError:
    LIB_OK = False

# Tool function signature
def tool_name(param: str, option: int = 10) -> Dict[str, Any]:
    """
    Perform the operation.
    
    Args:
        param: Description
        option: Description
        
    Returns:
        Dict with results or error key
    """
    if not LIB_OK:
        return {"error": "Library not available", "fallback": ...}
    
    # Implementation
    return {"result": ...}
```

### Return Value Convention

All tool functions return a `Dict[str, Any]`:
- **Success:** Contains result data (e.g., `{"records": {...}, "count": 5}`)
- **Error:** Contains `"error"` key (e.g., `{"error": "Description of failure"}`)
- **Optional:** May include `"warning"` key for non-fatal issues

### Testing Practices

- Modules are designed for REPL testing — import and call directly
- Graceful degradation allows testing even without optional dependencies
- External tools check availability via `shutil.which()` before execution

---

## Key Classes and Components

### `ScanWorker` (workers.py)

QThread-based worker for background execution:

```python
worker = ScanWorker("DNS Lookup", dns_tools.dns_lookup, "example.com", record_types=["A", "MX"])
worker.result_ready.connect(on_result)
worker.error_occurred.connect(on_error)
worker.finished_scan.connect(on_done)
worker.start()
```

### `ResultFormatter` (workers.py)

Converts raw results to styled HTML for display:

```python
html = ResultFormatter.format("DNS Lookup", result_dict, target="example.com")
text_edit.setHtml(html)
```

### `ToolPanel` (main_window.py)

Base class for all tool UIs. Provides helper methods:
- `_text()`, `_combo()`, `_spin()`, `_dspin()` — Input field creators
- `_check()`, `_checkgroup()` — Checkbox helpers
- `_val()` — Extract value from field by name
- `get_kwargs()` — Override to return tool function arguments

---

## Adding a New Tool (3 Steps)

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

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `PyQt6>=6.5.0` | GUI framework |
| `dnspython>=2.4.0` | DNS resolution & reverse lookups |
| `python-whois>=0.9.0` | WHOIS data parsing |
| `ipwhois>=1.3.0` | RDAP / ASN lookups |
| `requests>=2.31.0` | HTTP requests |
| `beautifulsoup4>=4.12.0` | HTML parsing for web tools |
| `lxml>=4.9.0` | Faster HTML parser for bs4 |
| `netaddr>=0.8.0` | CIDR / subnet utilities |
| `urllib3>=2.0.0` | HTTP library (suppress warnings) |

---

## Key Bindings

| Shortcut | Action |
|----------|--------|
| `Ctrl+Enter` | Run current tool |
| Click sidebar item | Switch tool panel |

---

## Export Functionality

Click **↓ Export** in the toolbar to save accumulated results as:
- **JSON** — Structured, full data
- **TXT** — Human-readable plain text

---

## Security and Legal Considerations

> **You are responsible for how you use this tool.** Only scan systems you own or have explicit written permission to test.

### Recommendations

- Run in a dedicated virtual environment
- Never store credentials or sensitive results in shared directories
- Treat all retrieved data as potentially sensitive PII
- Use a VPN or isolated VM for active scanning tasks
- Add delays when making many API calls to avoid rate-limiting

---

## File Locations

- **Project Root:** `/mnt/sda1/TOOLS/files/`
- **Virtual Environment:** `/mnt/sda1/TOOLS/files/.venv/`
- **Main Entry:** `/mnt/sda1/TOOLS/files/main.py`
