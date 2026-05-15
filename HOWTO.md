# HOWTO.md - Recon 9 OSINT Application

## Overview
Recon 9 is a modular OSINT desktop application built with Python 3.10+ and PyQt6. It features a dark GitHub-inspired theme and performs network reconnaissance tasks including DNS lookups, port scanning, WHOIS queries, and web analysis.

---

## Build, Test, and Run Commands

### Setup
```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Standard run
python main.py

# Or via module
python -m main
```

### Testing Individual Modules
```bash
# Test a module directly
python -c "from dns_tools import dns_lookup; print(dns_lookup('example.com'))"

# Test with pytest (if test files exist)
python -m pytest tests/ -v

# Run a specific test
python -m pytest tests/test_dns_tools.py -v

# Run a single test function
python -m pytest tests/test_dns_tools.py::test_dns_lookup -v
```

### Code Quality
```bash
# Run black formatter
python -m black .

# Run flake8 linter
python -m flake8 .

# Check types with mypy
python -m mypy .
```

---

## Project Structure

```
.
├── main.py              # Entry point, QApplication setup, dark palette
├── main_window.py       # MainWindow, ToolPanel base, all 22 panel subclasses
├── workers.py           # ScanWorker (QThread), ResultFormatter (HTML output)
├── dns_tools.py         # DNS lookup, reverse DNS, subdomains, shared DNS
├── network_tools.py     # Ping, traceroute, TCP/UDP scan, subnet, banner grab
├── ip_tools.py          # WHOIS, ASN, geolocation, IP information
├── web_tools.py         # HTTP headers, link extraction, analytics, social media
├── external_tools.py    # Nmap, RustScan wrappers
├── bulk_tools.py        # Bulk operations for all tool types
├── report_generator.py  # HTML report generation with visualizations
├── requirements.txt     # Python dependencies
└── assets/              # Icons, sounds, static files
```

---

## Code Style Guidelines

### Python Version and Type Hints
- Target Python 3.10+
- **Always use type hints** for function parameters and return types
- Import `typing` module for complex types: `Dict`, `List`, `Any`, `Optional`, `Callable`
- Use lowercase with underscores for variable names: `host_name`, `port_spec`

### Import Conventions
```python
# Standard library first
import os
import sys
import re
from typing import Dict, List, Any, Optional

# Third-party libraries (PyQt6 first, then others)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout

# Local imports last
import dns_tools
from workers import ScanWorker
```

### Module Structure
```python
"""
Module Name
Brief description of what the module handles.
"""

# Section dividers for larger modules
# ─────────────────────────────────────────────────────────────────────────────

# Private helpers prefixed with underscore
def _helper_function(args):
    ...

# Public functions with docstrings
def public_function(param: str) -> Dict[str, Any]:
    """
    One-line summary.
    
    Args:
        param: Description
        
    Returns:
        Description of returned dict
    """
```

### Docstring Format
```python
def function_name(arg1: str, arg2: Optional[int] = None) -> Dict[str, Any]:
    """
    Brief description of what the function does.
    
    Args:
        arg1: Description of first argument
        arg2: Description of second argument (default: None)
        
    Returns:
        Description of return value
    """
```

### Error Handling
- Always catch specific exceptions rather than bare `except:`
- Return error dicts from tool functions, never raise:
  ```python
  def tool_function(target: str) -> Dict[str, Any]:
      try:
          result = do_something(target)
          return {"success": True, "data": result}
      except SpecificError as exc:
          return {"error": str(exc)}
      except Exception as exc:
          return {"error": f"Unexpected error: {exc}"}
  ```
- Always include `timeout` on network requests (typically 10-15 seconds)
- Graceful degradation: detect optional dependencies and fall back

### Naming Conventions
| Element | Convention | Example |
|---------|------------|---------|
| Modules | lowercase | `dns_tools.py` |
| Functions | snake_case | `dns_lookup()` |
| Classes | PascalCase | `ScanWorker` |
| Constants | UPPER_SNAKE | `SERVICE_MAP` |
| Private methods | _prefix | `_helper_method()` |
| Qt widgets | camelCase in code | `lineEdit`, `pushButton` |
| Object names | lowercase | `setObjectName("btn_run")` |

### PyQt6 Patterns

#### Threading (Critical)
```python
from PyQt6.QtCore import QThread, pyqtSignal

class ScanWorker(QThread):
    result_ready = pyqtSignal(str, object)   # (tool_name, result_dict)
    progress_msg = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    finished_scan = pyqtSignal()
    
    def run(self) -> None:
        try:
            result = self.scan_func(*self.args, **self.kwargs)
            if not self._cancelled:
                self.result_ready.emit(self.tool_name, result)
        except Exception:
            self.error_occurred.emit(traceback.format_exc())
        finally:
            self.finished_scan.emit()
```

#### UI Construction
```python
# Use field helpers in ToolPanel subclasses
def __init__(self):
    super().__init__("Tool Name", "Description", tool_function)
    self._add_section("Target")
    self._text("target", "Target", "example.com")
    self._spin("port", "Port", 1, 65535, 80)
    self._check("verbose", "Verbose mode")
    self._stretch()  # Pushes content to top

def get_kwargs(self) -> Dict[str, Any]:
    return {"target": self._val("target", ""), "port": self._val("port", 80)}
```

### Regular Expressions
- Use raw strings: `r"pattern"`
- Compile patterns at module level: `ANALYTICS_PATTERNS: Dict[str, re.Pattern] = {...}`
- Use verbose mode for complex patterns: `re.compile(r"""
    pattern
    here
""", re.VERBOSE | re.IGNORECASE)`

### Dict Keys and JSON
- Use consistent key names across all tools
- Include `"error"` key when failures occur
- Always return `Dict[str, Any]`, never `None` for errors
- Keys should be snake_case: `"open_ports"`, `"total_targets"`

### HTML/UI Colors (Dark Theme)
```python
# GitHub dark-inspired palette
BG      = QColor(13,  17,  23)   # #0d1117
BG2     = QColor(22,  27,  34)   # #161b22
BG3     = QColor(33,  38,  45)   # #21262d
FG      = QColor(201, 209, 217)  # #c9d1d9
ACCENT  = QColor(88,  166, 255)  # #58a6ff
```

### Tool Panel Registration
```python
# 1. Add to TOOL_CATALOGUE tuple
TOOL_CATALOGUE: List[tuple] = [
    ("🌐  DNS Tools", [
        ("tool_id", "Display Name", "🔍"),
    ]),
]

# 2. Create panel class (15-20 lines typical)
class MyToolPanel(ToolPanel):
    def __init__(self):
        super().__init__("My Tool", "Description.", module.function)
        self._add_section("Settings")
        self._text("target", "Target", "default.example.com")
        self._stretch()
    
    def get_kwargs(self) -> Dict[str, Any]:
        return {"target": self._val("target", "")}
    
    def get_target(self) -> str:
        return self._val("target", "")

# 3. Add to PANEL_MAP
PANEL_MAP: Dict[str, type] = {
    "tool_id": MyToolPanel,
}
```

### External Tool Wrappers
```python
def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def _run(cmd: List[str], timeout: int = 300) -> Dict[str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": str(proc.returncode)}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out.", "returncode": "-1"}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"'{cmd[0]}' not found in PATH.", "returncode": "-1"}
```

### Third-Party API Usage
- Always set User-Agent header: `{"User-Agent": "OSINT-Suite/1.0"}`
- Handle rate limiting (HTTP 429) gracefully
- Use `verify=False` for SSL verification when needed (OSINT targets may have bad certs)
- Respect rate limits and add delays between bulk operations

### Preset Configuration Format
```python
PRESET_NAME: Dict[str, Any] = {
    "flags": ["-T4", "-sV", "-p", "80,443"],
    "description": "Brief description of what this preset does.",
}
```

---

## Adding New Tools

### 1. Create the function in appropriate module
```python
# modules/my_tools.py
def my_new_scan(target: str, option: int = 10) -> Dict[str, Any]:
    """Perform my new scan."""
    result: Dict[str, Any] = {"target": target}
    # ... implementation
    return result
```

### 2. Create the panel class
```python
# main_window.py
class MyNewPanel(ToolPanel):
    def __init__(self):
        super().__init__("My New Scan", "Short description.", my_tools.my_new_scan)
        self._text("target", "Target", "example.com")
        self._spin("option", "Option", 1, 100, 10)
        self._stretch()
    
    def get_kwargs(self) -> Dict[str, Any]:
        return {"target": self._val("target", ""), "option": self._val("option", 10)}
```

### 3. Register in catalog and map
```python
TOOL_CATALOGUE → add tuple to appropriate category
PANEL_MAP → {"my_new_scan": MyNewPanel}
```

---

## Security Considerations
- Never log or expose credentials
- Use `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` for self-signed certs
- All network operations should have timeouts
- Warn users about rate limiting third-party APIs
- Use `verify=False` sparingly and only when necessary

---

## Style Enforcement
- No comments unless explaining non-obvious logic
- Maximum line length: 120 characters
- Use f-strings for string formatting
- Prefer `isinstance()` checks over type comparison
- Use `from __future__ import annotations` for forward references
