"""
Main Window – Recon 9
Full PyQt6 GUI: sidebar navigation, per-tool panels, live results viewer,
export controls, and dark GitHub-inspired stylesheet.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from PyQt6.QtCore import Qt, QSize, QPoint, QRect, pyqtSlot
from PyQt6.QtGui import QFont, QIcon, QTextCursor, QColor, QPixmap
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QDoubleSpinBox,
)

from workers import ScanWorker, ResultFormatter
from report_generator import HTMLReportGenerator
import dns_tools
import network_tools
import ip_tools
import web_tools
import external_tools
import bulk_tools
import ip_generator
import api_config


# ─────────────────────────────────────────────────────────────────────────────
# Stylesheet
# ─────────────────────────────────────────────────────────────────────────────

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px;
}

/* ── Sidebar tree ── */
QTreeWidget {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 4px 2px;
    outline: none;
}
QTreeWidget::item {
    padding: 6px 10px;
    border-radius: 4px;
    color: #c9d1d9;
}
QTreeWidget::item:hover   { background-color: #21262d; }
QTreeWidget::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}
QTreeWidget::branch {
    background: transparent;
}

/* ── Line edits ── */
QLineEdit {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #c9d1d9;
    selection-background-color: #1f6feb;
}
QLineEdit:focus   { border-color: #58a6ff; }
QLineEdit:disabled { color: #484f58; border-color: #21262d; }

/* ── Combo boxes ── */
QComboBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 32px 6px 10px;
    color: #c9d1d9;
    min-width: 200px;
}
QComboBox:focus          { border-color: #58a6ff; }
QComboBox::drop-down     { border: none; width: 28px; subcontrol-origin: padding; subcontrol-position: right center; }
QComboBox::down-arrow    { image: none; border: none; width: 0; height: 0;
                           border-left: 5px solid transparent;
                           border-right: 5px solid transparent;
                           border-top: 6px solid #8b949e; }
QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #58a6ff;
    border-radius: 4px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
    color: #c9d1d9;
    outline: none;
    padding: 4px 0px;
}
QComboBox QAbstractItemView::item {
    background-color: #161b22;
    color: #c9d1d9;
    padding: 7px 14px;
    min-height: 26px;
    border: none;
}
QComboBox QAbstractItemView::item:hover {
    background-color: #21262d;
    color: #e6edf3;
}
QComboBox QAbstractItemView::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}
QComboBox QAbstractScrollArea QScrollBar:vertical {
    width: 10px;
    background-color: #161b22;
    border-radius: 5px;
    margin: 0px;
}
QComboBox QAbstractScrollArea QScrollBar::handle:vertical {
    background-color: #30363d;
    border-radius: 5px;
    min-height: 20px;
}
QComboBox QAbstractScrollArea QScrollBar::handle:vertical:hover {
    background-color: #484f58;
}
QComboBox QAbstractScrollArea QScrollBar::handle:vertical:pressed {
    background-color: #58a6ff;
}
QComboBox QAbstractScrollArea QScrollBar::add-line:vertical,
QComboBox QAbstractScrollArea QScrollBar::sub-line:vertical {
    height: 0px;
}
QComboBox QAbstractScrollArea QScrollBar::add-page:vertical,
QComboBox QAbstractScrollArea QScrollBar::sub-page:vertical {
    background: none;
}

/* ── Spin boxes ── */
QSpinBox, QDoubleSpinBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 5px 8px;
    color: #c9d1d9;
}
QSpinBox:focus, QDoubleSpinBox:focus { border-color: #58a6ff; }
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    background: #21262d; border: none; width: 16px;
}

/* ── Push buttons ── */
QPushButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 7px 16px;
    color: #c9d1d9;
    font-weight: 500;
}
QPushButton:hover    { background-color: #30363d; border-color: #58a6ff; }
QPushButton:pressed  { background-color: #161b22; }
QPushButton:disabled { color: #484f58; border-color: #21262d; }

QPushButton#btn_run {
    background-color: #238636;
    border-color: #2ea043;
    color: #ffffff;
    font-weight: 600;
    min-width: 110px;
}
QPushButton#btn_run:hover   { background-color: #2ea043; }
QPushButton#btn_run:disabled { background-color: #161b22; border-color: #21262d; color: #484f58; }

QPushButton#btn_cancel {
    background-color: #6e0808;
    border-color: #f85149;
    color: #f85149;
}
QPushButton#btn_cancel:hover { background-color: #b62324; color: #fff; }

QPushButton#btn_export {
    background-color: #0d419d;
    border-color: #388bfd;
    color: #79c0ff;
}
QPushButton#btn_export:hover { background-color: #1158c7; }

/* ── Check boxes ── */
QCheckBox { spacing: 8px; color: #c9d1d9; }
QCheckBox::indicator {
    width: 14px; height: 14px;
    border: 1px solid #30363d;
    border-radius: 3px;
    background: #161b22;
}
QCheckBox::indicator:checked {
    background-color: #1f6feb;
    border-color: #388bfd;
    image: none;
}
QCheckBox::indicator:hover { border-color: #58a6ff; }

/* ── Group boxes ── */
QGroupBox {
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-top: 12px;
    padding-top: 6px;
    color: #8b949e;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 4px;
}

/* ── Text edit (results) ── */
QTextEdit {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 8px;
    color: #c9d1d9;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #1f6feb;
}

/* ── Progress bar ── */
QProgressBar {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    height: 6px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #58a6ff;
    border-radius: 4px;
}

/* ── Status bar ── */
QStatusBar {
    background-color: #161b22;
    border-top: 1px solid #21262d;
    color: #8b949e;
    font-size: 12px;
}

/* ── Toolbar ── */
QToolBar {
    background-color: #161b22;
    border-bottom: 1px solid #21262d;
    padding: 4px 8px;
    spacing: 6px;
}

/* ── Splitter ── */
QSplitter::handle {
    background-color: #21262d;
}
QSplitter::handle:horizontal { width: 2px; }
QSplitter::handle:vertical   { height: 2px; }

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #0d1117; width: 8px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #30363d; border-radius: 4px; min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #58a6ff; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: #0d1117; height: 8px; margin: 0;
}
QScrollBar::handle:horizontal {
    background: #30363d; border-radius: 4px; min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #58a6ff; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Labels ── */
QLabel#lbl_tool_title {
    color: #e6edf3;
    font-size: 18px;
    font-weight: 700;
    padding-top: 4px;
    padding-bottom: 2px;
}
QLabel#lbl_tool_desc {
    color: #8b949e;
    font-size: 13px;
}
QLabel#lbl_section {
    color: #8b949e;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tool catalogue
# ─────────────────────────────────────────────────────────────────────────────

# Format: (category_label, [ (tool_id, display_name, icon_char), ... ])
TOOL_CATALOGUE: List[tuple] = [
    ("🌐  DNS Tools", [
        ("dns_lookup",       "DNS Lookup",          "🔍"),
        ("reverse_dns",      "Reverse DNS",         "↩"),
        ("find_subdomains",  "Find Subdomains",     "🌲"),
        ("find_shared_dns",  "Find Shared DNS",     "🔗"),
    ]),
    ("🔌  Network", [
        ("test_ping",        "Test Ping",           "📡"),
        ("traceroute",       "Traceroute",          "🗺"),
        ("tcp_port_scan",    "TCP Port Scan",       "🔓"),
        ("udp_port_scan",    "UDP Port Scan",       "📭"),
        ("subnet_lookup",    "Subnet Lookup",       "📐"),
        ("banner_grab",      "Banner Grabbing",     "🏷"),
    ]),
    ("📋  WHOIS", [
        ("whois_lookup",     "WHOIS Lookup",        "📄"),
        ("asn_lookup",       "ASN Lookup",          "🏢"),
    ]),
    ("🌍  IP Information", [
        ("ip_geolocation",   "IP Geolocation",      "📍"),
        ("ip_information",   "IP Information",      "ℹ"),
        ("reverse_ip",       "Reverse IP Lookup",   "🔄"),
    ]),
    ("🌐  Web Tools", [
        ("http_headers",     "HTTP Headers",        "📨"),
        ("extract_links",    "Extract Page Links",  "🔗"),
        ("reverse_analytics","Reverse Analytics",   "📊"),
        ("social_media",     "Social Media Extractor","📱"),
    ]),
    ("🛠  External Tools", [
        ("nmap_scan",        "Nmap Port Scanner",   "🔭"),
        ("nmap_os",          "Nmap OS Detection",   "💻"),
        ("rustscan",         "RustScan",            "⚡"),
        ("masscan",          "Masscan",             "🚀"),
        ("fping",            "Fping",               "📡"),
        ("netdiscover",      "Netdiscover",         "🔎"),
        ("upnp_discovery",   "UPnP Discovery",      "🔌"),
    ]),
    ("🗂  Bulk Tools", [
        ("bulk_dns",         "Bulk DNS Lookup",     "📋"),
        ("bulk_ping",        "Bulk Ping",           "📡"),
        ("bulk_whois",       "Bulk WHOIS",          "📄"),
        ("bulk_geolocation", "Bulk Geolocation",    "📍"),
        ("bulk_http",        "Bulk HTTP Headers",   "📨"),
        ("bulk_nmap",        "Bulk Nmap Scan",      "🔬"),
        ("bulk_shodan",      "Bulk Shodan Search",  "🔍"),
        ("ip_generator",     "IP Generator (CIDR)", "🔢"),
        ("bulk_ping_cidr",   "Bulk Ping - CIDR",    "📡"),
    ]),
]


# ─────────────────────────────────────────────────────────────────────────────
# Custom ComboBox – popup anchored below widget, capped height with scrollbar
# ─────────────────────────────────────────────────────────────────────────────

class BoundedComboBox(QComboBox):
    """QComboBox with a showPopup override that:
    - Always opens directly below the widget (not floating off-screen)
    - Caps visible rows at MAX_ROWS; extra items scroll
    - Sizes popup width to fit the longest item text
    """
    MAX_ROWS = 12
    ROW_H    = 32   # px per item (matches stylesheet padding)

    def showPopup(self) -> None:
        # Measure longest item
        fm = self.fontMetrics()
        max_tw = max((fm.horizontalAdvance(self.itemText(i))
                      for i in range(self.count())), default=100)
        popup_w = max(max_tw + 48, 260)          # 48 = padding + scrollbar

        # Cap height to MAX_ROWS rows
        visible   = min(self.count(), self.MAX_ROWS)
        popup_h   = visible * self.ROW_H + 10    # +10 for view border/padding

        # Position: bottom-left of the combo widget, in screen coordinates
        pos = self.mapToGlobal(QPoint(0, self.height()))

        # Apply geometry to the view's container (the floating QFrame Qt uses)
        container = self.view().window()
        container.setFixedSize(popup_w, popup_h)
        container.move(pos)

        super().showPopup()

        # Re-apply after Qt's own showPopup adjusts things
        container.setFixedSize(popup_w, popup_h)
        container.move(pos)


# ─────────────────────────────────────────────────────────────────────────────
# Tool Panel base
# ─────────────────────────────────────────────────────────────────────────────

class ToolPanel(QWidget):
    """Generic tool panel – subclassed once per tool."""

    def __init__(
        self,
        title: str,
        description: str,
        tool_func: Callable,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.title       = title
        self.description = description
        self.tool_func   = tool_func
        self._fields: Dict[str, QWidget] = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Scroll area so tall panels don't clip
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(10)
        self._build_header()
        scroll.setWidget(container)
        outer.addWidget(scroll)

    def _build_header(self) -> None:
        lbl_title = QLabel(self.title)
        lbl_title.setObjectName("lbl_tool_title")
        self._layout.addWidget(lbl_title)

        lbl_desc = QLabel(self.description)
        lbl_desc.setObjectName("lbl_tool_desc")
        lbl_desc.setWordWrap(True)
        self._layout.addWidget(lbl_desc)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("background:#30363d;border:none;height:1px;margin:6px 0 10px 0;")
        self._layout.addWidget(line)

    # ── Field helpers ────────────────────────────────────────────────────────

    def _add_section(self, title: str) -> None:
        lbl = QLabel(title)
        lbl.setObjectName("lbl_section")
        self._layout.addWidget(lbl)

    def _add_field(
        self,
        name: str,
        label: str,
        widget: QWidget,
        hint: str = "",
    ) -> QWidget:
        row = QHBoxLayout()
        row.setSpacing(8)
        lbl = QLabel(label)
        lbl.setMinimumWidth(130)
        lbl.setStyleSheet("color:#8b949e;")
        row.addWidget(lbl)
        row.addWidget(widget, 1)
        if hint:
            lbl_hint = QLabel(hint)
            lbl_hint.setStyleSheet("color:#484f58;font-size:11px;")
            row.addWidget(lbl_hint)
        self._layout.addLayout(row)
        self._fields[name] = widget
        return widget

    def _text(self, name: str, label: str, placeholder: str = "", hint: str = "") -> QLineEdit:
        w = QLineEdit()
        w.setPlaceholderText(placeholder)
        return self._add_field(name, label, w, hint)

    def _text_area(self, name: str, label: str, placeholder: str = "", multiline: bool = True, hint: str = "") -> QTextEdit:
        w = QTextEdit()
        w.setPlaceholderText(placeholder)
        w.setMaximumHeight(200)
        w.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self._add_field(name, label, w, hint)
        return w

    def _combo(self, name: str, label: str, items: List[str], hint: str = "") -> BoundedComboBox:
        w = BoundedComboBox()
        w.addItems(items)
        # Set widget width to fit the longest item
        fm = w.fontMetrics()
        max_tw = max((fm.horizontalAdvance(t) for t in items), default=100)
        w.setMinimumWidth(min(max_tw + 48, 420))
        return self._add_field(name, label, w, hint)

    def _spin(self, name: str, label: str, lo: int, hi: int, default: int, hint: str = "") -> QSpinBox:
        w = QSpinBox()
        w.setRange(lo, hi)
        w.setValue(default)
        return self._add_field(name, label, w, hint)

    def _dspin(self, name: str, label: str, lo: float, hi: float, default: float, step: float = 0.5) -> QDoubleSpinBox:
        w = QDoubleSpinBox()
        w.setRange(lo, hi)
        w.setValue(default)
        w.setSingleStep(step)
        self._add_field(name, label, w)
        return w

    def _check(self, name: str, label: str, checked: bool = False) -> QCheckBox:
        w = QCheckBox(label)
        w.setChecked(checked)
        self._layout.addWidget(w)
        self._fields[name] = w
        return w

    def _checkgroup(self, name: str, group_label: str, options: List[str], defaults: List[str]) -> QGroupBox:
        box = QGroupBox(group_label)
        grid = QHBoxLayout(box)
        grid.setSpacing(6)
        checks: Dict[str, QCheckBox] = {}
        for opt in options:
            cb = QCheckBox(opt)
            cb.setChecked(opt in defaults)
            grid.addWidget(cb)
            checks[opt] = cb
        grid.addStretch()
        self._layout.addWidget(box)
        self._fields[name] = checks      # store dict of checkboxes
        return box

    def _stretch(self) -> None:
        self._layout.addStretch()

    # ── Data extraction ──────────────────────────────────────────────────────

    def get_kwargs(self) -> Dict[str, Any]:
        """Override in subclass to extract panel-specific inputs."""
        return {}

    def get_target(self) -> str:
        """Return primary target string for display in result header."""
        w = self._fields.get("target") or self._fields.get("url") or self._fields.get("ip")
        if isinstance(w, QLineEdit):
            return w.text().strip()
        return ""

    # ── Helper to read field values ──────────────────────────────────────────

    def _val(self, name: str, default: Any = None) -> Any:
        w = self._fields.get(name)
        if w is None:
            return default
        if isinstance(w, QLineEdit):
            return w.text().strip() or default
        if isinstance(w, QComboBox):
            return w.currentText()
        if isinstance(w, (QSpinBox, QDoubleSpinBox)):
            return w.value()
        if isinstance(w, QCheckBox):
            return w.isChecked()
        if isinstance(w, QTextEdit):
            return w.toPlainText()
        if isinstance(w, dict):   # check group
            return [k for k, cb in w.items() if cb.isChecked()]
        return default


# ─────────────────────────────────────────────────────────────────────────────
# Individual tool panels
# ─────────────────────────────────────────────────────────────────────────────

class DNSLookupPanel(ToolPanel):
    def __init__(self):
        super().__init__("DNS Lookup",
                         "Query one or more DNS record types for a domain or hostname.",
                         dns_tools.dns_lookup)
        self._add_section("Target")
        self._text("target", "Domain / IP", "example.com")
        self._checkgroup("record_types", "Record Types",
                         ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
                         ["A", "AAAA", "MX", "NS", "TXT"])
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "record_types": self._val("record_types") or None}

    def get_target(self): return self._val("target", "")


class ReverseDNSPanel(ToolPanel):
    def __init__(self):
        super().__init__("Reverse DNS", "Look up the hostname associated with an IP address.", dns_tools.reverse_dns)
        self._add_section("Target")
        self._text("ip", "IP Address", "8.8.8.8")
        self._stretch()

    def get_kwargs(self): return {"ip": self._val("ip", "")}
    def get_target(self): return self._val("ip", "")


class FindSubdomainsPanel(ToolPanel):
    def __init__(self):
        super().__init__("Find Subdomains",
                         "Discover subdomains via certificate transparency logs and brute-force.",
                         dns_tools.find_subdomains)
        self._add_section("Target")
        self._text("domain", "Domain", "example.com")
        self._add_section("Methods")
        self._check("use_crt",   "✔  Certificate Transparency (crt.sh)", checked=True)
        self._check("use_brute", "✔  Brute-force common subdomains",     checked=True)
        self._stretch()

    def get_kwargs(self):
        return {"domain": self._val("domain", ""),
                "use_crt": self._val("use_crt", True),
                "use_brute": self._val("use_brute", True)}

    def get_target(self): return self._val("domain", "")


class FindSharedDNSPanel(ToolPanel):
    def __init__(self):
        super().__init__("Find Shared DNS",
                         "Identify nameservers and find other domains sharing them.",
                         dns_tools.find_shared_dns)
        self._add_section("Target")
        self._text("domain", "Domain", "example.com")
        self._stretch()

    def get_kwargs(self): return {"domain": self._val("domain", "")}
    def get_target(self): return self._val("domain", "")


class PingPanel(ToolPanel):
    def __init__(self):
        super().__init__("Test Ping", "Send ICMP echo requests to test host reachability.", network_tools.test_ping)
        self._add_section("Target")
        self._text("host", "Host / IP", "8.8.8.8")
        self._spin("count", "Ping Count", 1, 50, 4)
        self._stretch()

    def get_kwargs(self): return {"host": self._val("host", ""), "count": self._val("count", 4)}
    def get_target(self): return self._val("host", "")


class TraceroutePanel(ToolPanel):
    def __init__(self):
        super().__init__("Traceroute", "Trace the network route to a destination host.", network_tools.traceroute)
        self._add_section("Target")
        self._text("host", "Host / IP", "8.8.8.8")
        self._spin("max_hops", "Max Hops", 1, 64, 30)
        self._stretch()

    def get_kwargs(self): return {"host": self._val("host", ""), "max_hops": self._val("max_hops", 30)}
    def get_target(self): return self._val("host", "")


class TCPScanPanel(ToolPanel):
    def __init__(self):
        super().__init__("TCP Port Scan",
                         "Multi-threaded TCP connect scan. Use CIDR or ranges like 1-1024, 80,443.",
                         network_tools.tcp_port_scan)
        self._add_section("Target")
        self._text("host", "Host / IP", "scanme.nmap.org")
        self._text("port_spec", "Port Range", "1-1024", hint="e.g. 1-1024 or 80,443,8080")
        self._add_section("Options")
        self._dspin("timeout", "Timeout (s)", 0.1, 10.0, 1.0)
        self._spin("threads", "Threads", 10, 500, 100)
        self._stretch()

    def get_kwargs(self):
        return {"host": self._val("host", ""), "port_spec": self._val("port_spec", "1-1024"),
                "timeout": self._val("timeout", 1.0), "threads": self._val("threads", 100)}

    def get_target(self): return self._val("host", "")


class UDPScanPanel(ToolPanel):
    def __init__(self):
        super().__init__("UDP Port Scan",
                         "UDP scan of specified ports. May require root. Results can be ambiguous.",
                         network_tools.udp_port_scan)
        self._add_section("Target")
        self._text("host", "Host / IP", "scanme.nmap.org")
        self._text("port_spec", "Port List", "53,67,68,69,123,161,500,514")
        self._dspin("timeout", "Timeout (s)", 0.5, 15.0, 2.0)
        self._stretch()

    def get_kwargs(self):
        return {"host": self._val("host", ""), "port_spec": self._val("port_spec", ""),
                "timeout": self._val("timeout", 2.0)}

    def get_target(self): return self._val("host", "")


class SubnetPanel(ToolPanel):
    def __init__(self):
        super().__init__("Subnet Lookup", "Analyse a CIDR block: network/broadcast/hosts/mask.", network_tools.subnet_lookup)
        self._add_section("CIDR Block")
        self._text("cidr", "CIDR", "192.168.1.0/24")
        self._stretch()

    def get_kwargs(self): return {"cidr": self._val("cidr", "")}
    def get_target(self): return self._val("cidr", "")


class BannerGrabPanel(ToolPanel):
    def __init__(self):
        super().__init__("Banner Grabbing",
                         "Connect to ports and capture service banners / HTTP headers.",
                         network_tools.banner_grab)
        self._add_section("Target")
        self._text("host", "Host / IP", "scanme.nmap.org")
        self._text("port_spec", "Ports", "21,22,25,80,443,8080")
        self._dspin("timeout", "Timeout (s)", 0.5, 15.0, 3.0)
        self._stretch()

    def get_kwargs(self):
        return {"host": self._val("host", ""), "port_spec": self._val("port_spec", ""),
                "timeout": self._val("timeout", 3.0)}

    def get_target(self): return self._val("host", "")


class WhoisPanel(ToolPanel):
    def __init__(self):
        super().__init__("WHOIS Lookup", "Retrieve registration data for a domain or IP address.", ip_tools.whois_lookup)
        self._add_section("Target")
        self._text("target", "Domain / IP", "example.com")
        self._stretch()

    def get_kwargs(self): return {"target": self._val("target", "")}
    def get_target(self): return self._val("target", "")


class ASNPanel(ToolPanel):
    def __init__(self):
        super().__init__("ASN Lookup", "Retrieve Autonomous System information for an IP address.", ip_tools.asn_lookup)
        self._add_section("Target")
        self._text("ip_or_asn", "IP / ASN", "8.8.8.8", hint="e.g. 8.8.8.8 or AS15169")
        self._stretch()

    def get_kwargs(self): return {"ip_or_asn": self._val("ip_or_asn", "")}
    def get_target(self): return self._val("ip_or_asn", "")


class IPGeoPanel(ToolPanel):
    def __init__(self):
        super().__init__("IP Geolocation", "Geolocate an IP: country, city, ISP, lat/lon, timezone.", ip_tools.ip_geolocation)
        self._add_section("Target")
        self._text("ip_or_host", "IP / Hostname", "8.8.8.8")
        self._stretch()

    def get_kwargs(self): return {"ip_or_host": self._val("ip_or_host", "")}
    def get_target(self): return self._val("ip_or_host", "")


class IPInfoPanel(ToolPanel):
    def __init__(self):
        super().__init__("IP Information", "Aggregate: geolocation + ASN + reverse DNS in one call.", ip_tools.ip_information)
        self._add_section("Target")
        self._text("ip_or_host", "IP / Hostname", "8.8.8.8")
        self._stretch()

    def get_kwargs(self): return {"ip_or_host": self._val("ip_or_host", "")}
    def get_target(self): return self._val("ip_or_host", "")


class ReverseIPPanel(ToolPanel):
    def __init__(self):
        super().__init__("Reverse IP Lookup", "Find all domains hosted on the same IP (HackerTarget API).", ip_tools.reverse_ip_lookup)
        self._add_section("Target")
        self._text("ip_or_host", "IP / Hostname", "93.184.216.34")
        self._stretch()

    def get_kwargs(self): return {"ip_or_host": self._val("ip_or_host", "")}
    def get_target(self): return self._val("ip_or_host", "")


class HTTPHeadersPanel(ToolPanel):
    def __init__(self):
        super().__init__("HTTP Headers", "Fetch response headers and analyse security settings.", web_tools.http_headers)
        self._add_section("Target")
        self._text("url", "URL", "https://example.com")
        self._add_section("Options")
        self._check("follow_redirects", "Follow redirects", checked=True)
        self._text("user_agent", "User-Agent", "Mozilla/5.0 (OSINT-Suite)")
        self._stretch()

    def get_kwargs(self):
        ua = self._val("user_agent", "") or "Mozilla/5.0 (OSINT-Suite)"
        return {"url": self._val("url", ""), "follow_redirects": self._val("follow_redirects", True),
                "user_agent": ua}

    def get_target(self): return self._val("url", "")


class ExtractLinksPanel(ToolPanel):
    def __init__(self):
        super().__init__("Extract Page Links", "Crawl a page and list all hyperlinks (internal and/or external).", web_tools.extract_links)
        self._add_section("Target")
        self._text("url", "URL", "https://example.com")
        self._combo("filter_mode", "Filter", ["all", "internal", "external"])
        self._stretch()

    def get_kwargs(self):
        return {"url": self._val("url", ""), "filter_mode": self._val("filter_mode", "all")}

    def get_target(self): return self._val("url", "")


class ReverseAnalyticsPanel(ToolPanel):
    def __init__(self):
        super().__init__("Reverse Analytics",
                         "Detect tracking IDs, analytics tags, and technology stack hints.",
                         web_tools.reverse_analytics)
        self._add_section("Target")
        self._text("url", "URL", "https://example.com")
        self._stretch()

    def get_kwargs(self): return {"url": self._val("url", "")}
    def get_target(self): return self._val("url", "")


class SocialMediaPanel(ToolPanel):
    def __init__(self):
        super().__init__("Social Media Extractor",
                         "Scan a webpage for links to social media profiles and contact emails.",
                         web_tools.extract_social_media)
        self._add_section("Target")
        self._text("url", "URL", "https://example.com")
        self._stretch()

    def get_kwargs(self): return {"url": self._val("url", "")}
    def get_target(self): return self._val("url", "")


class NmapScanPanel(ToolPanel):
    def __init__(self):
        super().__init__("Nmap Port Scanner", "Run Nmap with preset or custom flags.", external_tools.nmap_port_scan)
        presets = list(external_tools.NMAP_SCAN_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Target", "scanme.nmap.org")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._text("port_spec", "Port Override", "", hint="optional, e.g. 80,443")
        self._text("custom_flags", "Extra Flags", "", hint="e.g. --script=http-title")
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "port_spec": self._val("port_spec") or None,
                "custom_flags": self._val("custom_flags", "")}

    def get_target(self): return self._val("target", "")


class NmapOSPanel(ToolPanel):
    def __init__(self):
        super().__init__("Nmap OS Detection",
                         "Detect operating system via Nmap (-O). Requires root/admin.",
                         external_tools.nmap_os_detection)
        self._add_section("Target")
        self._text("target", "Target", "scanme.nmap.org")
        self._stretch()

    def get_kwargs(self): return {"target": self._val("target", "")}
    def get_target(self): return self._val("target", "")


class RustScanPanel(ToolPanel):
    def __init__(self):
        super().__init__("RustScan", "Ultra-fast port scanner. Finds open ports then optionally pipes to Nmap.", external_tools.rustscan)
        presets = list(external_tools.RUSTSCAN_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Target", "scanme.nmap.org")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._text("port_spec", "Port Range", "1-10000", hint="e.g., 1-1000 or 80,443,8080")
        self._spin("batch_size", "Batch Size", 100, 65000, 4500)
        self._spin("timeout_ms", "Timeout (ms)", 100, 10000, 1500)
        self._text("extra_flags", "Extra Flags", "", hint="e.g., --ulimit 5000")
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "port_spec": self._val("port_spec", "1-10000"),
                "batch_size": self._val("batch_size", 4500), "timeout_ms": self._val("timeout_ms", 1500),
                "extra_flags": self._val("extra_flags", "")}

    def get_target(self): return self._val("target", "")


class MasscanPanel(ToolPanel):
    def __init__(self):
        super().__init__("Masscan", "Ultra-fast port scanner. Can scan the entire Internet in minutes.", external_tools.masscan)
        presets = list(external_tools.MASSCAN_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Target", "45.33.32.156", hint="IP address or subnet (e.g., 192.168.1.0/24). Hostnames auto-resolved.")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._text("ports", "Ports", "top100", hint="e.g., 80,443 or 1-1000 or top100")
        self._spin("rate", "Packets/sec", 100, 10000000, 10000)
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "ports": self._val("ports", "top100"), "rate": self._val("rate", 10000)}

    def get_target(self): return self._val("target", "")


class FpingPanel(ToolPanel):
    def __init__(self):
        super().__init__("Fping", "Fast ICMP ping sweep for host discovery. Great for subnet scanning.", external_tools.fping)
        presets = list(external_tools.FPING_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Target", "192.168.1.0/24", hint="IP, hostname, subnet (e.g., 192.168.1.0/24 or 192.168.1.1-100)")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._spin("timeout_ms", "Timeout (ms)", 50, 5000, 500)
        self._spin("retries", "Retries", 0, 10, 2)
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "timeout_ms": self._val("timeout_ms", 500), "retries": self._val("retries", 2)}

    def get_target(self): return self._val("target", "")


class NetdiscoverPanel(ToolPanel):
    def __init__(self):
        super().__init__("Netdiscover", "ARP-based network discovery. Live results for ALL modes!", external_tools.netdiscover)
        presets = list(external_tools.NETDISCOVER_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Subnet (CIDR)", "192.168.1.0/24", hint="e.g., 192.168.1.0/24 (not used in passive/continuous mode)")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        # Set default to fast scan
        combo.setCurrentText("Fast Active Scan")
        self._combo("mode", "Mode", ["active", "passive", "continuous"])
        self._spin("count", "Packet Count", 0, 1000, 30, hint="Lower = faster")
        self._spin("delay", "Delay (ms)", 0, 10000, 200, hint="Lower = faster")
        self._add_section("💡 Live Results: Watch output appear in real-time below!")
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "mode": self._val("mode", "active"), "count": self._val("count", 30),
                "delay": self._val("delay", 200), "timeout": 120}

    def get_target(self): return self._val("target", "")


class UPnPDiscoveryPanel(ToolPanel):
    def __init__(self):
        super().__init__("UPnP Discovery", "Discover devices via UPnP/SSDP. May reveal internal network devices.", external_tools.upnp_discovery)
        presets = list(external_tools.UPNP_PRESETS.keys())
        self._add_section("Target")
        self._text("target", "Target IP", "192.168.1.1", hint="Router IP (local network works best)")
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._text("port", "Port(s)", "1900", hint="UPnP port (default: 1900)")
        self._text("script", "NSE Scripts", "upnp-info", hint="e.g., upnp-info, broadcast-upnp-info")
        self._add_section("⚠️ Note: TCP scans work without root. UDP requires sudo.")
        self._stretch()

    def get_kwargs(self):
        return {"target": self._val("target", ""), "preset": self._val("preset", ""),
                "port": self._val("port", "1900"), "script": self._val("script", "upnp-info")}

    def get_target(self): return self._val("target", "")


# ─────────────────────────────────────────────────────────────────────────────
# Bulk Tool Panels
# ─────────────────────────────────────────────────────────────────────────────

class BulkDNSPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk DNS Lookup",
                         "Query DNS records for multiple domains/IPs at once. One target per line.",
                         bulk_tools.bulk_dns_lookup)
        self._add_section("Targets")
        self._text_area("targets", "Domains / IPs", "example.com\ngoogle.com\n8.8.8.8", multiline=True)
        self._add_section("Record Types")
        self._checkgroup("record_types", "Records",
                         ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
                         ["A", "AAAA", "MX", "NS", "TXT"])
        self._add_section("Options")
        self._spin("delay", "Delay between queries (ms)", 0, 5000, 100)
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        return {"targets": targets, "record_types": self._val("record_types") or None,
                "delay": self._val("delay", 100)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkPingPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk Ping",
                         "Send ICMP echo requests to multiple hosts. One host/IP per line.",
                         bulk_tools.bulk_ping)
        self._add_section("Targets")
        self._text_area("targets", "Hosts / IPs", "8.8.8.8\n1.1.1.1\ngoogle.com", multiline=True)
        self._add_section("Options")
        self._spin("count", "Ping Count", 1, 50, 4)
        self._spin("delay", "Delay between pings (ms)", 0, 5000, 100)
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        return {"targets": targets, "count": self._val("count", 4),
                "delay": self._val("delay", 100)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkWhoisPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk WHOIS",
                         "Retrieve WHOIS data for multiple domains/IPs. One target per line.",
                         bulk_tools.bulk_whois)
        self._add_section("Targets")
        self._text_area("targets", "Domains / IPs", "example.com\ngoogle.com\n8.8.8.8", multiline=True)
        self._add_section("Options")
        self._spin("delay", "Delay between queries (ms)", 0, 5000, 200)
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        return {"targets": targets, "delay": self._val("delay", 200)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkGeoPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk Geolocation",
                         "Geolocate multiple IP addresses. One IP per line. Results are grouped by country and city.",
                         bulk_tools.bulk_geolocation)
        self._add_section("Targets")
        self._text_area("targets", "IP Addresses", "8.8.8.8\n1.1.1.1\n208.67.222.222", multiline=True)
        self._add_section("Display Options")
        self._check("group_by_country", "Group results by country", checked=True)
        self._check("show_coordinates", "Show coordinates", checked=True)
        self._check("show_isp", "Show ISP/Organization", checked=True)
        self._add_section("Options")
        self._spin("delay", "Delay between queries (ms)", 0, 5000, 100)
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        return {"targets": targets, "delay": self._val("delay", 100)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkHTTPPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk HTTP Headers",
                         "Fetch HTTP headers for multiple URLs. One URL per line.",
                         bulk_tools.bulk_http_headers)
        self._add_section("Targets")
        self._text_area("targets", "URLs", "https://example.com\nhttps://google.com\nhttps://github.com", multiline=True)
        self._add_section("Options")
        self._check("follow_redirects", "Follow redirects", checked=True)
        self._text("user_agent", "User-Agent", "Mozilla/5.0 (OSINT-Suite)")
        self._spin("delay", "Delay between requests (ms)", 0, 5000, 200)
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        ua = self._val("user_agent", "") or "Mozilla/5.0 (OSINT-Suite)"
        return {"targets": targets, "follow_redirects": self._val("follow_redirects", True),
                "user_agent": ua, "delay": self._val("delay", 200)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkNmapPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk Nmap Scan",
                         "Perform Nmap scans on multiple targets. One host/IP per line. Results show per-host port tables and service summaries.",
                         bulk_tools.bulk_nmap_scan)
        presets = list(external_tools.NMAP_SCAN_PRESETS.keys())
        self._add_section("Targets")
        self._text_area("targets", "Hosts / IPs", "scanme.nmap.org\n8.8.8.8\ngoogle.com", multiline=True)
        self._add_section("Scan Configuration")
        combo = self._combo("preset", "Preset", presets)
        self._text("port_spec", "Port Override", "", hint="optional, e.g. 80,443 or 1-1000")
        self._text("custom_flags", "Extra Flags", "", hint="e.g. --script=http-title")
        self._add_section("Display Options")
        self._check("show_services", "Show service summary cloud", checked=True)
        self._check("show_geolocation", "Show geolocation for discovered IPs", checked=True)
        self._checkgroup("os_filter", "OS Detection", ["None", "Light", "Aggressive"], ["None"])
        self._add_section("Timing Options")
        self._spin("delay", "Delay between scans (ms)", 0, 10000, 500, hint="Avoid rate limiting")
        self._spin("timeout", "Timeout per scan (sec)", 60, 3600, 600, hint="Max time per target")
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        
        # Build custom flags based on OS detection choice
        os_mode = self._val("os_filter", ["None"])
        custom = self._val("custom_flags", "")
        if "Light" in os_mode:
            custom += " -O" if not custom else " -O"
        elif "Aggressive" in os_mode:
            custom += " -A" if not custom else " -A"
        
        return {"targets": targets, "preset": self._val("preset", "Quick Scan (-T4 top 100)"),
                "port_spec": self._val("port_spec") or None,
                "custom_flags": custom.strip(),
                "delay": self._val("delay", 500),
                "timeout_per_scan": self._val("timeout", 600)}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class BulkShodanPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk Shodan Search",
                         "Search Shodan for multiple IP addresses. Extracts Country, City, Organization, CVEs, and open ports. Results grouped by location. Tip: Add your Shodan session cookie for full access.",
                         bulk_tools.bulk_shodan_search)
        self._add_section("Targets")
        self._text_area("targets", "IP Addresses", "8.8.8.8\n1.1.1.1\n208.67.222.222", multiline=True)
        self._add_section("Authentication (Optional)")
        self._text("cookie", "Shodan Session Cookie", "", 
                   hint="Get from browser cookies after logging in to shodan.io")
        self._add_section("Extraction Options")
        self._check("extract_cves", "Extract CVE vulnerabilities", checked=True)
        self._check("extract_ports", "Extract open ports", checked=True)
        self._add_section("Rate Limiting")
        self._spin("delay", "Delay between queries (ms)", 500, 10000, 1000, 
                   hint="Shodan may rate-limit. 1000ms recommended.")
        self._stretch()

    def get_kwargs(self):
        targets_text = self._val("targets", "")
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]
        cookie = self._val("cookie", "")
        return {"targets": targets, 
                "delay": self._val("delay", 1000),
                "extract_cves": self._val("extract_cves", True),
                "extract_ports": self._val("extract_ports", True),
                "cookie": cookie if cookie else None}

    def get_target(self):
        targets_text = self._val("targets", "")
        count = len([t for t in targets_text.split("\n") if t.strip()])
        return f"{count} target(s)"


class IPGeneratorPanel(ToolPanel):
    def __init__(self):
        super().__init__("IP Generator from CIDR",
                         "Generate all IP addresses from a CIDR range (e.g., 192.168.1.0/24). Useful for bulk scanning.",
                         ip_generator.cidr_info)
        self._add_section("CIDR Range")
        self._text("cidr", "CIDR Notation", "192.168.1.0/24", 
                   hint="e.g., 192.168.1.0/24 or 10.0.0.0/8")
        self._add_section("Options")
        self._check("skip_network_broadcast", "Skip network & broadcast addresses", checked=True)
        self._stretch()

    def get_kwargs(self):
        return {"cidr": self._val("cidr", "")}

    def get_target(self):
        return self._val("cidr", "")


class BulkPingCIDRPanel(ToolPanel):
    def __init__(self):
        super().__init__("Bulk Ping - CIDR Range",
                         "Ping all IPs in a CIDR range to discover live hosts. Results sorted by status (Up/Down).",
                         ip_generator.bulk_ping_cidr)
        self._add_section("CIDR Range")
        self._text("cidr", "CIDR Notation", "192.168.1.0/24", 
                   hint="e.g., 192.168.1.0/24 (max /22 for 1024 IPs)")
        self._add_section("Ping Options")
        self._spin("count", "Ping Count", 1, 10, 2, hint="Number of pings per host")
        self._dspin("timeout", "Timeout (seconds)", 0.5, 10.0, 1.0, 0.5)
        self._spin("threads", "Concurrent Threads", 10, 500, 100, hint="Higher = faster but more load")
        self._stretch()

    def get_kwargs(self):
        return {
            "cidr": self._val("cidr", ""),
            "count": self._val("count", 2),
            "timeout": self._val("timeout", 1.0),
            "threads": self._val("threads", 100),
        }

    def get_target(self):
        return self._val("cidr", "")


# ─────────────────────────────────────────────────────────────────────────────
# Settings Panel
# ─────────────────────────────────────────────────────────────────────────────

class SettingsPanel(ToolPanel):
    """Settings panel for API key management and application preferences."""
    
    def __init__(self):
        super().__init__("Settings", "Configure API keys and application preferences.", None)
        self._api_fields: Dict[str, Dict[str, QWidget]] = {}
        self._build_settings()
    
    def _build_settings(self) -> None:
        """Build the settings UI with API key management."""
        # API Keys Section
        self._add_section("🔑 API Key Management")
        
        # Description label
        desc_lbl = QLabel("Configure API keys for external services. Keys are stored locally in api_config.json")
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color:#8b949e;font-size:12px;margin-bottom:8px;")
        self._layout.addWidget(desc_lbl)
        
        # Load all services
        services = api_config.get_all_services()
        
        # Create API key cards for each service
        for service_id, service_data in services.items():
            self._create_api_key_card(service_id, service_data)
        
        # Application Preferences Section
        self._add_section("⚙️ Application Preferences")

        # Info label
        info_lbl = QLabel("API-dependent tools in the sidebar are highlighted in blue for easy identification.")
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet("color:#484f58;font-size:11px;")
        self._layout.addWidget(info_lbl)

        # Add stretch at the end
        self._stretch()
    
    def _create_api_key_card(self, service_id: str, service_data: Dict[str, Any]) -> None:
        """Create a card UI for managing a single API service."""
        card = QGroupBox()
        card.setStyleSheet("""
            QGroupBox {
                border: 1px solid #30363d;
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 10px;
                background-color: #161b22;
            }
        """)
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(8)
        
        # Header row with name and status
        header_layout = QHBoxLayout()
        
        # Service name
        name_lbl = QLabel(f"{service_data.get('name', service_id)}")
        name_lbl.setStyleSheet("color:#e6edf3;font-size:13px;font-weight:600;")
        header_layout.addWidget(name_lbl)
        
        # Free tier badge
        if service_data.get('free_tier', False):
            free_badge = QLabel("FREE")
            free_badge.setStyleSheet("background-color:#238636;color:#ffffff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600;")
            header_layout.addWidget(free_badge)
        
        header_layout.addStretch()
        
        # Enable/disable toggle
        enable_check = QCheckBox("Enabled")
        enable_check.setChecked(service_data.get('enabled', False))
        enable_check.setObjectName(f"enable_{service_id}")
        enable_check.setStyleSheet("color:#8b949e;")
        header_layout.addWidget(enable_check)
        
        card_layout.addLayout(header_layout)
        
        # Description
        desc_lbl = QLabel(service_data.get('description', ''))
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("color:#484f58;font-size:11px;")
        card_layout.addWidget(desc_lbl)
        
        # API Key input row
        key_layout = QHBoxLayout()
        key_layout.setSpacing(8)
        
        # Key input field
        key_input = QLineEdit()
        key_input.setPlaceholderText("Enter API key...")
        key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_input.setText(service_data.get('key', ''))
        key_input.setObjectName(f"key_{service_id}")
        key_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 10px;
                color: #c9d1d9;
            }
            QLineEdit:focus { border-color: #58a6ff; }
        """)
        key_layout.addWidget(key_input, 1)
        
        # Show/Hide toggle button
        show_btn = QPushButton("👁")
        show_btn.setFixedWidth(40)
        show_btn.setObjectName(f"show_{service_id}")
        show_btn.setToolTip("Show/Hide API key")
        show_btn.clicked.connect(lambda checked, sid=service_id: self._toggle_key_visibility(sid))
        key_layout.addWidget(show_btn)
        
        # Save button
        save_btn = QPushButton("💾 Save")
        save_btn.setObjectName(f"save_{service_id}")
        save_btn.setToolTip("Save API key")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                border: 1px solid #2ea043;
                border-radius: 6px;
                padding: 6px 12px;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
            QPushButton:pressed { background-color: #161b22; }
        """)
        save_btn.clicked.connect(lambda checked, sid=service_id: self._save_api_key(sid))
        key_layout.addWidget(save_btn)
        
        card_layout.addLayout(key_layout)
        
        # URL link
        if service_data.get('url'):
            url_lbl = QLabel(f"🔗 <a href='{service_data['url']}' style='color:#58a6ff;text-decoration:none;'>Visit {service_data.get('name', service_id)} website</a>")
            url_lbl.setOpenExternalLinks(True)
            url_lbl.setStyleSheet("color:#58a6ff;font-size:11px;")
            card_layout.addWidget(url_lbl)
        
        # Store references
        self._api_fields[service_id] = {
            'key': key_input,
            'enable': enable_check,
        }
        
        self._layout.addWidget(card)
    
    def _toggle_key_visibility(self, service_id: str) -> None:
        """Toggle password echo mode for API key field."""
        field = self._api_fields.get(service_id, {}).get('key')
        if field:
            if field.echoMode() == QLineEdit.EchoMode.Password:
                field.setEchoMode(QLineEdit.EchoMode.Normal)
            else:
                field.setEchoMode(QLineEdit.EchoMode.Password)
    
    def _save_api_key(self, service_id: str) -> None:
        """Save API key for a specific service."""
        key_field = self._api_fields.get(service_id, {}).get('key')
        enable_check = self._api_fields.get(service_id, {}).get('enable')
        
        if not key_field or not enable_check:
            return
        
        key_value = key_field.text().strip()
        is_enabled = enable_check.isChecked()
        
        # Update configuration
        success_key = api_config.update_service_key(service_id, key_value)
        success_enable = api_config.update_service_enabled(service_id, is_enabled)
        
        if success_key and success_enable:
            self._show_save_notification(service_id, key_value, is_enabled)
        else:
            QMessageBox.critical(self, "Save Error", f"Failed to save settings for {service_id}")
    
    def _show_save_notification(self, service_id: str, key: str, enabled: bool) -> None:
        """Show a notification after saving API key."""
        services = api_config.get_all_services()
        service_name = services.get(service_id, {}).get('name', service_id)
        
        status = "Enabled" if enabled else "Disabled"
        key_status = "Key set" if key else "No key"
        
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Settings Saved")
        msg.setText(f"{service_name}")
        msg.setInformativeText(f"Status: {status} | {key_status}")
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #161b22;
                color: #c9d1d9;
            }
            QLabel { color: #c9d1d9; font-size: 12px; }
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        msg.exec()
    
    def get_kwargs(self) -> Dict[str, Any]:
        return {}

    def get_target(self) -> str:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Map tool_id → panel class
PANEL_MAP: Dict[str, type] = {
    "dns_lookup":        DNSLookupPanel,
    "reverse_dns":       ReverseDNSPanel,
    "find_subdomains":   FindSubdomainsPanel,
    "find_shared_dns":   FindSharedDNSPanel,
    "test_ping":         PingPanel,
    "traceroute":        TraceroutePanel,
    "tcp_port_scan":     TCPScanPanel,
    "udp_port_scan":     UDPScanPanel,
    "subnet_lookup":     SubnetPanel,
    "banner_grab":       BannerGrabPanel,
    "whois_lookup":      WhoisPanel,
    "asn_lookup":        ASNPanel,
    "ip_geolocation":    IPGeoPanel,
    "ip_information":    IPInfoPanel,
    "reverse_ip":        ReverseIPPanel,
    "http_headers":      HTTPHeadersPanel,
    "extract_links":     ExtractLinksPanel,
    "reverse_analytics": ReverseAnalyticsPanel,
    "social_media":      SocialMediaPanel,
    "nmap_scan":         NmapScanPanel,
    "nmap_os":           NmapOSPanel,
    "rustscan":          RustScanPanel,
    "masscan":           MasscanPanel,
    "fping":             FpingPanel,
    "netdiscover":       NetdiscoverPanel,
    "upnp_discovery":    UPnPDiscoveryPanel,
    # Bulk tools
    "bulk_dns":          BulkDNSPanel,
    "bulk_ping":         BulkPingPanel,
    "bulk_whois":        BulkWhoisPanel,
    "bulk_geolocation":  BulkGeoPanel,
    "bulk_http":         BulkHTTPPanel,
    "bulk_nmap":         BulkNmapPanel,
    "bulk_shodan":       BulkShodanPanel,
    "ip_generator":      IPGeneratorPanel,
    "bulk_ping_cidr":    BulkPingCIDRPanel,
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

# Path to assets
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
ICON_PATH = os.path.join(ASSETS_DIR, "9-removebg-preview-removebg-preview-Picsart-AiImageEnhancer.png")


class MainWindow(QMainWindow):
    """Top-level application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Recon 9  v9.0")
        self.resize(1280, 860)
        self.setMinimumSize(900, 600)

        # Set window icon
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        self._active_worker: Optional[ScanWorker] = None
        self._workers: List[ScanWorker] = []
        self._result_history: List[Dict] = []
        self._current_panel: Optional[ToolPanel] = None
        self._was_cancelled = False  # Track cancellation state

        self.setStyleSheet(STYLESHEET)
        self._build_ui()
        self._populate_sidebar()
        self._check_tools()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Toolbar ──────────────────────────────────────────────────────────
        tb = QToolBar("Main Toolbar")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)

        tb.addWidget(QLabel("  Target:  "))
        self._target_bar = QLineEdit()
        self._target_bar.setPlaceholderText("Quick target override (optional)")
        self._target_bar.setMaximumWidth(340)
        self._target_bar.setToolTip(
            "Paste a target here and click a tool – it will auto-fill the panel's target field."
        )
        self._target_bar.returnPressed.connect(self._push_target)
        tb.addWidget(self._target_bar)
        tb.addSeparator()

        self._btn_run = QPushButton("▶  Run")
        self._btn_run.setObjectName("btn_run")
        self._btn_run.setShortcut("Ctrl+Return")
        self._btn_run.setToolTip("Run the selected tool  (Ctrl+Enter)")
        self._btn_run.clicked.connect(self._run_tool)
        tb.addWidget(self._btn_run)

        self._btn_cancel = QPushButton("■  Stop")
        self._btn_cancel.setObjectName("btn_cancel")
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.clicked.connect(self._cancel_scan)
        tb.addWidget(self._btn_cancel)

        tb.addSeparator()

        self._btn_export = QPushButton("↓  Export")
        self._btn_export.setObjectName("btn_export")
        self._btn_export.clicked.connect(self._export_results)
        tb.addWidget(self._btn_export)

        btn_clear = QPushButton("⌫  Clear")
        btn_clear.clicked.connect(self._clear_results)
        tb.addWidget(btn_clear)

        tb.addSeparator()

        self._btn_graph = QPushButton("⬡  Load Graph")
        self._btn_graph.setObjectName("btn_graph")
        self._btn_graph.setStyleSheet(
            "QPushButton#btn_graph { background: #21262d; color: #58a6ff; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 6px 12px; font-weight: 600; }"
            "QPushButton#btn_graph:hover { background: #30363d; border-color: #58a6ff; }"
        )
        self._btn_graph.setToolTip("Open interactive graph view of all scan results")
        self._btn_graph.clicked.connect(self._open_graph_view)
        tb.addWidget(self._btn_graph)

        tb.addSeparator()

        btn_settings = QPushButton("⚙️  Settings")
        btn_settings.clicked.connect(self._open_settings)
        tb.addWidget(btn_settings)

        # ── Central splitter ─────────────────────────────────────────────────
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(main_splitter)

        # ── Left sidebar ─────────────────────────────────────────────────────
        self._sidebar = QTreeWidget()
        self._sidebar.setHeaderHidden(True)
        self._sidebar.setFixedWidth(220)
        self._sidebar.setAnimated(True)
        self._sidebar.itemClicked.connect(self._on_tool_selected)
        main_splitter.addWidget(self._sidebar)

        # ── Right panel ───────────────────────────────────────────────────────
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(right_splitter)
        main_splitter.setStretchFactor(1, 4)

        # Tool panel stack
        self._stack = QStackedWidget()
        self._stack.setMinimumHeight(240)

        # Placeholder / welcome screen
        welcome = self._make_welcome()
        self._stack.addWidget(welcome)

        right_splitter.addWidget(self._stack)

        # ── Results panel ─────────────────────────────────────────────────────
        results_frame = QWidget()
        rl = QVBoxLayout(results_frame)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)

        results_hdr = QHBoxLayout()
        lbl_res = QLabel("Results")
        lbl_res.setStyleSheet("color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;")
        results_hdr.addWidget(lbl_res)
        results_hdr.addStretch()
        
        self._lbl_result_count = QLabel("")
        self._lbl_result_count.setStyleSheet("color:#484f58;font-size:11px;")
        results_hdr.addWidget(self._lbl_result_count)
        rl.addLayout(results_hdr)

        # Results text view
        self._results_view = QTextEdit()
        self._results_view.setReadOnly(True)
        self._results_view.setMinimumHeight(200)
        rl.addWidget(self._results_view)

        right_splitter.addWidget(results_frame)
        right_splitter.setStretchFactor(0, 2)
        right_splitter.setStretchFactor(1, 3)

        # ── Status bar ────────────────────────────────────────────────────────
        self._status = QStatusBar()
        self.setStatusBar(self._status)

        self._lbl_status = QLabel("Ready")
        self._status.addWidget(self._lbl_status)

        self._progress = QProgressBar()
        self._progress.setMaximumWidth(150)
        self._progress.setRange(0, 0)    # indeterminate
        self._progress.setVisible(False)
        self._status.addPermanentWidget(self._progress)

        self._lbl_tool_indicator = QLabel("")
        self._lbl_tool_indicator.setStyleSheet("color:#58a6ff;")
        self._status.addPermanentWidget(self._lbl_tool_indicator)

    def _make_welcome(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        l.setSpacing(20)

        # Load and display logo image
        if os.path.exists(ICON_PATH):
            pixmap = QPixmap(ICON_PATH)
            # Scale pixmap while maintaining aspect ratio
            scaled_pixmap = pixmap.scaled(400, 200, Qt.AspectRatioMode.KeepAspectRatio,
                                          Qt.TransformationMode.SmoothTransformation)
            logo_lbl = QLabel()
            logo_lbl.setPixmap(scaled_pixmap)
            logo_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            l.addWidget(logo_lbl)
        else:
            # Fallback text logo
            lbl = QLabel("RECON 9")
            lbl.setStyleSheet("color:#58a6ff;font-size:36px;font-weight:700;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            l.addWidget(lbl)

        sub = QLabel("Select a tool from the sidebar to get started.")
        sub.setStyleSheet("color:#8b949e;font-size:14px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        l.addWidget(sub)
        return w

    # ── Sidebar population ───────────────────────────────────────────────────

    def _populate_sidebar(self) -> None:
        self._panel_map: Dict[str, ToolPanel] = {}
        self._sidebar_items: Dict[str, QTreeWidgetItem] = {}  # Store items for filtering

        # API-dependent tools set
        self._api_tools = api_config.get_tools_requiring_api()

        for category, tools in TOOL_CATALOGUE:
            cat_item = QTreeWidgetItem([category])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            cat_item.setFont(0, QFont("Segoe UI", 10, QFont.Weight.Bold))
            cat_item.setForeground(0, QColor("#8b949e"))

            for tool_id, display_name, icon in tools:
                child = QTreeWidgetItem([f"  {icon}  {display_name}"])
                child.setData(0, Qt.ItemDataRole.UserRole, tool_id)

                # Mark API-dependent tools
                is_api_tool = tool_id in self._api_tools
                if is_api_tool:
                    child.setForeground(0, QColor("#58a6ff"))  # Blue tint for API tools
                    child.setToolTip(0, "Requires API access")

                cat_item.addChild(child)
                self._sidebar_items[tool_id] = child

                # Create & register panel
                panel_cls = PANEL_MAP.get(tool_id)
                if panel_cls:
                    panel = panel_cls()
                    self._panel_map[tool_id] = panel
                    self._stack.addWidget(panel)

            # Store category item reference
            self._sidebar_items[category] = cat_item
            self._sidebar.addTopLevelItem(cat_item)
            cat_item.setExpanded(False)  # Collapsed by default

        # Create Settings panel separately (not in sidebar, accessible via toolbar)
        settings_panel = SettingsPanel()
        self._panel_map["settings"] = settings_panel
        self._stack.addWidget(settings_panel)

    # ── Tool selection ───────────────────────────────────────────────────────

    @pyqtSlot(QTreeWidgetItem, int)
    def _on_tool_selected(self, item: QTreeWidgetItem, _col: int) -> None:
        tool_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not tool_id:
            return
        panel = self._panel_map.get(tool_id)
        if panel:
            self._current_panel = panel
            self._stack.setCurrentWidget(panel)
            self._lbl_tool_indicator.setText(panel.title)
            # Auto-push toolbar target if set
            if self._target_bar.text().strip():
                self._push_target()

    # ── Target auto-fill ─────────────────────────────────────────────────────

    def _push_target(self) -> None:
        """Copy toolbar target into the current panel's target field."""
        target = self._target_bar.text().strip()
        if not target or not self._current_panel:
            return
        for key in ("target", "url", "ip", "ip_or_host", "ip_or_asn", "domain", "host", "cidr"):
            w = self._current_panel._fields.get(key)
            if isinstance(w, QLineEdit):
                w.setText(target)
                break

    # ── Run / cancel ─────────────────────────────────────────────────────────

    @pyqtSlot()
    def _run_tool(self) -> None:
        if not self._current_panel:
            self._set_status("Select a tool first.", colour="#d29922")
            return
        if self._active_worker and self._active_worker.isRunning():
            self._set_status("A scan is already running.", colour="#d29922")
            return

        panel = self._current_panel
        kwargs = panel.get_kwargs()
        target = panel.get_target()

        if not target:
            QMessageBox.warning(self, "No Target", "Please enter a target before running the scan.")
            return

        # Append separator in results
        ts = datetime.now().strftime("%H:%M:%S")
        self._results_view.append(
            f"<hr style='border-color:#21262d;'>"
            f"<span style='color:#484f58;font-size:11px;'>[ {ts} ]  </span>"
            f"<span style='color:#58a6ff;'>{panel.title}</span>"
            f"<span style='color:#484f58;'>  →  {target}</span><br>"
        )

        worker = ScanWorker(panel.title, panel.tool_func, **kwargs)
        worker.result_ready.connect(self._on_result)
        worker.error_occurred.connect(self._on_error)
        worker.progress_msg.connect(self._on_progress)
        worker.live_output.connect(self._on_live_output)  # Live streaming for netdiscover
        worker.finished_scan.connect(self._on_finished)

        self._active_worker = worker
        self._workers.append(worker)

        self._btn_run.setEnabled(False)
        self._btn_cancel.setEnabled(True)
        self._progress.setVisible(True)
        self._set_status(f"Running {panel.title}…", colour="#58a6ff")

        worker.start()

    @pyqtSlot()
    def _cancel_scan(self) -> None:
        if self._active_worker and self._active_worker.isRunning():
            self._active_worker.cancel()
            self._was_cancelled = True  # Track cancellation
            # Immediately update UI to stop animation
            self._btn_run.setEnabled(True)
            self._btn_cancel.setEnabled(False)
            self._progress.setVisible(False)
            self._active_worker = None
            self._set_status("Scan cancelled.", colour="#d29922")

    # ── Worker signals ────────────────────────────────────────────────────────

    @pyqtSlot(str, object)
    def _on_result(self, tool_name: str, result: Any) -> None:
        target = self._current_panel.get_target() if self._current_panel else ""
        html = ResultFormatter.format(tool_name, result, target)
        self._results_view.append(html)

        # Move cursor to bottom
        cursor = self._results_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._results_view.setTextCursor(cursor)

        # Store in history
        self._result_history.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "target": target,
            "result": result,
        })
        count = len(self._result_history)
        self._lbl_result_count.setText(f"{count} result{'s' if count != 1 else ''}")

    @pyqtSlot(str)
    def _on_error(self, msg: str) -> None:
        self._results_view.append(
            f"<span style='color:#f85149;'>{ResultFormatter._esc(msg)}</span><br>"
        )
        self._set_status("Error — see results.", colour="#f85149")

    @pyqtSlot(str)
    def _on_progress(self, msg: str) -> None:
        self._set_status(msg, colour="#58a6ff")

    @pyqtSlot(str, str)
    def _on_live_output(self, tool_name: str, output: str) -> None:
        """Handle live streaming output from tools like netdiscover."""
        # Format netdiscover output as code block for table alignment
        if "Netdiscover" in tool_name:
            # Use monospace font and preserve spacing for table format
            self._results_view.append(
                f"<span style='color:#79c0ff;font-size:11px;'>[{tool_name}]</span> "
                f"<span style='color:#a5d6ff;font-family:monospace;white-space:pre;'>{ResultFormatter._esc(output)}</span>"
            )
        else:
            # Default format for other tools
            self._results_view.append(
                f"<span style='color:#79c0ff;font-size:11px;'>[{tool_name}]</span> "
                f"<span style='color:#a5d6ff;'>{ResultFormatter._esc(output)}</span><br>"
            )
        
        # Auto-scroll to bottom
        cursor = self._results_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._results_view.setTextCursor(cursor)

    @pyqtSlot()
    def _on_finished(self) -> None:
        self._btn_run.setEnabled(True)
        self._btn_cancel.setEnabled(False)
        self._progress.setVisible(False)
        
        # Only update status and worker if not cancelled (cancel already did this)
        if not self._was_cancelled:
            self._active_worker = None
            self._set_status("Scan complete.", colour="#3fb950")
        else:
            self._was_cancelled = False  # Reset flag for next scan

    # ── Export ────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _export_results(self) -> None:
        if not self._result_history:
            QMessageBox.information(self, "No Results", "Run a scan first.")
            return

        # Show dialog to choose export format
        format_dialog = QFileDialog(self)
        format_dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        format_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        format_dialog.setNameFilters([
            "HTML Graph - Only (*.html)",
            "HTML Report - Full (*.html)",
            "CSV (*.csv)",
            "JSON (*.json)",
            "Text (*.txt)",
            "All Files (*)"
        ])
        format_dialog.selectNameFilter("HTML Graph - Only (*.html)")

        # Generate default filename with timestamp
        default_filename = f"graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        format_dialog.selectFile(default_filename)

        if format_dialog.exec():
            path = format_dialog.selectedFiles()[0]
            chosen_filter = format_dialog.selectedNameFilter()
        else:
            return

        if not path:
            return

        try:
            # Get the last result for CSV export
            last_result = self._result_history[-1] if self._result_history else None

            # Ensure .html extension
            if path.endswith(".html") or "HTML" in chosen_filter:
                if not path.endswith(".html"):
                    path += ".html"
                
                # Check which HTML format
                if "Graph - Only" in chosen_filter:
                    # Export graph only
                    html_content = HTMLReportGenerator.generate_graph_only(
                        self._result_history,
                        title=f"Recon 9 Graph - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    )
                else:
                    # Export full report
                    html_content = HTMLReportGenerator.generate_report(
                        self._result_history,
                        title=f"OSINT Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    )
                
                with open(path, "w", encoding="utf-8") as f:
                    f.write(html_content)

            elif path.endswith(".csv") or "CSV" in chosen_filter:
                # Ensure .csv extension
                if not path.endswith(".csv"):
                    path += ".csv"
                if last_result:
                    csv_content = ResultFormatter.export_to_csv(
                        last_result["tool"],
                        last_result["result"]
                    )
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(csv_content)
                else:
                    QMessageBox.warning(self, "Export Error", "No bulk results to export as CSV")
                    return

            elif path.endswith(".json") or "JSON" in chosen_filter:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._result_history, f, indent=2, default=str)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    for entry in self._result_history:
                        f.write(ResultFormatter.format_plain_text(
                            entry["tool"], entry["result"], entry["target"]
                        ))
                        f.write("\n\n")

            self._set_status(f"Exported → {os.path.basename(path)}", colour="#3fb950")
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    @pyqtSlot()
    def _clear_results(self) -> None:
        self._results_view.clear()
        self._result_history.clear()
        self._lbl_result_count.setText("")
        self._set_status("Results cleared.", colour="#8b949e")

    @pyqtSlot()
    def _open_graph_view(self) -> None:
        """Save interactive graph HTML and show the path."""
        if not self._result_history:
            QMessageBox.information(self, "No Results", "Run a scan first to display the graph.")
            return
        
        # Generate graph-only HTML
        import time
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"/tmp/recon9_graph_{timestamp}.html"
        
        html_content = HTMLReportGenerator.generate_graph_only(
            self._result_history,
            title=f"Recon 9 Graph - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Show message with file path
            QMessageBox.information(
                self, 
                "Graph Saved", 
                f"Interactive graph saved to:\n\n{filename}\n\nOpen this file in your browser to view the Maltego-style graph."
            )
            self._set_status(f"Graph saved: {filename}", colour="#3fb950")
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Could not save graph: {exc}")

    # ── Tool availability check ───────────────────────────────────────────────

    def _check_tools(self) -> None:
        avail = external_tools.check_external_tools()
        missing = [t for t, ok in avail.items() if not ok and t in ("nmap", "rustscan")]
        if missing:
            self._set_status(
                f"Optional tools not found: {', '.join(missing)}. Install for full functionality.",
                colour="#d29922",
            )
        else:
            self._set_status("Ready — all external tools detected.", colour="#3fb950")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, colour: str = "#8b949e") -> None:
        self._lbl_status.setText(msg)
        self._lbl_status.setStyleSheet(f"color:{colour};")

    def _open_settings(self) -> None:
        """Open the Settings panel."""
        settings_panel = self._panel_map.get("settings")
        if settings_panel:
            self._current_panel = settings_panel
            self._stack.setCurrentWidget(settings_panel)
            self._lbl_tool_indicator.setText(settings_panel.title)

    def closeEvent(self, event) -> None:
        for w in self._workers:
            if w.isRunning():
                w.cancel()
        event.accept()