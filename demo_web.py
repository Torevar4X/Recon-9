"""
demo_web.py – Browser-based Maltego-style graph demo for Recon 9.
Run:  python3 demo_web.py
Open: http://localhost:5000
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, render_template_string
from graph_extractor import GraphExtractor

app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Demo scenarios
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = {
    "DNS Recon — example.com": (
        "DNS Lookup",
        {
            "records": {
                "A":     ["93.184.216.34"],
                "AAAA":  ["2606:2800:021f:cb07:6820:80da:af6b:8b2c"],
                "MX":    ["0 mail.example.com.", "10 alt1.mail.example.com."],
                "NS":    ["ns1.example.com.", "ns2.example.com.", "ns3.example.com."],
                "TXT":   ["v=spf1 -all", "google-site-verification=abc123"],
                "CNAME": ["www.example.com."],
            }
        },
        "example.com",
    ),
    "Subdomain Discovery — github.com": (
        "Find Subdomains",
        {
            "subdomains": [
                {"subdomain": "api.github.com",           "ips": ["140.82.114.5"]},
                {"subdomain": "gist.github.com",          "ips": ["140.82.114.4"]},
                {"subdomain": "raw.githubusercontent.com","ips": ["185.199.108.133"]},
                {"subdomain": "codeload.github.com",      "ips": ["140.82.114.10"]},
                {"subdomain": "assets-cdn.github.com",    "ips": ["185.199.108.153"]},
                {"subdomain": "mail.github.com",          "ips": ["64.233.184.26"]},
                {"subdomain": "smtp.github.com",          "ips": ["64.233.184.27"]},
                {"subdomain": "status.github.com",        "ips": ["185.199.108.153"]},
            ]
        },
        "github.com",
    ),
    "Port Scan — scanme.nmap.org": (
        "TCP Port Scan",
        {
            "open_ports": [
                {"port": 22,   "service": "ssh",     "state": "open", "banner": "OpenSSH 8.9p1"},
                {"port": 80,   "service": "http",    "state": "open", "banner": "Apache/2.4.52"},
                {"port": 443,  "service": "https",   "state": "open"},
                {"port": 3306, "service": "mysql",   "state": "open"},
                {"port": 8080, "service": "http-alt","state": "open", "banner": "nginx/1.18"},
                {"port": 9200, "service": "elastic", "state": "open"},
                {"port": 6379, "service": "redis",   "state": "open"},
            ]
        },
        "45.33.32.156",
    ),
    "IP Geolocation — 8.8.8.8": (
        "IP Geolocation",
        {
            "ip": "8.8.8.8", "country": "United States", "countryCode": "US",
            "city": "Mountain View", "region": "California",
            "lat": 37.386, "lon": -122.0838,
            "org": "AS15169 Google LLC", "asn": "AS15169", "isp": "Google LLC",
            "timezone": "America/Los_Angeles",
        },
        "8.8.8.8",
    ),
    "WHOIS — openai.com": (
        "WHOIS Lookup",
        {
            "domain_name": "OPENAI.COM", "registrar": "MarkMonitor, Inc.",
            "creation_date": "2015-08-21", "expiration_date": "2030-08-21",
            "name_servers": ["ns1.cloudflare.com","ns2.cloudflare.com","ns3.cloudflare.com"],
            "registrant": "OpenAI, LLC",
        },
        "openai.com",
    ),
    "Traceroute — 1.1.1.1": (
        "Traceroute",
        {
            "hops": [
                {"ttl":1,"ip":"192.168.1.1"},  {"ttl":2,"ip":"10.0.0.1"},
                {"ttl":3,"ip":"72.14.215.165"},{"ttl":4,"ip":"74.125.244.1"},
                {"ttl":5,"ip":"108.170.238.104"},{"ttl":6,"ip":"141.101.72.1"},
                {"ttl":7,"ip":"1.1.1.1"},
            ]
        },
        "1.1.1.1",
    ),
    "Social Media — twitter.com": (
        "Social Media Finder",
        {
            "profiles": [
                {"platform":"Twitter/X",   "url":"https://twitter.com/twitter"},
                {"platform":"Facebook",    "url":"https://facebook.com/twitter"},
                {"platform":"Instagram",   "url":"https://instagram.com/twitter"},
                {"platform":"LinkedIn",    "url":"https://linkedin.com/company/twitter"},
                {"platform":"YouTube",     "url":"https://youtube.com/twitter"},
                {"platform":"TikTok",      "url":"https://tiktok.com/@twitter"},
            ],
            "trackers": [
                "Google Analytics (UA-30775-1)", "Google Tag Manager",
                "Twitter Pixel", "Hotjar",
            ],
        },
        "twitter.com",
    ),
    "Full OSINT — microsoft.com": (
        "DNS Lookup",
        {
            "records": {
                "A":  ["20.112.52.29","20.81.111.85","20.84.181.62"],
                "MX": ["10 microsoft-com.mail.protection.outlook.com."],
                "NS": ["ns1-205.azure-dns.com.","ns2-205.azure-dns.net.",
                       "ns3-205.azure-dns.org.","ns4-205.azure-dns.info."],
                "TXT":["v=spf1 include:spf.protection.outlook.com -all","MS=ms88689016"],
            },
            "subdomains": [
                {"subdomain":"www.microsoft.com",   "ips":["20.112.52.29"]},
                {"subdomain":"azure.microsoft.com", "ips":["20.81.111.85"]},
                {"subdomain":"docs.microsoft.com",  "ips":["13.107.42.14"]},
                {"subdomain":"login.microsoft.com", "ips":["20.190.128.0"]},
                {"subdomain":"mail.microsoft.com",  "ips":["40.90.4.15"]},
            ],
        },
        "microsoft.com",
    ),
}


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
    "url":       {"bg": "#1a2f4a", "border": "#58a6ff", "text": "#58a6ff"},
    "tracker":   {"bg": "#2e2200", "border": "#e3b341", "text": "#e3b341"},
    "social":    {"bg": "#3d1010", "border": "#ff7b72", "text": "#ff7b72"},
    "cname":     {"bg": "#0d2a14", "border": "#56d364", "text": "#56d364"},
    "banner":    {"bg": "#0d1f3c", "border": "#79c0ff", "text": "#79c0ff"},
    "default":   {"bg": "#21262d", "border": "#8b949e", "text": "#8b949e"},
}

NODE_ICONS = {
    "target": "◉", "domain": "🌐", "ip": "⬡", "subdomain": "◈",
    "port": "⬟", "mx": "✉", "ns": "⬡", "txt": "T", "asn": "AS",
    "geo": "📍", "whois": "W", "service": "S", "url": "↗",
    "tracker": "◎", "social": "♦", "cname": "↩", "banner": "B",
    "default": "●",
}

NODE_SHAPES = {
    "target": "ellipse", "domain": "hexagon", "ip": "diamond",
    "subdomain": "ellipse", "port": "rectangle", "mx": "ellipse",
    "ns": "ellipse", "txt": "rectangle", "asn": "hexagon",
    "geo": "ellipse", "whois": "rectangle", "service": "ellipse",
    "url": "ellipse", "tracker": "diamond", "social": "ellipse",
    "cname": "ellipse", "banner": "rectangle", "default": "ellipse",
}

NODE_SIZES = {
    "target": 54, "domain": 46, "ip": 42, "subdomain": 36,
    "port": 32, "mx": 32, "ns": 32, "txt": 28, "asn": 38,
    "geo": 32, "whois": 32, "service": 28, "url": 28,
    "tracker": 32, "social": 32, "cname": 28, "banner": 28,
    "default": 28,
}


def build_cytoscape_elements(nodes, edges):
    elements = []
    for n in nodes:
        ntype = n.get("type", "default")
        colors = NODE_COLORS.get(ntype, NODE_COLORS["default"])
        size = NODE_SIZES.get(ntype, 28)
        elements.append({
            "data": {
                "id": n["id"],
                "label": n["label"],
                "type": ntype,
                "tooltip": n.get("tooltip", n["label"]),
                "bg": colors["bg"],
                "border": colors["border"],
                "textColor": colors["text"],
                "icon": NODE_ICONS.get(ntype, "●"),
                "size": size,
                "shape": NODE_SHAPES.get(ntype, "ellipse"),
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
    return elements


@app.route("/")
def index():
    scenario_names = list(SCENARIOS.keys())
    return render_template_string(HTML_TEMPLATE, scenarios=scenario_names)


@app.route("/api/scenario/<int:idx>")
def get_scenario(idx):
    names = list(SCENARIOS.keys())
    if idx < 0 or idx >= len(names):
        return jsonify({"error": "not found"}), 404
    name = names[idx]
    tool_name, data, target = SCENARIOS[name]
    nodes, edges = GraphExtractor.extract(tool_name, data, target)
    elements = build_cytoscape_elements(nodes, edges)
    return jsonify({
        "name": name,
        "elements": elements,
        "node_count": len(nodes),
        "edge_count": len(edges),
    })


# ─────────────────────────────────────────────────────────────────────────────
# HTML template
# ─────────────────────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon 9 — Graph Demo</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg:      #0d1117;
  --bg2:     #161b22;
  --bg3:     #21262d;
  --border:  #30363d;
  --text:    #c9d1d9;
  --muted:   #8b949e;
  --dim:     #484f58;
  --accent:  #58a6ff;
  --green:   #3fb950;
  --red:     #f85149;
  --orange:  #f0883e;
}
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; height:100vh; display:flex; flex-direction:column; overflow:hidden; }

/* ── Header ── */
header {
  display:flex; align-items:center; gap:16px;
  padding:0 20px; height:52px; flex-shrink:0;
  background:var(--bg2); border-bottom:1px solid var(--border);
}
.logo { color:var(--accent); font-size:16px; font-weight:700; letter-spacing:0.5px; white-space:nowrap; }
.logo span { color:var(--muted); font-weight:400; }
.sep { width:1px; height:24px; background:var(--border); }

.scenario-label { color:var(--muted); font-size:12px; white-space:nowrap; }
select {
  background:var(--bg3); color:var(--text); border:1px solid var(--border);
  border-radius:6px; padding:5px 10px; font-size:12px; cursor:pointer;
  min-width:270px; outline:none;
}
select:hover { border-color:var(--accent); }

.btn {
  background:var(--accent); color:#fff; border:none; border-radius:6px;
  padding:6px 16px; font-size:12px; font-weight:600; cursor:pointer;
  white-space:nowrap; transition:background .15s;
}
.btn:hover { background:#388bfd; }

.spacer { flex:1; }

/* legend */
.legend { display:flex; align-items:center; gap:10px; }
.legend-item { display:flex; align-items:center; gap:4px; font-size:11px; color:var(--muted); }
.legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }

/* ── Body ── */
.body-row { display:flex; flex:1; overflow:hidden; }

/* ── Sidebar ── */
aside {
  width:236px; flex-shrink:0;
  background:var(--bg2); border-right:1px solid var(--border);
  display:flex; flex-direction:column; overflow:hidden;
}
.aside-header {
  padding:10px 12px 8px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; justify-content:space-between;
}
.aside-header h3 { font-size:11px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
.btn-copy-all {
  background:transparent; border:1px solid var(--border); color:var(--muted);
  border-radius:4px; padding:3px 8px; font-size:10px; cursor:pointer;
  display:flex; align-items:center; gap:4px; transition:all .15s;
}
.btn-copy-all:hover { border-color:var(--accent); color:var(--accent); }
.aside-body { flex:1; overflow-y:auto; padding:6px 6px; }
.aside-body::-webkit-scrollbar { width:4px; }
.aside-body::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

.node-card {
  background:var(--bg3); border:1px solid var(--border);
  border-radius:6px; padding:7px 9px; margin-bottom:5px;
  cursor:pointer; transition:border-color .15s; position:relative;
}
.node-card:hover { border-color:var(--accent); }
.node-card:hover .nc-copy { opacity:1; }
.node-card.selected { border-color:var(--accent); background:#1a2a3f; }
.nc-header { display:flex; align-items:center; gap:7px; margin-bottom:2px; }
.nc-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.nc-label { font-size:12px; font-weight:600; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }
.nc-copy {
  opacity:0; background:var(--bg3); border:1px solid var(--border);
  color:var(--muted); border-radius:3px; padding:1px 5px; font-size:10px;
  cursor:pointer; transition:all .15s; flex-shrink:0;
}
.nc-copy:hover { border-color:var(--green); color:var(--green); }
.nc-copy.copied { color:var(--green); border-color:var(--green); }
.nc-type { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.3px; }
.nc-tip { font-size:10px; color:var(--dim); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

.stats-row { display:flex; gap:8px; padding:8px 12px; border-top:1px solid var(--border); }
.stat { flex:1; text-align:center; }
.stat-val { font-size:17px; font-weight:700; color:var(--accent); }
.stat-lbl { font-size:10px; color:var(--muted); }

/* ── Detail panel ── */
#detail-panel {
  width:260px; flex-shrink:0;
  background:var(--bg2); border-left:1px solid var(--border);
  display:flex; flex-direction:column; overflow:hidden;
  transform:translateX(100%); transition:transform .25s ease;
}
#detail-panel.open { transform:translateX(0); }
.dp-header {
  padding:10px 12px 8px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; justify-content:space-between;
}
.dp-header h3 { font-size:11px; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:.5px; }
.dp-close { background:none; border:none; color:var(--muted); font-size:16px; cursor:pointer; padding:0 2px; line-height:1; }
.dp-close:hover { color:var(--text); }
.dp-body { flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:10px; }
.dp-body::-webkit-scrollbar { width:4px; }
.dp-body::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
.dp-badge {
  display:inline-flex; align-items:center; gap:6px;
  padding:4px 10px; border-radius:20px; font-size:11px; font-weight:600;
  border:1px solid; width:fit-content;
}
.dp-field { display:flex; flex-direction:column; gap:4px; }
.dp-field label { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; }
.dp-value {
  background:var(--bg3); border:1px solid var(--border); border-radius:5px;
  padding:7px 10px; font-size:12px; color:var(--text);
  word-break:break-all; line-height:1.5; font-family:monospace;
}
.dp-copy-row { display:flex; gap:6px; flex-wrap:wrap; }
.dp-btn {
  display:flex; align-items:center; gap:5px;
  background:var(--bg3); border:1px solid var(--border);
  color:var(--muted); border-radius:5px; padding:5px 10px;
  font-size:11px; cursor:pointer; transition:all .15s;
}
.dp-btn:hover { border-color:var(--accent); color:var(--accent); }
.dp-btn.copied { border-color:var(--green) !important; color:var(--green) !important; }
.dp-divider { height:1px; background:var(--border); margin:2px 0; }
.dp-connections { display:flex; flex-direction:column; gap:4px; }
.dp-conn-item {
  display:flex; align-items:center; gap:7px;
  padding:5px 8px; border-radius:5px; background:var(--bg3);
  font-size:11px; cursor:pointer; border:1px solid transparent; transition:border-color .12s;
}
.dp-conn-item:hover { border-color:var(--border); }
.dp-conn-dot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
.dp-conn-lbl { color:var(--text); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.dp-conn-type { font-size:9px; color:var(--dim); text-transform:uppercase; }

/* toast */
#toast {
  position:fixed; bottom:40px; left:50%; transform:translateX(-50%) translateY(20px);
  background:#238636; color:#fff; padding:7px 18px; border-radius:6px;
  font-size:12px; font-weight:600; pointer-events:none;
  opacity:0; transition:opacity .2s, transform .2s; z-index:9999;
}
#toast.show { opacity:1; transform:translateX(-50%) translateY(0); }

/* ── Graph canvas ── */
#cy {
  width:100%; height:100%;
  background:var(--bg);
  background-image: radial-gradient(circle, #2a2d33 1px, transparent 1px);
  background-size: 30px 30px;
}

/* ── Footer ── */
footer {
  height:26px; flex-shrink:0; display:flex; align-items:center;
  padding:0 14px; gap:20px;
  background:var(--bg2); border-top:1px solid var(--border);
  font-size:10px; color:var(--dim);
}
.status-dot { width:7px; height:7px; border-radius:50%; background:var(--green); }
#status-text { color:var(--muted); }
#node-info { color:var(--accent); margin-left:auto; }

/* ── Tooltip ── */
#tooltip {
  position:fixed; display:none; z-index:999;
  background:var(--bg2); border:1px solid var(--border);
  border-radius:8px; padding:10px 13px;
  font-size:12px; max-width:280px; pointer-events:none;
  box-shadow:0 8px 24px rgba(0,0,0,.5);
}
#tooltip .tt-type { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px; margin-bottom:4px; }
#tooltip .tt-label { font-size:13px; font-weight:600; color:var(--text); margin-bottom:4px; }
#tooltip .tt-tip { font-size:11px; color:var(--muted); }

/* Loading overlay */
#loading {
  position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
  background:rgba(13,17,23,.85); z-index:100; gap:12px; font-size:14px; color:var(--muted);
}
.spinner {
  width:22px; height:22px; border:2px solid var(--border);
  border-top-color:var(--accent); border-radius:50%;
  animation:spin .7s linear infinite;
}
@keyframes spin { to { transform:rotate(360deg); } }
</style>
</head>
<body>

<header>
  <div class="logo">◈ Recon 9 <span>· Graph Demo</span></div>
  <div class="sep"></div>
  <span class="scenario-label">Scenario:</span>
  <select id="scenario-select">
    {% for s in scenarios %}
    <option value="{{ loop.index0 }}">{{ s }}</option>
    {% endfor %}
  </select>
  <button class="btn" onclick="loadScenario()">▶ Load</button>
  <div class="spacer"></div>
  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#58a6ff"></div>Target/Domain</div>
    <div class="legend-item"><div class="legend-dot" style="background:#f0883e"></div>IP</div>
    <div class="legend-item"><div class="legend-dot" style="background:#3fb950"></div>Subdomain</div>
    <div class="legend-item"><div class="legend-dot" style="background:#f85149"></div>Port</div>
    <div class="legend-item"><div class="legend-dot" style="background:#ffd60a"></div>Geo</div>
    <div class="legend-item"><div class="legend-dot" style="background:#d2a8ff"></div>MX/NS/ASN</div>
  </div>
</header>

<div class="body-row">
  <!-- Left Sidebar -->
  <aside>
    <div class="aside-header">
      <h3>Nodes</h3>
      <button class="btn-copy-all" onclick="copyAll('text')" title="Copy all node values as plain text">⎘ Copy All</button>
    </div>
    <div class="aside-body" id="node-list"></div>
    <div class="stats-row">
      <div class="stat"><div class="stat-val" id="node-count">0</div><div class="stat-lbl">Nodes</div></div>
      <div class="stat"><div class="stat-val" id="edge-count">0</div><div class="stat-lbl">Edges</div></div>
      <div class="stat">
        <div class="stat-val" style="font-size:13px;">
          <button class="dp-btn" style="padding:3px 7px;font-size:10px;" onclick="copyAll('json')" title="Export as JSON">JSON</button>
        </div>
        <div class="stat-lbl">Export</div>
      </div>
    </div>
  </aside>

  <!-- Graph -->
  <div style="flex:1;position:relative;display:flex;flex-direction:column;">
    <div id="loading"><div class="spinner"></div> Loading graph…</div>
    <div id="cy" style="flex:1;"></div>
  </div>

  <!-- Right Detail Panel -->
  <div id="detail-panel">
    <div class="dp-header">
      <h3>Node Detail</h3>
      <button class="dp-close" onclick="closeDetail()" title="Close">✕</button>
    </div>
    <div class="dp-body" id="dp-body">
      <p style="color:var(--dim);font-size:12px;">Click a node in the graph to inspect it here.</p>
    </div>
  </div>
</div>

<footer>
  <div class="status-dot"></div>
  <span id="status-text">Ready</span>
  <span>Scroll = zoom · Drag = pan · Click node = copy</span>
  <span id="node-info"></span>
</footer>

<div id="tooltip">
  <div class="tt-type" id="tt-type"></div>
  <div class="tt-label" id="tt-label"></div>
  <div class="tt-tip" id="tt-tip"></div>
</div>

<div id="toast">Copied!</div>

<script>
let cy = null;
let currentData = null;

const COLOR_MAP = {
  target:    {bg:'#1f6feb', border:'#58a6ff'},
  domain:    {bg:'#1a3a5c', border:'#79c0ff'},
  ip:        {bg:'#4a2000', border:'#f0883e'},
  subdomain: {bg:'#0d3320', border:'#3fb950'},
  port:      {bg:'#3d0c0a', border:'#f85149'},
  mx:        {bg:'#2d1b4e', border:'#d2a8ff'},
  ns:        {bg:'#3a2a00', border:'#ffa657'},
  txt:       {bg:'#21262d', border:'#8b949e'},
  asn:       {bg:'#1e1040', border:'#b08eff'},
  geo:       {bg:'#3a2e00', border:'#ffd60a'},
  whois:     {bg:'#0f2a2c', border:'#a8dadc'},
  tracker:   {bg:'#2e2200', border:'#e3b341'},
  social:    {bg:'#3d1010', border:'#ff7b72'},
  cname:     {bg:'#0d2a14', border:'#56d364'},
  banner:    {bg:'#0d1f3c', border:'#79c0ff'},
  default:   {bg:'#21262d', border:'#8b949e'},
};

// ── Copy helpers ─────────────────────────────────────────────────────────────

function copyText(text, btnEl) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied!');
    if (btnEl) {
      const orig = btnEl.textContent;
      btnEl.textContent = '✓ Copied';
      btnEl.classList.add('copied');
      setTimeout(() => { btnEl.textContent = orig; btnEl.classList.remove('copied'); }, 1800);
    }
  }).catch(() => {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Copied!');
  });
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

function copyAll(format) {
  if (!currentData) return;
  const nodes = currentData.elements.filter(e => !e.data.source);
  if (format === 'json') {
    const out = nodes.map(n => ({
      type:    n.data.type,
      label:   n.data.label,
      tooltip: n.data.tooltip,
    }));
    copyText(JSON.stringify(out, null, 2));
    showToast('JSON copied — ' + nodes.length + ' nodes');
  } else {
    const lines = nodes.map(n => `[${n.data.type.toUpperCase()}]  ${n.data.tooltip || n.data.label}`);
    copyText(lines.join('\n'));
    showToast('Copied — ' + nodes.length + ' nodes');
  }
}

// ── Detail panel ─────────────────────────────────────────────────────────────

function openDetail(nodeData) {
  const panel = document.getElementById('detail-panel');
  const body  = document.getElementById('dp-body');
  const c     = COLOR_MAP[nodeData.type] || COLOR_MAP.default;
  const conns = getConnections(nodeData.id);

  // Build connection list HTML
  let connHtml = '';
  if (conns.length) {
    connHtml = `
      <div class="dp-field">
        <label>Connected nodes (${conns.length})</label>
        <div class="dp-connections">
          ${conns.map(n => {
            const cc = COLOR_MAP[n.type] || COLOR_MAP.default;
            return `<div class="dp-conn-item" onclick="focusNode('${n.id}')">
              <div class="dp-conn-dot" style="background:${cc.border}"></div>
              <span class="dp-conn-lbl" title="${n.tooltip}">${n.label}</span>
              <span class="dp-conn-type">${n.type}</span>
            </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  const jsonStr = JSON.stringify({type:nodeData.type, label:nodeData.label, detail:nodeData.tooltip}, null, 2);

  body.innerHTML = `
    <div class="dp-badge" style="color:${c.border};border-color:${c.border};background:${c.bg}22;">
      ${nodeData.icon || '●'} &nbsp; ${nodeData.type.toUpperCase()}
    </div>

    <div class="dp-field">
      <label>Label / Value</label>
      <div class="dp-value">${escHtml(nodeData.label)}</div>
    </div>

    <div class="dp-copy-row">
      <button class="dp-btn" onclick="copyText(${JSON.stringify(nodeData.label)}, this)">⎘ Copy Value</button>
      ${nodeData.tooltip && nodeData.tooltip !== nodeData.label
        ? `<button class="dp-btn" onclick="copyText(${JSON.stringify(nodeData.tooltip)}, this)">⎘ Copy Detail</button>`
        : ''}
      <button class="dp-btn" onclick="copyText(${JSON.stringify(jsonStr)}, this)">⎘ Copy JSON</button>
    </div>

    ${nodeData.tooltip && nodeData.tooltip !== nodeData.label ? `
    <div class="dp-field">
      <label>Full Detail</label>
      <div class="dp-value" style="font-size:11px;">${escHtml(nodeData.tooltip)}</div>
    </div>` : ''}

    <div class="dp-divider"></div>
    ${connHtml}
  `;

  panel.classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
}

function getConnections(nodeId) {
  if (!cy) return [];
  const node = cy.getElementById(nodeId);
  return node.neighborhood('node').map(n => n.data());
}

function focusNode(nodeId) {
  if (!cy) return;
  const node = cy.getElementById(nodeId);
  cy.animate({ fit:{ eles: node.closedNeighborhood(), padding:80 } }, { duration:350 });
  node.emit('tap');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function initCytoscape(elements) {
  if (cy) { cy.destroy(); cy = null; }
  document.getElementById('loading').style.display = 'flex';

  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
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
          'transition-property':     'background-color, border-color, border-width',
          'transition-duration':     '0.15s',
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-width': 3,
          'border-color': '#ffffff',
          'overlay-opacity': 0.08,
          'overlay-color':   '#58a6ff',
        }
      },
      {
        selector: 'node:active',
        style: { 'overlay-opacity': 0.12 }
      },
      {
        selector: 'edge',
        style: {
          'width':              1.5,
          'line-color':         '#30363d',
          'target-arrow-color': '#30363d',
          'target-arrow-shape':'triangle',
          'arrow-scale':        0.8,
          'curve-style':        'bezier',
          'label':              'data(label)',
          'font-size':          9,
          'color':              '#484f58',
          'text-background-color':   '#0d1117',
          'text-background-opacity': 0.8,
          'text-background-padding': '2px',
          'opacity':            0.7,
        }
      },
      {
        selector: 'edge:selected',
        style: { 'line-color':'#58a6ff','target-arrow-color':'#58a6ff', 'opacity':1 }
      },
      {
        selector: '.highlighted',
        style: { 'border-color':'#ffffff','border-width':3,'opacity':1 }
      },
      {
        selector: '.faded',
        style: { 'opacity': 0.15 }
      }
    ],
    layout: {
      name: 'cose',
      animate: true,
      animationDuration: 900,
      animationEasing: 'ease-out-cubic',
      randomize: true,
      nodeRepulsion: 12000,
      idealEdgeLength: 120,
      edgeElasticity: 200,
      gravity: 0.25,
      numIter: 600,
      nodeDimensionsIncludeLabels: true,
      fit: true,
      padding: 60,
    },
    minZoom: 0.1,
    maxZoom: 4,
    wheelSensitivity: 0.3,
  });

  // Hide loading after layout stops
  cy.one('layoutstop', () => {
    document.getElementById('loading').style.display = 'none';
    setStatus('Graph loaded — ' + cy.nodes().length + ' nodes, ' + cy.edges().length + ' edges');
  });

  // Tooltip on hover
  const tooltip = document.getElementById('tooltip');
  cy.on('mouseover', 'node', function(e) {
    const d = e.target.data();
    document.getElementById('tt-type').textContent  = d.type.toUpperCase();
    document.getElementById('tt-label').textContent = d.label;
    document.getElementById('tt-tip').textContent   = d.tooltip || '';
    const c = COLOR_MAP[d.type] || COLOR_MAP.default;
    document.getElementById('tt-type').style.color  = c.border;
    tooltip.style.display = 'block';
  });
  cy.on('mouseout', 'node', () => { tooltip.style.display = 'none'; });
  cy.on('mousemove', function(e) {
    tooltip.style.left = (e.originalEvent.clientX + 14) + 'px';
    tooltip.style.top  = (e.originalEvent.clientY - 10) + 'px';
  });

  // Click — highlight neighbours + open detail panel
  cy.on('tap', 'node', function(e) {
    const node = e.target;
    const d = node.data();
    cy.elements().removeClass('highlighted faded');
    const connected = node.closedNeighborhood();
    cy.elements().not(connected).addClass('faded');
    connected.addClass('highlighted');
    node.removeClass('faded');
    document.getElementById('node-info').textContent =
      (d.icon||'●') + '  ' + d.label + '  [' + d.type + ']';

    // Highlight in sidebar
    document.querySelectorAll('.node-card').forEach(c => c.classList.remove('selected'));
    const card = document.getElementById('card-' + CSS.escape(d.id));
    if (card) { card.classList.add('selected'); card.scrollIntoView({block:'nearest'}); }

    // Open detail panel
    openDetail(d);
  });

  cy.on('tap', function(e) {
    if (e.target === cy) {
      cy.elements().removeClass('highlighted faded');
      document.getElementById('node-info').textContent = '';
      document.querySelectorAll('.node-card').forEach(c => c.classList.remove('selected'));
      closeDetail();
    }
  });
}

function buildSidebar(elements) {
  const nodes = elements.filter(e => !e.data.source);
  const list  = document.getElementById('node-list');
  list.innerHTML = '';
  document.getElementById('node-count').textContent = nodes.length;
  document.getElementById('edge-count').textContent = elements.filter(e => e.data.source).length;

  nodes.forEach(n => {
    const d = n.data;
    const c = COLOR_MAP[d.type] || COLOR_MAP.default;
    const copyVal = d.tooltip || d.label;

    const card = document.createElement('div');
    card.className = 'node-card';
    card.id = 'card-' + d.id;
    card.innerHTML = `
      <div class="nc-header">
        <div class="nc-dot" style="background:${c.border}"></div>
        <div class="nc-label" title="${d.tooltip || d.label}">${d.label}</div>
        <button class="nc-copy" title="Copy value" onclick="event.stopPropagation(); copyCardValue(this, ${JSON.stringify(copyVal)})">⎘</button>
      </div>
      <div class="nc-type">${d.type}</div>
      ${d.tooltip && d.tooltip !== d.label ? `<div class="nc-tip" title="${d.tooltip}">${d.tooltip}</div>` : ''}
    `;
    card.onclick = () => {
      if (!cy) return;
      const node = cy.getElementById(d.id);
      if (node.length) {
        cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 } }, { duration: 400 });
        node.emit('tap');
      }
    };
    list.appendChild(card);
  });
}

function copyCardValue(btn, text) {
  copyText(text, btn);
  btn.textContent = '✓';
  setTimeout(() => { btn.textContent = '⎘'; }, 1800);
}

function setStatus(msg) {
  document.getElementById('status-text').textContent = msg;
}

async function loadScenario() {
  const idx = document.getElementById('scenario-select').value;
  document.getElementById('loading').style.display = 'flex';
  setStatus('Fetching data…');
  try {
    const res  = await fetch('/api/scenario/' + idx);
    const data = await res.json();
    currentData = data;
    buildSidebar(data.elements);
    initCytoscape(data.elements);
    setStatus('Loaded: ' + data.name);
  } catch (err) {
    setStatus('Error: ' + err.message);
    document.getElementById('loading').style.display = 'none';
  }
}

// Load first scenario on page ready
window.addEventListener('load', loadScenario);

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (!cy) return;
  if (e.key === 'f' || e.key === 'F') cy.fit(60);
  if (e.key === '+') cy.zoom(cy.zoom() * 1.2);
  if (e.key === '-') cy.zoom(cy.zoom() / 1.2);
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
