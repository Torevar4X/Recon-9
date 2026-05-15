"""
Web Tools Module
Handles: HTTP Headers, Extract Page Links,
         Reverse Analytics, Social Media Extractor
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Set

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

_DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Headers
# ─────────────────────────────────────────────────────────────────────────────

def http_headers(
    url: str,
    follow_redirects: bool = True,
    user_agent: str = _DEFAULT_UA,
) -> Dict[str, Any]:
    """
    Fetch HTTP response headers and a basic security assessment.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.head(
            url,
            allow_redirects=follow_redirects,
            timeout=12,
            headers={"User-Agent": user_agent},
            verify=False,      # Some OSINT targets have bad certs
        )
    except requests.exceptions.SSLError:
        # Retry without SSL verify
        try:
            import urllib3; urllib3.disable_warnings()
            resp = requests.head(url, allow_redirects=follow_redirects, timeout=12,
                                 headers={"User-Agent": user_agent}, verify=False)
        except Exception as exc:
            return {"url": url, "error": str(exc)}
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    headers_dict = dict(resp.headers)
    redirect_chain = [r.url for r in resp.history] + [resp.url]

    # Security header analysis
    security = _analyse_security_headers(headers_dict)

    return {
        "url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "http_version": "HTTP/1.1",
        "redirect_chain": redirect_chain if len(redirect_chain) > 1 else [],
        "headers": headers_dict,
        "security_analysis": security,
        "server": headers_dict.get("Server", "Not disclosed"),
        "content_type": headers_dict.get("Content-Type", "Unknown"),
        "powered_by": headers_dict.get("X-Powered-By", "Not disclosed"),
    }


def _analyse_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Rate presence/absence of common security headers."""
    checks = {
        "Strict-Transport-Security": "HSTS (forces HTTPS)",
        "Content-Security-Policy": "CSP (XSS/injection protection)",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "Referrer-Policy": "Referrer information control",
        "Permissions-Policy": "Feature/permissions policy",
        "X-XSS-Protection": "Legacy XSS filter (deprecated but informative)",
    }
    lower_headers = {k.lower(): v for k, v in headers.items()}
    present = {}
    missing = []
    for header, desc in checks.items():
        if header.lower() in lower_headers:
            present[header] = {"value": lower_headers[header.lower()], "description": desc}
        else:
            missing.append({"header": header, "description": desc})

    score = len(present) * 100 // len(checks)
    return {"present": present, "missing": missing, "score_pct": score}


# ─────────────────────────────────────────────────────────────────────────────
# Extract Page Links
# ─────────────────────────────────────────────────────────────────────────────

def extract_links(
    url: str,
    filter_mode: str = "all",   # "all" | "internal" | "external"
    user_agent: str = _DEFAULT_UA,
) -> Dict[str, Any]:
    """
    Fetch a page and extract all hyperlinks.
    filter_mode: 'all', 'internal' (same domain), 'external' (different domain).
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    base_domain = urlparse(url).netloc

    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": user_agent}, verify=False)
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    if not BS4_OK:
        # Regex fallback
        raw_links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        links = [urljoin(url, l) for l in raw_links]
    else:
        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            full = urljoin(url, tag["href"])
            if full.startswith("http"):
                links.append(full)

    # Deduplicate
    seen: Set[str] = set()
    unique_links: List[str] = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique_links.append(link)

    # Filter
    if filter_mode == "internal":
        unique_links = [l for l in unique_links if urlparse(l).netloc == base_domain]
    elif filter_mode == "external":
        unique_links = [l for l in unique_links if urlparse(l).netloc != base_domain]

    internal = [l for l in unique_links if urlparse(l).netloc == base_domain]
    external = [l for l in unique_links if urlparse(l).netloc != base_domain]

    return {
        "url": url,
        "base_domain": base_domain,
        "total": len(unique_links),
        "internal_count": len(internal),
        "external_count": len(external),
        "links": unique_links[:500],   # cap at 500
        "filter_applied": filter_mode,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Reverse Analytics
# ─────────────────────────────────────────────────────────────────────────────

ANALYTICS_PATTERNS: Dict[str, re.Pattern] = {
    "Google Analytics UA":   re.compile(r"UA-\d{4,10}-\d{1,4}", re.I),
    "Google Analytics GA4":  re.compile(r"G-[A-Z0-9]{8,12}", re.I),
    "Google Tag Manager":    re.compile(r"GTM-[A-Z0-9]{6,8}", re.I),
    "Facebook Pixel":        re.compile(r"fbq\(['\"]init['\"],\s*['\"](\d{13,16})['\"]", re.I),
    "Hotjar":                re.compile(r"hjid['\"]?\s*[=:]\s*['\"]?(\d+)", re.I),
    "Mixpanel":              re.compile(r"mixpanel\.init\(['\"]([a-f0-9]{32})['\"]", re.I),
    "Segment":               re.compile(r"analytics\.load\(['\"]([a-zA-Z0-9]{20,40})['\"]", re.I),
    "Bing UET":              re.compile(r"UETv2.*?['\"](\d{7,9})['\"]", re.I),
    "Yandex Metrica":        re.compile(r"ym\(\s*(\d{7,9})\s*,\s*['\"]init['\"]", re.I),
    "Cloudflare Insights":   re.compile(r"cloudflareinsights\.com/beacon.*?token=['\"]?([a-f0-9]{32})", re.I),
    "Intercom":              re.compile(r"app_id\s*:\s*['\"]([a-z0-9]{8})['\"]", re.I),
    "Drift":                 re.compile(r"drift\.load\(['\"]([a-z0-9]{12,20})['\"]", re.I),
}


def reverse_analytics(url: str) -> Dict[str, Any]:
    """
    Scan a webpage's HTML/JS for known analytics and tracking identifiers.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": _DEFAULT_UA}, verify=False)
        html = resp.text
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    found: Dict[str, List[str]] = {}
    for name, pattern in ANALYTICS_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            # Flatten & deduplicate
            flat = list(dict.fromkeys(
                m if isinstance(m, str) else m[0] if m else "" for m in matches
            ))
            flat = [f for f in flat if f]
            if flat:
                found[name] = flat

    # Detect technology stack via HTML hints
    tech_hints: List[str] = []
    lower_html = html.lower()
    stack_signals = {
        "WordPress": "wp-content",
        "Shopify": "cdn.shopify.com",
        "Drupal": "sites/default/files",
        "Joomla": "joomla",
        "Squarespace": "squarespace.com",
        "Wix": "wix.com",
        "React": "__react",
        "Vue.js": "vue.min.js",
        "Angular": "ng-version",
        "Next.js": "__next",
        "Nuxt.js": "__nuxt",
        "jQuery": "jquery",
        "Bootstrap": "bootstrap",
        "Tailwind CSS": "tailwind",
        "Cloudflare": "cloudflare",
        "Nginx": "nginx",
        "Apache": "apache",
    }
    for tech, signal in stack_signals.items():
        if signal.lower() in lower_html:
            tech_hints.append(tech)

    return {
        "url": url,
        "analytics_ids": found,
        "total_trackers": sum(len(v) for v in found.values()),
        "technology_hints": tech_hints,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Social Media Extractor
# ─────────────────────────────────────────────────────────────────────────────

SOCIAL_PLATFORMS: Dict[str, re.Pattern] = {
    "Facebook":   re.compile(r"facebook\.com/(?!share|sharer|plugins)[a-zA-Z0-9._%@+-]{3,}", re.I),
    "Twitter/X":  re.compile(r"(?:twitter|x)\.com/(?!intent|share|home)[a-zA-Z0-9_]{1,50}", re.I),
    "Instagram":  re.compile(r"instagram\.com/[a-zA-Z0-9._]{2,40}/?", re.I),
    "LinkedIn":   re.compile(r"linkedin\.com/(?:in|company|school)/[a-zA-Z0-9._-]{2,100}", re.I),
    "YouTube":    re.compile(r"youtube\.com/(?:channel|c|user|@)[a-zA-Z0-9._-]{2,60}", re.I),
    "TikTok":     re.compile(r"tiktok\.com/@[a-zA-Z0-9._]{2,40}", re.I),
    "Pinterest":  re.compile(r"pinterest\.com/[a-zA-Z0-9._]{2,40}", re.I),
    "Snapchat":   re.compile(r"snapchat\.com/add/[a-zA-Z0-9._-]{2,30}", re.I),
    "Reddit":     re.compile(r"reddit\.com/(?:r|u)/[a-zA-Z0-9._-]{2,40}", re.I),
    "GitHub":     re.compile(r"github\.com/[a-zA-Z0-9._-]{2,39}(?!/[a-zA-Z])", re.I),
    "Telegram":   re.compile(r"t\.me/[a-zA-Z0-9_]{4,32}", re.I),
    "Discord":    re.compile(r"discord(?:\.gg|app\.com/invite)/[a-zA-Z0-9]{5,20}", re.I),
    "WhatsApp":   re.compile(r"wa\.me/\d{7,15}", re.I),
    "Medium":     re.compile(r"medium\.com/@?[a-zA-Z0-9._-]{2,40}", re.I),
    "Mastodon":   re.compile(r"mastodon\.social/@[a-zA-Z0-9._-]{2,40}", re.I),
}


def extract_social_media(url: str) -> Dict[str, Any]:
    """
    Scan a webpage for links to social media profiles.
    Also looks for social meta tags (og:, twitter:).
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": _DEFAULT_UA}, verify=False)
        html = resp.text
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    results: Dict[str, List[str]] = {}
    for platform, pattern in SOCIAL_PLATFORMS.items():
        matches = set(pattern.findall(html))
        if matches:
            results[platform] = ["https://" + m if not m.startswith("http") else m
                                  for m in sorted(matches)]

    # Extract Open Graph and Twitter card meta tags
    meta: Dict[str, str] = {}
    if BS4_OK:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("meta"):
            prop = tag.get("property") or tag.get("name") or ""
            if prop.startswith(("og:", "twitter:")):
                meta[prop] = tag.get("content", "")

    # Email addresses
    emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html)))
    # Remove common false positives
    emails = [e for e in emails if not any(x in e.lower() for x in ("example", "yourdomain", "email@"))]

    return {
        "url": url,
        "social_profiles": results,
        "platform_count": len(results),
        "email_addresses": emails[:30],
        "og_meta_tags": {k: v for k, v in meta.items() if k.startswith("og:")},
        "twitter_meta_tags": {k: v for k, v in meta.items() if k.startswith("twitter:")},
    }
