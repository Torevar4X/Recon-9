"""
API Configuration Manager
Handles storage and retrieval of API keys for external services.
Keys are stored in a local JSON file (api_config.json) in the application directory.
"""

import json
import os
from typing import Dict, Any, Optional

# Configuration file path
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_config.json")

# Default API configuration structure
DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "hackertarget": {
        "name": "HackerTarget",
        "description": "Used for: Reverse IP Lookup, Shared DNS Finder",
        "key": "",
        "enabled": True,
        "free_tier": True,
        "url": "https://hackertarget.com/",
    },
    "ipinfo": {
        "name": "IPinfo.io",
        "description": "Used for: IP Geolocation, IP Information",
        "key": "",
        "enabled": True,
        "free_tier": True,
        "url": "https://ipinfo.io/",
    },
    "ipapi": {
        "name": "IP-API.com",
        "description": "Used for: ASN Lookup (fallback)",
        "key": "",
        "enabled": True,
        "free_tier": True,
        "url": "http://ip-api.com/",
    },
    "shodan": {
        "name": "Shodan",
        "description": "Used for: Advanced IP reconnaissance (optional)",
        "key": "",
        "enabled": False,
        "free_tier": False,
        "url": "https://www.shodan.io/",
    },
    "virustotal": {
        "name": "VirusTotal",
        "description": "Used for: Domain/IP reputation analysis (optional)",
        "key": "",
        "enabled": False,
        "free_tier": True,
        "url": "https://www.virustotal.com/",
    },
    "securitytrails": {
        "name": "SecurityTrails",
        "description": "Used for: DNS history, subdomain discovery (optional)",
        "key": "",
        "enabled": False,
        "free_tier": True,
        "url": "https://securitytrails.com/",
    },
    "crtsh": {
        "name": "Certificate Transparency (crt.sh)",
        "description": "Used for: Subdomain discovery via certificate logs",
        "key": "",
        "enabled": True,
        "free_tier": True,
        "url": "https://crt.sh/",
    },
}


def load_config() -> Dict[str, Dict[str, Any]]:
    """
    Load API configuration from file.
    Returns default config if file doesn't exist or is invalid.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
            # Merge with defaults to ensure all keys exist
            config = DEFAULT_CONFIG.copy()
            for service, data in saved_config.items():
                if service in config:
                    config[service].update(data)
            return config
        except (json.JSONDecodeError, IOError):
            # Return defaults if file is corrupted
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Dict[str, Any]]) -> bool:
    """
    Save API configuration to file.
    Returns True on success, False on failure.
    """
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except IOError:
        return False


def get_api_key(service: str) -> Optional[str]:
    """
    Get the API key for a specific service.
    Returns None if service not found or key is empty.
    """
    config = load_config()
    service_config = config.get(service, {})
    if service_config.get("enabled", False):
        return service_config.get("key", "").strip() or None
    return None


def is_service_enabled(service: str) -> bool:
    """
    Check if a service is enabled in the configuration.
    """
    config = load_config()
    service_config = config.get(service, {})
    return service_config.get("enabled", False)


def update_service_key(service: str, key: str) -> bool:
    """
    Update the API key for a specific service.
    Returns True on success.
    """
    config = load_config()
    if service in config:
        config[service]["key"] = key.strip()
        return save_config(config)
    return False


def update_service_enabled(service: str, enabled: bool) -> bool:
    """
    Enable or disable a specific service.
    Returns True on success.
    """
    config = load_config()
    if service in config:
        config[service]["enabled"] = enabled
        return save_config(config)
    return False


def get_all_services() -> Dict[str, Dict[str, Any]]:
    """
    Get all service configurations.
    """
    return load_config()


# Tools that require API keys (for filtering purposes)
API_DEPENDENT_TOOLS = {
    "reverse_ip": ["hackertarget"],
    "find_shared_dns": ["hackertarget"],
    "ip_geolocation": ["ipinfo"],
    "ip_information": ["ipinfo", "ipapi"],
    "asn_lookup": ["ipapi"],
    # Optional future integrations
    "shodan_scan": ["shodan"],
    "virustotal_scan": ["virustotal"],
    "securitytrails_subdomains": ["securitytrails"],
}


def get_tools_requiring_api(service: Optional[str] = None) -> set:
    """
    Get the set of tools that require API access.
    If service is specified, returns tools requiring that specific service.
    """
    if service:
        return {tool for tool, services in API_DEPENDENT_TOOLS.items() if service in services}
    return set(API_DEPENDENT_TOOLS.keys())
