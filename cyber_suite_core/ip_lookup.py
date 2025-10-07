import requests
import shodan
from typing import Dict, Any, Union

from . import config_manager

def lookup_ip(ip: str) -> Dict[str, Any]:
    """
    Performs an IP lookup, using Shodan if an API key is available,
    otherwise falling back to a free GeoIP service.
    """
    shodan_api_key = config_manager.get_shodan_api_key()
    
    if shodan_api_key and shodan_api_key != 'YOUR_API_KEY_HERE':
        try:
            return shodan_ip_lookup(ip, shodan_api_key)
        except Exception as e:
            # If Shodan fails for any reason, we can still fall back
            return {"error": f"Shodan lookup failed: {e}", "fallback_data": free_ip_lookup(ip)}
    else:
        return free_ip_lookup(ip)

def free_ip_lookup(ip: str) -> Dict[str, Any]:
    """Performs a free IP lookup using the ip-api.com service and returns the data."""
    result = {"source": "ip-api.com"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        data = response.json()
        if data.get('status') == 'success':
            result.update(data)
        else:
            result['error'] = data.get('message', 'Unknown error')
    except requests.exceptions.RequestException as e:
        result['error'] = f"Network error: {e}"
    return result

def shodan_ip_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    """Performs a detailed IP lookup using the Shodan API and returns the data."""
    result = {"source": "Shodan"}
    try:
        api = shodan.Shodan(api_key)
        host_data = api.host(ip)
        result.update(host_data)
    except shodan.APIError as e:
        result['error'] = f"Shodan API error: {e}"
    return result
