import requests
from typing import Dict, Any, List, Optional

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def lookup_cves_by_product(product_name: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Looks up CVEs for a given product and optional version using the NVD API.
    Returns a dictionary containing the results.
    """
    results = {"product": product_name, "version": version, "cves": [], "error": None}
    
    # NVD API uses CPE (Common Platform Enumeration) for product searches
    # A simplified CPE format for software applications is cpe:/a:<vendor>:<product>:<version>
    # For simplicity, we'll use a direct product name search for now.
    # A more robust solution would involve a CPE lookup first.
    
    params = {"keywordSearch": product_name}
    if version:
        params["version"] = version

    try:
        response = requests.get(NVD_API_BASE_URL, params=params)
        response.raise_for_status() # Raise an exception for HTTP errors
        data = response.json()

        if data.get('vulnerabilities'):
            for vuln_entry in data['vulnerabilities']:
                cve = vuln_entry['cve']
                cve_id = cve['id']
                description = "No description available."
                for desc in cve['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
                
                cvss_score = "N/A"
                if cve.get('metrics') and cve['metrics'].get('cvssMetricV31'):
                    cvss_score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                elif cve.get('metrics') and cve['metrics'].get('cvssMetricV2'):
                    cvss_score = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']

                results['cves'].append({
                    'id': cve_id,
                    'description': description,
                    'cvss_score': cvss_score
                })
        else:
            results['error'] = "No vulnerabilities found for the specified product/version."

    except requests.exceptions.RequestException as e:
        results['error'] = f"Network or API error: {e}"
    except Exception as e:
        results['error'] = f"An unexpected error occurred: {e}"
        
    return results
