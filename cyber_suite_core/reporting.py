from typing import Dict, Any, List, Optional
import json
import os
import datetime

def generate_report(report_data: Dict[str, Any], output_file: str) -> None:
    """
    Generates a Markdown report from various tool results.
    report_data should be a dictionary where keys are tool names (e.g., 'scan', 'lookup')
    and values are their respective results.
    """
    report_content = []
    report_content.append(f"# CyberSuite Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report_content.append("\n---\n")

    for tool_name, results in report_data.items():
        report_content.append(f"## {tool_name.replace('_', ' ').title()} Results\n")
        if not results:
            report_content.append("No data available.\n")
            continue

        if results.get("error"):
            report_content.append(f"**Error:** {results['error']}\n")
            if "fallback_data" in results:
                report_content.append("**Fallback Data:**\n")
                report_content.extend(_format_dict_to_markdown(results["fallback_data"], indent_level=1))
            report_content.append("\n")
            continue

        if tool_name == "ip_lookup":
            report_content.append(f"**Source:** {results.get('source', 'Unknown')}\n")
            report_content.append(f"**Target:** {results.get('ip_str', results.get('query'))}\n")
            report_content.extend(_format_dict_to_markdown(results, exclude_keys=['source', 'ip_str', 'query', 'data', 'vulnerabilities']))
            
            if results.get('data'): # Shodan specific ports
                report_content.append("### Open Ports (Shodan)\n")
                report_content.append("| Port | Transport | Service |\n")
                report_content.append("|------|-----------|---------|\n")
                for port_data in results['data']:
                    report_content.append(f"| {port_data.get('port')} | {port_data.get('transport')} | {port_data.get('product')} |\n")
                report_content.append("\n")

        elif tool_name == "port_scan":
            report_content.append(f"**Target:** {results.get('target')}\n")
            report_content.append(f"**Resolved IP:** {results.get('resolved_ip')}\n")
            if results.get('open_ports'):
                report_content.append("### Open Ports\n")
                report_content.append("| Port | Service |\n")
                report_content.append("|------|---------|\n")
                for p in results['open_ports']:
                    report_content.append(f"| {p['port']} | {p['service']} |\n")
            else:
                report_content.append("No open ports found.\n")
            report_content.append("\n")

        elif tool_name == "cve_lookup":
            report_content.append(f"**Product:** {results.get('product')}\n")
            if results.get('version'):
                report_content.append(f"**Version:** {results.get('version')}\n")
            if results.get('cves'):
                report_content.append("### Found CVEs\n")
                report_content.append("| CVE ID | CVSS | Description |\n")
                report_content.append("|--------|------|-------------|\n")
                for cve in results['cves']:
                    # Truncate description for table if too long
                    desc = cve['description']
                    if len(desc) > 100:
                        desc = desc[:97] + "..."
                    report_content.append(f"| {cve['id']} | {cve['cvss_score']} | {desc} |\n")
            else:
                report_content.append("No CVEs found.\n")
            report_content.append("\n")

        elif tool_name == "password_crack":
            report_content.append(f"**Hash to Audit:** {results.get('hash')}\n")
            report_content.append(f"**Algorithm:** {results.get('algorithm')}\n")
            if results.get('cracked_password'):
                report_content.append(f"**Cracked Password:** {results['cracked_password']}\n")
            else:
                report_content.append("Password not found in wordlist.\n")
            report_content.append("\n")

        elif tool_name == "log_monitor_events":
            report_content.append(f"**Log File:** {results.get('log_file_path')}\n")
            if results.get('events'):
                report_content.append("### Detected Events\n")
                report_content.append("| Rule Name | Log Line | Timestamp |\n")
                report_content.append("|-----------|----------|-----------|\n")
                for event in results['events']:
                    report_content.append(f"| {event['rule_name']} | {event['log_line'].strip()} | {datetime.datetime.fromtimestamp(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')} |\n")
            else:
                report_content.append("No events detected.\n")
            report_content.append("\n")

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.writelines(report_content)
    except IOError as e:
        raise IOError(f"Could not write report to {output_file}: {e}")

def _format_dict_to_markdown(data: Dict[str, Any], indent_level: int = 0, exclude_keys: Optional[List[str]] = None) -> List[str]:
    """Helper to format a dictionary into markdown key-value pairs."""
    if exclude_keys is None:
        exclude_keys = []
    lines = []
    indent = '  ' * indent_level
    for key, value in data.items():
        if key in exclude_keys:
            continue
        if isinstance(value, dict):
            lines.append(f"{indent}**{key.replace('_', ' ').title()}:**\n")
            lines.extend(_format_dict_to_markdown(value, indent_level + 1))
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                lines.append(f"{indent}**{key.replace('_', ' ').title()}:**\n")
                for item in value:
                    lines.append(f"{indent}- ")
                    lines.extend(_format_dict_to_markdown(item, indent_level + 1))
            else:
                lines.append(f"{indent}**{key.replace('_', ' ').title()}:** {value}\n")
        else:
            lines.append(f"{indent}**{key.replace('_', ' ').title()}:** {value}\n")
    return lines
