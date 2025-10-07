import argparse
import sys
import time
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from typing import Optional

# Import from the core library
from cyber_suite_core.password_tools import generate_password, audit_password_hash
from cyber_suite_core.ip_lookup import lookup_ip
from cyber_suite_core.port_scanner import scan_ports, parse_port_range
from cyber_suite_core.cve_lookup import lookup_cves_by_product
from cyber_suite_core.log_monitor import LogMonitor, get_log_monitor_rules
from cyber_suite_core.reporting import generate_report
from cyber_suite_core.config_manager import config

def print_lookup_results(console: Console, results: dict):
    """Helper function to print IP lookup results in a nice format."""
    if results.get("error"):
        console.print(f"[bold red]Error:[/] {results['error']}")
        if "fallback_data" in results:
            console.print("[cyan]Attempting fallback...[/]")
            print_lookup_results(console, results["fallback_data"])
        return

    source = results.get("source", "Unknown")
    title = f"{source} IP Lookup Results for {results.get('ip_str', results.get('query'))}"
    
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Property", style="dim", width=20)
    table.add_column("Value")

    # Generic fields from free lookup
    if source == "ip-api.com":
        table.add_row("ISP", results.get('isp', 'N/A'))
        table.add_row("Organization", results.get('org', 'N/A'))
        table.add_row("Country", results.get('country', 'N/A'))
        table.add_row("Region", results.get('regionName', 'N/A'))
        table.add_row("City", results.get('city', 'N/A'))
    
    # Fields from Shodan
    elif source == "Shodan":
        table.add_row("Organization", results.get('org', 'N/A'))
        table.add_row("ISP", results.get('isp', 'N/A'))
        table.add_row("ASN", results.get('asn', 'N/A'))
        table.add_row("Country", results.get('country_name', 'N/A'))
        table.add_row("City", results.get('city', 'N/A'))
        table.add_row("Last Update", results.get('last_update', 'N/A'))
        table.add_row("Hostnames", ", ".join(results.get('hostnames', [])))
        table.add_row("Domains", ", ".join(results.get('domains', [])))

    console.print(table)

    # Print Shodan-specific port/vulnerability data
    if source == "Shodan" and results.get('data'):
        port_table = Table(title="Open Ports", show_header=True, header_style="bold green")
        port_table.add_column("Port")
        port_table.add_column("Transport")
        port_table.add_column("Service")
        for port_data in results['data']:
            port_table.add_row(str(port_data.get('port')), port_data.get('transport'), port_data.get('product'))
        console.print(port_table)

def main():
    # Force UTF-8 encoding for console output on Windows
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8')

    console = Console()
    parser = argparse.ArgumentParser(description="CyberSuite - A modular cyber security toolkit.")
    subparsers = parser.add_subparsers(dest="command", help="Available tools", required=True)

    # Password Generator Command
    pass_parser = subparsers.add_parser("pass", help="Generate a secure password.")
    pass_parser.add_argument("-l", "--length", type=int, default=16, help="Length of the password.")
    pass_parser.add_argument("--no-uppercase", action="store_false", dest="uppercase", help="Exclude uppercase letters.")
    pass_parser.add_argument("--no-lowercase", action="store_false", dest="lowercase", help="Exclude lowercase letters.")
    pass_parser.add_argument("--no-digits", action="store_false", dest="digits", help="Exclude digits.")
    pass_parser.add_argument("--no-symbols", action="store_false", dest="symbols", help="Exclude symbols.")
    pass_parser.set_defaults(uppercase=True, lowercase=True, digits=True, symbols=True)

    # IP Lookup Command
    lookup_parser = subparsers.add_parser("lookup", help="Look up information for an IP address.")
    lookup_parser.add_argument("ip", help="The IP address to look up.")

    # Port Scanner Command
    scan_parser = subparsers.add_parser("scan", help="Scan a target for open TCP ports.")
    scan_parser.add_argument("target", help="The IP address or domain to scan.")
    scan_parser.add_argument("--ports", default="1-1024", help="Port range to scan (e.g., 80, 443, 1-1024).")
    scan_parser.add_argument("--threads", type=int, default=100, help="Number of threads to use for scanning.")

    # CVE Lookup Command
    cve_parser = subparsers.add_parser("cvelookup", help="Look up CVEs for a product/version using NVD.")
    cve_parser.add_argument("product", help="The product name (e.g., 'apache http server').")
    cve_parser.add_argument("--version", help="Optional: The product version (e.g., '2.4.50').")

    # Password Cracker Command
    crack_parser = subparsers.add_parser("crack", help="Audit password strength using a wordlist.")
    crack_parser.add_argument("hash", help="The password hash to crack.")
    crack_parser.add_argument("wordlist", help="Path to the wordlist file.")
    crack_parser.add_argument("--algorithm", default="sha256", help="Hash algorithm (e.g., md5, sha1, sha256, sha512).")

    # Log Monitor Command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor a log file for specific patterns.")
    monitor_parser.add_argument("log_file", nargs='?', help="Path to the log file to monitor. Defaults to config.ini setting.")

    # Reporting Command
    report_parser = subparsers.add_parser("report", help="Generate a consolidated report from tool results.")
    report_parser.add_argument("input_json", help="Path to a JSON file containing results from various tools.")
    report_parser.add_argument("output_file", help="Path to the output Markdown report file.")

    args = parser.parse_args()

    if args.command == "pass":
        password = generate_password(
            length=args.length,
            include_uppercase=args.uppercase,
            include_lowercase=args.lowercase,
            include_digits=args.digits,
            include_symbols=args.symbols
        )
        if password:
            console.print(f"[bold green]Generated Password:[/] {password}")
        else:
            console.print("[bold red]Error: Cannot generate a password. At least one character set must be included.[/]")
    
    elif args.command == "lookup":
        with console.status("[bold cyan]Looking up IP..."):
            results = lookup_ip(args.ip)
        print_lookup_results(console, results)

    elif args.command == "scan":
        ports_to_scan = parse_port_range(args.ports)
        if not ports_to_scan:
            console.print("[bold red]Error:[/] Invalid port range specified.")
            return

        with Progress(console=console) as progress:
            scan_task = progress.add_task("[cyan]Scanning...", total=len(ports_to_scan))
            
            def progress_callback():
                progress.update(scan_task, advance=1)

            console.print(f"[bold cyan]Scanning {args.target} on {len(ports_to_scan)} port(s)...[/]")
            results = scan_ports(
                target=args.target, 
                port_range_str=args.ports, 
                num_threads=args.threads,
                progress_callback=progress_callback
            )

        if results.get("error"):
            console.print(f"[bold red]Error:[/] {results['error']}")
            return

        console.print(f"Scan complete for [bold]{results['target']}[/] (resolved to [bold]{results['resolved_ip']}[/]).")
        
        if results["open_ports"]:
            table = Table(title="Open Ports", show_header=True, header_style="bold green")
            table.add_column("Port", style="cyan")
            table.add_column("Service")
            for p in results["open_ports"]:
                table.add_row(str(p['port']), p['service'])
            console.print(table)
        else:
            console.print("[yellow]No open ports found in the specified range.[/]")

    elif args.command == "cvelookup":
        with console.status(f"[bold cyan]Looking up CVEs for {args.product}..."):
            results = lookup_cves_by_product(args.product, args.version)
        
        if results.get("error"):
            console.print(f"[bold red]Error:[/] {results['error']}")
            return
        
        console.print(f"CVE lookup complete for [bold]{args.product}[/]{f' version [bold]{args.version}[/]' if args.version else ''}.")

        if results["cves"]:
            table = Table(title="Found CVEs", show_header=True, header_style="bold red")
            table.add_column("CVE ID", style="yellow")
            table.add_column("CVSS", style="cyan")
            table.add_column("Description")
            for cve in results["cves"]:
                table.add_row(cve['id'], str(cve['cvss_score']), cve['description'])
            console.print(table)
        else:
            console.print("[bold green]No CVEs found for the specified product/version.[/]")

    elif args.command == "crack":
        console.print(f"[bold cyan]Auditing password hash with {args.algorithm} using {args.wordlist}...[/]")
        try:
            with console.status("[bold yellow]Cracking in progress...[/]"):
                cracked_password = audit_password_hash(args.hash, args.wordlist, args.algorithm)
            if cracked_password:
                console.print(f"[bold green]Password cracked![/] Original: [bold yellow]{cracked_password}[/] (Hash: [bold yellow]{args.hash}[/])")
            else:
                console.print("[bold red]Password not found in wordlist.[/]")
        except FileNotFoundError as e:
            console.print(f"[bold red]Error:[/] {e}")
        except ValueError as e:
            console.print(f"[bold red]Error:[/] {e}")
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred:[/] {e}")

    elif args.command == "monitor":
        log_file_path = args.log_file or config.get('LOG_MONITOR', 'LOG_FILE_PATH', fallback=None)
        if not log_file_path:
            console.print("[bold red]Error: Log file path not specified and not found in config.ini.[/]")
            return

        rules = get_log_monitor_rules()
        if not rules:
            console.print("[bold yellow]Warning: No log monitoring rules found in config.ini. Monitoring for all changes.[/]")
            # If no rules, create a default rule to just print all new lines
            rules = [{'pattern': '.*', 'name': 'Any new line'}]

        console.print(f"[bold cyan]Monitoring log file:[/] {log_file_path}")
        console.print("[bold yellow]Press Ctrl+C to stop monitoring.[/]")

        def event_callback(event_data):
            console.print(f"[bold red]ALERT ({event_data['rule_name']}):[/] {event_data['log_line'].strip()} (Timestamp: {time.ctime(event_data['timestamp'])})")

        monitor = LogMonitor(log_file_path, rules, event_callback)
        try:
            monitor.start()
            while True:
                time.sleep(1) # Keep main thread alive
        except KeyboardInterrupt:
            console.print("[bold blue]Stopping log monitor.[/]")
        finally:
            monitor.stop()

    elif args.command == "report":
        try:
            with open(args.input_json, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            generate_report(report_data, args.output_file)
            console.print(f"[bold green]Report successfully generated to[/] [cyan]{args.output_file}[/]")
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/] Input JSON file not found: {args.input_json}")
        except json.JSONDecodeError:
            console.print(f"[bold red]Error:[/] Invalid JSON format in input file: {args.input_json}")
        except IOError as e:
            console.print(f"[bold red]Error:[/] Could not write report: {e}")
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred during report generation:[/] {e}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()