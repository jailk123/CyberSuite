import socket
import threading
from queue import Queue
from typing import List, Dict, Any, Callable, Optional

# Well-known ports dictionary
WELL_KNOWN_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP Proxy"
}

def _scan_port_worker(q: Queue, target_ip: str, open_ports: List[Dict[str, Any]], progress_callback: Optional[Callable[[], None]]):
    """Worker thread function to scan a single port."""
    while not q.empty():
        port = q.get()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((target_ip, port))
                service = WELL_KNOWN_PORTS.get(port, "Unknown")
                open_ports.append({"port": port, "service": service})
            except (socket.timeout, ConnectionRefusedError):
                pass
            finally:
                if progress_callback:
                    progress_callback()
                q.task_done()

def parse_port_range(port_range_str: str) -> List[int]:
    """Parses a port range string (e.g., '80,443,1-1024') into a list of integers."""
    ports = set()
    parts = port_range_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end < 65536:
                    ports.update(range(start, end + 1))
            except ValueError:
                # Handle cases like 'abc-123'
                pass
        else:
            try:
                port_num = int(part)
                if 0 < port_num < 65536:
                    ports.add(port_num)
            except ValueError:
                # Handle non-integer parts
                pass
    return sorted(list(ports))

def scan_ports(target: str, port_range_str: str, num_threads: int = 100, progress_callback: Optional[Callable[[], None]] = None) -> Dict[str, Any]:
    """Scans a target for open ports and returns the results."""
    results = {"target": target, "open_ports": [], "resolved_ip": None, "error": None}
    try:
        target_ip = socket.gethostbyname(target)
        results["resolved_ip"] = target_ip
    except socket.gaierror:
        results["error"] = f"Could not resolve hostname '{target}'."
        return results

    ports_to_scan = parse_port_range(port_range_str)
    if not ports_to_scan:
        results["error"] = "No valid ports to scan."
        return results

    q = Queue()
    for port in ports_to_scan:
        q.put(port)

    open_ports_list = []
    
    actual_num_threads = min(num_threads, len(ports_to_scan))

    for _ in range(actual_num_threads):
        t = threading.Thread(
            target=_scan_port_worker, 
            args=(q, target_ip, open_ports_list, progress_callback), 
            daemon=True
        )
        t.start()

    q.join()  # Wait for all ports to be scanned

    results["open_ports"] = sorted(open_ports_list, key=lambda x: x['port'])
    return results
