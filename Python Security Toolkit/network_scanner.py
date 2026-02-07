#!/usr/bin/env python3
"""
Network Scanner - Host Discovery and TCP Port Scanner

Performs ICMP ping sweep for host discovery and TCP port scanning on
security-relevant ports. Includes service identification and basic
banner grabbing. Built entirely on the Python standard library.

Author: Jacob Phillips | Cloud Security Engineer
Certifications: SC-200, Security+

DISCLAIMER:
    This tool is intended for AUTHORIZED security assessments only.
    Unauthorized scanning of networks you do not own or have explicit
    written permission to test is illegal and unethical. Always obtain
    proper authorization before scanning any network.

Usage:
    python network_scanner.py --subnet 192.168.1.0/24
    python network_scanner.py --subnet 10.0.0.0/24 --ports 22,80,443 --timeout 2
    python network_scanner.py --subnet 172.16.0.0/24 --output results.json
"""

import argparse
import ipaddress
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Top 25 security-relevant ports
DEFAULT_PORTS: List[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCBind
    135,   # MS-RPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP Proxy
    8443,  # HTTPS Alt
    27017, # MongoDB
]

# Service name mapping
SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DEFAULT_TIMEOUT: float = 1.0
DEFAULT_MAX_THREADS: int = 50
BANNER_GRAB_TIMEOUT: float = 2.0
PING_TIMEOUT: int = 1

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PortResult:
    """Result of scanning a single port."""

    port: int
    state: str
    service: str
    banner: str


@dataclass
class HostResult:
    """Result of scanning a single host."""

    ip_address: str
    is_alive: bool
    open_ports: List[dict] = field(default_factory=list)


@dataclass
class ScanReport:
    """Complete network scan report."""

    subnet: str
    scan_start: str
    scan_end: str
    scan_duration_seconds: float
    total_hosts_in_subnet: int
    hosts_discovered: int
    total_open_ports: int
    hosts: List[dict]


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        verbose: If True, set log level to DEBUG; otherwise INFO.

    Returns:
        Configured Logger instance.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("network_scanner")
    logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


# ---------------------------------------------------------------------------
# Host discovery
# ---------------------------------------------------------------------------


def ping_host(ip: str, timeout: int = PING_TIMEOUT) -> bool:
    """Check if a host is alive using ICMP ping.

    Args:
        ip: Target IP address string.
        timeout: Ping timeout in seconds.

    Returns:
        True if the host responds, False otherwise.
    """
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def discover_hosts(
    subnet: str,
    max_threads: int,
    logger: logging.Logger,
) -> List[str]:
    """Discover live hosts in a subnet via ICMP ping sweep.

    Args:
        subnet: CIDR notation subnet (e.g., "192.168.1.0/24").
        max_threads: Maximum concurrent ping threads.
        logger: Logger instance.

    Returns:
        List of IP address strings for live hosts.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet} - {exc}")

    hosts = list(network.hosts())
    total = len(hosts)
    logger.info("Starting ping sweep on %s (%d hosts)...", subnet, total)

    alive: List[str] = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(ping_host, str(ip)): str(ip) for ip in hosts
        }

        completed = 0
        for future in as_completed(futures):
            ip = futures[future]
            completed += 1

            if completed % 50 == 0:
                logger.info("Ping sweep progress: %d/%d", completed, total)

            try:
                if future.result():
                    alive.append(ip)
                    logger.info("Host discovered: %s", ip)
            except Exception as exc:
                logger.debug("Error pinging %s: %s", ip, exc)

    alive.sort(key=lambda x: ipaddress.ip_address(x))
    logger.info("Ping sweep complete: %d/%d hosts alive", len(alive), total)
    return alive


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------


def scan_port(
    ip: str, port: int, timeout: float = DEFAULT_TIMEOUT
) -> Optional[PortResult]:
    """Attempt a TCP connection to a single port.

    Args:
        ip: Target IP address.
        port: Target port number.
        timeout: Connection timeout in seconds.

    Returns:
        A PortResult if the port is open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            service = SERVICE_MAP.get(port, "Unknown")
            banner = grab_banner(sock, ip, port)
            sock.close()
            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
            )
        else:
            sock.close()
            return None

    except (socket.timeout, socket.error, OSError):
        return None


def grab_banner(
    sock: socket.socket, ip: str, port: int
) -> str:
    """Attempt to grab a service banner from an open port.

    Sends a minimal probe and reads the response. For HTTP ports,
    sends a HEAD request.

    Args:
        sock: Connected socket object.
        ip: Target IP address (for HTTP Host header).
        port: Target port number.

    Returns:
        Banner string, or "--" if no banner received.
    """
    try:
        sock.settimeout(BANNER_GRAB_TIMEOUT)

        # For HTTP ports, send a HEAD request
        if port in (80, 8080, 8443, 443):
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
            sock.sendall(request.encode())
        else:
            # For other ports, try passive banner grab first
            pass

        banner_data = sock.recv(1024)
        banner = banner_data.decode("utf-8", errors="replace").strip()

        # Clean up banner - take first meaningful line
        lines = banner.split("\n")
        for line in lines:
            line = line.strip()
            if line:
                # Truncate long banners
                if len(line) > 80:
                    line = line[:77] + "..."
                return line

        return "--"

    except (socket.timeout, socket.error, OSError, UnicodeDecodeError):
        return "--"


def scan_host_ports(
    ip: str,
    ports: List[int],
    timeout: float,
    max_threads: int,
    logger: logging.Logger,
) -> List[PortResult]:
    """Scan multiple ports on a single host.

    Args:
        ip: Target IP address.
        ports: List of port numbers to scan.
        timeout: Connection timeout per port.
        max_threads: Maximum concurrent scanning threads.
        logger: Logger instance.

    Returns:
        List of PortResult objects for open ports.
    """
    open_ports: List[PortResult] = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.info(
                        "  %s:%d open (%s)",
                        ip,
                        result.port,
                        result.service,
                    )
            except Exception as exc:
                logger.debug("Error scanning %s:%d - %s", ip, port, exc)

    open_ports.sort(key=lambda p: p.port)
    return open_ports


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(
    subnet: str,
    scan_start: float,
    scan_end: float,
    total_hosts: int,
    host_results: List[HostResult],
) -> ScanReport:
    """Build the final scan report.

    Args:
        subnet: The scanned subnet in CIDR notation.
        scan_start: Scan start timestamp.
        scan_end: Scan end timestamp.
        total_hosts: Total hosts in the subnet.
        host_results: List of HostResult objects.

    Returns:
        A ScanReport instance.
    """
    duration = round(scan_end - scan_start, 2)
    start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_start))
    end_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_end))

    total_open = sum(len(h.open_ports) for h in host_results)

    return ScanReport(
        subnet=subnet,
        scan_start=start_str,
        scan_end=end_str,
        scan_duration_seconds=duration,
        total_hosts_in_subnet=total_hosts,
        hosts_discovered=len(host_results),
        total_open_ports=total_open,
        hosts=[asdict(h) for h in host_results],
    )


def print_report(report: ScanReport) -> None:
    """Print a formatted scan report to the console.

    Args:
        report: The completed ScanReport.
    """
    print("\n" + "=" * 62)
    print("              NETWORK SCAN RESULTS")
    print("=" * 62)
    print(f"  Subnet           : {report.subnet}")
    print(f"  Scan start       : {report.scan_start}")
    print(f"  Scan end         : {report.scan_end}")
    print(f"  Duration         : {report.scan_duration_seconds}s")
    print(f"  Hosts in subnet  : {report.total_hosts_in_subnet}")
    print(f"  Hosts discovered : {report.hosts_discovered}")
    print(f"  Total open ports : {report.total_open_ports}")
    print("-" * 62)

    for host in report.hosts:
        print(f"\n  Host: {host['ip_address']}")
        if host["open_ports"]:
            print(f"    {'PORT':<12}{'STATE':<10}{'SERVICE':<18}{'BANNER'}")
            print(f"    {'-' * 55}")
            for port_info in host["open_ports"]:
                port_str = f"{port_info['port']}/tcp"
                print(
                    f"    {port_str:<12}{port_info['state']:<10}"
                    f"{port_info['service']:<18}{port_info['banner']}"
                )
        else:
            print("    No open ports found in scanned range.")

    print("\n" + "-" * 62)
    print(f"  Total open ports : {report.total_open_ports}")
    print("=" * 62)

    # Disclaimer
    print(
        "\n  DISCLAIMER: This scan was performed for authorized security"
        "\n  assessment purposes only. Ensure you have proper authorization"
        "\n  before scanning any network.\n"
    )


def save_report(
    report: ScanReport, output_path: str, logger: logging.Logger
) -> None:
    """Save the scan report as a JSON file.

    Args:
        report: The completed ScanReport.
        output_path: File path for the JSON output.
        logger: Logger instance.
    """
    report_dict = asdict(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)
    logger.info("Report saved to %s", output_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_ports(ports_str: str) -> List[int]:
    """Parse a comma-separated port string into a list of integers.

    Supports individual ports and ranges (e.g., "22,80,100-110,443").

    Args:
        ports_str: Comma-separated port specification.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If the port specification is invalid.
    """
    ports: Set[int] = set()

    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Invalid port range: {part}")
                ports.update(range(start_port, end_port + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")

    return sorted(ports)


def parse_arguments() -> argparse.Namespace:
    """Parse and return command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Network Scanner - Host discovery and TCP port scanning.\n\n"
            "DISCLAIMER: Authorized use only. Do not scan networks without "
            "explicit written permission."
        ),
        epilog=(
            "Examples:\n"
            "  python network_scanner.py --subnet 192.168.1.0/24\n"
            "  python network_scanner.py --subnet 10.0.0.0/24 --ports 22,80,443\n"
            "  python network_scanner.py --subnet 172.16.0.0/24 --output results.json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--subnet",
        "-s",
        required=True,
        help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--ports",
        "-p",
        default=None,
        help=(
            "Comma-separated ports or ranges to scan (e.g., 22,80,100-110). "
            "Default: top 25 security-relevant ports"
        ),
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds per port (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_MAX_THREADS,
        help=f"Maximum concurrent threads (default: {DEFAULT_MAX_THREADS})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path for JSON report (optional)",
    )
    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Skip ping sweep and scan all hosts in subnet",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    """Main entry point for the network scanner.

    Returns:
        Exit code: 0 for success, 2 for errors.
    """
    args = parse_arguments()
    logger = configure_logging(verbose=args.verbose)

    # Print disclaimer
    print("\n" + "*" * 62)
    print("  AUTHORIZED USE ONLY")
    print("  Ensure you have written permission to scan the target network.")
    print("*" * 62 + "\n")

    logger.info("Network Scanner starting...")

    # Parse ports
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            logger.error("Invalid port specification: %s", exc)
            return 2
    else:
        ports = DEFAULT_PORTS

    logger.info("Scanning %d ports per host", len(ports))

    # Validate subnet
    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
        total_hosts = len(list(network.hosts()))
    except ValueError as exc:
        logger.error("Invalid subnet: %s", exc)
        return 2

    scan_start = time.time()

    # Host discovery
    if args.skip_ping:
        alive_hosts = [str(ip) for ip in network.hosts()]
        logger.info("Skipping ping sweep, scanning all %d hosts", len(alive_hosts))
    else:
        try:
            alive_hosts = discover_hosts(args.subnet, args.threads, logger)
        except ValueError as exc:
            logger.error(str(exc))
            return 2

    if not alive_hosts:
        logger.warning("No live hosts discovered in %s", args.subnet)
        scan_end = time.time()
        report = generate_report(args.subnet, scan_start, scan_end, total_hosts, [])
        print_report(report)
        return 0

    # Port scan each discovered host
    host_results: List[HostResult] = []

    for ip in alive_hosts:
        logger.info("Scanning ports on %s...", ip)
        open_ports = scan_host_ports(ip, ports, args.timeout, args.threads, logger)

        result = HostResult(
            ip_address=ip,
            is_alive=True,
            open_ports=[asdict(p) for p in open_ports],
        )
        host_results.append(result)

    scan_end = time.time()

    # Build and display report
    report = generate_report(
        args.subnet, scan_start, scan_end, total_hosts, host_results
    )
    print_report(report)

    # Save JSON report if requested
    if args.output:
        save_report(report, args.output, logger)

    return 0


if __name__ == "__main__":
    sys.exit(main())
