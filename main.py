#!/usr/bin/env python3
"""LAN Scanner & Active Port Scanner - Command Line Interface.

A network auditing and learning utility that discovers hosts on a local subnet
and maps active TCP/UDP ports with rate limiting and ethical safety controls.
"""

import argparse
import ipaddress
import signal
import sys
import time
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from exporters import export_csv, export_html, export_json, export_xml
from scanner.banner import grab_banner
from scanner.concurrent_scan import ConcurrentScanEngine
from scanner.cve_lookup import get_cve_engine
from scanner.host_discovery import arp_sweep
from scanner.models import Host, PortResult
from scanner.port_probe import tcp_connect_probe
from scanner.stealth import tcp_syn_probe
from scanner.udp_probe import udp_probe
from ui.terminal import display_header, display_host_results, display_summary
from utils.network import get_local_ip, get_subnet_24, is_admin
from utils.ports import TOP_100_PORTS, TOP_1000_PORTS, parse_port_string
from utils.safety import RateLimiter, print_authorization_notice, validate_target

console = Console()


def build_argument_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser with all required options.

    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="lan_scanner",
        description="Educational LAN Scanner & Active Port Scanner for Authorized Audits",
    )

    parser.add_argument(
        "-t", "--target",
        dest="target",
        type=str,
        default=None,
        help="Target IP (e.g. 192.168.1.1) or CIDR subnet (e.g. 192.168.1.0/24). Defaults to local /24 subnet.",
    )

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports",
        dest="ports",
        type=str,
        default=None,
        help="Ports to scan: single (80), list (22,80,443), or range (1-1024). Default: top 100 ports.",
    )
    port_group.add_argument(
        "--top100",
        dest="top100",
        action="store_true",
        help="Scan the top 100 most common TCP ports (default).",
    )
    port_group.add_argument(
        "--top1000",
        dest="top1000",
        action="store_true",
        help="Scan the top 1000 common TCP ports.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-socket connection timeout in seconds (default: 1.0s).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Maximum concurrent probe threads (default: 100, capped at 500).",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Explicit network interface identifier to utilize for scanning.",
    )
    parser.add_argument(
        "--max-pps",
        type=int,
        default=0,
        help="Rate limit: maximum packets/probes per second (0 = unthrottled).",
    )
    parser.add_argument(
        "--allow-public",
        action="store_true",
        default=False,
        help="Explicit safety override to permit scanning public IP addresses.",
    )
    parser.add_argument(
        "--arp-only",
        action="store_true",
        default=False,
        help="Discover active hosts using ARP without launching port probes.",
    )
    parser.add_argument(
        "--no-banners",
        dest="no_banners",
        action="store_true",
        default=False,
        help="Skip service banner grabbing on discovered open ports.",
    )
    parser.add_argument(
        "-sS", "--stealth",
        dest="stealth",
        action="store_true",
        default=False,
        help="Perform TCP SYN (half-open) stealth scan (requires admin/root).",
    )
    parser.add_argument(
        "-sU", "--udp",
        dest="udp",
        action="store_true",
        default=False,
        help="Perform UDP port scan with service payloads (DNS, NTP, SNMP).",
    )

    # Exporter options
    export_group = parser.add_argument_group("Report Exporters")
    export_group.add_argument(
        "--json",
        dest="json_file",
        type=str,
        default=None,
        help="Export scan results to specified JSON file path.",
    )
    export_group.add_argument(
        "--csv",
        dest="csv_file",
        type=str,
        default=None,
        help="Export scan results to specified CSV spreadsheet file path.",
    )
    export_group.add_argument(
        "--xml",
        dest="xml_file",
        type=str,
        default=None,
        help="Export scan results to Nmap-compatible XML file path.",
    )
    export_group.add_argument(
        "--html",
        dest="html_file",
        type=str,
        default=None,
        help="Export scan results to standalone interactive HTML report path.",
    )
    export_group.add_argument(
        "--show-all",
        dest="show_all",
        action="store_true",
        default=False,
        help="Display all ports (including closed/filtered) in results table.",
    )

    return parser


def display_banner(admin_status: bool) -> None:
    """Print the rich title banner and runtime environment parameters."""
    mode_text = "[bold green]Administrator (Raw Sockets Enabled)[/bold green]" if admin_status else "[bold yellow]Standard User (Falling back to TCP Connect Scan)[/bold yellow]"
    console.print(
        Panel.fit(
            f"[bold cyan]LAN SCANNER & ACTIVE PORT SCANNER[/bold cyan]\n"
            f"[dim]Educational Network Auditing Tool | Authorized Testing Only[/dim]\n"
            f"Execution Privilege: {mode_text}",
            border_style="cyan",
        )
    )


def resolve_target_hosts(target: Optional[str], interface: Optional[str], timeout: float) -> List[Host]:
    """Determine the list of target hosts to scan based on target parameter.

    Args:
        target (Optional[str]): Provided target string or None.
        interface (Optional[str]): Designated network interface.
        timeout (float): Network discovery timeout.

    Returns:
        List[Host]: List of Host instances to scan.
    """
    if not target:
        local_ip = get_local_ip()
        subnet = get_subnet_24(local_ip)
        console.print(f"[*] No target specified. Auto-detected local subnet: [bold cyan]{subnet}[/bold cyan]")
        console.print("[*] Initiating Layer 2 ARP host discovery sweep...")
        hosts = arp_sweep(subnet, timeout=timeout, iface=interface)
        if not hosts:
            console.print(f"[yellow]No active neighbors detected on {subnet}. Adding local host {local_ip} for testing.[/yellow]")
            hosts = [Host(ip=local_ip, hostname="localhost")]
        return hosts

    # Single IP or subnet provided
    if "/" in target:
        console.print(f"[*] Discovering active hosts across designated subnet [bold cyan]{target}[/bold cyan]...")
        hosts = arp_sweep(target, timeout=timeout, iface=interface)
        if not hosts:
            console.print("[yellow]No active hosts answered ARP sweep. Testing network range directly...[/yellow]")
            try:
                net = ipaddress.ip_network(target, strict=False)
                # Cap direct host generation to first 256 addresses for safety
                hosts = [Host(ip=str(ip)) for idx, ip in enumerate(net.hosts()) if idx < 256]
            except Exception:
                hosts = []
        return hosts
    else:
        # Single target IP or hostname
        return [Host(ip=target)]


def main() -> int:
    """Main program entrypoint."""
    parser = build_argument_parser()
    args = parser.parse_args()

    # Step 1: Ethical & Safety Notice
    print_authorization_notice()

    admin_rights = is_admin()
    display_banner(admin_rights)

    # Step 2: Target Validation & Safety Boundary Check
    target_to_check = args.target if args.target else get_subnet_24()
    is_safe, msg = validate_target(target_to_check, allow_public=args.allow_public)
    if not is_safe:
        console.print(f"[bold red]{msg}[/bold red]")
        return 1

    if "WARNING" in msg:
        console.print(f"[bold red]{msg}[/bold red]\n")

    # Step 3: Determine Ports to Scan
    if args.ports:
        try:
            target_ports = parse_port_string(args.ports)
        except ValueError as err:
            console.print(f"[bold red]Port Parsing Error: {err}[/bold red]")
            return 1
    elif args.top1000:
        target_ports = TOP_1000_PORTS
    else:
        # Default is Top 100 ports
        target_ports = TOP_100_PORTS

    console.print(f"[*] Target Port List: [cyan]{len(target_ports)} ports[/cyan] queued per host.")
    if args.max_pps > 0:
        console.print(f"[*] Rate Limiter: Throttled to [bold yellow]{args.max_pps} packets/sec[/bold yellow].")

    # Step 4: Host Discovery
    start_time = time.time()
    try:
        hosts = resolve_target_hosts(args.target, args.interface, args.timeout)
    except Exception as exc:
        console.print(f"[bold red]Host Discovery Failed: {exc}[/bold red]")
        return 1

    console.print(f"[+] Discovered [bold green]{len(hosts)}[/bold green] live target host(s).\n")

    if args.arp_only:
        # Display hosts table and exit
        table = Table(title="Discovered Network Hosts", show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="white")
        table.add_column("Vendor / Manufacturer", style="green")
        for h in hosts:
            table.add_row(h.ip, h.mac or "N/A", h.vendor)
        console.print(table)
        return 0

    # Step 5: Concurrent Port Probing
    rate_limiter = RateLimiter(max_pps=args.max_pps) if args.max_pps > 0 else None
    engine = ConcurrentScanEngine(
        max_threads=args.threads,
        timeout=args.timeout,
        rate_limiter=rate_limiter,
    )

    # Clean signal handling for Ctrl+C
    interrupted = False

    def _sigint_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        console.print("\n[bold yellow][!] Scan cancelled by user (Ctrl+C). Terminating workers cleanly...[/bold yellow]")
        engine.cancel()

    signal.signal(signal.SIGINT, _sigint_handler)

    total_probes = len(hosts) * len(target_ports)
    # Determine probe strategy
    if args.udp:
        probe_fn = udp_probe
        console.print("[*] Scan Technique: [bold magenta]UDP Scan (Service Payloads + ICMP Handling)[/bold magenta]")
    elif args.stealth:
        probe_fn = tcp_syn_probe
        console.print("[*] Scan Technique: [bold magenta]TCP SYN Stealth (Half-Open) Scan[/bold magenta]")
    else:
        probe_fn = tcp_connect_probe
        console.print("[*] Scan Technique: [bold green]TCP Connect Scan (3-Way Handshake)[/bold green]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning target ports...", total=total_probes)

        for host in hosts:
            if engine.cancel_event.is_set():
                break

            def _port_callback(result: PortResult):
                progress.advance(task_id, 1)

            engine.scan_host(
                host=host,
                ports=target_ports,
                probe_fn=probe_fn,
                on_result=_port_callback,
            )

    elapsed_time = time.time() - start_time

    # Step 6: Service Banner Grabbing & Offline CVE Lookup
    cve_engine = get_cve_engine()
    if not engine.cancel_event.is_set():
        for host in hosts:
            for p in host.open_ports:
                if not args.no_banners and not p.banner:
                    banner, service, _ = grab_banner(
                        ip=host.ip,
                        port=p.port,
                        timeout=min(1.5, args.timeout),
                        default_service=p.service,
                    )
                    p.banner = banner
                    if service != "unknown":
                        p.service = service
                # Match against offline CVE signature table
                cve_engine.annotate_port(p)

    # Step 7: Formatted Results Display & Summary Panel
    display_host_results(hosts, show_all_states=args.show_all)
    total_open_ports = sum(len(h.open_ports) for h in hosts)

    # Display Security Hints Panel if any CVEs matched
    all_cves = [c for h in hosts for p in h.ports for c in p.cve_list]
    if all_cves:
        cve_lines = [
            f"[bold red]{c.get('cve_id')}[/bold red] ({c.get('severity')} - CVSS {c.get('cvss')}): "
            f"{c.get('title')}\n  Fix: [bold green]{c.get('fix')}[/bold green]"
            for c in all_cves
        ]
        cve_summary = "\n\n".join(cve_lines)
        console.print(
            Panel(
                f"{cve_summary}\n\n[dim italic]DISCLAIMER: Basic vulnerability hints only, based on banner heuristics. "
                f"Not a full vulnerability scanner.[/dim italic]",
                title="[bold red]Security Vulnerability Hints[/bold red]",
                border_style="red",
            )
        )

    display_summary(len(hosts), total_open_ports, elapsed_time, interrupted=interrupted)

    # Step 8: Multi-Format Exporters
    if args.json_file:
        out = export_json(hosts, args.json_file, target=target_to_check, scan_time=elapsed_time)
        console.print(f"[bold green][+][/bold green] JSON report generated: [cyan]{out}[/cyan]")
    if args.csv_file:
        out = export_csv(hosts, args.csv_file)
        console.print(f"[bold green][+][/bold green] CSV report generated: [cyan]{out}[/cyan]")
    if args.xml_file:
        out = export_xml(hosts, args.xml_file, target=target_to_check, scan_time=elapsed_time)
        console.print(f"[bold green][+][/bold green] XML report generated: [cyan]{out}[/cyan]")
    if args.html_file:
        out = export_html(hosts, args.html_file, target=target_to_check, scan_time=elapsed_time)
        console.print(f"[bold green][+][/bold green] HTML report generated: [cyan]{out}[/cyan]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
