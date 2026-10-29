"""Terminal formatting and Rich UI rendering components for LAN Scanner.

Provides styled header banners, color-coded tables for port status states,
progress bars, and execution summary panels.
"""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.models import Host, PortResult

console = Console()


def format_state(state: str) -> str:
    """Apply terminal color formatting based on port scan state.

    Color Scheme:
    - OPEN: Bright Green
    - CLOSED: Bright Red
    - FILTERED: Bright Yellow
    - OPEN|FILTERED: Purple / Magenta

    Args:
        state (str): Port state string.

    Returns:
        str: Color-formatted Rich markup string.
    """
    state_upper = state.upper()
    if state_upper == "OPEN":
        return "[bold green]OPEN[/bold green]"
    elif state_upper == "CLOSED":
        return "[bold red]CLOSED[/bold red]"
    elif state_upper == "FILTERED":
        return "[bold yellow]FILTERED[/bold yellow]"
    elif "OPEN|FILTERED" in state_upper:
        return "[bold magenta]OPEN|FILTERED[/bold magenta]"
    return state


def display_header(admin_status: bool) -> None:
    """Render the application header panel with execution privilege details.

    Args:
        admin_status (bool): True if running with administrative / root rights.
    """
    if admin_status:
        priv_text = "[bold green]Administrator / Root (Raw Socket Layer-2/3 Enabled)[/bold green]"
    else:
        priv_text = "[bold yellow]Standard User (TCP Connect 3-Way Handshake Mode)[/bold yellow]"

    content = (
        "[bold cyan]LAN SCANNER & ACTIVE PORT SCANNER[/bold cyan]\n"
        "[dim]Educational Network Auditing & Discovery Tool | Authorized Testing Only[/dim]\n"
        f"Execution Privilege: {priv_text}"
    )
    console.print(Panel.fit(content, border_style="cyan"))


def display_host_results(hosts: List[Host], show_all_states: bool = False) -> None:
    """Print structured, color-coded tables of discovered hosts and their ports.

    Args:
        hosts (List[Host]): Discovered hosts containing port probe results.
        show_all_states (bool): If True, display closed and filtered ports alongside open ports.
    """
    console.print("\n" + "=" * 80)
    console.print("[bold cyan]SCAN RESULTS[/bold cyan]")
    console.print("=" * 80)

    for host in hosts:
        ports_to_show = host.ports if show_all_states else host.open_ports

        title_str = (
            f"Host: [bold white]{host.ip}[/bold white] "
            f"({host.vendor}) | MAC: [dim]{host.mac or 'Local / Unknown'}[/dim]"
        )

        table = Table(
            title=title_str,
            show_header=True,
            header_style="bold blue",
            border_style="dim",
        )
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Proto", style="white", width=6)
        table.add_column("State", width=16)
        table.add_column("Service", style="green", width=16)
        table.add_column("Banner / Version", style="yellow")
        table.add_column("Security / CVE", style="red")

        if not ports_to_show:
            table.add_row("-", "-", "[dim]No open ports found[/dim]", "-", "-", "-")
        else:
            for p in ports_to_show:
                cve_text = ", ".join(c.get("cve_id", "") for c in p.cve_list if isinstance(c, dict))
                table.add_row(
                    str(p.port),
                    p.protocol.upper(),
                    format_state(p.state),
                    p.service,
                    p.banner if p.banner else "[dim]-[/dim]",
                    cve_text if cve_text else "[dim]-[/dim]",
                )

        console.print(table)
        console.print()


def display_summary(
    hosts_count: int,
    open_ports_count: int,
    elapsed_time: float,
    interrupted: bool = False,
) -> None:
    """Display the scan execution summary box.

    Args:
        hosts_count (int): Total live hosts evaluated.
        open_ports_count (int): Total open ports identified.
        elapsed_time (float): Elapsed seconds.
        interrupted (bool): True if scan was terminated prematurely via Ctrl+C.
    """
    status_label = "[bold yellow][INTERRUPTED - PARTIAL RESULTS][/bold yellow] " if interrupted else ""
    summary_text = (
        f"{status_label}Hosts Scanned: [bold green]{hosts_count}[/bold green] | "
        f"Total Open Ports: [bold green]{open_ports_count}[/bold green] | "
        f"Time Taken: [bold cyan]{elapsed_time:.2f}s[/bold cyan]"
    )
    border = "yellow" if interrupted else "green"
    console.print(Panel(summary_text, title="[bold]Scan Execution Summary[/bold]", border_style=border))
