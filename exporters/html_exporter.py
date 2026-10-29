"""HTML report exporter for LAN Scanner scan results.

Builds an attractive, self-contained HTML dashboard report with modern CSS styling,
summary metrics, device inventory tables, and vulnerability indicators that operates
completely offline.
"""

from datetime import datetime
import html
from typing import List

from scanner.models import Host


def export_html(
    hosts: List[Host],
    filepath: str,
    target: str = "Local Subnet",
    scan_time: float = 0.0,
) -> str:
    """Generate a self-contained HTML report from scan results.

    Args:
        hosts (List[Host]): Discovered hosts and their port results.
        filepath (str): Output HTML destination path (.html).
        target (str): Target IP or CIDR scope.
        scan_time (float): Elapsed execution time in seconds.

    Returns:
        str: Verified file path of the generated HTML report.
    """
    total_open_ports = sum(len(h.open_ports) for h in hosts)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate Host Cards HTML
    hosts_html = []
    for host in hosts:
        open_count = len(host.open_ports)
        status_color = "#10b981" if open_count > 0 else "#6b7280"

        # Build ports table for this host
        ports_rows = []
        if not host.ports:
            ports_rows.append(
                "<tr><td colspan='5' style='text-align: center; color: #9ca3af;'>No ports probed</td></tr>"
            )
        else:
            for p in host.ports:
                badge_class = "badge-open" if p.state == "OPEN" else ("badge-closed" if p.state == "CLOSED" else "badge-filtered")
                cve_badges = ""
                if p.cve_list:
                    cve_badges = "".join(
                        f"<span class='cve-pill' title='{html.escape(c.get('description', ''))}'>{html.escape(c.get('cve_id', ''))} ({html.escape(c.get('severity', ''))})</span>"
                        for c in p.cve_list if isinstance(c, dict)
                    )

                none_cve_badge = '<span style="color:#9ca3af;">None</span>'

                ports_rows.append(
                    f"<tr>"
                    f"<td><strong>{p.port}</strong>/{html.escape(p.protocol.upper())}</td>"
                    f"<td><span class='badge {badge_class}'>{html.escape(p.state)}</span></td>"
                    f"<td>{html.escape(p.service)}</td>"
                    f"<td><code>{html.escape(p.banner or '-')}</code></td>"
                    f"<td>{cve_badges or none_cve_badge}</td>"
                    f"</tr>"
                )

        table_body = "\n".join(ports_rows)

        host_card = f"""
        <div class="card host-card">
            <div class="host-header">
                <div>
                    <h3 class="host-title">{html.escape(host.ip)}</h3>
                    <div class="host-meta">
                        <span><strong>MAC:</strong> {html.escape(host.mac or 'N/A')}</span> &bull;
                        <span><strong>Vendor:</strong> {html.escape(host.vendor)}</span>
                        {f"&bull; <span><strong>Hostname:</strong> {html.escape(host.hostname)}</span>" if host.hostname else ""}
                    </div>
                </div>
                <div>
                    <span class="open-badge" style="background-color: {status_color};">
                        {open_count} Open Port{'s' if open_count != 1 else ''}
                    </span>
                </div>
            </div>
            <table class="report-table">
                <thead>
                    <tr>
                        <th style="width: 15%;">Port</th>
                        <th style="width: 15%;">State</th>
                        <th style="width: 20%;">Service</th>
                        <th style="width: 30%;">Banner</th>
                        <th style="width: 20%;">Security / CVE</th>
                    </tr>
                </thead>
                <tbody>
                    {table_body}
                </tbody>
            </table>
        </div>
        """
        hosts_html.append(host_card)

    all_hosts_rendered = "\n".join(hosts_html) if hosts_html else "<div class='card'><p>No hosts discovered.</p></div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAN Scanner Audit Report - {html.escape(target)}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .header h1 {{ font-size: 2rem; color: var(--primary); margin-bottom: 0.5rem; }}
        .header p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .stat-value {{ font-size: 1.75rem; font-weight: bold; margin-top: 0.25rem; color: var(--text); }}
        .card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .host-header {{
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .host-title {{ font-size: 1.25rem; color: var(--primary); }}
        .host-meta {{ font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem; }}
        .open-badge {{
            color: #ffffff;
            font-size: 0.8rem;
            font-weight: bold;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}
        .report-table th {{
            background-color: rgba(15, 23, 42, 0.4);
            padding: 0.75rem 1.5rem;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }}
        .report-table td {{
            padding: 0.75rem 1.5rem;
            border-bottom: 1px solid rgba(51, 65, 85, 0.5);
        }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .badge-open {{ background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .badge-closed {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-filtered {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .cve-pill {{
            background-color: rgba(220, 38, 38, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(220, 38, 38, 0.4);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-right: 0.25rem;
        }}
        code {{
            background-color: rgba(15, 23, 42, 0.6);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
        }}
        .footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>LAN Scanner & Active Port Scanner</h1>
            <p>Comprehensive Security Audit & Network Discovery Report</p>
        </header>

        <section class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Target Scope</div>
                <div class="stat-value" style="font-size: 1.3rem;">{html.escape(target)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Hosts Discovered</div>
                <div class="stat-value">{len(hosts)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Open Ports Identified</div>
                <div class="stat-value" style="color: var(--success);">{total_open_ports}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Scan Duration</div>
                <div class="stat-value">{scan_time:.2f}s</div>
            </div>
        </section>

        <section class="hosts-section">
            {all_hosts_rendered}
        </section>

        <footer class="footer">
            <p>Generated on {now_str} by <strong>LAN Scanner & Active Port Scanner</strong></p>
            <p>Authorized Testing & Educational Research Use Only</p>
        </footer>
    </div>
</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    return filepath
