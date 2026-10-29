"""UI-independent scan orchestration and result shaping for the dashboards.

This module deliberately imports **no third-party UI or data libraries**
(no Streamlit, no pandas, no numpy). It is the single source of truth for
"what happens when the user presses Scan", so both front ends can share it:

* ``dashboard/app.py``              - the optional Streamlit dashboard
* ``dashboard/standalone_server.py`` - the dependency-free stdlib dashboard

Keeping the logic here means environments where pandas/Streamlit cannot be
imported (for example a Windows Application Control policy blocking a pandas
DLL) can still run a fully working web dashboard.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from scanner.banner import grab_banner
from scanner.concurrent_scan import ConcurrentScanEngine
from scanner.cve_lookup import get_cve_engine
from scanner.host_discovery import arp_sweep
from scanner.models import Host, PortResult
from scanner.port_probe import tcp_connect_probe
from scanner.stealth import tcp_syn_probe
from scanner.udp_probe import udp_probe
from utils.network import get_local_ip, get_subnet_24, is_admin
from utils.ports import TOP_100_PORTS, TOP_1000_PORTS, parse_port_string
from utils.safety import AUTHORIZATION_NOTICE, RateLimiter, validate_target

# --------------------------------------------------------------------------- #
# Option labels (shared so both front ends render identical choices)
# --------------------------------------------------------------------------- #

TCP_CONNECT_MODE = "TCP Connect (Standard 3-Way Handshake)"
SYN_MODE = "TCP SYN Stealth (Half-Open)"
UDP_MODE = "UDP Scan (Service Payloads + ICMP)"
ARP_MODE = "ARP Host Discovery Sweep Only"
SCAN_MODES: List[str] = [TCP_CONNECT_MODE, SYN_MODE, UDP_MODE, ARP_MODE]

TOP_100_SELECTION = "Top 100 Common Ports"
TOP_1000_SELECTION = "Top 1000 Ports"
CUSTOM_SELECTION = "Custom Range / List"
PORT_SELECTIONS: List[str] = [TOP_100_SELECTION, TOP_1000_SELECTION, CUSTOM_SELECTION]

RISK_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

PLAIN_LANGUAGE_GUIDE = [
    ("Device found", "A device that responded to the scan."),
    ("Open port", "A network service appears to be listening; confirm it is expected."),
    ("Closed port", "The device responded, but no service accepted the connection on that port."),
    ("Filtered", "A firewall or network rule may have blocked the check."),
    ("Vulnerability hint", "A possible match based on service information, not proof of a vulnerability."),
    ("No findings", "This scan did not detect a matching issue; it does not guarantee the device is secure."),
]

# Type alias for progress callbacks: (message, fraction_complete 0.0-1.0)
ProgressCallback = Callable[[str, float], None]
CancelCallback = Callable[[], bool]


# --------------------------------------------------------------------------- #
# Configuration / outcome containers
# --------------------------------------------------------------------------- #


@dataclass
class ScanConfig:
    """User-supplied scan options, mirroring the dashboard sidebar."""

    target: str
    scan_mode: str = TCP_CONNECT_MODE
    port_selection: str = TOP_100_SELECTION
    custom_ports: str = ""
    threads: int = 50
    timeout: float = 1.0
    max_pps: int = 0
    grab_banners: bool = True
    allow_public: bool = False

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Build a config from an untrusted dictionary (HTTP JSON / session state).

        Unknown keys are ignored and every value is coerced to a safe type so a
        malformed request can never crash the scan engine.
        """

        def _as_int(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        def _as_float(value: Any, default: float) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def _as_bool(value: Any, default: bool) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            if value is None:
                return default
            return bool(value)

        data = data or {}
        return cls(
            target=str(data.get("target", "") or "").strip(),
            scan_mode=str(data.get("scan_mode") or TCP_CONNECT_MODE),
            port_selection=str(data.get("port_selection") or TOP_100_SELECTION),
            custom_ports=str(data.get("custom_ports", "") or ""),
            threads=_as_int(data.get("threads"), 50),
            timeout=_as_float(data.get("timeout"), 1.0),
            max_pps=_as_int(data.get("max_pps"), 0),
            grab_banners=_as_bool(data.get("grab_banners"), True),
            allow_public=_as_bool(data.get("allow_public"), False),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "port_selection": self.port_selection,
            "custom_ports": self.custom_ports,
            "threads": self.threads,
            "timeout": self.timeout,
            "max_pps": self.max_pps,
            "grab_banners": self.grab_banners,
            "allow_public": self.allow_public,
        }


@dataclass
class ScanOutcome:
    """Result of a single scan run."""

    hosts: List[Host] = field(default_factory=list)
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        """True when the scan completed without a fatal error."""
        return self.error is None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def resolve_ports(config: ScanConfig) -> List[int]:
    """Translate the port selection option into a concrete port list.

    Raises:
        ValueError: If a custom port specification cannot be parsed.
    """
    if config.scan_mode == ARP_MODE:
        return []
    if config.port_selection == TOP_100_SELECTION:
        return list(TOP_100_PORTS)
    if config.port_selection == TOP_1000_SELECTION:
        return list(TOP_1000_PORTS)
    return parse_port_string(config.custom_ports)


def port_risk_level(port: PortResult) -> str:
    """Derive a coarse risk label for a single port result."""
    if port.cve_list:
        severities = [str(c.get("severity", "MEDIUM")).upper() for c in port.cve_list if isinstance(c, dict)]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        return "MEDIUM"
    if port.is_open:
        return "LOW"
    return "INFORMATIONAL"


def flatten_hosts(hosts: List[Host]) -> List[Dict[str, Any]]:
    """Flatten hosts/ports into table rows.

    This replaces the old ``pandas.DataFrame(...)`` construction, so no
    third-party dataframe library is required anywhere in the project.
    """
    rows: List[Dict[str, Any]] = []
    for host in hosts:
        if not host.ports:
            rows.append(
                {
                    "ip": host.ip,
                    "mac": host.mac or "N/A",
                    "vendor": host.vendor,
                    "port": "-",
                    "protocol": "-",
                    "state": "UP (Host Active)",
                    "service": "-",
                    "banner": "-",
                    "risk": "INFORMATIONAL",
                }
            )
            continue
        for port in host.ports:
            rows.append(
                {
                    "ip": host.ip,
                    "mac": host.mac or "Local / Unknown",
                    "vendor": host.vendor,
                    "port": port.port,
                    "protocol": port.protocol.upper(),
                    "state": port.state,
                    "service": port.service,
                    "banner": port.banner or "-",
                    "risk": port_risk_level(port),
                }
            )
    return rows


def service_summary(hosts: List[Host]) -> Dict[str, int]:
    """Count open ports per "service (port)" bucket, highest count first."""
    counts: Dict[str, int] = {}
    for host in hosts:
        for port in host.open_ports:
            label = f"{port.service} ({port.port})"
            counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def risk_summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count risk labels across flattened rows in a stable, meaningful order."""
    counts: Dict[str, int] = {}
    for row in rows:
        label = str(row.get("risk", "INFORMATIONAL"))
        counts[label] = counts.get(label, 0) + 1
    ordered = {level: counts[level] for level in RISK_ORDER if level in counts}
    for label, value in counts.items():
        if label not in ordered:
            ordered[label] = value
    return ordered


def collect_cves(hosts: List[Host]) -> List[Dict[str, Any]]:
    """Return every CVE hint found, annotated with its host and port."""
    findings: List[Dict[str, Any]] = []
    for host in hosts:
        for port in host.ports:
            for cve in port.cve_list:
                if not isinstance(cve, dict):
                    continue
                enriched = dict(cve)
                enriched.setdefault("ip", host.ip)
                enriched.setdefault("port", port.port)
                findings.append(enriched)
    return findings


def summarize(hosts: List[Host]) -> Dict[str, Any]:
    """Build the KPI block shown at the top of either dashboard."""
    rows = flatten_hosts(hosts)
    cves = collect_cves(hosts)
    return {
        "hosts": len(hosts),
        "open_ports": sum(len(h.open_ports) for h in hosts),
        "alerts": len(cves),
        "critical": sum(1 for c in cves if str(c.get("severity", "")).upper() == "CRITICAL"),
        "rows": len(rows),
    }


def environment_info() -> Dict[str, Any]:
    """Describe the local environment for dashboard headers/forms."""
    return {
        "local_ip": get_local_ip(),
        "subnet": get_subnet_24(),
        "is_admin": is_admin(),
        "authorization_notice": AUTHORIZATION_NOTICE,
        "scan_modes": SCAN_MODES,
        "port_selections": PORT_SELECTIONS,
        "plain_language_guide": [{"term": t, "meaning": m} for t, m in PLAIN_LANGUAGE_GUIDE],
    }


# --------------------------------------------------------------------------- #
# The scan itself
# --------------------------------------------------------------------------- #


def run_scan(
    config: ScanConfig,
    on_progress: Optional[ProgressCallback] = None,
    should_cancel: Optional[CancelCallback] = None,
) -> ScanOutcome:
    """Execute a scan described by ``config``.

    Args:
        config: Validated scan options.
        on_progress: Optional callback receiving ``(message, fraction)``.
        should_cancel: Optional callback polled between hosts; return True to abort.

    Returns:
        ScanOutcome: Hosts discovered plus status/error/warning information.
    """

    def report(message: str, fraction: float) -> None:
        if on_progress is not None:
            try:
                on_progress(message, max(0.0, min(1.0, fraction)))
            except Exception:  # pragma: no cover - progress must never break a scan
                pass

    started = time.time()
    outcome = ScanOutcome()

    target = (config.target or "").strip()

    # Step 1: Safety verification
    is_safe, message = validate_target(target, allow_public=config.allow_public)
    if not is_safe:
        outcome.error = message
        outcome.elapsed = time.time() - started
        return outcome
    if "WARNING" in message:
        outcome.warnings.append(message)

    # Step 2: Resolve target ports
    try:
        target_ports = resolve_ports(config)
    except ValueError as exc:
        outcome.error = f"Port Specification Error: {exc}"
        outcome.elapsed = time.time() - started
        return outcome

    # Step 3: Discover hosts
    report("Discovering active hosts on the network...", 0.02)
    try:
        if "/" in target or not target:
            hosts = arp_sweep(target or get_subnet_24(), timeout=config.timeout)
            if not hosts:
                hosts = [Host(ip=get_local_ip(), hostname="localhost")]
        else:
            hosts = [Host(ip=target)]
    except ValueError as exc:
        outcome.error = f"Target Error: {exc}"
        outcome.elapsed = time.time() - started
        return outcome
    except Exception as exc:  # pragma: no cover - driver/permission failures
        outcome.error = f"Host discovery failed: {exc}"
        outcome.elapsed = time.time() - started
        return outcome

    if config.scan_mode == ARP_MODE:
        report("Host discovery complete.", 1.0)
        outcome.hosts = hosts
        outcome.elapsed = time.time() - started
        return outcome

    # Step 4: Choose probe technique
    if "SYN" in config.scan_mode:
        probe_fn = tcp_syn_probe
    elif "UDP" in config.scan_mode:
        probe_fn = udp_probe
    else:
        probe_fn = tcp_connect_probe

    # Step 5: Concurrent port probes
    rate_limiter = RateLimiter(max_pps=config.max_pps) if config.max_pps > 0 else None
    engine = ConcurrentScanEngine(
        max_threads=config.threads,
        timeout=config.timeout,
        rate_limiter=rate_limiter,
    )

    total_probes = max(1, len(hosts) * len(target_ports))
    completed = 0

    report(
        f"Scanning {len(target_ports)} ports across {len(hosts)} host(s)...",
        0.05,
    )

    for host in hosts:
        if should_cancel is not None and should_cancel():
            outcome.cancelled = True
            break

        def _on_result(_result: PortResult) -> None:
            nonlocal completed
            completed += 1
            # Reserve the last 25% of the bar for banner/CVE enrichment.
            report(
                f"Probing {host.ip} - {completed}/{total_probes} checks",
                0.05 + 0.70 * (completed / total_probes),
            )

        try:
            engine.scan_host(host=host, ports=target_ports, probe_fn=probe_fn, on_result=_on_result)
        except Exception as exc:  # pragma: no cover - probe-level failures
            outcome.warnings.append(f"Scan of {host.ip} reported: {exc}")

    # Step 6: Service banners & CVE lookup
    if config.grab_banners and not outcome.cancelled:
        report("Extracting service banners and querying the CVE database...", 0.85)
        try:
            cve_engine = get_cve_engine()
        except Exception:  # pragma: no cover - missing data file
            cve_engine = None
        for host in hosts:
            for port in host.open_ports:
                if should_cancel is not None and should_cancel():
                    outcome.cancelled = True
                    break
                if not port.banner:
                    try:
                        banner, service, _server = grab_banner(
                            ip=host.ip,
                            port=port.port,
                            timeout=min(1.5, config.timeout),
                            default_service=port.service,
                        )
                        port.banner = banner
                        if service != "unknown":
                            port.service = service
                    except Exception:  # pragma: no cover - banner failures are non-fatal
                        pass
                if cve_engine is not None:
                    try:
                        cve_engine.annotate_port(port)
                    except Exception:  # pragma: no cover
                        pass

    report("Scan completed." if not outcome.cancelled else "Scan cancelled.", 1.0)
    outcome.hosts = hosts
    outcome.elapsed = time.time() - started
    return outcome
