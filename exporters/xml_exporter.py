"""Nmap-compatible XML report exporter for LAN Scanner scan results.

Generates structured XML files formatted according to the standard Nmap XML DTD
specification, enabling integration with vulnerability scanners, SIEM platforms,
and network management suites.
"""

from datetime import datetime
import time
from typing import List
import xml.dom.minidom
import xml.etree.ElementTree as ET

from scanner.models import Host


def export_xml(
    hosts: List[Host],
    filepath: str,
    target: str = "Local Subnet",
    scan_time: float = 0.0,
) -> str:
    """Generate an Nmap-style XML file from scan results.

    Args:
        hosts (List[Host]): Scanned Host instances.
        filepath (str): Output XML file path (.xml).
        target (str): Target string.
        scan_time (float): Elapsed seconds.

    Returns:
        str: Verified file path of the written XML report.
    """
    now_ts = int(time.time())
    now_str = datetime.now().strftime("%a %b %d %H:%M:%S %Y")

    root = ET.Element(
        "nmaprun",
        {
            "scanner": "lanscanner",
            "args": f"lanscanner -t {target}",
            "start": str(now_ts),
            "startstr": now_str,
            "version": "1.0",
            "xmloutputversion": "1.05",
        },
    )

    # Scaninfo header
    ET.SubElement(
        root,
        "scaninfo",
        {
            "type": "connect",
            "protocol": "tcp",
            "numservices": str(sum(len(h.ports) for h in hosts)),
        },
    )

    # Host records
    for host in hosts:
        host_elem = ET.SubElement(root, "host")

        # Status
        ET.SubElement(host_elem, "status", {"state": "up", "reason": "arp-or-echo"})

        # IP Address
        ET.SubElement(host_elem, "address", {"addr": host.ip, "addrtype": "ipv4"})

        # MAC Address & Vendor
        if host.mac:
            mac_attrs = {"addr": host.mac, "addrtype": "mac"}
            if host.vendor:
                mac_attrs["vendor"] = host.vendor
            ET.SubElement(host_elem, "address", mac_attrs)

        # Hostnames
        hostnames_elem = ET.SubElement(host_elem, "hostnames")
        if host.hostname:
            ET.SubElement(hostnames_elem, "hostname", {"name": host.hostname, "type": "user"})

        # Ports
        ports_elem = ET.SubElement(host_elem, "ports")
        for p in host.ports:
            port_elem = ET.SubElement(
                ports_elem,
                "port",
                {"protocol": p.protocol.lower(), "portid": str(p.port)},
            )
            ET.SubElement(
                port_elem,
                "state",
                {"state": p.state.lower(), "reason": "syn-ack" if p.is_open else "conn-refused"},
            )
            svc_attrs = {"name": p.service}
            if p.banner:
                svc_attrs["product"] = p.banner[:32]
            ET.SubElement(port_elem, "service", svc_attrs)

            if p.banner:
                script_elem = ET.SubElement(port_elem, "script", {"id": "banner", "output": p.banner})

    # Runstats footer
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(
        runstats,
        "finished",
        {"time": str(now_ts), "timestr": now_str, "elapsed": f"{scan_time:.2f}"},
    )
    ET.SubElement(
        runstats,
        "hosts",
        {"up": str(len(hosts)), "down": "0", "total": str(len(hosts))},
    )

    # Pretty-print XML output
    rough_string = ET.tostring(root, encoding="utf-8")
    reparsed = xml.dom.minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ", encoding="utf-8")

    with open(filepath, "wb") as f:
        f.write(pretty_xml)

    return filepath
