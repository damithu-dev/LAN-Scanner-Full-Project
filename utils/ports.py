"""Port parsing and port list management utilities.

Supports parsing individual ports, comma-separated lists, ranges, and
curated top-100 and top-1000 common port lists.
"""

from typing import List, Set


# Standard Nmap-derived Top 100 TCP ports
TOP_100_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155
]

# Generate Top 1000 ports (Top 100 + additional well-known service ports up to 1000 unique ports)
def _build_top_1000_ports() -> List[int]:
    """Generate a sorted list of the top 1000 most common network ports."""
    ports: Set[int] = set(TOP_100_PORTS)
    # Include all standard IANA system ports 1-500
    for p in range(1, 501):
        ports.add(p)
    # Include popular high-port database, web, cache, and admin services
    extended_ports = [
        554, 636, 808, 843, 888, 902, 981, 992, 1080, 1194, 1234, 1434, 1521,
        1883, 1935, 2082, 2083, 2086, 2087, 2222, 2375, 2376, 2483, 2484, 3001,
        3268, 3269, 3307, 3690, 4000, 4040, 4242, 4443, 4444, 4567, 5001, 5050,
        5222, 5269, 5353, 5433, 5555, 5601, 5672, 5901, 5902, 5984, 5985, 5986,
        6379, 6443, 6667, 7000, 7001, 7077, 7443, 7777, 8082, 8083, 8084, 8085,
        8086, 8087, 8088, 8089, 8090, 8181, 8200, 8333, 8444, 8500, 8880, 8883,
        8889, 9001, 9042, 9092, 9200, 9300, 9418, 9990, 11211, 15672, 27017,
        27018, 27019, 28017, 50000, 50070
    ]
    ports.update(extended_ports)
    # Pad to reach exactly 1000 ports using lowest unused ports
    curr = 501
    while len(ports) < 1000 and curr <= 65535:
        ports.add(curr)
        curr += 1
    return sorted(list(ports))

TOP_1000_PORTS: List[int] = _build_top_1000_ports()


# Well-known default service port mappings
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "cslistener",
    27017: "mongodb",
}


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """Resolve a port number to its standard service name.

    Args:
        port (int): Port number (1-65535).
        protocol (str): Protocol name ('tcp' or 'udp').

    Returns:
        str: Service name (e.g. 'http', 'ssh') or 'unknown'.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    import socket
    try:
        return socket.getservbyport(port, protocol.lower())
    except Exception:
        return "unknown"


def parse_port_string(port_str: str) -> List[int]:
    """Parse a flexible port specification string into a sorted list of unique valid ports.

    Accepts formats:
    - Single port: "80"
    - Comma-separated: "80,22,443"
    - Ranges: "1-1024", "8000-8080"
    - Combinations: "22,80,443,8000-8010"

    Args:
        port_str (str): Input port string.

    Returns:
        List[int]: Sorted, deduplicated list of valid port numbers (1-65535).

    Raises:
        ValueError: If port string contains non-numeric syntax, inverted ranges,
                    or numbers outside 1-65535.
    """
    if not port_str or not port_str.strip():
        raise ValueError("Port specification string cannot be empty.")

    clean_str = port_str.strip()
    result_ports: Set[int] = set()

    for part in clean_str.split(","):
        segment = part.strip()
        if not segment:
            continue

        if "-" in segment:
            range_parts = segment.split("-")
            if len(range_parts) != 2:
                raise ValueError(f"Malformed port range specification: '{segment}'")
            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
            except ValueError as exc:
                raise ValueError(f"Port range must contain integers: '{segment}'") from exc

            if start < 1 or end > 65535:
                raise ValueError(f"Port numbers out of valid range (1-65535): '{segment}'")
            if start > end:
                raise ValueError(f"Inverted port range: start ({start}) > end ({end}) in '{segment}'")

            for p in range(start, end + 1):
                result_ports.add(p)
        else:
            try:
                port_num = int(segment)
            except ValueError as exc:
                raise ValueError(f"Invalid non-integer port value: '{segment}'") from exc

            if port_num < 1 or port_num > 65535:
                raise ValueError(f"Port number {port_num} is outside valid boundary (1-65535).")

            result_ports.add(port_num)

    if not result_ports:
        raise ValueError("No valid ports parsed from specification.")

    return sorted(list(result_ports))
