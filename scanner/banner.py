"""Service detection and banner grabbing module.

Safely probes open TCP ports, captures response banners for protocols including
HTTP, HTTPS, SSH, FTP, and SMTP, sanitizes untrusted binary and terminal escape
sequences, and applies regular expressions to extract service names and version strings.
"""

import re
import socket
import ssl
from typing import Optional, Tuple


# Maximum permissible banner length to avoid memory bloat and terminal disruption
MAX_BANNER_LENGTH = 256

# Regex to strip non-printable characters and ANSI escape codes
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Common regex patterns to detect services and version numbers
SERVICE_PATTERNS = [
    # SSH patterns: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    (re.compile(r"^SSH-[\d\.]+-OpenSSH[_-]([^\s\r\n]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"^SSH-[\d\.]+-([A-Za-z0-9_-]+)[_-]([^\s\r\n]+)", re.IGNORECASE), None),
    (re.compile(r"^SSH-[\d\.]+", re.IGNORECASE), "SSH"),
    # FTP patterns: 220 (vsFTPd 2.3.4), 220 ProFTPD 1.3.5, 220 Pure-FTPd
    (re.compile(r"220[- ].*vsftpd\s+([\d\.]+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"220[- ].*ProFTPD\s+([\d\.\w]+)", re.IGNORECASE), "ProFTPD"),
    (re.compile(r"220[- ].*Pure-FTPd", re.IGNORECASE), "Pure-FTPd"),
    (re.compile(r"220[- ].*FileZilla Server\s+([\d\.]+)", re.IGNORECASE), "FileZilla"),
    (re.compile(r"220[- ].*Microsoft FTP Service", re.IGNORECASE), "Microsoft-FTP"),
    # SMTP patterns: 220 mail.domain.com ESMTP Postfix, 220 Exim 4.93
    (re.compile(r"220[- ].*Postfix(?:\s*\(([^\)]+)\))?", re.IGNORECASE), "Postfix"),
    (re.compile(r"220[- ].*Exim\s+([\d\.]+)", re.IGNORECASE), "Exim"),
    (re.compile(r"220[- ].*Sendmail\s+([\d\./]+)", re.IGNORECASE), "Sendmail"),
    (re.compile(r"220[- ].*ESMTP", re.IGNORECASE), "SMTP"),
    # HTTP Server header patterns: Server: Apache/2.4.41 (Ubuntu)
    (re.compile(r"Server:\s*Apache/([\d\.]+)", re.IGNORECASE), "Apache"),
    (re.compile(r"Server:\s*nginx/([\d\.]+)", re.IGNORECASE), "nginx"),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d\.]+)", re.IGNORECASE), "Microsoft-IIS"),
    (re.compile(r"Server:\s*lighttpd/([\d\.]+)", re.IGNORECASE), "lighttpd"),
    (re.compile(r"Server:\s*Werkzeug/([\d\.]+)", re.IGNORECASE), "Werkzeug"),
    (re.compile(r"Server:\s*([A-Za-z0-9_-]+)/([\d\.]+)", re.IGNORECASE), None),
    (re.compile(r"Server:\s*([^\r\n]+)", re.IGNORECASE), None),
    # Redis
    (re.compile(r"-ERR unknown command|redis_version:([\d\.]+)", re.IGNORECASE), "Redis"),
    # MySQL / MariaDB
    (re.compile(r"([\d\.]+-[0-9a-zA-Z\.\+]+-MariaDB)", re.IGNORECASE), "MariaDB"),
    (re.compile(r"([\d\.]+)-MySQL", re.IGNORECASE), "MySQL"),
]


def sanitize_banner(raw_data: str, max_length: int = MAX_BANNER_LENGTH) -> str:
    """Sanitize raw banner strings by stripping control characters and trimming length.

    Treats incoming banner data as untrusted text to prevent terminal escape injection,
    log poisoning, and buffer corruption.

    Args:
        raw_data (str): Unsanitized raw banner text from socket.
        max_length (int): Maximum allowable character length (default: 256).

    Returns:
        str: Cleaned, single-line printable ASCII string.
    """
    if not raw_data:
        return ""

    # Strip ANSI terminal escape sequences
    cleaned = ANSI_ESCAPE_PATTERN.sub("", raw_data)

    # Normalize carriage returns and newlines into spaces
    cleaned = re.sub(r"[\r\n\t]+", " ", cleaned)

    # Strip non-printable ASCII characters (preserve space to tilde: 0x20 to 0x7E)
    cleaned = "".join(ch for ch in cleaned if 32 <= ord(ch) <= 126)

    # Trim excess whitespace
    cleaned = cleaned.strip()

    # Enforce maximum length limit
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."

    return cleaned


def parse_service_and_version(
    banner: str,
    port: int = 0,
    default_service: str = "unknown",
) -> Tuple[str, str]:
    """Parse service name and version string from a sanitized banner using regex.

    Args:
        banner (str): Sanitized banner text.
        port (int): Port number for context.
        default_service (str): Fallback service name if unrecognized.

    Returns:
        Tuple[str, str]: (detected_service, detected_version)
    """
    if not banner:
        return default_service, ""

    for pattern, fixed_name in SERVICE_PATTERNS:
        match = pattern.search(banner)
        if match:
            groups = match.groups()
            if fixed_name:
                version = groups[0] if groups and groups[0] else ""
                return fixed_name, version
            else:
                # Dynamic matching from regex groups
                if len(groups) >= 2 and groups[0] and groups[1]:
                    return groups[0], groups[1]
                elif len(groups) >= 1 and groups[0]:
                    return groups[0], ""

    return default_service, ""


def grab_banner(
    ip: str,
    port: int,
    timeout: float = 2.0,
    default_service: str = "unknown",
) -> Tuple[str, str, str]:
    """Safely connect to an open TCP port, retrieve banner, and extract service info.

    Attempts passive listening first (for SSH, FTP, SMTP), and falls back to
    active HTTP probes if no initial banner is emitted.

    Args:
        ip (str): Target IPv4 address.
        port (int): Target port number.
        timeout (float): Read/connect timeout in seconds.
        default_service (str): Fallback service name.

    Returns:
        Tuple[str, str, str]: (sanitized_banner, service_name, version)
    """
    raw_banner = ""

    # Strategy 1: Standard TCP stream connection (Passive read first, then active probe)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Check for immediate banner (common in SSH, FTP, SMTP, Telnet)
        try:
            initial_data = sock.recv(1024)
            if initial_data:
                raw_banner = initial_data.decode("utf-8", errors="ignore")
        except (socket.timeout, TimeoutError):
            pass

        # If passive read produced nothing, send an active HTTP probe
        if not raw_banner:
            http_probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: LANScanner/1.0\r\n\r\n"
            try:
                sock.sendall(http_probe.encode("ascii"))
                http_data = sock.recv(2048)
                if http_data:
                    raw_banner = http_data.decode("utf-8", errors="ignore")
            except Exception:
                pass

        sock.close()
    except Exception:
        pass

    # Strategy 2: If port is HTTPS / SSL-enabled (e.g. 443, 8443) and nothing was received
    if not raw_banner and port in (443, 8443):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=ip) as ssl_sock:
                ssl_sock.connect((ip, port))
                ssl_probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                ssl_sock.sendall(ssl_probe.encode("ascii"))
                ssl_data = ssl_sock.recv(2048)
                if ssl_data:
                    raw_banner = ssl_data.decode("utf-8", errors="ignore")
        except Exception:
            pass

    sanitized = sanitize_banner(raw_banner)
    service, version = parse_service_and_version(sanitized, port=port, default_service=default_service)

    return sanitized, service, version
