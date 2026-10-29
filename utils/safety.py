"""Safety rules, target authorization checks, and rate limiting controls.

Ensures the scanner strictly abides by ethical hacking boundaries:
- Default blocking of public IP addresses unless explicitly permitted.
- Authorization notice on startup.
- Token-bucket rate limiting for packet pacing.
"""

import ipaddress
import time
import threading
from typing import Tuple


AUTHORIZATION_NOTICE = """
================================================================================
                           ETHICAL USE & AUTHORIZATION NOTICE
================================================================================
 This tool is designed exclusively for educational exercises, home lab testing,
 and authorized penetration testing on systems you own or have explicit, written
 permission to audit.

 Unauthorized network scanning may violate local laws (e.g. Computer Fraud and
 Abuse Act, Computer Misuse Act), trigger intrusion detection alerts, and lead
 to disciplinary or legal action.

 SAFEGUARDS IN EFFECT:
   - Scanning public IP ranges is BLOCKED by default.
   - Private subnets (RFC 1918), 127.0.0.1, and lab bridges are permitted.
   - Use --allow-public only in authorized, controlled external testing environments.
================================================================================
"""


def is_target_private(target_str: str) -> bool:
    """Determine whether an IP address or network CIDR falls within private/local scope.

    Recognized safe scopes:
    - Loopback (127.0.0.0/8)
    - RFC 1918 Private Ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Link-local (169.254.0.0/16)
    - Carrier-grade NAT (100.64.0.0/10)
    - Standard Docker bridge networks (172.17.0.0/16, etc.)

    Args:
        target_str (str): Target IPv4 address or CIDR notation (e.g., '192.168.1.1' or '192.168.1.0/24').

    Returns:
        bool: True if completely private, loopback, or link-local; False if public.
    """
    clean_target = target_str.strip()
    try:
        if "/" in clean_target:
            net = ipaddress.ip_network(clean_target, strict=False)
            return net.is_private or net.is_loopback or net.is_link_local
        ip = ipaddress.ip_address(clean_target)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # If hostname, we cannot safely guarantee it is private without resolution
        return False


def validate_target(target: str, allow_public: bool = False) -> Tuple[bool, str]:
    """Validate target IP or subnet against safety rules.

    Args:
        target (str): Target IP, CIDR, or hostname.
        allow_public (bool): If True, permit public IPs with an explicit warning.

    Returns:
        Tuple[bool, str]: (is_allowed, reason_or_warning_message)
    """
    if not target or not target.strip():
        return False, "Target specification cannot be empty."

    target = target.strip()

    if is_target_private(target):
        return True, "Target is within permitted private/local address space."

    if allow_public:
        return (
            True,
            f"WARNING: Target '{target}' is a PUBLIC address. "
            "Public scanning is enabled via --allow-public. Ensure you possess full legal authorization!",
        )

    return (
        False,
        f"SAFETY BLOCK: Target '{target}' appears to be a public IP or unresolved hostname. "
        "By default, LAN Scanner blocks scanning public networks to prevent unauthorized probes. "
        "To override for authorized testing, specify the --allow-public flag.",
    )


def print_authorization_notice() -> None:
    """Print the required safety and authorization notice to stdout."""
    print(AUTHORIZATION_NOTICE)


class RateLimiter:
    """Thread-safe rate limiter to constrain packets or probes per second (PPS).

    Attributes:
        max_pps (int): Maximum packets or requests per second (0 or None disables throttling).
    """

    def __init__(self, max_pps: int = 0):
        """Initialize the rate limiter with a target PPS."""
        self.max_pps = max_pps
        self.interval = (1.0 / max_pps) if (max_pps and max_pps > 0) else 0.0
        self._last_time = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block until the permitted rate interval has elapsed."""
        if self.interval <= 0:
            return

        with self._lock:
            now = time.time()
            elapsed = now - self._last_time
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self._last_time = time.time()
