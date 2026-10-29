"""Unit tests for Phase 3: Service Detection and Banner Grabbing.

Validates:
1. Banner sanitization (ANSI sequences, control chars, newlines, max length capping).
2. Service and version extraction across HTTP, SSH, FTP, and SMTP.
3. Socket banner grabbing logic and fallbacks via socket mocking.
"""

from unittest.mock import MagicMock, patch
import pytest

from scanner.banner import grab_banner, parse_service_and_version, sanitize_banner


# ==============================================================================
# 1. Banner Sanitization Tests
# ==============================================================================

def test_sanitize_banner_ansi_stripping():
    """Verify ANSI escape sequences are completely stripped from untrusted banner text."""
    colored_text = "\x1b[31mWarning: \x1b[1mSecure Gateway\x1b[0m"
    sanitized = sanitize_banner(colored_text)
    assert sanitized == "Warning: Secure Gateway"
    assert "\x1b" not in sanitized


def test_sanitize_banner_whitespace_and_control_chars():
    """Verify carriage returns, newlines, tabs, and null bytes are cleaned."""
    raw = "SSH-2.0-OpenSSH_8.4p1\r\n\tProtocol\x00Version\n"
    sanitized = sanitize_banner(raw)
    assert sanitized == "SSH-2.0-OpenSSH_8.4p1 ProtocolVersion"
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "\x00" not in sanitized


def test_sanitize_banner_length_limit():
    """Verify strings exceeding max_length are truncated with an ellipsis."""
    long_string = "A" * 300
    sanitized = sanitize_banner(long_string, max_length=50)
    assert len(sanitized) == 50
    assert sanitized.endswith("...")


def test_sanitize_banner_empty_or_none():
    """Verify handling of empty or falsy input."""
    assert sanitize_banner("") == ""
    assert sanitize_banner(None) == ""


# ==============================================================================
# 2. Service and Version Regex Parsing Tests
# ==============================================================================

def test_parse_ssh_banners():
    """Verify SSH banner regex parsing."""
    banner1 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    svc1, ver1 = parse_service_and_version(banner1)
    assert svc1 == "OpenSSH"
    assert ver1 == "8.9p1"

    banner2 = "SSH-2.0-dropbear_2020.81"
    svc2, ver2 = parse_service_and_version(banner2)
    assert svc2 == "dropbear"
    assert ver2 == "2020.81"


def test_parse_ftp_banners():
    """Verify FTP banner regex parsing for vsftpd and ProFTPD."""
    vsftpd_banner = "220 (vsFTPd 2.3.4)"
    svc1, ver1 = parse_service_and_version(vsftpd_banner)
    assert svc1 == "vsftpd"
    assert ver1 == "2.3.4"

    proftpd_banner = "220 ProFTPD 1.3.5 Server (Debian)"
    svc2, ver2 = parse_service_and_version(proftpd_banner)
    assert svc2 == "ProFTPD"
    assert ver2 == "1.3.5"


def test_parse_smtp_banners():
    """Verify SMTP banner parsing for Postfix and Exim."""
    postfix_banner = "220 mail.example.com ESMTP Postfix (Ubuntu)"
    svc1, _ = parse_service_and_version(postfix_banner)
    assert svc1 == "Postfix"

    exim_banner = "220 mail.test.lan ESMTP Exim 4.93 Tue, 27 Oct 2026"
    svc2, ver2 = parse_service_and_version(exim_banner)
    assert svc2 == "Exim"
    assert ver2 == "4.93"


def test_parse_http_banners():
    """Verify HTTP Server header parsing for Apache, Nginx, and Werkzeug."""
    apache_banner = "HTTP/1.1 200 OK Date: Tue, 27 Oct 2026 Server: Apache/2.4.41 (Ubuntu) Content-Type: text/html"
    svc1, ver1 = parse_service_and_version(apache_banner)
    assert svc1 == "Apache"
    assert ver1 == "2.4.41"

    nginx_banner = "HTTP/1.1 301 Moved Server: nginx/1.18.0 Location: https://test/"
    svc2, ver2 = parse_service_and_version(nginx_banner)
    assert svc2 == "nginx"
    assert ver2 == "1.18.0"


def test_parse_unknown_service_fallback():
    """Verify fallback to default_service when banner does not match known signatures."""
    unknown_banner = "Hello client welcome to custom socket"
    svc, ver = parse_service_and_version(unknown_banner, default_service="custom-app")
    assert svc == "custom-app"
    assert ver == ""


# ==============================================================================
# 3. Socket Banner Grabbing Tests (Mocked)
# ==============================================================================

@patch("socket.socket")
def test_grab_banner_passive_success(mock_socket_cls):
    """Verify passive banner retrieval when service greets immediately."""
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1\r\n"
    mock_socket_cls.return_value = mock_sock

    banner, svc, ver = grab_banner("127.0.0.1", 22, timeout=0.5)
    assert "OpenSSH_8.2p1" in banner
    assert svc == "OpenSSH"
    assert ver == "8.2p1"


@patch("socket.socket")
def test_grab_banner_active_http_probe(mock_socket_cls):
    """Verify active HTTP HEAD probe is sent when passive read returns empty."""
    mock_sock = MagicMock()
    # First recv returns empty (triggering active HTTP probe), second recv returns HTTP headers
    mock_sock.recv.side_effect = [b"", b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"]
    mock_socket_cls.return_value = mock_sock

    banner, svc, ver = grab_banner("127.0.0.1", 80, timeout=0.5)
    assert "nginx/1.24.0" in banner
    assert svc == "nginx"
    assert ver == "1.24.0"
    mock_sock.sendall.assert_called_once()


@patch("socket.socket")
def test_grab_banner_timeout_graceful_handling(mock_socket_cls):
    """Verify graceful return when socket connection fails or times out."""
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = TimeoutError("Timed out")
    mock_socket_cls.return_value = mock_sock

    banner, svc, ver = grab_banner("127.0.0.1", 9999, timeout=0.1, default_service="unknown")
    assert banner == ""
    assert svc == "unknown"
    assert ver == ""
