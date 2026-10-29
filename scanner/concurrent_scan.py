"""Concurrent port scanning engine using ThreadPoolExecutor.

Manages multithreaded scanning over port ranges and host targets with thread-safe
result queues, rate limiting, and cancellation support.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import threading
from typing import Callable, List, Optional

from scanner.models import Host, PortResult
from scanner.port_probe import tcp_connect_probe
from utils.safety import RateLimiter

# Maximum allowable worker threads for system safety and socket exhaustion prevention
MAX_SAFE_THREADS = 500


class ConcurrentScanEngine:
    """Thread-safe engine for orchestrating concurrent port scanning tasks.

    Attributes:
        max_threads (int): Maximum worker threads (default: 100, capped at 500).
        timeout (float): Per-socket connection timeout in seconds.
        rate_limiter (Optional[RateLimiter]): Rate limiter instance for packet pacing.
        is_cancelled (threading.Event): Signal flag to gracefully abort running scans.
    """

    def __init__(
        self,
        max_threads: int = 100,
        timeout: float = 1.0,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """Initialize the concurrent scan engine with worker parameters."""
        self.max_threads = min(max(1, max_threads), MAX_SAFE_THREADS)
        self.timeout = max(0.1, timeout)
        self.rate_limiter = rate_limiter
        self.cancel_event = threading.Event()
        self.results_queue: queue.Queue[PortResult] = queue.Queue()

    def cancel(self) -> None:
        """Signal all active scan routines to terminate early."""
        self.cancel_event.set()

    def scan_ports(
        self,
        ip: str,
        ports: List[int],
        probe_fn: Callable[..., PortResult] = tcp_connect_probe,
        on_result: Optional[Callable[[PortResult], None]] = None,
    ) -> List[PortResult]:
        """Scan a list of ports on a single target IP using ThreadPoolExecutor.

        Args:
            ip (str): Target IPv4 address.
            ports (List[int]): List of port numbers to probe.
            probe_fn (Callable): Probe function executing the test (default: tcp_connect_probe).
            on_result (Optional[Callable[[PortResult], None]]): Callback triggered per port.

        Returns:
            List[PortResult]: List of all probe results sorted by port number.
        """
        results: List[PortResult] = []
        if not ports or self.cancel_event.is_set():
            return results

        def _worker(target_port: int) -> Optional[PortResult]:
            if self.cancel_event.is_set():
                return None
            res = probe_fn(
                ip=ip,
                port=target_port,
                timeout=self.timeout,
                rate_limiter=self.rate_limiter,
            )
            self.results_queue.put(res)
            if on_result:
                try:
                    on_result(res)
                except Exception:
                    pass
            return res

        workers = min(self.max_threads, len(ports))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {executor.submit(_worker, p): p for p in ports}
            for future in as_completed(future_to_port):
                if self.cancel_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception:
                    pass

        results.sort(key=lambda p: p.port)
        return results

    def scan_host(
        self,
        host: Host,
        ports: List[int],
        probe_fn: Callable[..., PortResult] = tcp_connect_probe,
        on_result: Optional[Callable[[PortResult], None]] = None,
    ) -> Host:
        """Scan specified ports for a Host object and store results inside host.ports.

        Args:
            host (Host): Target Host object.
            ports (List[int]): List of ports to scan.
            probe_fn (Callable): Underlying probe function.
            on_result (Optional[Callable[[PortResult], None]]): Callback on port completion.

        Returns:
            Host: Updated Host object populated with PortResult entries.
        """
        port_results = self.scan_ports(
            ip=host.ip,
            ports=ports,
            probe_fn=probe_fn,
            on_result=on_result,
        )
        for pr in port_results:
            host.add_port(pr)
        return host

    def scan_hosts(
        self,
        hosts: List[Host],
        ports: List[int],
        probe_fn: Callable[..., PortResult] = tcp_connect_probe,
        on_result: Optional[Callable[[Host, PortResult], None]] = None,
    ) -> List[Host]:
        """Scan a collection of hosts across the specified port list.

        Args:
            hosts (List[Host]): Discovered live hosts.
            ports (List[int]): Ports to scan for each host.
            probe_fn (Callable): Probe function.
            on_result (Optional[Callable[[Host, PortResult], None]]): Callback per port result.

        Returns:
            List[Host]: List of hosts with populated scan results.
        """
        for host in hosts:
            if self.cancel_event.is_set():
                break

            def _host_result_callback(pr: PortResult) -> None:
                if on_result:
                    on_result(host, pr)

            self.scan_host(
                host=host,
                ports=ports,
                probe_fn=probe_fn,
                on_result=_host_result_callback,
            )

        return hosts
