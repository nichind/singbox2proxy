"""
Batch proxy engine — run many proxies via shared sing-box instances.
"""

import dataclasses
import json
import logging
import os
import random
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterator, List, Optional

from .base import SingBoxCore, _get_default_core
from .parsers import parse_link

logger = logging.getLogger("singbox2proxy")

_port_range_lock = threading.Lock()


@dataclasses.dataclass
class ProxyCheckResult:
    """Result of checking a single proxy."""

    url: str
    working: bool
    ip: Optional[str] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    protocol: Optional[str] = None


class BatchProxy:
    """A single proxy inside a :class:`SingBoxBatch`.

    Attributes:
        url: Original proxy link.
        protocol: Protocol name (``vless``, ``trojan``, ``ss``, …).
        socks_port: Local SOCKS5 port assigned to this proxy.
        index: Position inside the batch.
    """

    __slots__ = ("url", "protocol", "socks_port", "index", "_batch")

    def __init__(self, url: str, protocol: str, socks_port: int, index: int, batch: "SingBoxBatch"):
        self.url = url
        self.protocol = protocol
        self.socks_port = socks_port
        self.index = index
        self._batch = batch

    # -- Proxy URLs ----------------------------------------------------

    @property
    def socks_url(self) -> str:
        """``socks5://127.0.0.1:<port>``"""
        return f"socks5://127.0.0.1:{self.socks_port}"

    @property
    def socks5h_url(self) -> str:
        """``socks5h://127.0.0.1:<port>`` (remote DNS resolution)."""
        return f"socks5h://127.0.0.1:{self.socks_port}"

    @property
    def proxies(self) -> dict:
        """Dict suitable for ``requests.get(..., proxies=)``."""
        u = self.socks5h_url
        return {"http": u, "https": u}

    def request(self, method: str, url: str, **kwargs):
        """Make an HTTP request through this proxy (requires ``requests`` or ``curl_cffi``)."""
        return self._batch._request(self, method, url, **kwargs)

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def check(self, test_url: str = "https://api.ipify.org?format=json", timeout: float = 5) -> ProxyCheckResult:
        """Test this proxy and return a :class:`ProxyCheckResult`."""
        t0 = time.time()
        try:
            resp = self.get(test_url, timeout=timeout)
            latency = (time.time() - t0) * 1000
            if resp.status_code == 200:
                ip = None
                try:
                    ip = resp.json().get("ip")
                except Exception:
                    pass
                return ProxyCheckResult(url=self.url, working=True, ip=ip, latency_ms=round(latency, 1), protocol=self.protocol)
            return ProxyCheckResult(
                url=self.url, working=False, error=f"HTTP {resp.status_code}", latency_ms=round(latency, 1), protocol=self.protocol
            )
        except Exception as e:
            return ProxyCheckResult(url=self.url, working=False, error=str(e)[:200], protocol=self.protocol)

    @property
    def running(self) -> bool:
        return self._batch.running

    def __repr__(self):
        state = "running" if self.running else "stopped"
        return f"<BatchProxy [{self.index}] {self.protocol} socks={self.socks_port} {state}>"


class SingBoxBatch:
    """Run many proxies through shared sing-box processes.

    Example::

        # Load and start
        batch = SingBoxBatch(["vless://...", "trojan://...", "ss://..."])

        # Use any proxy
        resp = batch[0].get("https://example.com")
        print(batch[0].socks_url)   # socks5://127.0.0.1:40000

        # Iterate
        for proxy in batch:
            print(proxy.protocol, proxy.socks_url)

        # Check which work
        results = batch.check()
        working = [p for p in batch if p.check().working]

        # Context manager
        with SingBoxBatch(urls) as b:
            for p in b:
                p.get("https://api.ipify.org?format=json")

        # From file
        batch = SingBoxBatch.from_file("proxies.txt")
    """

    def __init__(
        self,
        urls: List[str],
        batch_size: int = 30,
        core: Optional[SingBoxCore] = None,
        start: bool = True,
        chain_proxy=None,
        log_level: str = "error",
    ):
        """
        Args:
            urls: Proxy URLs to load.
            batch_size: Outbounds per sing-box process (memory vs concurrency trade-off).
            core: Optional :class:`SingBoxCore`. Uses the default if *None*.
            start: Start sing-box processes immediately (default ``True``).
            chain_proxy: Optional upstream proxy — a URL string or a
                :class:`~singbox2proxy.base.SingBoxProxy` instance.
                All batch proxies will route through it (chain).
            log_level: sing-box log level (``error``, ``warn``, ``info``, ``debug``).
        """
        self.batch_size = max(1, batch_size)
        self.core = core or _get_default_core()
        self.log_level = log_level
        self._chain_proxy_arg = chain_proxy
        self._chain_proxy_owned = None  # SingBoxProxy we started ourselves
        self._chain_proxy_port: Optional[int] = None
        self._processes: list[subprocess.Popen] = []
        self._config_paths: list[str] = []
        self._proxies: list[BatchProxy] = []
        self._parse_errors: list[tuple[int, str, str]] = []
        self._running = False
        self._req_mod = None
        self._lock = threading.Lock()

        self._parse_all(urls)
        if start:
            self.start()

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "SingBoxBatch":
        """Load proxy URLs from a text file (one per line, ``#`` comments)."""
        with open(path, encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return cls(urls, **kwargs)

    def start(self):
        """Parse configs and start sing-box processes."""
        if self._running:
            return
        self._start_chain_proxy()
        self._start_all_batches()
        self._running = True

    def stop(self):
        """Stop all sing-box processes and release resources."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            for proc in self._processes:
                _kill_process(proc)
            self._processes.clear()
            for path in self._config_paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            self._config_paths.clear()
            if self._chain_proxy_owned:
                try:
                    self._chain_proxy_owned.stop()
                except Exception:
                    pass
                self._chain_proxy_owned = None
            self._chain_proxy_port = None

    @property
    def running(self) -> bool:
        return self._running

    def __len__(self):
        return len(self._proxies)

    def __getitem__(self, index) -> BatchProxy:
        return self._proxies[index]

    def __iter__(self) -> Iterator[BatchProxy]:
        return iter(self._proxies)

    def __contains__(self, item):
        return item in self._proxies

    # -- Context manager -----------------------------------------------

    def __enter__(self):
        if not self._running:
            self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def __del__(self):
        try:
            self.stop()
        except Exception:
            pass

    def check(
        self,
        test_url: str = "https://api.ipify.org?format=json",
        timeout: float = 5,
        workers: Optional[int] = None,
        on_result: Optional[Callable[[ProxyCheckResult], None]] = None,
    ) -> List[ProxyCheckResult]:
        """Check all proxies concurrently.

        Args:
            test_url: URL to test.
            timeout: Per-request timeout.
            workers: Concurrent workers (defaults to total proxy count, capped at 100).
            on_result: Optional callback per result.

        Returns:
            List of :class:`ProxyCheckResult`.
        """
        w = workers or min(len(self._proxies), 100)
        results: list[ProxyCheckResult] = []

        with ThreadPoolExecutor(max_workers=w) as pool:
            futures = {pool.submit(p.check, test_url, timeout): p for p in self._proxies}
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                if on_result:
                    on_result(r)

        # Include parse errors
        for idx, url, err in self._parse_errors:
            proto = url.split("://")[0] if "://" in url else "unknown"
            r = ProxyCheckResult(url=url, working=False, error=err, protocol=proto)
            results.append(r)
            if on_result:
                on_result(r)

        return results

    def check_iter(
        self,
        test_url: str = "https://api.ipify.org?format=json",
        timeout: float = 5,
        workers: Optional[int] = None,
    ) -> Iterator[ProxyCheckResult]:
        """Yield :class:`ProxyCheckResult` as each proxy is tested."""
        w = workers or min(len(self._proxies), 100)

        with ThreadPoolExecutor(max_workers=w) as pool:
            futures = {pool.submit(p.check, test_url, timeout): p for p in self._proxies}
            for fut in as_completed(futures):
                yield fut.result()

        for idx, url, err in self._parse_errors:
            proto = url.split("://")[0] if "://" in url else "unknown"
            yield ProxyCheckResult(url=url, working=False, error=err, protocol=proto)

    def _request(self, proxy: BatchProxy, method: str, url: str, **kwargs):
        """Execute a request through *proxy*'s SOCKS port."""
        req = self._get_req_module()
        if kwargs.get("proxies") is None:
            kwargs["proxies"] = proxy.proxies
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = 10
        return req.request(method, url, **kwargs)

    def _get_req_module(self):
        if self._req_mod is not None:
            return self._req_mod
        try:
            import requests

            self._req_mod = requests
            return requests
        except ImportError:
            pass
        try:
            from curl_cffi import requests as creq

            self._req_mod = creq
            return creq
        except ImportError:
            pass
        raise ImportError("Install 'requests' or 'curl_cffi' for HTTP requests.")

    def _parse_all(self, urls: List[str]):
        """Parse all URLs into outbound dicts; record failures."""
        self._parsed_batches: list[list[tuple[int, str, dict]]] = []
        current_batch: list[tuple[int, str, dict]] = []

        global_idx = 0
        for url in urls:
            try:
                outbound = parse_link(url)
                current_batch.append((global_idx, url, outbound))
                global_idx += 1
            except Exception as e:
                self._parse_errors.append((global_idx, url, f"Parse error: {e}"))
                global_idx += 1
                continue

            if len(current_batch) >= self.batch_size:
                self._parsed_batches.append(current_batch)
                current_batch = []

        if current_batch:
            self._parsed_batches.append(current_batch)

    def _start_chain_proxy(self):
        """Resolve chain_proxy arg into a SOCKS port."""
        if not self._chain_proxy_arg:
            return
        from .base import SingBoxProxy

        arg = self._chain_proxy_arg
        if isinstance(arg, SingBoxProxy):
            self._chain_proxy_port = arg.socks_port
            logger.info(f"Chain proxy (existing): socks5://127.0.0.1:{arg.socks_port}")
        elif isinstance(arg, str):
            logger.info(f"Starting chain proxy: {arg[:60]}...")
            proxy = SingBoxProxy(arg)
            self._chain_proxy_owned = proxy
            self._chain_proxy_port = proxy.socks_port
            logger.info(f"Chain proxy ready: socks5://127.0.0.1:{proxy.socks_port}")
        else:
            raise TypeError(f"chain_proxy must be a URL string or SingBoxProxy, got {type(arg)}")

    def _start_all_batches(self):
        """Build configs, start processes, create BatchProxy objects."""
        proxy_idx = len(self._proxies)
        for batch in self._parsed_batches:
            self._start_one_batch(batch, proxy_idx)
            proxy_idx = len(self._proxies)
        self._parsed_batches.clear()

    def _start_one_batch(self, batch, start_index: int):
        """Start a single sing-box process for a batch of outbounds."""
        base_port = _find_port_range(len(batch))
        if base_port is None:
            logger.error(f"No free port range for batch of {len(batch)}")
            return

        config = _build_config(batch, base_port, upstream_port=self._chain_proxy_port, log_level=self.log_level)
        config_path = _write_config(config)
        self._config_paths.append(config_path)

        if self.core and self.core.executable:
            ok, msg = self.core.check_config(config_path)
            if not ok:
                logger.error(f"Config invalid: {msg}")
                os.unlink(config_path)
                return

        process = _start_singbox(self.core.executable, config_path)
        self._processes.append(process)

        if not _wait_ready(process, base_port, len(batch)):
            logger.error("sing-box failed to start for batch")
            _kill_process(process)
            return

        for idx, (global_idx, url, _outbound) in enumerate(batch):
            proto = url.split("://")[0] if "://" in url else "unknown"
            bp = BatchProxy(
                url=url,
                protocol=proto,
                socks_port=base_port + idx,
                index=start_index + idx,
                batch=self,
            )
            self._proxies.append(bp)

    def add(self, urls) -> List[BatchProxy]:
        """Add proxy URL(s) at runtime. Returns the new :class:`BatchProxy` handles.

        Args:
            urls: A single URL string, or a list of URL strings.

        The new proxies are started in a fresh sing-box process (separate batch).
        """
        if isinstance(urls, str):
            urls = [urls]
        if not urls:
            return []

        parsed: list[tuple[int, str, dict]] = []
        base_idx = len(self._proxies) + len(self._parse_errors)
        for u in urls:
            try:
                outbound = parse_link(u)
                parsed.append((base_idx, u, outbound))
                base_idx += 1
            except Exception as e:
                self._parse_errors.append((base_idx, u, f"Parse error: {e}"))
                base_idx += 1

        if not parsed:
            return []

        new_proxies: list[BatchProxy] = []
        for i in range(0, len(parsed), self.batch_size):
            chunk = parsed[i : i + self.batch_size]
            before = len(self._proxies)
            self._start_one_batch(chunk, before)
            new_proxies.extend(self._proxies[before:])

        return new_proxies

    def remove(self, proxy: BatchProxy) -> bool:
        """Remove a proxy from the batch.

        Marks it as removed so it won't appear in iteration or checks.
        The underlying sing-box process is *not* restarted — the port just
        becomes unused until the batch is stopped.

        Returns ``True`` if the proxy was found and removed.
        """
        with self._lock:
            try:
                self._proxies.remove(proxy)
                # Re-index
                for i, p in enumerate(self._proxies):
                    p.index = i
                return True
            except ValueError:
                return False

    def __repr__(self):
        state = "running" if self._running else "stopped"
        return f"<SingBoxBatch proxies={len(self._proxies)} processes={len(self._processes)} {state}>"


def _build_config(parsed, base_port, upstream_port=None, log_level="error"):
    inbounds = []
    outbounds = []
    rules = []
    for idx, (_i, _url, outbound) in enumerate(parsed):
        out_tag = f"proxy-{idx}"
        in_tag = f"socks-{idx}"
        outbound["tag"] = out_tag
        if upstream_port:
            outbound["detour"] = "upstream"
        outbounds.append(outbound)
        inbounds.append(
            {
                "type": "socks",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": base_port + idx,
            }
        )
        rules.append({"inbound": [in_tag], "outbound": out_tag})
    outbounds.append({"type": "direct", "tag": "direct"})
    if upstream_port:
        outbounds.append(
            {
                "type": "socks",
                "tag": "upstream",
                "server": "127.0.0.1",
                "server_port": upstream_port,
            }
        )
    return {
        "log": {"level": log_level},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }


def _find_port_range(count: int) -> Optional[int]:
    with _port_range_lock:
        for _ in range(30):
            base = random.randint(10000, 60000 - count)
            if all(not _port_used(base + i) for i in range(count)):
                return base
    return None


def _port_used(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.01)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _write_config(config: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="sb_batch_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _start_singbox(executable: str, config_path: str) -> subprocess.Popen:
    cmd = [executable, "run", "-c", config_path]
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        kwargs["preexec_fn"] = os.setsid
    return subprocess.Popen(cmd, **kwargs)


def _wait_ready(process: subprocess.Popen, base_port: int, count: int, timeout: float = 15) -> bool:
    deadline = time.time() + timeout
    check_ports = {base_port, base_port + count - 1} if count > 1 else {base_port}
    ready = set()
    while time.time() < deadline:
        if process.poll() is not None:
            return False
        for p in check_ports - ready:
            if _port_used(p):
                ready.add(p)
        if ready == check_ports:
            return True
        time.sleep(0.05)
    return False


def _kill_process(process: subprocess.Popen):
    try:
        _psutil = None
        try:
            import psutil as _psutil
        except ImportError:
            pass

        if _psutil:
            try:
                parent = _psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except _psutil.NoSuchProcess:
                        pass
                parent.kill()
                parent.wait(timeout=3)
                return
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                return
            except Exception:
                pass

        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=5,
            )
        else:
            import signal

            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
            process.wait(timeout=2)
        except Exception:
            pass
