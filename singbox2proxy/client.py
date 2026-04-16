"""HTTP client for making requests through SingBox proxies."""

from __future__ import annotations

import importlib.util
import logging
import threading
import time

logger = logging.getLogger("singbox2proxy")

_pysocks_available = None


def _has_pysocks_support() -> bool:
    """Return True if pysocks (socks) is installed/importable."""
    global _pysocks_available
    if _pysocks_available is None:
        _pysocks_available = importlib.util.find_spec("socks") is not None
    return bool(_pysocks_available)


def _import_request_module():
    try:
        import curl_cffi  # type: ignore

        return curl_cffi
    except ImportError:
        try:
            import requests

            return requests
        except ImportError:
            return None


default_request_module = _import_request_module()


class SingBoxClient:
    """HTTP client for making requests through SingBox proxies.

    This class provides an interface for making HTTP requests through a SingBoxProxy
    instance. It automatically configures proxy settings, handles retries, and supports both
    curl-cffi and requests libraries as backends.

    The client uses connection pooling via sessions and supports
    automatic retry logic with exponential backoff. It can be used standalone or as part
    of a SingBoxProxy instance.

    Example:
        Basic usage with SingBoxProxy:
        >>> proxy = SingBoxProxy("vmess://...")
        >>> client = SingBoxClient(client=proxy)
        >>> response = client.get("https://api.ipify.org")
        >>> print(response.text)

        Standalone usage with custom retry settings:
        >>> client = SingBoxClient(auto_retry=True, retry_times=5, timeout=30)
        >>> response = client.post("https://example.com/api", json={"key": "value"})

        Context manager usage:
        >>> with SingBoxClient(client=proxy) as client:
        ...     response = client.get("https://example.com")
        ...     print(response.status_code)

        Custom module usage:
        >>> import requests
        >>> client = SingBoxClient(module=requests, timeout=20)
    """

    def __init__(
        self,
        client=None,
        auto_retry: bool = True,
        retry_times: int = 2,
        timeout: int = 10,
        module=None,
        proxies: dict | None = None,
    ):
        """Initialize a SingBoxClient instance.

        Args:
            client: Optional SingBoxProxy instance to use for proxy configuration.
            auto_retry: Enable automatic retry on failed requests (default: True).
            retry_times: Maximum number of retry attempts (default: 2).
            timeout: Default timeout in seconds (default: 10).
            module: HTTP library to use (curl_cffi or requests). Auto-detects if None.
            proxies: Explicit proxies mapping to override proxy settings.
        """
        self.client = client
        self._proxy_override = proxies
        self.proxy = proxies
        self.auto_retry = auto_retry
        self.retry_times = retry_times
        self.timeout = timeout
        self.module = module or default_request_module
        self._session = None
        self._session_lock = threading.RLock()
        self._request_func = None

    def _set_parent(self, proxy):
        """Attach this client to a SingBoxProxy instance without re-instantiation."""
        self.client = proxy
        self.proxy = None
        return self

    def _ensure_request_callable(self):
        """Locate and cache the request function from the configured HTTP library."""
        if self._request_func is None and self.module is not None:
            request_callable = getattr(self.module, "request", None)
            if request_callable is None:
                nested = getattr(self.module, "requests", None)
                if nested:
                    request_callable = getattr(nested, "request", None)
            self._request_func = request_callable
        return self._request_func

    def _get_session(self):
        """Get or create a session object for connection pooling."""
        if self.module is None:
            return None
        if self._session is not None:
            return self._session
        with self._session_lock:
            if self._session is not None:
                return self._session
            candidates = []
            for attr in ("Session", "session"):
                candidate = getattr(self.module, attr, None)
                if candidate:
                    candidates.append(candidate)
            nested = getattr(self.module, "requests", None)
            if nested:
                for attr in ("Session", "session"):
                    candidate = getattr(nested, attr, None)
                    if candidate:
                        candidates.append(candidate)
            for candidate in candidates:
                try:
                    session = candidate() if callable(candidate) else candidate
                except Exception:
                    continue
                if hasattr(session, "request"):
                    self._session = session
                    break
            return self._session

    def _get_proxy_mapping(self):
        """Resolve the proxy configuration for outbound HTTP requests."""
        if self._proxy_override is not None:
            self.proxy = self._proxy_override
            return self._proxy_override
        if self.client:
            mapping = self.client.proxy_for_requests
            self.proxy = mapping
            return mapping
        self.proxy = None
        return None

    @staticmethod
    def _proxies_require_socks(proxies) -> bool:
        if not proxies:
            return False
        for value in proxies.values():
            if isinstance(value, str) and value.lower().startswith("socks"):
                return True
        return False

    def _request_backend_supports_socks(self) -> bool:
        if self.module is None:
            return False
        module_name = getattr(self.module, "__name__", self.module.__class__.__name__).lower()
        if module_name.startswith("curl_cffi"):
            return True
        if "requests" in module_name:
            return self._has_pysocks()
        return True

    @staticmethod
    def _has_pysocks() -> bool:
        return _has_pysocks_support()

    def _validate_proxy_support(self, proxies):
        if not proxies:
            raise RuntimeError("No proxy mapping provided to SingBoxClient.")
        if not self._proxies_require_socks(proxies):
            return
        if not self._request_backend_supports_socks():
            raise RuntimeError(
                "SOCKS proxies require the 'pysocks' package when using requests. "
                "Install pysocks or enable the HTTP inbound port to avoid leaking traffic."
            )

    def close(self):
        """Close the session and release resources."""
        if self._session and hasattr(self._session, "close"):
            try:
                self._session.close()
            except Exception:
                pass
        self._session = None

    def request(self, method: str, url: str, **kwargs):
        """Make an HTTP request with automatic retry logic.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
            url: Target URL.
            **kwargs: Additional arguments passed to the underlying request function.

        Returns:
            Response: HTTP response object.

        Raises:
            ImportError: If no HTTP request module is available.
        """
        start_time = time.time()
        if self.module is None:
            raise ImportError("No HTTP request module available. Please install 'curl-cffi' or 'requests'.")
        request_callable = self._ensure_request_callable()
        if request_callable is None:
            raise ImportError("The configured request module does not expose a request() function.")
        session = self._get_session()
        if session and hasattr(session, "request"):
            request_callable = session.request

        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.timeout

        proxies = kwargs.get("proxies")
        if proxies is None:
            proxies = self._get_proxy_mapping()
            if proxies is None:
                raise RuntimeError("No proxy configuration available. Attach a SingBoxProxy instance or pass proxies= explicitly.")
            kwargs["proxies"] = proxies

        self._validate_proxy_support(kwargs["proxies"])

        base_kwargs = dict(kwargs)
        retry_times = base_kwargs.pop("retries", self.retry_times if self.auto_retry else 0)
        attempts = 0
        while attempts <= retry_times:
            try:
                response = request_callable(method=method, url=url, **dict(base_kwargs))
                response.raise_for_status()
                logger.debug(f"Request to {url} succeeded in {time.time() - start_time:.2f} seconds")
                return response
            except Exception as e:
                if attempts < retry_times:
                    attempts += 1
                    time.sleep(min(0.2 * attempts, 1))
                    continue
                logger.error(f"Request to {url} failed after {attempts} attempts: {str(e)} and {time.time() - start_time:.2f} seconds")
                raise e

    def get(self, url, **kwargs):
        """Make a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        """Make a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        """Make a PUT request."""
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        """Make a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    def patch(self, url, **kwargs):
        """Make a PATCH request."""
        return self.request("PATCH", url, **kwargs)

    def head(self, url, **kwargs):
        """Make a HEAD request."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        """Make an OPTIONS request."""
        return self.request("OPTIONS", url, **kwargs)

    def download(self, url, destination, chunk_size=8192, **kwargs):
        """Download a file from a URL to a local destination.

        Args:
            url: URL of the file to download.
            destination: Local file path to save the file.
            chunk_size: Size of chunks to read/write (default: 8192).
            **kwargs: Additional arguments passed to request().

        Returns:
            str: Path to the downloaded file.
        """
        kwargs.setdefault("stream", True)
        response = self.request("GET", url, **kwargs)

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(destination, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logger.debug(f"Download progress: {progress:.1f}% ({downloaded}/{total_size} bytes)")

        logger.info(f"Downloaded {url} to {destination} ({downloaded} bytes)")
        return destination

    def get_json(self, url, **kwargs):
        """Make a GET request and parse JSON response."""
        response = self.get(url, **kwargs)
        return response.json()

    def post_json(self, url, json_data=None, **kwargs):
        """Make a POST request with JSON data and parse JSON response."""
        response = self.post(url, json=json_data, **kwargs)
        return response.json()

    @property
    def is_session_active(self):
        """Check if a session is currently active."""
        return self._session is not None

    def __repr__(self):
        has_proxy = self.proxy is not None or self._proxy_override is not None or self.client is not None
        return (
            f"<SingBoxClient proxy={has_proxy} "
            f"timeout={self.timeout} auto_retry={self.auto_retry} "
            f"retry_times={self.retry_times} session={self.is_session_active}>"
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.close()
        except Exception:
            pass
        return False

    def __del__(self):
        """Ensure resources are cleaned up when the object is garbage collected."""
        try:
            self.close()
        except Exception:
            pass
