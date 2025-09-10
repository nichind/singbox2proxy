class SingBoxClient:
    "HTTP client for SingBox"

    def __init__(self, client=None, auto_retry: bool = True, retry_times: int = 2, timeout: int = 10):
        self.client = client
        self.proxy = client.proxy_for_requests if client else None
        self.auto_retry = auto_retry
        self.retry_times = retry_times
        self.timeout = timeout
        self.module = self._import_request_module()

    def _import_request_module(self):
        try:
            import curl_cffi
            return curl_cffi
        except ImportError:
            try:
                import requests
                return requests
            except ImportError:
                raise ImportError("Neither 'curl_cffi' nor 'requests' module is available. Please install one of them.")

    def request(self, method: str, url: str, **kwargs):
        "Make an HTTP request with retries"
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.timeout
        if kwargs.get("proxies") is None:
            kwargs["proxies"] = self.proxy

        retries = 0
        while retries <= self.retry_times:
            try:
                response = self.module.request(method=method, url=url, **kwargs)
                response.raise_for_status()
                return response
            except Exception as e:
                raise e

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)
