from singbox2proxy import SingBoxProxy
import unittest
import requests
import os


TEST_LINK = os.environ.get("TEST_SINGBOX_LINK")


@unittest.skipIf(not TEST_LINK, "TEST_SINGBOX_LINK environment variable not set")
class TestSingBoxFetch(unittest.TestCase):
    def test_fetch_ip(self):
        proxy = SingBoxProxy(TEST_LINK)
        requests_proxies = {
            "http": proxy.http_proxy_url,
            "https": proxy.http_proxy_url,
        }
        ip = requests.get("https://api.ipify.org?format=json", proxies=requests_proxies, timeout=10).json()
        self.assertIsNotNone(ip)
        self.assertIn("ip", ip)


if __name__ == "__main__":
    unittest.main()
