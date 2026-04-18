from __future__ import annotations

import json
import os
import sys
import time
import unittest
from unittest import mock

from singbox2proxy import SingBoxProxy


TEST_LINK = os.environ.get("TEST_SINGBOX_LINK")


def _read_config(proxy: SingBoxProxy) -> dict:
    path = proxy.create_config_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    finally:
        if os.path.exists(path):
            os.remove(path)


def _find_tun_inbound(config: dict) -> dict | None:
    for inbound in config.get("inbounds", []):
        if inbound.get("type") == "tun":
            return inbound
    return None


class TestTunConfig(unittest.TestCase):
    def test_tun_disabled_by_default(self):
        proxy = SingBoxProxy("socks://127.0.0.1:1080", config_only=True)
        config = _read_config(proxy)
        self.assertIsNone(_find_tun_inbound(config))

    def test_tun_basic_fields(self):
        proxy = SingBoxProxy("socks://127.0.0.1:1080", config_only=True, tun_enabled=True)
        config = _read_config(proxy)
        tun = _find_tun_inbound(config)
        self.assertIsNotNone(tun)
        self.assertEqual(tun["type"], "tun")
        self.assertTrue(tun["auto_route"])
        self.assertTrue(tun["strict_route"])
        self.assertEqual(tun["stack"], "system")
        self.assertEqual(tun["address"], ["172.19.0.1/30"])

    def test_tun_auto_redirect_on_linux(self):
        with mock.patch.object(sys, "platform", "linux"):
            proxy = SingBoxProxy("socks://127.0.0.1:1080", config_only=True, tun_enabled=True)
            with mock.patch.object(SingBoxProxy, "_parse_core_version", return_value=(1, 13, 0)):
                config = _read_config(proxy)
        self.assertTrue(_find_tun_inbound(config).get("auto_redirect"))

    def test_tun_no_auto_redirect_on_windows(self):
        with mock.patch.object(sys, "platform", "win32"):
            proxy = SingBoxProxy("socks://127.0.0.1:1080", config_only=True, tun_enabled=True)
            with mock.patch.object(SingBoxProxy, "_parse_core_version", return_value=(1, 13, 0)):
                config = _read_config(proxy)
        self.assertNotIn("auto_redirect", _find_tun_inbound(config))

    def test_tun_auto_redirect_skipped_for_old_core(self):
        with mock.patch.object(sys, "platform", "linux"):
            proxy = SingBoxProxy("socks://127.0.0.1:1080", config_only=True, tun_enabled=True)
            with mock.patch.object(SingBoxProxy, "_parse_core_version", return_value=(1, 9, 0)):
                config = _read_config(proxy)
        self.assertNotIn("auto_redirect", _find_tun_inbound(config))

    def test_tun_auto_redirect_explicit_off(self):
        with mock.patch.object(sys, "platform", "linux"):
            proxy = SingBoxProxy(
                "socks://127.0.0.1:1080",
                config_only=True,
                tun_enabled=True,
                tun_auto_redirect=False,
            )
            with mock.patch.object(SingBoxProxy, "_parse_core_version", return_value=(1, 13, 0)):
                config = _read_config(proxy)
        self.assertNotIn("auto_redirect", _find_tun_inbound(config))


def _has_privileges() -> bool:
    if sys.platform.startswith("win"):
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


@unittest.skipUnless(
    TEST_LINK
    and (sys.platform.startswith("linux") or sys.platform.startswith("win"))
    and _has_privileges(),
    "Live TUN test requires Linux/Windows + root/admin + TEST_SINGBOX_LINK",
)
class TestTunLiveSystemVpn(unittest.TestCase):
    IP_URL = "https://api.ipify.org?format=json"

    def _fetch_proxy_ip(self) -> str:
        proxy = SingBoxProxy(TEST_LINK)
        try:
            return proxy.get(self.IP_URL, timeout=15).json()["ip"]
        finally:
            proxy.stop()

    def _fetch_system_ip(self) -> str:
        import requests

        return requests.get(self.IP_URL, timeout=15).json()["ip"]

    def test_tun_captures_system_traffic(self):
        proxy_ip = self._fetch_proxy_ip()
        baseline_ip = self._fetch_system_ip()
        self.assertNotEqual(proxy_ip, baseline_ip)

        tun_proxy = SingBoxProxy(TEST_LINK, tun_enabled=True)
        try:
            time.sleep(5)
            observed = self._fetch_system_ip()
        finally:
            tun_proxy.stop()

        self.assertEqual(observed, proxy_ip)


if __name__ == "__main__":
    unittest.main()
