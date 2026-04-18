"""Unit tests for URL parsers, config generation, QR, and recent fixes.

All tests use config_only=True â€” no sing-box binary or network required.
"""

import base64
import json
import os
import unittest
from unittest.mock import patch, MagicMock

from singbox2proxy import SingBoxProxy


def _make_proxy(url, **kwargs):
    """Create a SingBoxProxy in config_only mode for testing."""
    return SingBoxProxy(url, config_only=True, **kwargs)


# ---------------------------------------------------------------------------
# VMess parser
# ---------------------------------------------------------------------------
class TestParseVmess(unittest.TestCase):
    def _vmess_url(self, obj):
        return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()

    def test_basic(self):
        url = self._vmess_url(
            {
                "v": "2",
                "ps": "test",
                "add": "1.2.3.4",
                "port": "443",
                "id": "aaaa-bbbb",
                "scy": "auto",
                "aid": "0",
                "net": "tcp",
                "type": "none",
                "tls": "",
            }
        )
        p = _make_proxy(url)
        cfg = p.generate_config()
        out = cfg["outbounds"][0]
        self.assertEqual(out["type"], "vmess")
        self.assertEqual(out["server"], "1.2.3.4")
        self.assertEqual(out["server_port"], 443)
        self.assertEqual(out["uuid"], "aaaa-bbbb")

    def test_ws_transport(self):
        url = self._vmess_url(
            {
                "add": "srv.example.com",
                "port": "8080",
                "id": "uuid-1",
                "net": "ws",
                "host": "cdn.example.com",
                "path": "/ws",
                "tls": "tls",
                "sni": "sni.example.com",
            }
        )
        p = _make_proxy(url)
        out = p.generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "ws")
        self.assertEqual(out["transport"]["path"], "/ws")
        self.assertEqual(out["transport"]["headers"]["Host"], "cdn.example.com")
        self.assertTrue(out["tls"]["enabled"])
        self.assertEqual(out["tls"]["server_name"], "sni.example.com")

    def test_grpc_transport(self):
        url = self._vmess_url(
            {
                "add": "grpc.test",
                "port": "443",
                "id": "uuid-g",
                "net": "grpc",
                "path": "my-service",
                "tls": "",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "grpc")
        self.assertEqual(out["transport"]["service_name"], "my-service")

    def test_http_transport(self):
        url = self._vmess_url(
            {
                "add": "h.test",
                "port": "443",
                "id": "uuid-h",
                "net": "http",
                "host": "cdn.h.test",
                "path": "/h2",
                "tls": "tls",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "http")
        self.assertEqual(out["transport"]["path"], "/h2")
        self.assertIn("cdn.h.test", out["transport"]["host"])

    def test_httpupgrade_transport(self):
        url = self._vmess_url(
            {
                "add": "hu.test",
                "port": "443",
                "id": "uuid-hu",
                "net": "httpupgrade",
                "path": "/upgrade",
                "tls": "tls",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "httpupgrade")
        self.assertEqual(out["transport"]["path"], "/upgrade")

    def test_alpn_and_insecure(self):
        url = self._vmess_url(
            {
                "add": "a.test",
                "port": "443",
                "id": "uuid-a",
                "net": "tcp",
                "tls": "tls",
                "alpn": "h2,http/1.1",
                "skip-cert-verify": "true",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertTrue(out["tls"]["insecure"])

    def test_ws_early_data(self):
        url = self._vmess_url(
            {
                "add": "ed.test",
                "port": "443",
                "id": "uuid-ed",
                "net": "ws",
                "path": "/ws",
                "tls": "tls",
                "ed": "2048",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["max_early_data"], 2048)
        self.assertEqual(out["transport"]["early_data_header_name"], "Sec-WebSocket-Protocol")

    def test_invalid_base64_raises(self):
        with self.assertRaises(ValueError):
            _make_proxy("vmess://not-valid-json!!!").generate_config()

    def test_fp_fingerprint(self):
        url = self._vmess_url(
            {
                "add": "fp.test",
                "port": "443",
                "id": "uuid-fp",
                "net": "tcp",
                "tls": "tls",
                "fp": "chrome",
            }
        )
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertTrue(out["tls"]["utls"]["enabled"])
        self.assertEqual(out["tls"]["utls"]["fingerprint"], "chrome")


# ---------------------------------------------------------------------------
# VLESS parser
# ---------------------------------------------------------------------------
class TestParseVless(unittest.TestCase):
    def test_basic_tcp(self):
        url = "vless://uuid-123@example.com:443?security=none&type=tcp#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "vless")
        self.assertEqual(out["server"], "example.com")
        self.assertEqual(out["server_port"], 443)
        self.assertEqual(out["uuid"], "uuid-123")

    def test_reality(self):
        url = "vless://uuid@host.com:443?security=reality&sni=sni.com&pbk=PUBKEY&sid=SHORTID&type=tcp&flow=xtls-rprx-vision#r"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertTrue(out["tls"]["enabled"])
        self.assertTrue(out["tls"]["reality"]["enabled"])
        self.assertEqual(out["tls"]["reality"]["public_key"], "PUBKEY")
        self.assertEqual(out["tls"]["reality"]["short_id"], "SHORTID")
        self.assertEqual(out["flow"], "xtls-rprx-vision")

    def test_ws_tls(self):
        url = "vless://uid@h.com:443?type=ws&path=/v&host=cdn.h.com&security=tls&sni=s.com#ws"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "ws")
        self.assertEqual(out["transport"]["path"], "/v")
        self.assertTrue(out["tls"]["enabled"])

    def test_default_port(self):
        url = "vless://uid@host.com?security=none&type=tcp#no-port"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["server_port"], 443)

    def test_amp_entity_handling(self):
        url = "vless://uid@h.com:443?type=tcp&amp;security=tls&amp;sni=s.com#amp"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertTrue(out["tls"]["enabled"])

    def test_http_transport(self):
        url = "vless://uid@h.com:443?type=http&host=cdn.com&path=/h2&security=tls&sni=s.com#ht"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "http")
        self.assertIn("cdn.com", out["transport"]["host"])

    def test_httpupgrade_transport(self):
        url = "vless://uid@h.com:443?type=httpupgrade&path=/up&security=tls&sni=s.com#hu"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "httpupgrade")
        self.assertEqual(out["transport"]["path"], "/up")

    def test_alpn_and_fingerprint(self):
        url = "vless://uid@h.com:443?type=tcp&security=tls&sni=s.com&alpn=h2,http/1.1&fp=chrome#af"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(out["tls"]["utls"]["fingerprint"], "chrome")


# ---------------------------------------------------------------------------
# Shadowsocks parser
# ---------------------------------------------------------------------------
class TestParseShadowsocks(unittest.TestCase):
    def test_base64_userinfo(self):
        userinfo = base64.b64encode(b"aes-256-gcm:mypassword").decode()
        url = f"ss://{userinfo}@1.2.3.4:8388#test"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "shadowsocks")
        self.assertEqual(out["server"], "1.2.3.4")
        self.assertEqual(out["server_port"], 8388)
        self.assertEqual(out["method"], "aes-256-gcm")
        self.assertEqual(out["password"], "mypassword")

    def test_full_base64(self):
        data = base64.b64encode(b"aes-128-gcm:pass123@5.6.7.8:9999").decode()
        url = f"ss://{data}#full"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["server"], "5.6.7.8")
        self.assertEqual(out["server_port"], 9999)
        self.assertEqual(out["method"], "aes-128-gcm")
        self.assertEqual(out["password"], "pass123")

    def test_ss_with_query_params_stays_ss(self):
        """SS link with query params must NOT be misidentified as VLESS."""
        userinfo = base64.b64encode(b"chacha20-ietf-poly1305:pw").decode()
        url = f"ss://{userinfo}@1.1.1.1:443?plugin=v2ray-plugin;mode%3Dwebsocket#q"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "shadowsocks")

    def test_ss_plugin(self):
        userinfo = base64.b64encode(b"aes-256-gcm:mypass").decode()
        url = f"ss://{userinfo}@1.2.3.4:443?plugin=obfs-local&plugin_opts=obfs%3Dhttp%3Bobfs-host%3Dexample.com#p"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["plugin"], "obfs-local")
        self.assertIn("obfs-host", out["plugin_opts"])


# ---------------------------------------------------------------------------
# Trojan parser
# ---------------------------------------------------------------------------
class TestParseTrojan(unittest.TestCase):
    def test_basic(self):
        url = "trojan://mypassword@trojan.example.com:443?sni=sni.com#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "trojan")
        self.assertEqual(out["server"], "trojan.example.com")
        self.assertEqual(out["password"], "mypassword")
        self.assertTrue(out["tls"]["enabled"])
        self.assertEqual(out["tls"]["server_name"], "sni.com")

    def test_ws_transport(self):
        url = "trojan://pass@h.com:443?type=ws&path=/t&host=cdn.com#ws"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "ws")
        self.assertEqual(out["transport"]["path"], "/t")

    def test_http_transport(self):
        url = "trojan://pass@h.com:443?type=http&host=cdn.com&path=/h2#ht"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["transport"]["type"], "http")
        self.assertIn("cdn.com", out["transport"]["host"])

    def test_alpn_fp_insecure(self):
        url = "trojan://pass@h.com:443?sni=s.com&alpn=h2,http/1.1&fp=firefox&allowInsecure=1#af"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(out["tls"]["utls"]["fingerprint"], "firefox")
        self.assertTrue(out["tls"]["insecure"])


# ---------------------------------------------------------------------------
# Hysteria2 parser
# ---------------------------------------------------------------------------
class TestParseHysteria2(unittest.TestCase):
    def test_hy2_scheme(self):
        url = "hy2://password@hy.com:443?sni=s.com&insecure=0#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "hysteria2")
        self.assertEqual(out["password"], "password")
        self.assertFalse(out["tls"]["insecure"])

    def test_hysteria2_scheme(self):
        url = "hysteria2://pass@h.com:8443?sni=s.com&obfs=obfspw#o"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "hysteria2")
        self.assertEqual(out["obfs"]["type"], "salamander")
        self.assertEqual(out["obfs"]["password"], "obfspw")

    def test_insecure_flag(self):
        url = "hy2://p@h.com:443?insecure=1#i"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertTrue(out["tls"]["insecure"])

    def test_alpn(self):
        url = "hy2://p@h.com:443?sni=s.com&alpn=h3#a"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h3"])

    def test_obfs_password_param(self):
        url = "hy2://p@h.com:443?obfs-password=secret&sni=s.com#op"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["obfs"]["type"], "salamander")
        self.assertEqual(out["obfs"]["password"], "secret")


# ---------------------------------------------------------------------------
# Hysteria v1 parser
# ---------------------------------------------------------------------------
class TestParseHysteria(unittest.TestCase):
    def test_basic(self):
        url = "hysteria://hyst.example.com:443?auth=secret&peer=sni.com&insecure=0&upmbps=100&downmbps=200#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "hysteria")
        self.assertEqual(out["auth_str"], "secret")
        self.assertEqual(out["tls"]["server_name"], "sni.com")
        self.assertEqual(out["up_mbps"], 100)
        self.assertEqual(out["down_mbps"], 200)

    def test_sni_param(self):
        url = "hysteria://h.com:443?auth=pw&sni=explicit.com#s"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["server_name"], "explicit.com")

    def test_alpn(self):
        url = "hysteria://h.com:443?auth=pw&alpn=h3&peer=s.com#a"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h3"])


# ---------------------------------------------------------------------------
# TUIC parser
# ---------------------------------------------------------------------------
class TestParseTuic(unittest.TestCase):
    def test_basic(self):
        url = "tuic://myuuid:mypassword@tuic.com:443?sni=s.com&congestion_control=bbr#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "tuic")
        self.assertEqual(out["server"], "tuic.com")
        self.assertEqual(out["server_port"], 443)
        self.assertEqual(out["uuid"], "myuuid")
        self.assertEqual(out["password"], "mypassword")
        self.assertEqual(out["congestion_control"], "bbr")

    def test_alpn(self):
        url = "tuic://uid:pw@t.com:443?alpn=h3#a"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["tls"]["alpn"], ["h3"])

    def test_missing_password_raises(self):
        url = "tuic://onlyuuid@tuic.com:443#nopw"
        with self.assertRaises(ValueError):
            _make_proxy(url).generate_config()


# ---------------------------------------------------------------------------
# WireGuard parser
# ---------------------------------------------------------------------------
class TestParseWireguard(unittest.TestCase):
    def test_parse_link_returns_clean_dict(self):
        """Parser returns a clean outbound-style dict (no internal markers)."""
        from singbox2proxy.parsers import parse_wireguard_link

        url = "wg://PRIVKEY@wg.com:51820?public_key=PUBKEY&local_address=10.0.0.2/32#tag"
        out = parse_wireguard_link(url)
        self.assertEqual(out["type"], "wireguard")
        self.assertEqual(out["server"], "wg.com")
        self.assertEqual(out["server_port"], 51820)
        self.assertEqual(out["private_key"], "PRIVKEY")
        self.assertEqual(out["peer_public_key"], "PUBKEY")
        self.assertEqual(out["local_address"], ["10.0.0.2/32"])
        # No internal markers leak into public API
        self.assertNotIn("_is_endpoint", out)

    def test_endpoint_format_on_new_singbox(self):
        """On sing-box >=1.11, WireGuard uses endpoint format."""
        url = "wg://PRIVKEY@wg.com:51820?public_key=PUBKEY&local_address=10.0.0.2/32#tag"
        p = _make_proxy(url)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 13, 0)):
            cfg = p.generate_config()
        self.assertIn("endpoints", cfg)
        ep = cfg["endpoints"][0]
        self.assertEqual(ep["type"], "wireguard")
        self.assertEqual(ep["peers"][0]["address"], "wg.com")
        self.assertEqual(cfg["route"]["final"], "proxy")

    def test_legacy_outbound_on_old_singbox(self):
        """On sing-box <1.11, WireGuard stays as outbound."""
        url = "wg://PRIVKEY@wg.com:51820?public_key=PUBKEY&local_address=10.0.0.2/32#tag"
        p = _make_proxy(url)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 10, 0)):
            cfg = p.generate_config()
        self.assertNotIn("endpoints", cfg)
        out = cfg["outbounds"][0]
        self.assertEqual(out["type"], "wireguard")
        self.assertEqual(out["server"], "wg.com")

    def test_missing_public_key_raises(self):
        url = "wg://PRIVKEY@wg.com:51820#nopk"
        with self.assertRaises(ValueError):
            _make_proxy(url).generate_config()


# ---------------------------------------------------------------------------
# SSH parser
# ---------------------------------------------------------------------------
class TestParseSsh(unittest.TestCase):
    def test_basic(self):
        url = "ssh://user:pass@ssh.com:22#tag"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "ssh")
        self.assertEqual(out["server"], "ssh.com")
        self.assertEqual(out["server_port"], 22)
        self.assertEqual(out["user"], "user")
        self.assertEqual(out["password"], "pass")

    def test_no_password(self):
        url = "ssh://user@ssh.com:2222#nopw"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["user"], "user")
        self.assertNotIn("password", out)


# ---------------------------------------------------------------------------
# HTTP parser
# ---------------------------------------------------------------------------
class TestParseHttp(unittest.TestCase):
    def test_http(self):
        url = "http://proxy.com:8080"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "http")
        self.assertEqual(out["server"], "proxy.com")
        self.assertEqual(out["server_port"], 8080)
        self.assertNotIn("tls", out)

    def test_https(self):
        url = "https://user:pass@proxy.com:443"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "http")
        self.assertTrue(out["tls"]["enabled"])
        self.assertEqual(out["username"], "user")
        self.assertEqual(out["password"], "pass")


# ---------------------------------------------------------------------------
# SOCKS parser
# ---------------------------------------------------------------------------
class TestParseSocks(unittest.TestCase):
    def test_socks5(self):
        url = "socks5://user:pass@socks.com:1080"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["type"], "socks")
        self.assertEqual(out["version"], "5")
        self.assertEqual(out["username"], "user")

    def test_socks4(self):
        url = "socks4://socks.com:1080"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["version"], "4")

    def test_socks_generic(self):
        url = "socks://socks.com:1080"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        self.assertEqual(out["version"], "5")


# ---------------------------------------------------------------------------
# NaiveProxy parser
# ---------------------------------------------------------------------------
class TestParseNaiveproxy(unittest.TestCase):
    def test_basic(self):
        url = "naive+https://user:pass@naive.com:443"
        out = _make_proxy(url).generate_config()["outbounds"][0]
        # Since sing-box 1.13.0, naive is a proper outbound type
        self.assertEqual(out["type"], "naive")
        self.assertEqual(out["server"], "naive.com")
        self.assertTrue(out["tls"]["enabled"])
        self.assertEqual(out["username"], "user")
        self.assertEqual(out["password"], "pass")


# ---------------------------------------------------------------------------
# Unsupported / invalid
# ---------------------------------------------------------------------------
class TestParseInvalid(unittest.TestCase):
    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            _make_proxy("ftp://example.com").generate_config()


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------
class TestConfigGeneration(unittest.TestCase):
    def test_inbounds_created(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        cfg = p.generate_config()
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertIn("socks-in", tags)
        self.assertIn("http-in", tags)

    def test_http_disabled(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, http_port=False)
        cfg = p.generate_config()
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertNotIn("http-in", tags)
        self.assertIn("socks-in", tags)

    def test_socks_disabled(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, socks_port=False)
        cfg = p.generate_config()
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertIn("http-in", tags)
        self.assertNotIn("socks-in", tags)

    def test_direct_outbound_present(self):
        cfg = _make_proxy("socks5://127.0.0.1:1080").generate_config()
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertIn("direct", tags)

    def test_block_outbound_on_old_singbox(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        with patch.object(type(p), "_parse_core_version", return_value=(1, 12, 0)):
            cfg = p.generate_config()
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertIn("block", tags)

    def test_no_block_outbound_on_new_singbox(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        with patch.object(type(p), "_parse_core_version", return_value=(1, 13, 0)):
            cfg = p.generate_config()
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        self.assertNotIn("block", tags)

    def test_tun_inbound(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        cfg = p.generate_config()
        tags = [ib["tag"] for ib in cfg["inbounds"]]
        self.assertIn("tun-in", tags)
        self.assertTrue(cfg["route"]["auto_detect_interface"])
        self.assertEqual(cfg["route"]["final"], "proxy")
        self.assertIn("dns", cfg)
        self.assertTrue(len(cfg["dns"]["servers"]) >= 2)
        dns_tags = [s["tag"] for s in cfg["dns"]["servers"]]
        self.assertIn("proxy-dns", dns_tags)
        self.assertIn("direct-dns", dns_tags)

    def test_tun_sniff_on_old_singbox(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 12, 0)):
            cfg = p.generate_config()
        tun = next(ib for ib in cfg["inbounds"] if ib["tag"] == "tun-in")
        self.assertTrue(tun["sniff"])
        self.assertTrue(tun["sniff_override_destination"])
        # 1.11+ uses hijack-dns action
        self.assertTrue(any(r.get("action") == "hijack-dns" for r in cfg["route"]["rules"]))

    def test_tun_no_sniff_on_new_singbox(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 13, 0)):
            cfg = p.generate_config()
        tun = next(ib for ib in cfg["inbounds"] if ib["tag"] == "tun-in")
        self.assertNotIn("sniff", tun)
        self.assertNotIn("sniff_override_destination", tun)
        # 1.13+: sniff via route rule
        self.assertTrue(any(r.get("action") == "sniff" for r in cfg["route"]["rules"]))
        # Still has hijack-dns
        self.assertTrue(any(r.get("action") == "hijack-dns" for r in cfg["route"]["rules"]))

    def test_tun_dns_outbound_on_old_singbox(self):
        """<1.11 needs explicit dns outbound instead of hijack-dns action."""
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 10, 0)):
            cfg = p.generate_config()
        out_tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertIn("dns-out", out_tags)
        self.assertTrue(any(r.get("outbound") == "dns-out" for r in cfg["route"]["rules"]))

    def test_tun_dns_new_format_on_112(self):
        """1.12+ uses new DNS server format (legacy removed at runtime in 1.14)."""
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 12, 0)):
            cfg = p.generate_config()
        for srv in cfg["dns"]["servers"]:
            self.assertEqual(srv["type"], "https")
            self.assertIn("server", srv)
            self.assertNotIn("address", srv)
        self.assertIn("default_domain_resolver", cfg["route"])
        self.assertNotIn("rules", cfg["dns"])

    def test_tun_dns_legacy_format_on_111(self):
        """<=1.11 still uses legacy DNS format."""
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, tun_enabled=True)
        with patch.object(type(p), "_parse_core_version", return_value=(1, 11, 0)):
            cfg = p.generate_config()
        for srv in cfg["dns"]["servers"]:
            self.assertIn("address", srv)
            self.assertNotIn("type", srv)
        self.assertTrue(any(r.get("outbound") == "any" for r in cfg["dns"]["rules"]))

    def test_route_passthrough(self):
        route = {"rules": [{"domain": ["example.com"], "outbound": "direct"}]}
        p = _make_proxy("socks5://127.0.0.1:1080", route=route)
        cfg = p.generate_config()
        self.assertIn("rules", cfg["route"])

    def test_config_file_written(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        path = p.create_config_file()
        try:
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertIn("outbounds", data)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_direct_connection_relay(self):
        """Relay without proxy URL creates direct outbound."""
        p = SingBoxProxy(None, config_only=True, relay_protocol="vmess")
        cfg = p.generate_config()
        self.assertEqual(cfg["outbounds"][0]["type"], "direct")


# ---------------------------------------------------------------------------
# Relay inbound & URL generation
# ---------------------------------------------------------------------------
class TestRelay(unittest.TestCase):
    def test_vmess_relay(self):
        p = SingBoxProxy("socks5://127.0.0.1:1080", config_only=True, relay_protocol="vmess", relay_host="1.2.3.4", relay_port=9999)
        cfg = p.generate_config()
        relay_ibs = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"]
        self.assertEqual(len(relay_ibs), 1)
        self.assertEqual(relay_ibs[0]["type"], "vmess")
        self.assertEqual(relay_ibs[0]["listen_port"], 9999)
        self.assertIsNotNone(p.relay_url)
        self.assertTrue(p.relay_url.startswith("vmess://"))

    def test_trojan_relay(self):
        p = SingBoxProxy(None, config_only=True, relay_protocol="trojan", relay_host="5.6.7.8", relay_port=8443)
        cfg = p.generate_config()
        relay_ib = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"][0]
        self.assertEqual(relay_ib["type"], "trojan")
        self.assertTrue(p.relay_url.startswith("trojan://"))

    def test_ss_relay(self):
        p = SingBoxProxy(None, config_only=True, relay_protocol="ss", relay_host="10.0.0.1", relay_port=7777)
        cfg = p.generate_config()
        relay_ib = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"][0]
        self.assertEqual(relay_ib["type"], "shadowsocks")
        self.assertTrue(p.relay_url.startswith("ss://"))

    def test_vless_relay(self):
        p = SingBoxProxy(None, config_only=True, relay_protocol="vless", relay_host="2.3.4.5", relay_port=4443)
        cfg = p.generate_config()
        relay_ib = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"][0]
        self.assertEqual(relay_ib["type"], "vless")
        self.assertEqual(len(relay_ib["users"]), 1)
        self.assertIn("uuid", relay_ib["users"][0])
        self.assertTrue(p.relay_url.startswith("vless://"))
        self.assertIn("2.3.4.5:4443", p.relay_url)

    def test_socks_relay_has_auth(self):
        p = SingBoxProxy(None, config_only=True, relay_protocol="socks", relay_host="1.1.1.1", relay_port=5555)
        cfg = p.generate_config()
        relay_ib = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"][0]
        self.assertEqual(relay_ib["type"], "socks")
        self.assertEqual(len(relay_ib["users"]), 1)
        self.assertIn("username", relay_ib["users"][0])
        self.assertIn("password", relay_ib["users"][0])
        self.assertTrue(len(relay_ib["users"][0]["password"]) > 0)
        # URL must contain credentials
        self.assertIn("relay:", p.relay_url)

    def test_http_relay_has_auth(self):
        p = SingBoxProxy(None, config_only=True, relay_protocol="http", relay_host="1.1.1.1", relay_port=6666)
        cfg = p.generate_config()
        relay_ib = [ib for ib in cfg["inbounds"] if ib["tag"] == "relay-in"][0]
        self.assertEqual(relay_ib["type"], "http")
        self.assertEqual(len(relay_ib["users"]), 1)
        self.assertIn("username", relay_ib["users"][0])
        self.assertIn("password", relay_ib["users"][0])
        # URL must contain credentials
        self.assertIn("relay:", p.relay_url)

    def test_deterministic_uuid_seed(self):
        p1 = SingBoxProxy(None, config_only=True, relay_protocol="vmess", relay_host="h", relay_port=1111, uuid_seed="seed1")
        p2 = SingBoxProxy(None, config_only=True, relay_protocol="vmess", relay_host="h", relay_port=2222, uuid_seed="seed1")
        p1.generate_config()
        p2.generate_config()
        self.assertEqual(p1._relay_credentials["uuid"], p2._relay_credentials["uuid"])

    def test_different_seeds_differ(self):
        p1 = SingBoxProxy(None, config_only=True, relay_protocol="vmess", relay_host="h", relay_port=1111, uuid_seed="aaa")
        p2 = SingBoxProxy(None, config_only=True, relay_protocol="vmess", relay_host="h", relay_port=2222, uuid_seed="bbb")
        p1.generate_config()
        p2.generate_config()
        self.assertNotEqual(p1._relay_credentials["uuid"], p2._relay_credentials["uuid"])


# ---------------------------------------------------------------------------
# Port allocation
# ---------------------------------------------------------------------------
class TestPortAllocation(unittest.TestCase):
    def test_pick_unused_port(self):
        port = SingBoxProxy._pick_unused_port()
        self.assertIsInstance(port, int)
        self.assertTrue(1024 < port < 65536)

    def test_exclude_single(self):
        port1 = SingBoxProxy._pick_unused_port()
        port2 = SingBoxProxy._pick_unused_port(exclude_port=port1)
        self.assertNotEqual(port1, port2)

    def test_exclude_list(self):
        port = SingBoxProxy._pick_unused_port(exclude_port=[1, 2, 3])
        self.assertNotIn(port, [1, 2, 3])

    def test_is_port_in_use_free(self):
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 0))
        _, occupied_port = s.getsockname()
        self.assertTrue(SingBoxProxy._is_port_in_use(occupied_port))
        s.close()
        self.assertFalse(SingBoxProxy._is_port_in_use(occupied_port))


# ---------------------------------------------------------------------------
# Deterministic credential generation
# ---------------------------------------------------------------------------
class TestDeterministicCredentials(unittest.TestCase):
    def test_uuid_deterministic(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        u1 = p._generate_deterministic_uuid("test-seed")
        u2 = p._generate_deterministic_uuid("test-seed")
        self.assertEqual(u1, u2)

    def test_uuid_different_seeds(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        u1 = p._generate_deterministic_uuid("seed-a")
        u2 = p._generate_deterministic_uuid("seed-b")
        self.assertNotEqual(u1, u2)

    def test_uuid_suffix_changes_result(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        u1 = p._generate_deterministic_uuid("seed", "vmess")
        u2 = p._generate_deterministic_uuid("seed", "trojan")
        self.assertNotEqual(u1, u2)

    def test_password_deterministic(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        pw1 = p._generate_deterministic_password("test-seed")
        pw2 = p._generate_deterministic_password("test-seed")
        self.assertEqual(pw1, pw2)
        self.assertEqual(len(pw1), 16)

    def test_password_custom_length(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        pw = p._generate_deterministic_password("seed", length=32)
        self.assertEqual(len(pw), 32)


# ---------------------------------------------------------------------------
# QR code function
# ---------------------------------------------------------------------------
class TestPrintQr(unittest.TestCase):
    @patch("singbox2proxy.cli.qrcode", create=True)
    def test_qr_called_when_module_available(self, mock_qrcode):
        from singbox2proxy.cli import _print_qr

        mock_qr_instance = MagicMock()
        mock_qr_instance.get_matrix.return_value = [[True, False], [False, True]]
        mock_qrcode.QRCode.return_value = mock_qr_instance
        mock_qrcode.constants = MagicMock()
        with patch.dict("sys.modules", {"qrcode": mock_qrcode}):
            _print_qr("vmess://test")
        mock_qr_instance.add_data.assert_called_once_with("vmess://test")
        mock_qr_instance.make.assert_called_once_with(fit=True)
        mock_qr_instance.get_matrix.assert_called_once()

    def test_qr_fallback_without_module(self):
        from singbox2proxy.cli import _print_qr

        with patch.dict("sys.modules", {"qrcode": None}):
            with patch("builtins.print") as mock_print:
                _print_qr("test://url")
                # Should print the hint about installing qrcode
                args = [str(c) for c in mock_print.call_args_list]
                self.assertTrue(any("qrcode" in a for a in args))


# ---------------------------------------------------------------------------
# SingBoxClient.__del__ no longer kills proxy
# ---------------------------------------------------------------------------
class TestClientDelNoKillProxy(unittest.TestCase):
    def test_del_does_not_stop_proxy(self):
        """Verify SingBoxClient.__del__ does not call client.stop()."""
        from singbox2proxy.base import SingBoxClient

        mock_proxy = MagicMock()
        client = SingBoxClient(client=mock_proxy)
        client.__del__()
        mock_proxy.stop.assert_not_called()


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------
class TestContextManager(unittest.TestCase):
    def test_proxy_properties(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        self.assertIsNotNone(p.socks_port)
        self.assertIsNotNone(p.http_port)
        # URLs are available even when not running (port-based)
        self.assertIn("socks5://", p.socks5_proxy_url)
        self.assertIn("http://", p.http_proxy_url)

    def test_proxy_repr(self):
        p = _make_proxy("socks5://127.0.0.1:1080")
        self.assertIn("SingBoxProxy", repr(p))
        self.assertIn("stopped", str(p))


# ---------------------------------------------------------------------------
# Batch engine (unit tests â€” no network or sing-box required)
# ---------------------------------------------------------------------------
class TestBatchChecker(unittest.TestCase):
    def test_build_config_multi_outbound(self):
        from singbox2proxy.batch import _build_config
        from singbox2proxy.parsers import parse_link

        urls = [
            "trojan://pass@1.2.3.4:443?security=tls&sni=example.com",
            "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@5.6.7.8:8388",
        ]
        parsed = [(i, u, parse_link(u)) for i, u in enumerate(urls)]
        config = _build_config(parsed, 40000)

        # 2 socks inbounds + 2 proxy outbounds + 1 direct
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertEqual(len(config["outbounds"]), 3)  # 2 proxy + direct
        self.assertEqual(config["outbounds"][-1]["type"], "direct")

        # Ports sequential
        ports = [ib["listen_port"] for ib in config["inbounds"]]
        self.assertEqual(ports, [40000, 40001])

        # Route rules: each inbound â†’ its outbound
        self.assertEqual(len(config["route"]["rules"]), 2)
        self.assertEqual(config["route"]["rules"][0]["inbound"], ["socks-0"])
        self.assertEqual(config["route"]["rules"][0]["outbound"], "proxy-0")
        self.assertEqual(config["route"]["rules"][1]["inbound"], ["socks-1"])
        self.assertEqual(config["route"]["rules"][1]["outbound"], "proxy-1")

    def test_port_range_finder(self):
        from singbox2proxy.batch import _find_port_range

        port = _find_port_range(5)
        self.assertIsNotNone(port)
        self.assertTrue(10000 <= port <= 60000)

    def test_check_result_dataclass(self):
        from singbox2proxy.batch import ProxyCheckResult

        r = ProxyCheckResult(url="ss://test", working=True, ip="1.2.3.4", latency_ms=42.5, protocol="ss")
        self.assertTrue(r.working)
        self.assertEqual(r.ip, "1.2.3.4")
        self.assertEqual(r.protocol, "ss")

    def test_batch_proxy_properties(self):
        from singbox2proxy.batch import BatchProxy, SingBoxBatch

        mock_batch = MagicMock(spec=SingBoxBatch)
        mock_batch.running = True
        bp = BatchProxy(url="vless://test@1.2.3.4:443", protocol="vless", socks_port=40000, index=0, batch=mock_batch)
        self.assertEqual(bp.socks_url, "socks5://127.0.0.1:40000")
        self.assertEqual(bp.socks5h_url, "socks5h://127.0.0.1:40000")
        self.assertEqual(bp.proxies, {"http": "socks5h://127.0.0.1:40000", "https": "socks5h://127.0.0.1:40000"})
        self.assertTrue(bp.running)
        self.assertIn("BatchProxy", repr(bp))
        self.assertIn("vless", repr(bp))

    def test_batch_parse_errors_tracked(self):
        from singbox2proxy.batch import SingBoxBatch

        batch = SingBoxBatch(["not-valid!!!", "also-bad!!!"], start=False)
        self.assertEqual(len(batch), 0)
        self.assertEqual(len(batch._parse_errors), 2)

    def test_batch_repr(self):
        from singbox2proxy.batch import SingBoxBatch

        batch = SingBoxBatch([], start=False)
        self.assertIn("SingBoxBatch", repr(batch))
        self.assertIn("stopped", repr(batch))

    def test_build_config_with_upstream(self):
        from singbox2proxy.batch import _build_config
        from singbox2proxy.parsers import parse_link

        urls = ["trojan://pass@1.2.3.4:443?security=tls&sni=example.com"]
        parsed = [(0, urls[0], parse_link(urls[0]))]
        config = _build_config(parsed, 40000, upstream_port=9999)

        # Should have upstream socks outbound
        tags = [o["tag"] for o in config["outbounds"]]
        self.assertIn("upstream", tags)

        # Upstream outbound points to local port
        upstream_ob = [o for o in config["outbounds"] if o["tag"] == "upstream"][0]
        self.assertEqual(upstream_ob["type"], "socks")
        self.assertEqual(upstream_ob["server"], "127.0.0.1")
        self.assertEqual(upstream_ob["server_port"], 9999)

        # Proxy outbound has detour
        proxy_ob = [o for o in config["outbounds"] if o["tag"] == "proxy-0"][0]
        self.assertEqual(proxy_ob["detour"], "upstream")


if __name__ == "__main__":
    unittest.main()
