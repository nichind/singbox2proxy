"""Proxy URL parsers for sing-box outbound configuration.

Each function takes a proxy link string and returns a sing-box outbound dict.
Supported: VMess, VLESS, Shadowsocks, Trojan, Hysteria v1/v2, TUIC,
WireGuard, SSH, HTTP/HTTPS, SOCKS, NaiveProxy.
"""

import base64
import binascii
import json
import logging
import urllib.parse

logger = logging.getLogger("singbox2proxy")


def _safe_base64_decode(data: str) -> str:
    """Safely decode base64 data"""
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        decoded_bytes = base64.b64decode(data)
        return decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"Invalid base64 data: {str(e)}")


def parse_vmess_link(link: str) -> dict:
    """Parse a VMess link into a sing-box outbound configuration."""
    if not link.startswith("vmess://"):
        raise ValueError("Not a valid VMess link")

    try:
        link = urllib.parse.unquote(link)
        b64_content = link[8:]
        decoded_content = _safe_base64_decode(b64_content)
        vmess_info = json.loads(decoded_content)

        server = str(vmess_info.get("add", "")).strip()
        port_str = str(vmess_info.get("port", "443")).strip()
        port = int(port_str) if port_str.isdigit() else 443
        uuid = str(vmess_info.get("id", "")).strip()
        security = str(vmess_info.get("scy", "auto")).strip()
        alter_id_str = str(vmess_info.get("aid", "0")).strip()
        alter_id = int(alter_id_str) if alter_id_str.isdigit() else 0

        outbound = {
            "type": "vmess",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": security,
            "alter_id": alter_id,
        }

        network = str(vmess_info.get("net", "tcp")).strip()
        host_header = str(vmess_info.get("host", "")).strip()
        path = str(vmess_info.get("path", "/")).strip()

        if network == "ws":
            ws_transport = {"type": "ws", "path": path, "headers": {"Host": host_header} if host_header else {}}
            ed = str(vmess_info.get("ed", "")).strip()
            if ed and ed.isdigit():
                ws_transport["max_early_data"] = int(ed)
                ws_transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            outbound["transport"] = ws_transport
        elif network == "grpc":
            service_name = str(vmess_info.get("path", "")).strip()
            outbound["transport"] = {"type": "grpc", "service_name": service_name}
        elif network == "http":
            outbound["transport"] = {"type": "http", "host": [host_header] if host_header else [], "path": path}
        elif network == "httpupgrade":
            outbound["transport"] = {"type": "httpupgrade", "path": path, "host": host_header or ""}
        elif network == "quic":
            outbound["transport"] = {"type": "quic"}

        if str(vmess_info.get("tls")).strip() == "tls":
            sni = str(vmess_info.get("sni", "")).strip()
            tls_config = {"enabled": True, "server_name": sni or host_header or server}
            alpn = str(vmess_info.get("alpn", "")).strip()
            if alpn:
                tls_config["alpn"] = alpn.split(",")
            fp = str(vmess_info.get("fp", "")).strip()
            if fp:
                tls_config["utls"] = {"enabled": True, "fingerprint": fp}
            if str(vmess_info.get("skip-cert-verify", "")).strip() == "true":
                tls_config["insecure"] = True
            outbound["tls"] = tls_config

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse VMess link: {str(e)}")
        raise ValueError(f"Invalid VMess format: {str(e)}")


def parse_vless_link(link: str) -> dict:
    """Parse a VLESS link into a sing-box outbound configuration."""
    if not link.startswith("vless://"):
        raise ValueError("Not a valid VLESS link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        if "@" not in parsed_url.netloc:
            raise ValueError("Invalid VLESS format: missing @ separator")

        user_info = parsed_url.netloc.split("@")[0]

        host_port = parsed_url.netloc.split("@")[1]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            try:
                port = int(port)
            except ValueError:
                host = host_port
                port = 443
        else:
            host = host_port
            port = 443

        query_string = parsed_url.query.replace("&amp;", "&")
        params = dict(urllib.parse.parse_qsl(query_string))

        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": host.strip(),
            "server_port": port,
            "uuid": user_info.strip(),
            "flow": params.get("flow", ""),
        }

        transport_type = params.get("type", "tcp")
        host_param = params.get("host", "")
        path_param = params.get("path", "/")
        if transport_type == "ws":
            outbound["transport"] = {"type": "ws", "path": path_param, "headers": {}}
            if host_param:
                outbound["transport"]["headers"]["Host"] = host_param
        elif transport_type == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", params.get("path", ""))}
        elif transport_type == "http":
            outbound["transport"] = {"type": "http", "host": [host_param] if host_param else [], "path": path_param}
        elif transport_type == "httpupgrade":
            outbound["transport"] = {"type": "httpupgrade", "path": path_param, "host": host_param or ""}
        elif transport_type == "quic":
            outbound["transport"] = {"type": "quic"}

        security = params.get("security", "none")
        if security == "tls":
            tls_config = {"enabled": True, "server_name": params.get("sni", params.get("host", host))}
            if params.get("alpn"):
                tls_config["alpn"] = params["alpn"].split(",")
            if params.get("fp"):
                tls_config["utls"] = {"enabled": True, "fingerprint": params["fp"]}
            if params.get("allowInsecure") == "1":
                tls_config["insecure"] = True
            outbound["tls"] = tls_config
        elif security == "reality":
            tls_config = {
                "enabled": True,
                "server_name": params.get("sni", params.get("host", host)),
                "reality": {"enabled": True, "public_key": params.get("pbk", ""), "short_id": params.get("sid", "")},
                "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            }
            if params.get("alpn"):
                tls_config["alpn"] = params["alpn"].split(",")
            outbound["tls"] = tls_config

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse VLESS link: {str(e)}")
        raise ValueError(f"Invalid VLESS format: {str(e)}")


def parse_shadowsocks_link(link: str) -> dict:
    """Parse a Shadowsocks link into a sing-box outbound configuration."""
    if not link.startswith("ss://"):
        raise ValueError("Not a valid Shadowsocks link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        if "@" in parsed_url.netloc:
            user_info_part, host_port = parsed_url.netloc.split("@", 1)

            try:
                user_info = _safe_base64_decode(user_info_part)
                if ":" in user_info:
                    method, password = user_info.split(":", 1)
                else:
                    method = "aes-256-cfb"
                    password = user_info
            except (ValueError, UnicodeDecodeError):
                if ":" in user_info_part:
                    method, password = user_info_part.split(":", 1)
                else:
                    method = "aes-256-gcm"
                    password = user_info_part

            if ":" in host_port:
                host, port = host_port.rsplit(":", 1)
            else:
                host = host_port
                port = "443"
        else:
            try:
                decoded = _safe_base64_decode(parsed_url.netloc)
                if "@" in decoded:
                    method_pass, host_port = decoded.split("@", 1)
                    method, password = method_pass.split(":", 1)
                    if ":" in host_port:
                        host, port = host_port.rsplit(":", 1)
                    else:
                        host = host_port
                        port = "443"
                else:
                    raise ValueError("Invalid format")
            except Exception:
                raise ValueError("Unable to decode Shadowsocks link")

        outbound = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": host.strip(),
            "server_port": int(port),
            "method": method.strip(),
            "password": password.strip(),
        }

        # SIP003 plugin support
        params = dict(urllib.parse.parse_qsl(parsed_url.query))
        plugin = params.get("plugin", "")
        if plugin:
            outbound["plugin"] = plugin
            plugin_opts = params.get("plugin_opts", params.get("plugin-opts", ""))
            if plugin_opts:
                outbound["plugin_opts"] = plugin_opts

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse Shadowsocks link: {str(e)}")
        raise ValueError(f"Invalid Shadowsocks format: {str(e)}")


def parse_trojan_link(link: str) -> dict:
    """Parse a Trojan link into a sing-box outbound configuration."""
    if not link.startswith("trojan://"):
        raise ValueError("Not a valid Trojan link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        password = parsed_url.username or ""
        host = parsed_url.hostname
        port = parsed_url.port or 443
        params = dict(urllib.parse.parse_qsl(parsed_url.query))

        outbound = {"type": "trojan", "tag": "proxy", "server": host, "server_port": port, "password": password}

        transport_type = params.get("type", "tcp")
        host_header = params.get("host", "")
        path_param = params.get("path", "/")
        if transport_type == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": path_param,
                "headers": {"Host": host_header} if host_header else {},
            }
        elif transport_type == "grpc":
            outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", params.get("path", ""))}
        elif transport_type == "http":
            outbound["transport"] = {"type": "http", "host": [host_header] if host_header else [], "path": path_param}
        elif transport_type == "httpupgrade":
            outbound["transport"] = {"type": "httpupgrade", "path": path_param, "host": host_header or ""}
        elif transport_type == "quic":
            outbound["transport"] = {"type": "quic"}

        sni = params.get("sni", host_header or host)
        tls_config = {"enabled": True, "server_name": sni}
        if params.get("alpn"):
            tls_config["alpn"] = params["alpn"].split(",")
        if params.get("fp"):
            tls_config["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if params.get("allowInsecure") == "1":
            tls_config["insecure"] = True
        outbound["tls"] = tls_config

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse Trojan link: {str(e)}")
        raise ValueError(f"Invalid Trojan format: {str(e)}")


def parse_hysteria2_link(link: str) -> dict:
    """Parse a Hysteria2 link into a sing-box outbound configuration."""
    if not link.startswith("hy2://") and not link.startswith("hysteria2://"):
        raise ValueError("Not a valid Hysteria2 link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        password = parsed_url.username or ""
        host = parsed_url.hostname
        port = parsed_url.port or 443
        params = dict(urllib.parse.parse_qsl(parsed_url.query))

        outbound = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port, "password": password}

        sni = params.get("sni", host)
        insecure = params.get("insecure", "0") == "1"
        tls_config = {"enabled": True, "server_name": sni, "insecure": insecure}
        if params.get("alpn"):
            tls_config["alpn"] = params["alpn"].split(",")
        outbound["tls"] = tls_config

        obfs_password = params.get("obfs-password", params.get("obfs", ""))
        if obfs_password:
            outbound["obfs"] = {"type": "salamander", "password": obfs_password}

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse Hysteria2 link: {str(e)}")
        raise ValueError(f"Invalid Hysteria2 format: {str(e)}")


def parse_tuic_link(link: str) -> dict:
    """Parse a TUIC link into a sing-box outbound configuration."""
    if not link.startswith("tuic://"):
        raise ValueError("Not a valid TUIC link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        # urlparse splits user:pass at ':', so use username + password separately
        uuid = parsed_url.username or ""
        password = parsed_url.password or ""
        if not uuid or not password:
            raise ValueError("TUIC link must contain uuid:password")

        host = parsed_url.hostname
        port = parsed_url.port or 443
        params = dict(urllib.parse.parse_qsl(parsed_url.query))

        outbound = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid, "password": password}

        sni = params.get("sni", host)
        insecure = params.get("insecure", "0") == "1"
        tls_config = {"enabled": True, "server_name": sni, "insecure": insecure}
        if params.get("alpn"):
            tls_config["alpn"] = params["alpn"].split(",")
        outbound["tls"] = tls_config

        if params.get("congestion_control"):
            outbound["congestion_control"] = params.get("congestion_control")
        if params.get("udp_relay_mode"):
            outbound["udp_relay_mode"] = params.get("udp_relay_mode")

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse TUIC link: {str(e)}")
        raise ValueError(f"Invalid TUIC format: {str(e)}")


def parse_wireguard_link(link: str) -> dict:
    """Parse a WireGuard link into a sing-box WireGuard configuration.

    Returns a dict with all WireGuard fields in a normalized format.
    The caller (generate_config) decides whether to use endpoint or legacy
    outbound format based on the installed sing-box version.
    """
    if not link.startswith("wg://"):
        raise ValueError("Not a valid WireGuard link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)

        private_key = parsed_url.username or ""
        if not private_key:
            raise ValueError("WireGuard link must contain a private key")

        host = parsed_url.hostname
        port = parsed_url.port or 51820
        params = dict(urllib.parse.parse_qsl(parsed_url.query))

        peer_public_key = params.get("public_key", "")
        if not peer_public_key:
            raise ValueError("WireGuard link must contain a peer_public_key")

        local_addresses = params.get("local_address", "172.16.0.2/32").split(",")

        result = {
            "type": "wireguard",
            "tag": "proxy",
            "server": host,
            "server_port": port,
            "private_key": private_key,
            "peer_public_key": peer_public_key,
            "local_address": local_addresses,
        }

        if params.get("mtu"):
            result["mtu"] = int(params.get("mtu"))
        if params.get("reserved"):
            result["reserved"] = [int(b.strip()) for b in params.get("reserved").split(",")]
        if params.get("pre_shared_key"):
            result["pre_shared_key"] = params["pre_shared_key"]

        return result
    except Exception as e:
        logger.error(f"Failed to parse WireGuard link: {str(e)}")
        raise ValueError(f"Invalid WireGuard format: {str(e)}")


def parse_ssh_link(link: str) -> dict:
    """Parse an SSH link into a sing-box outbound configuration."""
    if not link.startswith("ssh://"):
        raise ValueError("Not a valid SSH link")

    try:
        link = urllib.parse.unquote(link)
        parsed_url = urllib.parse.urlparse(link)

        user = parsed_url.username or ""
        password = parsed_url.password or ""
        host = parsed_url.hostname
        port = parsed_url.port or 22

        if not host or not user:
            raise ValueError("SSH link must contain user and host")

        outbound = {"type": "ssh", "tag": "proxy", "server": host, "server_port": port, "user": user}
        if password:
            outbound["password"] = password

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse SSH link: {str(e)}")
        raise ValueError(f"Invalid SSH format: {str(e)}")


def parse_http_link(link: str) -> dict:
    """Parse an HTTP proxy link into a sing-box outbound configuration."""
    if not link.startswith("http://") and not link.startswith("https://"):
        raise ValueError("Not a valid HTTP proxy link")

    try:
        link = urllib.parse.unquote(link)
        parsed_url = urllib.parse.urlparse(link)

        username = parsed_url.username or ""
        password = parsed_url.password or ""
        default_port = 443 if parsed_url.scheme == "https" else 80
        port = parsed_url.port or default_port

        outbound = {
            "type": "http",
            "tag": "proxy",
            "server": parsed_url.hostname,
            "server_port": port,
        }

        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password

        if parsed_url.scheme == "https":
            outbound["tls"] = {"enabled": True, "server_name": parsed_url.hostname}

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse HTTP link: {str(e)}")
        raise ValueError(f"Invalid HTTP format: {str(e)}")


def parse_socks_link(link: str) -> dict:
    """Parse a SOCKS link into a sing-box outbound configuration."""
    if not link.startswith("socks://") and not link.startswith("socks5://") and not link.startswith("socks4://"):
        raise ValueError("Not a valid SOCKS link")

    try:
        link = urllib.parse.unquote(link)
        parsed_url = urllib.parse.urlparse(link)

        username = parsed_url.username or ""
        password = parsed_url.password or ""
        version = "5"
        if parsed_url.scheme == "socks4":
            version = "4"

        outbound = {
            "type": "socks",
            "tag": "proxy",
            "server": parsed_url.hostname,
            "server_port": parsed_url.port or 1080,
            "version": version,
        }

        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse SOCKS link: {str(e)}")
        raise ValueError(f"Invalid SOCKS format: {str(e)}")


def parse_hysteria_link(link: str) -> dict:
    """Parse a Hysteria (v1) link into a sing-box outbound configuration."""
    if not link.startswith("hysteria://"):
        raise ValueError("Not a valid Hysteria link")

    try:
        link = urllib.parse.unquote(link.replace("&amp;", "&"))
        parsed_url = urllib.parse.urlparse(link)
        params = dict(urllib.parse.parse_qsl(parsed_url.query))

        outbound = {
            "type": "hysteria",
            "tag": "proxy",
            "server": parsed_url.hostname,
            "server_port": parsed_url.port,
            "auth_str": params.get("auth", ""),
        }

        sni = params.get("sni", params.get("peer", parsed_url.hostname))
        insecure = params.get("insecure", "0") == "1"
        tls_config = {"enabled": True, "server_name": sni, "insecure": insecure}
        if params.get("alpn"):
            tls_config["alpn"] = params["alpn"].split(",")
        outbound["tls"] = tls_config

        if params.get("upmbps"):
            outbound["up_mbps"] = int(params.get("upmbps"))
        if params.get("downmbps"):
            outbound["down_mbps"] = int(params.get("downmbps"))
        if params.get("obfsParam", params.get("obfs")):
            outbound["obfs"] = params.get("obfsParam", params.get("obfs"))

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse Hysteria link: {str(e)}")
        raise ValueError(f"Invalid Hysteria format: {str(e)}")


def parse_naiveproxy_link(link: str) -> dict:
    """Parse a NaiveProxy link into a sing-box outbound configuration.

    Since sing-box 1.13.0, 'naive' is a proper outbound type that uses
    Chromium's network stack for traffic-analysis resistance.
    Requires libcronet on Linux/Windows or a special build.
    """
    if not link.startswith("naive+https://"):
        raise ValueError("Not a valid NaiveProxy link")

    try:
        https_url = urllib.parse.unquote(link[6:])  # Remove "naive+"
        parsed_url = urllib.parse.urlparse(https_url)

        username = parsed_url.username or ""
        password = parsed_url.password or ""

        outbound = {
            "type": "naive",
            "tag": "proxy",
            "server": parsed_url.hostname,
            "server_port": parsed_url.port or 443,
        }
        if username:
            outbound["username"] = username
        if password:
            outbound["password"] = password

        outbound["tls"] = {"enabled": True, "server_name": parsed_url.hostname}

        return outbound
    except Exception as e:
        logger.error(f"Failed to parse NaiveProxy link: {str(e)}")
        raise ValueError(f"Invalid NaiveProxy format: {str(e)}")


def parse_link(url: str) -> dict:
    """Parse any supported proxy link into a sing-box outbound configuration.

    Args:
        url: Proxy URL string (vmess://, vless://, ss://, etc.)

    Returns:
        dict: sing-box outbound configuration

    Raises:
        ValueError: If the URL scheme is unsupported or the link is malformed.
    """
    if url.startswith("vmess://"):
        return parse_vmess_link(url)
    elif url.startswith("vless://"):
        return parse_vless_link(url)
    elif url.startswith("ss://"):
        return parse_shadowsocks_link(url)
    elif url.startswith("trojan://"):
        return parse_trojan_link(url)
    elif url.startswith(("hy2://", "hysteria2://")):
        return parse_hysteria2_link(url)
    elif url.startswith("hysteria://"):
        return parse_hysteria_link(url)
    elif url.startswith("tuic://"):
        return parse_tuic_link(url)
    elif url.startswith("wg://"):
        return parse_wireguard_link(url)
    elif url.startswith("ssh://"):
        return parse_ssh_link(url)
    elif url.startswith(("socks://", "socks4://", "socks5://")):
        return parse_socks_link(url)
    elif url.startswith("naive+https://"):
        return parse_naiveproxy_link(url)
    elif url.startswith(("http://", "https://")):
        return parse_http_link(url)
    else:
        raise ValueError(f"Unsupported link type: {url[:15]}...")
