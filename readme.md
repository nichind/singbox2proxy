## singbox2proxy

Integrate sing-box proxies into your python applications with ease.

singbox2proxy is basically a fork of [v2ray2proxy](https://github.com/nichind/v2ray2proxy) with enhanced perfomance and protocol support using [sing-box](https://github.com/SagerNet/sing-box) instead of xray-core.

 [![Pip module installs total downloads](https://img.shields.io/pypi/dm/singbox2proxy.svg)](https://pypi.org/project/singbox2proxy/)[![Run Tests](https://github.com/nichind/singbox2proxy/actions/workflows/build.yml/badge.svg)](https://github.com/nichind/singbox2proxy/actions/workflows/build.yml) [![Upload Python Package to PyPI when a Release is Created](https://github.com/nichind/singbox2proxy/actions/workflows/publish.yml/badge.svg)](https://github.com/nichind/singbox2proxy/actions/workflows/publish.yml)

#### Supported Protocols

This module supports these sing-box protocols:

- VMess (`vmess://`)
- VLESS (`vless://`)
- Shadowsocks (`ss://`)
- Trojan (`trojan://`)
- Hysteria2* (`hy2://`, `hysteria2://`)
- Hysteria* (`hysteria://`)
- TUIC* (`tuic://`)
- WireGuard (`wg://`)
- SSH (`ssh://`)
- HTTP/HTTPS (`http://`, `https://`)
- SOCKS (`socks://`, `socks4://`, `socks5://`)
- NaiveProxy* (`naive+https://`)

*: Chaining as a middle proxy not supported, according to the [sing-box docs](https://sing-box.sagernet.org/configuration/inbound/)

### Installation

with pip

```shell
pip install singbox2proxy 
```

with [uv](https://pypi.org/project/uv/)

```shell
uv install singbox2proxy 
```

build from source

```shell
git clone https://github.com/nichind/singbox2proxy.git
cd singbox2proxy
pip install -e .
```

### Python Usage

Using built-in [curl-cffi](https://pypi.org/project/curl-cffi/) or [requests](https://pypi.org/project/requests/) client

```python
from singbox2proxy import SingBoxProxy

proxy = SingBoxProxy("vless://...")
response = proxy.request("GET", "https://api.ipify.org?format=json")  # IF curl-cffi is installed, it will be used; otherwise, requests will be used.
print(response.status_code, response.text)  # 200, {"ip":"..."}
```

Integrating with your own HTTP client

```python
import requests
from singbox2proxy import SingBoxProxy

proxy = SingBoxProxy("hy2://...")
session = requests.Session()
session.proxies = proxy.proxy_for_requests  # {"http": "http://127.0.0.1:<port>", "https": "http://127.0.0.1:<port>"}
response = session.get("https://api.ipify.org?format=json")
print(response.status_code, response.text)  # 200, {"ip":"..."}
```

Example with aiohttp

```python
from singbox2proxy import SingBoxProxy
import aiohttp

async def main():
    proxy = SingBoxProxy("vmess://...")
    async with aiohttp.ClientSession(proxy=proxy.socks5_proxy_url or proxy.http_proxy_url) as session:
        async with session.get("https://api.ipify.org?format=json") as response:
            print(response.status, await response.text())  # 200, {"ip":"..."}
```

#### Chaining

Chained proxies allow you to route your traffic through multiple proxy servers if you'll ever need more privacy or easy restriction bypass. You can chain multiple proxies together by specifying a `chain_proxy` with a gate `SingBoxProxy` instance when creating a new `SingBoxProxy`.

> [!NOTE]
> See what protocols can be used as middleman proxies at [supported protocols](#supported-protocols)

```python
from singbox2proxy import SingBoxProxy

proxy1 = SingBoxProxy("vmess://...")
proxy2 = SingBoxProxy("vless://...", chain_proxy=proxy1)

response = proxy2.request("GET", "https://api.ipify.org?format=json")
print(response.status_code, response.text)  # 200, {"ip": "<proxy2's IP>"}
# Here, requests made through `proxy2` will first go through `proxy1`, then proxy1 will forward the request to proxy2, and finally proxy2 will send the request to the target server.
```

### CLI

> [!NOTE]
> If the `singbox2proxy` or `sb2p` command isn't working in your terminal, use `python -m singbox2proxy <command>`, `uv run -m singbox2proxy <command>`, etc. instead.

#### Basic Commands

Start a single proxy:

```shell
sb2p "vmess://eyJ2IjoiMiIsInBzIj..."
```

Specify custom ports:

```shell
sb2p "ss://..." --http-port 8080 --socks-port False  # Socks disabled
```

Test the proxy connection:

```shell
sb2p "trojan://..." --test
```

#### Proxy Chaining

Chain multiple proxies (traffic flows: you -> proxy1 -> proxy2 -> target):

```shell
sb2p "vmess://..." "vless://..." "hy2://..." --chain
```

> [!NOTE]
> See what protocols can be used as middleman proxies at [supported protocols](#supported-protocols)

The first URL becomes the entry point, and the last URL connects to the target server.

#### Configuration Management

Generate configuration without starting:

```shell
sb2p "vless://..." --config-only
```

Save configuration to file:

```shell
sb2p "vmess://..." --output-config config.json
```

#### Logging Options

Enable verbose logging:

```shell
sb2p "ss://..." --verbose
```

Disable all logging:

```shell
sb2p "hy2://..." --quiet
```

### Discaimer

I'm not responsible for possible misuse of this software. Please use it in accordance with the law and respect the terms of service of the services you access through proxies.

#### Consider leaving a star ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=nichind/singbox2proxy&type=Date)](https://github.com/nichind/singbox2proxy)