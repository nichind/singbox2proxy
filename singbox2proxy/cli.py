import argparse
import sys
import time
import signal
import json
import os
from .base import SingBoxProxy, default_core, enable_logging, disable_logging
import logging


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\nShutting down...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        prog="singbox2proxy",
        description="Start sing-box proxies from the command line",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  singbox2proxy "vless://..."
  singbox2proxy "vmess://..." "vless://..." --chain
  singbox2proxy "ss://..." --http-port 8080 --socks-port 1080
  singbox2proxy "trojan://..." --socks-port False
  singbox2proxy "hy2://..." --verbose --test
  singbox2proxy "vless://..." --set-system-proxy
  sudo singbox2proxy "vless://..." --tun
  sudo singbox2proxy "vmess://..." --tun --tun-stack gvisor --tun-address 10.0.0.1/24
        """,
    )

    parser.add_argument("urls", nargs="+", help="Proxy URLs (multiple URLs will be chained if --chain is used)")

    parser.add_argument("--chain", action="store_true", help="Chain multiple proxies (first proxy -> second proxy -> ... -> target)")

    parser.add_argument("--http-port", type=int, help="HTTP proxy port (default: auto-assign)")

    parser.add_argument("--socks-port", type=int, help="SOCKS proxy port (default: auto-assign)")

    parser.add_argument("--config-only", action="store_true", help="Generate configuration without starting the proxy")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument("--quiet", "-q", action="store_true", help="Disable all logging")

    parser.add_argument("--test", "-T", action="store_true", help="Test the proxy by making a request to ipify.org")

    parser.add_argument("--output-config", "-o", help="Save generated configuration to file")

    parser.add_argument("--cmd", "-C", help="Run a command with sing-box core executable")

    parser.add_argument("--tun", action="store_true", help="Enable TUN interface (system-wide VPN mode, requires root/admin privileges)")

    parser.add_argument("--tun-address", default="172.19.0.1/30", help="TUN interface address (default: 172.19.0.1/30)")

    parser.add_argument(
        "--tun-stack", default="system", choices=["system", "gvisor", "mixed"], help="TUN stack implementation (default: system)"
    )

    parser.add_argument("--tun-mtu", type=int, default=9000, help="TUN interface MTU (default: 9000)")

    parser.add_argument(
        "--tun-auto-route", action="store_true", default=True, help="Automatically configure routing rules (default: enabled)"
    )

    parser.add_argument("--no-tun-auto-route", dest="tun_auto_route", action="store_false", help="Disable automatic routing rules")

    parser.add_argument(
        "--set-system-proxy", action="store_true", help="Set system proxy settings to use this proxy (applied on start, reverted on stop)"
    )

    args = parser.parse_args()

    # Configure logging
    if args.quiet:
        disable_logging()
    elif args.verbose:
        enable_logging(logging.DEBUG)
    else:
        enable_logging(logging.INFO)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.cmd:
        print(f"sing-box core at {default_core.executable} is running command: {args.cmd}")
        print(default_core.run_command_output(args.cmd))

    # Check for root/admin privileges if TUN mode is enabled
    if args.tun:
        if os.name == "nt":  # Windows
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: TUN mode requires administrator privileges.", file=sys.stderr)
                print("Please run this command as administrator.", file=sys.stderr)
                sys.exit(1)
        else:  # Unix-like systems
            if os.geteuid() != 0:
                print("Error: TUN mode requires root privileges.", file=sys.stderr)
                print("Please run this command with sudo or as root.", file=sys.stderr)
                sys.exit(1)

    try:
        proxies = []

        if args.chain and len(args.urls) > 1:
            # Create chained proxies
            print(f"Creating proxy chain with {len(args.urls)} proxies...")

            # Create first proxy
            first_proxy = SingBoxProxy(
                args.urls[0],
                http_port=False,
                socks_port=None,
                config_only=args.config_only,
                tun_enabled=False,
            )
            proxies.append(first_proxy)

            # Create chained proxies
            chain_proxy = first_proxy
            for i, url in enumerate(args.urls[1:], 1):
                is_last = i == len(args.urls) - 1
                proxy = SingBoxProxy(
                    url,
                    http_port=args.http_port if is_last else False,
                    socks_port=args.socks_port if is_last else None,
                    chain_proxy=chain_proxy,
                    config_only=args.config_only,
                    tun_enabled=args.tun if is_last else False,
                    tun_address=args.tun_address,
                    tun_stack=args.tun_stack,
                    tun_mtu=args.tun_mtu,
                    tun_auto_route=args.tun_auto_route,
                    set_system_proxy=args.set_system_proxy if is_last else False,
                )
                proxies.append(proxy)
                chain_proxy = proxy

            main_proxy = chain_proxy

        else:
            # Create single proxy
            if len(args.urls) > 1:
                print("Warning: Multiple URLs provided but --chain not specified. Using only the first URL.")

            main_proxy = SingBoxProxy(
                args.urls[0],
                http_port=args.http_port,
                socks_port=args.socks_port,
                config_only=args.config_only,
                tun_enabled=args.tun,
                tun_address=args.tun_address,
                tun_stack=args.tun_stack,
                tun_mtu=args.tun_mtu,
                tun_auto_route=args.tun_auto_route,
                set_system_proxy=args.set_system_proxy,
            )
            proxies.append(main_proxy)

        def _save_config(config, path):
            with open(path, "w") as f:
                json.dump(config, f, indent=2)
            print(f"Configuration saved to {path}")

        if args.config_only:
            config = main_proxy.generate_config()
            print(json.dumps(config, indent=2))

            if args.output_config:
                _save_config(config, args.output_config)
            return

        if args.output_config:
            _save_config(main_proxy.config, args.output_config)

        # Print proxy information
        print("Proxy started successfully")
        if args.tun:
            print("  TUN Interface: Enabled")
            print(f"  TUN Address:   {args.tun_address}")
            print(f"  TUN Stack:     {args.tun_stack}")
        if main_proxy.http_port:
            print(f"  HTTP Proxy:  {main_proxy.http_proxy_url}")
        if main_proxy.socks_port:
            print(f"  SOCKS Proxy: {main_proxy.socks5_proxy_url}")
        if args.set_system_proxy:
            print("  System Proxy: Configured (will be restored on stop)")

        # Test the proxy if requested
        if args.test:
            print("\nTesting proxy connection...")
            try:
                response = main_proxy.request("GET", "https://api.ipify.org?format=json")
                if response.status_code == 200:
                    ip_data = response.json()
                    print(f"Proxy test successful! External IP: {ip_data['ip']}")
                else:
                    print(f"Proxy test failed with status code: {response.status_code}")
            except Exception as e:
                print(f"Proxy test failed: {str(e)}")
            sys.exit(0)

        print("\nProxy is running. Press Ctrl+C to stop.")

        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)

    finally:
        # Clean up all proxies
        for proxy in proxies:
            try:
                proxy.stop()
            except Exception:
                pass

    sys.exit(1)


if __name__ == "__main__":
    main()
