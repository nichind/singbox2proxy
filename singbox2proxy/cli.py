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
  singbox2proxy "vless://..." --relay vmess
  singbox2proxy "ss://..." --relay ss --relay-port 8443
  singbox2proxy --relay ss  # Direct connection relay
  sudo singbox2proxy "vless://..." --tun
  sudo singbox2proxy "vmess://..." --tun --tun-stack gvisor --tun-address 10.0.0.1/24
        """,
    )

    parser.add_argument(
        "urls",
        nargs="*",
        help="Proxy URLs (multiple URLs will be chained if --chain is used). Optional when using --relay for direct connection.",
    )

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

    parser.add_argument(
        "--relay",
        choices=["vmess", "trojan", "ss", "shadowsocks", "socks", "http"],
        help="Create a shareable proxy URL that relays traffic (e.g., --relay vmess). Can be used without a proxy URL for direct connection.",
    )

    parser.add_argument("--relay-host", help="Host/IP to use in the relay URL (default: auto-detect)")

    parser.add_argument("--relay-port", type=int, help="Port to use for the relay server (default: auto-assign)")

    parser.add_argument(
        "--relay-name",
        default="nichind.dev|singbox2proxy-relay",
        help="Name to use in the relay URL (default: nichind.dev|singbox2proxy-relay)",
    )

    parser.add_argument("--uuid-seed", help="Seed for deterministic UUID/password generation (makes relay URLs persistent across restarts)")

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

    # Validate arguments
    if not args.urls and not args.relay:
        parser.error("Either provide proxy URLs or use --relay for direct connection")

    if args.chain and args.relay:
        parser.error("Cannot use --chain with --relay")

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

            # Use first URL or None for direct connection
            config_url = args.urls[0] if args.urls else None

            main_proxy = SingBoxProxy(
                config_url,
                http_port=args.http_port,
                socks_port=args.socks_port,
                config_only=args.config_only,
                tun_enabled=args.tun,
                tun_address=args.tun_address,
                tun_stack=args.tun_stack,
                tun_mtu=args.tun_mtu,
                tun_auto_route=args.tun_auto_route,
                set_system_proxy=args.set_system_proxy,
                relay_protocol=args.relay,
                relay_host=args.relay_host,
                relay_port=args.relay_port,
                relay_name=args.relay_name,
                uuid_seed=args.uuid_seed,
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
        if args.relay and main_proxy.relay_url:
            print(f"\n  Relay URL: {main_proxy.relay_url}")
            print(f"  Protocol:  {args.relay}")
            if args.urls:
                print("  Share this URL to relay traffic through your proxy")
            else:
                print("  Share this URL for direct internet access from your server")

        # Test the proxy if requested
        if args.test:
            print("\nTesting proxy connection...")

            # Ping test
            print("\n1. Ping Test:")
            try:
                import time as time_module

                ping_times = []
                for i in range(3):
                    start = time_module.time()
                    response = main_proxy.request("GET", "https://www.google.com/generate_204", timeout=5)
                    elapsed = (time_module.time() - start) * 1000  # Convert to ms
                    if response.status_code in (200, 204):
                        ping_times.append(elapsed)
                        print(f"  Attempt {i + 1}: {elapsed:.2f} ms")
                    else:
                        print(f"  Attempt {i + 1}: Failed (status {response.status_code})")

                if ping_times:
                    avg_ping = sum(ping_times) / len(ping_times)
                    min_ping = min(ping_times)
                    max_ping = max(ping_times)
                    print(f"  Average: {avg_ping:.2f} ms (min: {min_ping:.2f} ms, max: {max_ping:.2f} ms)")
            except Exception as e:
                print(f"  Ping test failed: {str(e)}")

            # IP test
            print("\n2. IP Detection Test:")
            try:
                response = main_proxy.request("GET", "https://api.ipify.org?format=json")
                if response.status_code == 200:
                    ip_data = response.json()
                    print(f"  External IP: {ip_data['ip']}")
                    print("\n✓ All tests passed!")
                else:
                    print(f"  Failed with status code: {response.status_code}")
            except Exception as e:
                print(f"  IP test failed: {str(e)}")
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
