import argparse
import sys
import time
import signal
import json
from .base import SingBoxProxy, enable_logging, disable_logging
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
        """,
    )

    parser.add_argument("urls", nargs="+", help="Proxy URLs (multiple URLs will be chained if --chain is used)")

    parser.add_argument("--chain", action="store_true", help="Chain multiple proxies (first proxy -> second proxy -> ... -> target)")

    parser.add_argument("--http-port", type=int, help="HTTP proxy port (default: auto-assign)")

    parser.add_argument("--socks-port", type=int, help="SOCKS proxy port (default: auto-assign)")

    parser.add_argument("--config-only", action="store_true", help="Generate configuration without starting the proxy")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    parser.add_argument("--quiet", "-q", action="store_true", help="Disable all logging")

    parser.add_argument("--test", action="store_true", help="Test the proxy by making a request to ipify.org")

    parser.add_argument("--output-config", help="Save generated configuration to file")

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

    try:
        proxies = []

        if args.chain and len(args.urls) > 1:
            # Create chained proxies
            print(f"Creating proxy chain with {len(args.urls)} proxies...")

            # Create first proxy
            first_proxy = SingBoxProxy(args.urls[0], http_port=False, socks_port=None, config_only=args.config_only)
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
                )
                proxies.append(proxy)
                chain_proxy = proxy

            main_proxy = chain_proxy

        else:
            # Create single proxy
            if len(args.urls) > 1:
                print("Warning: Multiple URLs provided but --chain not specified. Using only the first URL.")

            main_proxy = SingBoxProxy(args.urls[0], http_port=args.http_port, socks_port=args.socks_port, config_only=args.config_only)
            proxies.append(main_proxy)

        if args.config_only:
            config = main_proxy.generate_config()
            print(json.dumps(config, indent=2))

            if args.output_config:
                with open(args.output_config, "w") as f:
                    json.dump(config, f, indent=2)
                print(f"Configuration saved to {args.output_config}")
            return

        if args.output_config:
            config = main_proxy.config
            with open(args.output_config, "w") as f:
                json.dump(config, f, indent=2)
            print(f"Configuration saved to {args.output_config}")

        # Print proxy information
        print("Proxy started successfully")
        if main_proxy.http_port:
            print(f"  HTTP Proxy:  {main_proxy.http_proxy_url}")
        if main_proxy.socks_port:
            print(f"  SOCKS Proxy: {main_proxy.socks5_proxy_url}")

        # Test the proxy if requested
        if args.test:
            print("\nTesting proxy connection...")
            try:
                response = main_proxy.request("GET", "https://api.ipify.org?format=json")
                if response.status_code == 200:
                    ip_data = response.json()
                    print(f"Proxy test successful! External IP: {ip_data['ip']}")
                else:
                    print("Proxy test failed with status code: {response.status_code}")
            except Exception as e:
                print(f"Proxy test failed: {str(e)}")

        print("\nProxy is running. Press Ctrl+C to stop.")

        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

    finally:
        # Clean up all proxies
        for proxy in proxies:
            try:
                proxy.stop()
            except Exception:
                pass
        print("Proxy stopped.")


if __name__ == "__main__":
    main()
