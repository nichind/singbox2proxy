import argparse
import sys
import time
import signal
import json
import os
from .base import SingBoxProxy, _get_default_core, _cleanup_all_processes, enable_logging, disable_logging  # noqa: F401
import logging

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

_quiet = False
_verbose = False


def _out(msg: str = ""):
    """Print unless --quiet."""
    if not _quiet:
        print(msg)


def _dbg(msg: str):
    """Print only with --verbose."""
    if _verbose:
        print(f"  [debug] {msg}")


def signal_handler(signum, frame):
    print("\nStopping...", file=sys.stderr)
    _cleanup_all_processes()
    sys.exit(0)


def _short_url(url: str, max_len: int = 60) -> str:
    if not url or len(url) <= max_len:
        return url or ""
    return url[: max_len - 3] + "..."


# QR settings (set from CLI args)
_qr_style = "half"  # half | ascii | none
_qr_invert = False  # swap black/white
_qr_border = 1  # quiet zone size


def _print_qr(text: str):
    """Render QR code based on current _qr_* settings."""
    if _qr_style == "none":
        return
    try:
        import qrcode

        qr = qrcode.QRCode(box_size=1, border=_qr_border, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(text)
        qr.make(fit=True)

        if _qr_style == "ascii":
            qr.print_ascii(invert=not _qr_invert)
            return

        matrix = qr.get_matrix()
        rows = len(matrix)
        cols = len(matrix[0]) if rows else 0
        for y in range(0, rows, 2):
            line = "  "
            for x in range(cols):
                top = matrix[y][x]
                bot = matrix[y + 1][x] if y + 1 < rows else False
                if _qr_invert:
                    top, bot = not top, not bot
                if top and bot:
                    line += "\u2588"
                elif top:
                    line += "\u2580"
                elif bot:
                    line += "\u2584"
                else:
                    line += " "
            print(line)
    except ImportError:
        print("  (pip install qrcode for QR display)")


def _run_test(proxy) -> bool:
    """Quick connectivity test. Returns True if passed."""
    _out("test:")
    passed = True

    # Latency
    try:
        pings = []
        for i in range(3):
            t0 = time.time()
            r = proxy.request("GET", "https://www.google.com/generate_204", timeout=5)
            ms = (time.time() - t0) * 1000
            if r.status_code in (200, 204):
                pings.append(ms)
            else:
                passed = False
        if pings:
            _out(f"  latency  {min(pings):.0f}/{sum(pings) / len(pings):.0f}/{max(pings):.0f} ms (min/avg/max)")
        else:
            _out("  latency  FAIL")
            passed = False
    except Exception as e:
        _out(f"  latency  FAIL ({e})")
        passed = False

    # Exit IP
    try:
        r = proxy.request("GET", "https://api.ipify.org?format=json", timeout=10)
        if r.status_code == 200:
            _out(f"  exit-ip  {r.json().get('ip', '?')}")
        else:
            _out(f"  exit-ip  FAIL (HTTP {r.status_code})")
            passed = False
    except Exception as e:
        _out(f"  exit-ip  FAIL ({e})")
        passed = False

    _out(f"  result   {'PASS' if passed else 'FAIL'}")
    return passed


def _print_status(proxy, args, proxies):
    """Compact proxy status."""
    parts = []

    # Version
    if proxy.core and proxy.core.version:
        parts.append(f"sing-box {proxy.core.version}")

    # Mode
    if args.chain and len(args.urls) > 1:
        parts.append(f"chain({len(args.urls)} hops)")
    if args.tun:
        parts.append("tun")
    if args.relay:
        parts.append(f"relay/{args.relay}")
    if args.set_system_proxy:
        parts.append("system-proxy")

    _out(" | ".join(parts) if parts else "ready")

    # Endpoints — always show
    if proxy.http_port:
        _out(f"  http   {proxy.http_proxy_url}")
    if proxy.socks_port:
        _out(f"  socks  {proxy.socks5_proxy_url}")

    # Chain hops (verbose only)
    if args.chain and len(args.urls) > 1:
        _dbg("chain:")
        for i, url in enumerate(args.urls):
            hop = proxies[i] if i < len(proxies) else None
            port = f" (:{hop.socks_port})" if hop and hop.socks_port else ""
            marker = ">" if i == len(args.urls) - 1 else " "
            _dbg(f"  {marker} hop {i + 1}: {_short_url(url)}{port}")

    # TUN
    if args.tun:
        _out(f"  tun    {args.tun_address} stack={args.tun_stack} mtu={args.tun_mtu}")

    # Relay
    if args.relay and proxy.relay_url:
        _out(f"  relay  {proxy.relay_url}")
        _print_qr(proxy.relay_url)


def _run_batch_check(args):
    """Run batch proxy check from a file."""
    from .batch import SingBoxBatch

    path = args.check
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    upstream = args.urls[0] if args.urls else None

    batch = SingBoxBatch.from_file(path, batch_size=args.batch_size, chain_proxy=upstream)
    total = len(batch)
    if total == 0:
        print("No proxies loaded.")
        return

    info = f"check {total} proxies"
    if upstream:
        info += f" via {_short_url(upstream, 50)}"
    _out(info)

    working = []
    dead = 0
    checked = 0
    t0 = time.time()
    w = len(str(total))

    def on_result(r):
        nonlocal checked, dead
        checked += 1
        if r.working:
            working.append(r)
            _out(f"  [{checked:>{w}}/{total}] {r.protocol:<8s} OK  {r.ip:<15s} {r.latency_ms:>6.0f}ms")
        else:
            dead += 1
            _dbg(f"  [{checked:>{w}}/{total}] {r.protocol:<8s} DEAD {(r.error or '')[:50]}")

    try:
        batch.check(timeout=args.timeout, workers=args.workers, on_result=on_result)
    finally:
        batch.stop()

    elapsed = time.time() - t0
    rate = f"{len(working) / total * 100:.0f}%" if total else "0%"
    print(f"{len(working)}/{total} working ({rate}) in {elapsed:.1f}s")

    if args.output_config and working:
        with open(args.output_config, "w", encoding="utf-8") as f:
            for r in sorted(working, key=lambda r: r.latency_ms or 9999):
                f.write(r.url + "\n")
        print(f"saved {len(working)} to {args.output_config}")


def main():
    parser = argparse.ArgumentParser(
        prog="singbox2proxy",
        description="Start sing-box proxies from the command line",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s "vless://..."                             single proxy
  %(prog)s "vmess://..." "vless://..." --chain        proxy chain
  %(prog)s "ss://..." --test                          start + test
  %(prog)s "hy2://..." --relay vmess                  relay mode
  %(prog)s --relay ss                                 direct relay
  %(prog)s "trojan://..." --config-only -o out.json   export config
  %(prog)s --cmd version                              sing-box command
  sudo %(prog)s "vless://..." --tun                   TUN/VPN mode
  %(prog)s --check proxies.txt                        batch check
  %(prog)s --check proxies.txt -o working.txt         save working
  %(prog)s --check proxies.txt --workers 20           parallel check
  %(prog)s "trojan://..." --check proxies.txt         check via upstream
  %(prog)s --check proxies.txt -q                     quiet (summary only)
        """,
    )

    parser.add_argument("urls", nargs="*", help="Proxy URL(s). Use --chain with multiple URLs.")

    mode_group = parser.add_argument_group("mode")
    mode_group.add_argument("--chain", action="store_true", help="Chain proxies (hop1 -> hop2 -> ... -> internet)")
    mode_group.add_argument(
        "--relay",
        choices=["vmess", "vless", "trojan", "ss", "shadowsocks", "socks", "http"],
        help="Create a shareable relay URL",
    )
    mode_group.add_argument("--config-only", action="store_true", help="Print config JSON, don't start proxy")
    mode_group.add_argument("--cmd", "-C", help="Run a sing-box subcommand and exit")
    mode_group.add_argument("--check", metavar="FILE", help="Batch-check proxies from file, print results")

    port_group = parser.add_argument_group("ports")
    port_group.add_argument("--http-port", type=int, help="HTTP proxy port (default: auto)")
    port_group.add_argument("--socks-port", type=int, help="SOCKS5 proxy port (default: auto)")

    tun_group = parser.add_argument_group("TUN (requires root/admin)")
    tun_group.add_argument("--tun", action="store_true", help="Enable TUN interface (system-wide VPN)")
    tun_group.add_argument("--tun-address", default="172.19.0.1/30", help="TUN address (default: 172.19.0.1/30)")
    tun_group.add_argument("--tun-stack", default="system", choices=["system", "gvisor", "mixed"], help="TUN stack (default: system)")
    tun_group.add_argument("--tun-mtu", type=int, default=9000, help="TUN MTU (default: 9000)")
    tun_group.add_argument("--tun-auto-route", action="store_true", default=True, help="Auto-configure routes (default: on)")
    tun_group.add_argument("--no-tun-auto-route", dest="tun_auto_route", action="store_false", help="Disable auto routing")
    tun_group.add_argument("--tun-auto-redirect", dest="tun_auto_redirect", action="store_true", default=None,
                           help="Enable Linux nftables auto_redirect (default: on for Linux)")
    tun_group.add_argument("--no-tun-auto-redirect", dest="tun_auto_redirect", action="store_false",
                           help="Disable auto_redirect")

    relay_group = parser.add_argument_group("relay")
    relay_group.add_argument("--relay-host", help="Host/IP for relay URL (default: auto-detect)")
    relay_group.add_argument("--relay-port", type=int, help="Relay listen port (default: auto)")
    relay_group.add_argument("--relay-name", default="nichind.dev|singbox2proxy-relay", help="Name in relay URL")
    relay_group.add_argument("--uuid-seed", help="Seed for deterministic credentials (stable relay URLs)")

    batch_group = parser.add_argument_group("batch check")
    batch_group.add_argument("--workers", "-w", type=int, help="Parallel workers for --check (default: auto)")
    batch_group.add_argument("--batch-size", type=int, default=50, help="Proxies per sing-box process (default: 50)")
    batch_group.add_argument("--timeout", type=int, default=5, help="Per-proxy timeout in seconds (default: 5)")

    out_group = parser.add_argument_group("output")
    out_group.add_argument("--test", "-T", action="store_true", help="Test proxy connection after starting")
    out_group.add_argument("--output-config", "-o", help="Save config JSON to file")
    out_group.add_argument("--set-system-proxy", action="store_true", help="Set OS proxy settings (restored on stop)")
    out_group.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    out_group.add_argument("--quiet", "-q", action="store_true", help="Suppress logging")
    out_group.add_argument(
        "--qr", choices=["half", "ascii", "none"], default="half", help="QR style: half-blocks (default), ascii, or none"
    )
    out_group.add_argument("--qr-invert", action="store_true", help="Invert QR colors (white bg, dark modules)")
    out_group.add_argument("--qr-border", type=int, default=1, help="QR quiet zone size (default: 1)")

    args = parser.parse_args()

    # --- Set output globals ---
    global _quiet, _verbose, _qr_style, _qr_invert, _qr_border
    _quiet = args.quiet
    _verbose = args.verbose
    _qr_style = args.qr
    _qr_invert = args.qr_invert
    _qr_border = args.qr_border

    # --- Logging ---
    if args.quiet:
        disable_logging()
    elif args.verbose:
        enable_logging(logging.DEBUG)
    else:
        enable_logging(logging.INFO)

    # --- Signal handlers ---
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # --- --cmd: run sing-box subcommand and exit ---
    if args.cmd:
        core = _get_default_core()
        if not core or not core.executable:
            print("Error: sing-box not found", file=sys.stderr)
            sys.exit(1)
        print(core.run_command_output(args.cmd))
        return

    # --- --check: batch check from file ---
    if args.check:
        _run_batch_check(args)
        return

    # --- Validate ---
    if not args.urls and not args.relay:
        parser.error("provide proxy URL(s) or use --relay for direct connection")

    if args.chain and args.relay:
        parser.error("--chain and --relay cannot be combined")

    if args.chain and len(args.urls) < 2:
        parser.error("--chain requires at least 2 URLs")

    if args.config_only and args.test:
        print("Warning: --test ignored with --config-only", file=sys.stderr)

    # --- TUN privilege check ---
    if args.tun:
        if os.name == "nt":
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: TUN mode requires administrator privileges.", file=sys.stderr)
                sys.exit(1)
        else:
            if os.geteuid() != 0:
                print("Error: TUN mode requires root (use sudo).", file=sys.stderr)
                sys.exit(1)

    # --- Build proxies ---
    proxies = []
    try:
        if args.chain and len(args.urls) > 1:
            _dbg(f"building chain ({len(args.urls)} hops)")
            for i, url in enumerate(args.urls):
                is_last = i == len(args.urls) - 1
                _dbg(f"  hop {i + 1}: {_short_url(url)}")
                proxy = SingBoxProxy(
                    url,
                    http_port=args.http_port if is_last else False,
                    socks_port=args.socks_port if is_last else None,
                    chain_proxy=proxies[-1] if proxies else None,
                    config_only=args.config_only,
                    tun_enabled=args.tun if is_last else False,
                    tun_address=args.tun_address,
                    tun_stack=args.tun_stack,
                    tun_mtu=args.tun_mtu,
                    tun_auto_route=args.tun_auto_route,
                    tun_auto_redirect=args.tun_auto_redirect,
                    set_system_proxy=args.set_system_proxy if is_last else False,
                )
                proxies.append(proxy)
            main_proxy = proxies[-1]
        else:
            if len(args.urls) > 1:
                print("Warning: multiple URLs without --chain; using first only.", file=sys.stderr)

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
                tun_auto_redirect=args.tun_auto_redirect,
                set_system_proxy=args.set_system_proxy,
                relay_protocol=args.relay,
                relay_host=args.relay_host,
                relay_port=args.relay_port,
                relay_name=args.relay_name,
                uuid_seed=args.uuid_seed,
            )
            proxies.append(main_proxy)

        # --- Config-only ---
        if args.config_only:
            config = main_proxy.generate_config()
            print(json.dumps(config, indent=2))
            if args.output_config:
                with open(args.output_config, "w") as f:
                    json.dump(config, f, indent=2)
                print(f"Config saved to {args.output_config}", file=sys.stderr)
            return

        # --- Save config ---
        if args.output_config:
            with open(args.output_config, "w") as f:
                json.dump(main_proxy.config, f, indent=2)
            _out(f"config saved to {args.output_config}")

        # --- Status ---
        _print_status(main_proxy, args, proxies)

        # --- Test ---
        if args.test:
            passed = _run_test(main_proxy)
            sys.exit(0 if passed else 1)

        # --- Run ---
        _out("running (ctrl+c to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    finally:
        for proxy in proxies:
            try:
                proxy.stop()
            except Exception:
                pass


if __name__ == "__main__":
    main()
