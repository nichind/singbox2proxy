import json
import tempfile
import os
import time
import subprocess
import random
import atexit
import logging
import base64
import binascii
import urllib.parse
import urllib.request
import socket
import signal
import threading
import weakref
import psutil
import shutil
import sys
from pathlib import Path


logger = logging.getLogger("singbox2proxy")
logger.setLevel(logging.WARNING)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s:%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)


logger.propagate = False


def enable_logging(level=logging.DEBUG):
    """Enable library logging at the specified level."""
    logger.setLevel(level)


def disable_logging():
    """Disable library logging."""
    logger.setLevel(logging.CRITICAL + 1)


# Global registry to track all active processes
_active_processes = weakref.WeakSet()
_cleanup_lock = threading.RLock()
_signal_handlers_registered = False

# Global port allocation tracking
_allocated_ports = set()
_port_allocation_lock = threading.RLock()


def _register_signal_handlers():
    """Register signal handlers for process cleanup."""
    global _signal_handlers_registered
    if _signal_handlers_registered:
        return

    def cleanup_handler(signum, frame):
        logger.info(f"Received signal {signum}, cleaning up sing-box processes...")
        _cleanup_all_processes()
        # Re-raise the signal for default handling
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    # Register handlers for common termination signals
    if os.name != "nt":  # Unix-like systems
        signal.signal(signal.SIGTERM, cleanup_handler)
        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGHUP, cleanup_handler)
    else:  # Windows
        signal.signal(signal.SIGTERM, cleanup_handler)
        signal.signal(signal.SIGINT, cleanup_handler)

    _signal_handlers_registered = True


def _cleanup_all_processes():
    """Emergency cleanup of all tracked processes."""
    with _cleanup_lock:
        processes_to_cleanup = list(_active_processes)
        for process_ref in processes_to_cleanup:
            try:
                if hasattr(process_ref, "_emergency_cleanup"):
                    process_ref._emergency_cleanup()
            except Exception as e:
                logger.error(f"Error in emergency cleanup: {e}")


# Register signal handlers and atexit cleanup
_register_signal_handlers()
atexit.register(_cleanup_all_processes)


class SingBoxCore:
    def __init__(self, executable: os.PathLike = None):
        start_time = time.time()
        if executable and not os.path.exists(executable):
            raise FileNotFoundError(f"Custom set sing-box executable not found: {executable}")
        if executable:
            logger.info(f"Using custom sing-box executable: {executable}")
        self.executable = executable or self._ensure_executable()
        logger.debug(f"SingBoxCore initialized in {time.time() - start_time:.2f} seconds")

    def _ensure_executable(self) -> str:
        """Ensure that the sing-box executable is available.
        Returns the path (terminal alias) to the executable, or None if not found/installed.
        """

        def _test_terminal() -> bool:
            "Check if sing-box is accessible from terminal"
            executables = ["sing-box"]
            if os.name == "nt":  # Windows
                executables.extend(["sing-box.exe"])

            for exe in executables:
                try:
                    # On Windows, use shell=True for better compatibility
                    kwargs = {"capture_output": True, "text": True, "timeout": 5}
                    if os.name == "nt":
                        kwargs["shell"] = True

                    result = subprocess.run([exe, "version"], **kwargs)
                    if result.returncode == 0 and "sing-box" in result.stdout.lower():
                        logger.info(f"Found sing-box executable '{exe}': {result.stdout.strip()}")
                        return True
                    else:
                        logger.debug(
                            f"'{exe}' version returned non-zero exit code or unexpected output: {result.stdout.strip()} {result.stderr.strip()}"
                        )
                except FileNotFoundError:
                    logger.debug(f"'{exe}' command not found in PATH")
                    continue
                except subprocess.TimeoutExpired:
                    logger.warning(f"'{exe}' version command timed out")
                    continue
                except Exception as e:
                    logger.debug(f"Error checking '{exe}' executable: {e}")
                    continue

            logger.warning("sing-box command not found in PATH")
            return False

        def _install_via_sh(
            beta: bool = False,
            version: str | None = None,
            use_sudo: bool = False,
            install_url: str = "https://sing-box.app/install.sh",
        ) -> bool:
            """Download and run the official sing-box install script.

            This uses the upstream install.sh which handles deb/rpm/Arch/OpenWrt/etc.
            Parameters:
              - beta: pass --beta to installer to install latest beta
              - version: pass --version <version> to installer
              - use_sudo: if True and not running as root, attempts to prefix with sudo
              - install_url: URL of the install script (default official URL)
            Returns:
              - True on success, raises RuntimeError on failure.
            """
            logger.info("Installing sing-box via upstream install script")
            if os.name == "nt":
                return False
                # raise NotImplementedError("Automatic install via install.sh is not supported on Windows")

            # Fetch installer script
            try:
                req = urllib.request.Request(
                    install_url,
                    headers={
                        "User-Agent": "sing-box-installer/singbox2proxy (+https://sing-box.app)",
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "close",
                    },
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    script_bytes = resp.read()
            except Exception as e:
                raise RuntimeError(f"Failed to download sing-box install script: {e}")

            # Build command
            cmd = ["sh", "-s", "--"]
            if beta:
                cmd.append("--beta")
            if version:
                cmd.extend(["--version", version])

            # If not root and sudo requested, try to use sudo
            if use_sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
                try:
                    sudo_path = shutil.which("sudo")
                    if sudo_path:
                        cmd.insert(0, sudo_path)
                    else:
                        logger.warning("Not running as root and sudo not found; installer may fail without privileges")
                except Exception:
                    logger.warning("Could not determine sudo availability; proceeding without sudo")

            logger.info(f"Running installer: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, input=script_bytes, check=True)
                logger.info("sing-box installation completed successfully")
                return True
            except subprocess.CalledProcessError as e:
                logger.warning(f"sing-box installer failed with exit code {e.returncode}")
                return False
            except Exception as e:
                logger.warning(f"Error running sing-box installer: {e}")
                return False

        def _install_via_package_manager() -> bool:
            """
            Attempt to install sing-box using common package managers.

            Returns True on success.
            """
            logger.info("Attempting installation via package manager")

            cmds = []

            try:
                # Windows
                if os.name == "nt":
                    if shutil.which("scoop"):
                        cmds.append(["scoop", "install", "sing-box"])
                    if shutil.which("choco"):
                        cmds.append(["choco", "install", "sing-box", "-y"])
                    if shutil.which("winget"):
                        cmds.append(
                            [
                                "winget",
                                "install",
                                "sing-box",
                                "--accept-package-agreements",
                                "--accept-source-agreements",
                            ]
                        )

                # macOS
                elif sys.platform == "darwin":
                    if shutil.which("brew"):
                        cmds.append(["brew", "install", "sing-box"])

                # Other Unix-like (Linux, FreeBSD, Termux, Alpine, etc.)
                else:
                    # AUR helpers / pacman (Arch)
                    if shutil.which("paru"):
                        cmds.append(["paru", "-S", "--noconfirm", "sing-box"])
                    if shutil.which("yay"):
                        cmds.append(["yay", "-S", "--noconfirm", "sing-box"])
                    if shutil.which("pacman"):
                        cmds.append(["pacman", "-S", "--noconfirm", "sing-box"])

                    # Debian/Ubuntu/AOSC etc.
                    if shutil.which("apt"):
                        cmds.append(["apt", "install", "-y", "sing-box"])
                    if shutil.which("apt-get"):
                        cmds.append(["apt-get", "install", "-y", "sing-box"])

                    # Alpine
                    if shutil.which("apk"):
                        cmds.append(["apk", "add", "sing-box"])

                    # Fedora / RHEL
                    if shutil.which("dnf"):
                        cmds.append(["dnf", "install", "-y", "sing-box"])
                    if shutil.which("yum"):
                        cmds.append(["yum", "install", "-y", "sing-box"])

                    # Nix
                    if shutil.which("nix-env"):
                        cmds.append(["nix-env", "-iA", "nixos.sing-box"])

                    # Termux / FreeBSD pkg
                    if shutil.which("pkg"):
                        # Termux and FreeBSD both use `pkg`, command forms differ; try a generic install
                        cmds.append(["pkg", "install", "-y", "sing-box"])

                    # Linuxbrew on Linux
                    if shutil.which("brew"):
                        cmds.append(["brew", "install", "sing-box"])

            except Exception as e:
                logger.warning(f"Error preparing package manager commands: {e}")
                return False

            if not cmds:
                logger.warning("No known package manager found on this system")
                return False

            for cmd in cmds:
                needs_sudo = False
                # common managers that require root privileges
                root_required = {"apt", "apt-get", "pacman", "dnf", "yum", "apk", "pkg"}
                if cmd and cmd[0] in root_required:
                    try:
                        if hasattr(os, "geteuid") and os.geteuid() != 0:
                            needs_sudo = True
                    except Exception:
                        needs_sudo = True

                final_cmd = list(cmd)
                if needs_sudo:
                    sudo_path = shutil.which("sudo")
                    if sudo_path:
                        final_cmd.insert(0, sudo_path)
                    else:
                        logger.info(f"Skipping command that requires root (sudo not found): {' '.join(cmd)}")
                        continue

                logger.info(f"Running package manager command: {' '.join(final_cmd)}")
                try:
                    proc = subprocess.run(final_cmd, check=False, capture_output=True, text=True, timeout=600)
                    proc_p = subprocess.Popen(
                        final_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, universal_newlines=True, bufsize=1
                    )

                    stdout_lines = []
                    stderr_lines = []

                    def _reader(stream, collector, is_stderr=False):
                        try:
                            for line in iter(stream.readline, ""):
                                # Print in real-time to stdout/stderr and collect
                                print(line, end="", flush=True)
                                collector.append(line)
                        except Exception:
                            pass
                        finally:
                            try:
                                stream.close()
                            except Exception:
                                pass

                    t_out = threading.Thread(target=_reader, args=(proc_p.stdout, stdout_lines), daemon=True)
                    t_err = threading.Thread(target=_reader, args=(proc_p.stderr, stderr_lines, True), daemon=True)
                    t_out.start()
                    t_err.start()

                    try:
                        proc_p.wait(timeout=600)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Package manager command timeout, killing: {' '.join(final_cmd)}")
                        try:
                            proc_p.kill()
                        except Exception:
                            pass
                        proc_p.wait(timeout=5)

                    t_out.join(timeout=1)
                    t_err.join(timeout=1)

                    stdout = "".join(stdout_lines)
                    stderr = "".join(stderr_lines)

                    # Create a CompletedProcess-like object so downstream code expecting proc.returncode/stdout/stderr works
                    proc = subprocess.CompletedProcess(args=final_cmd, returncode=proc_p.returncode, stdout=stdout, stderr=stderr)

                    logger.debug(f"Command stdout: {proc.stdout}")
                    logger.debug(f"Command stderr: {proc.stderr}")
                    if proc.returncode == 0:
                        logger.info(f"Package manager reported success: {' '.join(final_cmd)}")
                        return True
                    else:
                        logger.warning(f"Command failed ({proc.returncode}): {' '.join(final_cmd)}")
                except FileNotFoundError:
                    logger.debug(f"Command not found: {final_cmd[0]}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"Command timed out: {' '.join(final_cmd)}")
                except Exception as e:
                    logger.warning(f"Error running command {' '.join(final_cmd)}: {e}")

            logger.error("All package manager installation attempts failed")
            return False

        if _test_terminal():
            return "sing-box"

        try:
            if _install_via_sh():
                if _test_terminal():
                    return "sing-box"
        except Exception as e:
            logger.warning(f"Failed to install sing-box via install script: {e}")

        try:
            if _install_via_package_manager():
                if _test_terminal():
                    return "sing-box"
        except Exception as e:
            logger.warning(f"Failed to install sing-box via package manager: {e}")

        logger.warning("sing-box could not be installed automatically. Please install it manually.")
        return None

    def _version(self):
        if not self.executable:
            return None

        try:
            kwargs = {"capture_output": True, "text": True, "timeout": 1}
            if os.name == "nt":
                kwargs["shell"] = True

            result = subprocess.run([self.executable, "version"], **kwargs)
            if result.returncode == 0 and "sing-box" in result.stdout.lower():
                for line in result.stdout.splitlines():
                    if "version" in line.lower():
                        return line.strip().split("version")[-1].strip()
                return result.stdout.strip()
            else:
                logger.warning(f"Failed to get sing-box version: {result.stdout.strip()} {result.stderr.strip()}")
                return None
        except Exception as e:
            logger.warning(f"Error getting sing-box version: {e}")
            return None

    @property
    def version(self):
        """Get the sing-box executable version."""
        return self._version()


default_core = SingBoxCore()


def _safe_base64_decode(data: str) -> str:
    """Safely decode base64 data"""
    try:
        # Add padding if needed
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)

        # Try to decode
        decoded_bytes = base64.b64decode(data)
        return decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"Invalid base64 data: {str(e)}")


class SingBoxProxy:
    def __init__(
        self,
        config: os.PathLike | str,
        http_port: int | None = None,
        socks_port: int | None = None,
        chain_proxy: None = None,
        config_only: bool = False,
        config_file: os.PathLike | str | None = None,
        config_directory: os.PathLike | str | None = None,
        client: "SingBoxClient" = None,
        core: "SingBoxCore" = None,
    ):
        """
        Accepts either a local path (os.PathLike / str) or a URL (http:// or https://).
        If a URL is provided, self.config_url will be set and self.config_path will be None.
        If a local path is provided, self.config_path will be a pathlib.Path and self.config_url will be None.
        """
        start_time = time.time()
        self._original_config = config

        # Distinguish between URL and local path
        if isinstance(config, (str,)):
            parsed = urllib.parse.urlparse(config)
            # Treat strings that parse to a URL with a scheme and a network location as URLs.
            # This handles proxy link schemes like vless://, vmess://, ss://, trojan://, etc.
            # It also avoids misclassifying Windows paths like "C:\path" which have a scheme but no netloc.
            if parsed.scheme and parsed.netloc:
                self.config_url = config
                self.config_path = None
            else:
                self.config_path = Path(config)
                self.config_url = None
        elif isinstance(config, os.PathLike):
            self.config_path = Path(config)
            self.config_url = None
        else:
            raise TypeError("config must be a path-like or a string (local path or URL)")

        # Ports & Configuration
        self.http_port = http_port or (self._pick_unused_port() if http_port is not False else None)
        self.socks_port = socks_port or (self._pick_unused_port(self.http_port) if socks_port is not False else None)
        logger.debug(f"Ports selected in {time.time() - start_time:.2f} seconds")
        self.config_only = config_only
        self.chain_proxy = chain_proxy
        self.config_file = Path(config_file) if config_file else None
        self.config_directory = Path(config_directory) if config_directory else None

        # Runtime state
        self.singbox_process = None
        self.running = False
        self._cleanup_lock = threading.RLock()
        self._process_terminated = threading.Event()
        self._stdout_lines = []
        self._stderr_lines = []
        self._stdout_thread = None
        self._stderr_thread = None

        # Register this instance for global cleanup
        _active_processes.add(self)

        # set SingBoxCore
        self.core = core or default_core

        if client is not False:
            self.client = client._set_parent(self) if isinstance(client, SingBoxClient) else SingBoxClient(self)
            self.request = self.client.request
            self.get = self.client.get
            self.post = self.client.post

        # Start SingBox if not in config_only mode
        if not config_only:
            self.start()
        logger.debug(f"SingBoxProxy initialized in {time.time() - start_time:.2f} seconds")

    def __repr__(self) -> str:
        pid = None
        try:
            pid = self.singbox_process.pid if self.singbox_process else None
        except Exception:
            pid = None
        return (
            f"<SingBoxProxy http={self.http_port!r} socks={self.socks_port!r} "
            f"running={self.running!r} pid={pid!r} config_url={getattr(self, 'config_url', None)!r} "
            f"config_path={str(self.config_path) if getattr(self, 'config_path', None) else None!r}>"
        )

    def __str__(self) -> str:
        """print(SingBoxProxy)"""
        if self.running:
            try:
                socks = self.socks5_proxy_url
            except Exception:
                socks = f"127.0.0.1:{self.socks_port}"
            try:
                http = self.http_proxy_url
            except Exception:
                http = f"127.0.0.1:{self.http_port}"
            return f"SingBoxProxy(running, socks={socks}, http={http})"
        else:
            return f"SingBoxProxy(stopped, socks_port={self.socks_port}, http_port={self.http_port})"

    @property
    def proxy_for_requests(self, socks: bool = True):
        """Get a proxies dict suitable for requests library

        Example:
            proxy = SingBoxProxy(...)
            requests.get(url, proxies=proxy.proxy_for_requests)
        """
        if socks and self.socks_port:
            return {
                "http": self.socks5_proxy_url,
                "https": self.socks5_proxy_url,
            }
        elif self.http_port:
            return {
                "http": self.http_proxy_url,
                "https": self.http_proxy_url,
            }
        raise RuntimeError("Failed to determine proxy URL for requests")

    @property
    def proxies(self):
        return self.proxy_for_requests

    @property
    def stdout(self) -> str:
        """Get the captured stdout from the sing-box process."""
        return "".join(self._stdout_lines)

    @property
    def stderr(self) -> str:
        """Get the captured stderr from the sing-box process."""
        return "".join(self._stderr_lines)

    def _read_stream(self, stream, collector):
        """Reads a stream line by line and appends to a collector."""
        try:
            for line in iter(stream.readline, ""):
                if line:
                    collector.append(line)
                else:
                    break
        except (ValueError, OSError) as e:
            # Stream was closed or process terminated
            logger.debug(f"Stream read interrupted (process likely terminated): {e}")
        except Exception as e:
            logger.debug(f"Error reading stream: {e}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

    @classmethod
    def _is_port_in_use(cls, port: int) -> bool:
        """Check if a port is currently in use by trying to bind to it."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("localhost", port))
                return False
        except (socket.error, OSError):
            return True

    @classmethod
    def _pick_unused_port(cls, exclude_port: int | list = None) -> int:
        start_time = time.time()
        with _port_allocation_lock:
            # Try to get a system-assigned port first
            if not exclude_port:
                exclude_port = []
            elif isinstance(exclude_port, int):
                exclude_port = [exclude_port]

            # Add already allocated ports to exclude list
            exclude_port = exclude_port + list(_allocated_ports)

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("localhost", 0))  # Let OS choose a free port
                    _, port = s.getsockname()
                    if port not in exclude_port:
                        _allocated_ports.add(port)
                        return port
            except Exception as e:
                logger.warning(f"Failed to get system-assigned port: {str(e)}")

            # If that fails, try a few random ports
            for _ in range(100):
                port = random.randint(10000, 65000)
                if port not in exclude_port and not cls._is_port_in_use(port):
                    _allocated_ports.add(port)
                    logger.debug(f"Unused port picked in {time.time() - start_time:.2f} seconds")
                    return port

            raise RuntimeError("Could not find an unused port")

    def _parse_vmess_link(self, link: str) -> dict:
        """Parse a VMess link into a sing-box configuration."""
        if not link.startswith("vmess://"):
            raise ValueError("Not a valid VMess link")

        try:
            # URL-decode first, as base64 can contain '+' which might be a space
            link = urllib.parse.unquote(link)
            b64_content = link[8:]
            decoded_content = _safe_base64_decode(b64_content)
            vmess_info = json.loads(decoded_content)

            # Extract and clean up values
            server = str(vmess_info.get("add", "")).strip()
            port_str = str(vmess_info.get("port", "443")).strip()
            port = int(port_str) if port_str.isdigit() else 443
            uuid = str(vmess_info.get("id", "")).strip()
            security = str(vmess_info.get("scy", "auto")).strip()
            alter_id_str = str(vmess_info.get("aid", "0")).strip()
            alter_id = int(alter_id_str) if alter_id_str.isdigit() else 0

            # Create outbound configuration for sing-box
            outbound = {
                "type": "vmess",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": security,
                "alter_id": alter_id,
            }

            # Handle transport (network) settings
            network = str(vmess_info.get("net", "tcp")).strip()
            host_header = str(vmess_info.get("host", "")).strip()
            path = str(vmess_info.get("path", "/")).strip()

            if network == "ws":
                outbound["transport"] = {"type": "ws", "path": path, "headers": {"Host": host_header} if host_header else {}}
            elif network == "grpc":
                # gRPC service name is in 'path' for some clients
                service_name = str(vmess_info.get("path", "")).strip()
                outbound["transport"] = {"type": "grpc", "service_name": service_name}

            # Handle TLS settings
            if str(vmess_info.get("tls")).strip() == "tls":
                sni = str(vmess_info.get("sni", "")).strip()
                outbound["tls"] = {"enabled": True, "server_name": sni or host_header or server}

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse VMess link: {str(e)}")
            raise ValueError(f"Invalid VMess format: {str(e)}")

    def _parse_vless_link(self, link: str) -> dict:
        """Parse a VLESS link into a sing-box configuration."""
        if not link.startswith("vless://"):
            raise ValueError("Not a valid VLESS link")

        try:
            # Format: vless://uuid@host:port?param=value&param2=value2#remark
            # First decode any URL encoding - handle both & and &amp; separators
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Extract user info (uuid)
            if "@" not in parsed_url.netloc:
                raise ValueError("Invalid VLESS format: missing @ separator")

            user_info = parsed_url.netloc.split("@")[0]

            # Extract host and port
            host_port = parsed_url.netloc.split("@")[1]
            if ":" in host_port:
                host, port = host_port.rsplit(":", 1)
                try:
                    port = int(port)
                except ValueError:
                    # If port is not a number, treat the whole thing as host
                    host = host_port
                    port = 443  # Default port
            else:
                host = host_port
                port = 443  # Default port

            # Parse query parameters - handle both & and &amp; separators
            query_string = parsed_url.query.replace("&amp;", "&")
            params = dict(urllib.parse.parse_qsl(query_string))

            # Create outbound configuration for sing-box
            outbound = {
                "type": "vless",
                "tag": "proxy",
                "server": host.strip(),
                "server_port": port,
                "uuid": user_info.strip(),
                "flow": params.get("flow", ""),
            }

            # Handle transport settings
            transport_type = params.get("type", "tcp")
            if transport_type == "ws":
                outbound["transport"] = {"type": "ws", "path": params.get("path", "/"), "headers": {}}
                # Handle host header
                if params.get("host"):
                    outbound["transport"]["headers"]["Host"] = params.get("host")
            elif transport_type == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", params.get("path", ""))}

            # Handle TLS settings
            security = params.get("security", "none")
            if security == "tls":
                outbound["tls"] = {"enabled": True, "server_name": params.get("sni", params.get("host", host))}
            elif security == "reality":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", params.get("host", host)),
                    "reality": {"enabled": True, "public_key": params.get("pbk", ""), "short_id": params.get("sid", "")},
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                }

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse VLESS link: {str(e)}")
            raise ValueError(f"Invalid VLESS format: {str(e)}")

    def _parse_shadowsocks_link(self, link: str) -> dict:
        """Parse a Shadowsocks link into a sing-box configuration."""
        if not link.startswith("ss://"):
            raise ValueError("Not a valid Shadowsocks link")

        try:
            # URL decode the link first to handle encoded characters
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Check if this is actually a VLESS/VMess link disguised as SS
            query_params = dict(urllib.parse.parse_qsl(parsed_url.query.replace("&amp;", "&")))
            if any(param in query_params for param in ["type", "security", "encryption", "host", "path"]):
                # This looks like a VLESS/VMess link with ss:// prefix, treat as VLESS
                # Convert ss:// to vless:// and parse as VLESS
                vless_link = link.replace("ss://", "vless://", 1)
                return self._parse_vless_link(vless_link)

            # Handle standard Shadowsocks formats
            if "@" in parsed_url.netloc:
                # Format: ss://base64(method:password)@host:port or ss://userinfo@host:port
                user_info_part, host_port = parsed_url.netloc.split("@", 1)

                # Try to decode as base64 first
                try:
                    user_info = _safe_base64_decode(user_info_part)
                    if ":" in user_info:
                        method, password = user_info.split(":", 1)
                    else:
                        # Sometimes the format is just the password
                        method = "aes-256-cfb"  # Default method
                        password = user_info
                except (ValueError, UnicodeDecodeError):
                    # Not base64, treat as plain text (UUID format)
                    if ":" in user_info_part:
                        method, password = user_info_part.split(":", 1)
                    else:
                        # Assume it's a UUID/password
                        method = "aes-256-gcm"  # Modern default
                        password = user_info_part

                # Parse host and port
                if ":" in host_port:
                    host, port = host_port.rsplit(":", 1)
                else:
                    host = host_port
                    port = "443"  # Default port
            else:
                # Format: ss://base64(method:password@host:port)
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

            # Create outbound configuration for sing-box
            outbound = {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": host.strip(),
                "server_port": int(port),
                "method": method.strip(),
                "password": password.strip(),
            }

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse Shadowsocks link: {str(e)}")
            raise ValueError(f"Invalid Shadowsocks format: {str(e)}")

    def _parse_trojan_link(self, link: str) -> dict:
        """Parse a Trojan link into a sing-box configuration."""
        if not link.startswith("trojan://"):
            raise ValueError("Not a valid Trojan link")

        try:
            # Format: trojan://password@host:port?param=value&param2=value2#remark
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Extract password
            password = parsed_url.username or ""

            # Extract host and port
            host = parsed_url.hostname
            port = parsed_url.port or 443

            # Parse query parameters
            params = dict(urllib.parse.parse_qsl(parsed_url.query))

            # Create outbound configuration for sing-box
            outbound = {"type": "trojan", "tag": "proxy", "server": host, "server_port": port, "password": password}

            # Handle transport settings
            transport_type = params.get("type", "tcp")
            host_header = params.get("host", "")
            if transport_type == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": params.get("path", "/"),
                    "headers": {"Host": host_header} if host_header else {},
                }
            elif transport_type == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", params.get("path", ""))}

            # Handle TLS settings - Trojan always uses TLS
            sni = params.get("sni", host_header or host)
            outbound["tls"] = {"enabled": True, "server_name": sni}

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse Trojan link: {str(e)}")
            raise ValueError(f"Invalid Trojan format: {str(e)}")

    def _parse_hysteria2_link(self, link: str) -> dict:
        """Parse a Hysteria2 link into a sing-box configuration."""
        if not link.startswith("hy2://") and not link.startswith("hysteria2://"):
            raise ValueError("Not a valid Hysteria2 link")

        try:
            # Format: hy2://password@host:port?param=value#remark
            # or hysteria2://password@host:port?param=value#remark
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Extract password
            password = parsed_url.username or ""

            # Extract host and port
            host = parsed_url.hostname
            port = parsed_url.port or 443

            # Parse query parameters
            params = dict(urllib.parse.parse_qsl(parsed_url.query))

            # Create outbound configuration for sing-box
            outbound = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port, "password": password}

            # Handle TLS settings
            sni = params.get("sni", host)
            insecure = params.get("insecure", "0") == "1"
            outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": insecure}

            # Handle optional parameters
            obfs_pass = params.get("obfs", "")
            if obfs_pass:
                outbound["obfs"] = {"type": "salamander", "password": obfs_pass}

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse Hysteria2 link: {str(e)}")
            raise ValueError(f"Invalid Hysteria2 format: {str(e)}")

    def _parse_tuic_link(self, link: str) -> dict:
        """Parse a TUIC link into a sing-box configuration."""
        if not link.startswith("tuic://"):
            raise ValueError("Not a valid TUIC link")

        try:
            # Format: tuic://uuid:password@host:port?param=value#remark
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Extract uuid and password
            user_info = parsed_url.username or ""
            if ":" in user_info:
                uuid, password = user_info.split(":", 1)
            else:
                raise ValueError("TUIC link must contain uuid:password")

            # Extract host and port
            host = parsed_url.hostname
            port = parsed_url.port or 443

            # Parse query parameters
            params = dict(urllib.parse.parse_qsl(parsed_url.query))

            # Create outbound configuration for sing-box
            outbound = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid, "password": password}

            # Handle TLS settings
            sni = params.get("sni", host)
            insecure = params.get("insecure", "0") == "1"
            outbound["tls"] = {"enabled": True, "server_name": sni, "insecure": insecure}

            # Handle optional parameters
            if params.get("congestion_control"):
                outbound["congestion_control"] = params.get("congestion_control")

            if params.get("udp_relay_mode"):
                outbound["udp_relay_mode"] = params.get("udp_relay_mode")

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse TUIC link: {str(e)}")
            raise ValueError(f"Invalid TUIC format: {str(e)}")

    def _parse_wireguard_link(self, link: str) -> dict:
        """Parse a WireGuard link into a sing-box configuration."""
        if not link.startswith("wg://"):
            raise ValueError("Not a valid WireGuard link")

        try:
            # Custom WireGuard link format for this implementation
            # wg://private_key@server:port?public_key=...&local_address=...#remark
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Extract private key
            private_key = parsed_url.username or ""
            if not private_key:
                raise ValueError("WireGuard link must contain a private key")

            # Extract host and port
            host = parsed_url.hostname
            port = parsed_url.port or 51820  # Default WireGuard port

            # Parse query parameters
            params = dict(urllib.parse.parse_qsl(parsed_url.query))

            peer_public_key = params.get("public_key", "")
            if not peer_public_key:
                raise ValueError("WireGuard link must contain a peer_public_key")

            # Create outbound configuration for sing-box
            outbound = {
                "type": "wireguard",
                "tag": "proxy",
                "server": host,
                "server_port": port,
                "private_key": private_key,
                "peer_public_key": peer_public_key,
                "local_address": params.get("local_address", "172.16.0.2/32").split(","),
            }

            # Handle optional parameters
            if params.get("mtu"):
                outbound["mtu"] = int(params.get("mtu"))
            if params.get("reserved"):
                # Format: "1,2,3" -> [1, 2, 3]
                outbound["reserved"] = [int(b.strip()) for b in params.get("reserved").split(",")]

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse WireGuard link: {str(e)}")
            raise ValueError(f"Invalid WireGuard format: {str(e)}")

    def _parse_ssh_link(self, link: str) -> dict:
        """Parse an SSH link into a sing-box configuration."""
        if not link.startswith("ssh://"):
            raise ValueError("Not a valid SSH link")

        try:
            # Format: ssh://user:password@host:port#remark
            link = urllib.parse.unquote(link)
            parsed_url = urllib.parse.urlparse(link)

            # Extract user and password
            user = parsed_url.username or ""
            password = parsed_url.password or ""

            # Extract host and port
            host = parsed_url.hostname
            port = parsed_url.port or 22

            if not host or not user:
                raise ValueError("SSH link must contain user and host")

            # Create outbound configuration for sing-box
            outbound = {"type": "ssh", "tag": "proxy", "server": host, "server_port": port, "user": user}

            if password:
                outbound["password"] = password

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse SSH link: {str(e)}")
            raise ValueError(f"Invalid SSH format: {str(e)}")

    def _parse_http_link(self, link: str) -> dict:
        """Parse an HTTP proxy link into a sing-box configuration."""
        if not link.startswith("http://") and not link.startswith("https://"):
            raise ValueError("Not a valid HTTP proxy link")

        try:
            link = urllib.parse.unquote(link)
            parsed_url = urllib.parse.urlparse(link)

            # Extract user and password if present
            username = parsed_url.username or ""
            password = parsed_url.password or ""

            # Determine port
            default_port = 443 if parsed_url.scheme == "https" else 80
            port = parsed_url.port or default_port

            # Create outbound configuration for sing-box
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

            # Handle HTTPS
            if parsed_url.scheme == "https":
                outbound["tls"] = {"enabled": True, "server_name": parsed_url.hostname}

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse HTTP link: {str(e)}")
            raise ValueError(f"Invalid HTTP format: {str(e)}")

    def _parse_socks_link(self, link: str) -> dict:
        """Parse a SOCKS link into a sing-box configuration."""
        if not link.startswith("socks://") and not link.startswith("socks5://") and not link.startswith("socks4://"):
            raise ValueError("Not a valid SOCKS link")

        try:
            link = urllib.parse.unquote(link)
            parsed_url = urllib.parse.urlparse(link)

            # Extract user and password if present
            username = parsed_url.username or ""
            password = parsed_url.password or ""

            # Determine SOCKS version
            version = "5"  # Default to SOCKS5
            if parsed_url.scheme == "socks4":
                version = "4"

            # Create outbound configuration for sing-box
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

    def _parse_hysteria_link(self, link: str) -> dict:
        """Parse a Hysteria (v1) link into a sing-box configuration."""
        if not link.startswith("hysteria://"):
            raise ValueError("Not a valid Hysteria link")

        try:
            # Format: hysteria://host:port?auth=password&param=value#remark
            link = urllib.parse.unquote(link.replace("&amp;", "&"))
            parsed_url = urllib.parse.urlparse(link)

            # Parse query parameters
            params = dict(urllib.parse.parse_qsl(parsed_url.query))

            # Create outbound configuration for sing-box
            outbound = {
                "type": "hysteria",
                "tag": "proxy",
                "server": parsed_url.hostname,
                "server_port": parsed_url.port,
                "auth_str": params.get("auth", ""),
            }

            # Handle TLS settings
            sni = params.get("peer", parsed_url.hostname)
            insecure = params.get("insecure", "0") == "1"
            outbound["tls"] = {
                "enabled": True,
                "server_name": sni,
                "insecure": insecure,
            }

            # Handle optional parameters
            if params.get("upmbps"):
                outbound["up_mbps"] = int(params.get("upmbps"))
            if params.get("downmbps"):
                outbound["down_mbps"] = int(params.get("downmbps"))
            if params.get("obfs"):
                outbound["obfs"] = params.get("obfs")

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse Hysteria link: {str(e)}")
            raise ValueError(f"Invalid Hysteria format: {str(e)}")

    def _parse_naiveproxy_link(self, link: str) -> dict:
        """Parse a NaiveProxy link into a sing-box configuration."""
        if not link.startswith("naive+https://"):
            raise ValueError("Not a valid NaiveProxy link")

        try:
            # Remove naive+ prefix
            https_url = urllib.parse.unquote(link[6:])  # Remove "naive+"
            parsed_url = urllib.parse.urlparse(https_url)

            # Extract user and password
            username = parsed_url.username or ""
            password = parsed_url.password or ""

            # Create outbound configuration for sing-box
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

            # NaiveProxy always uses TLS
            outbound["tls"] = {"enabled": True, "server_name": parsed_url.hostname}

            return outbound
        except Exception as e:
            logger.error(f"Failed to parse NaiveProxy link: {str(e)}")
            raise ValueError(f"Invalid NaiveProxy format: {str(e)}")

    def generate_config(self, chain_proxy=None):
        """Generate sing-box configuration from link.

        Args:
            chain_proxy: Optional SingBoxProxy instance to chain through
        """
        try:
            # Determine the type of link and parse accordingly
            if self.config_url.startswith("vmess://"):
                outbound = self._parse_vmess_link(self.config_url)
            elif self.config_url.startswith("vless://"):
                outbound = self._parse_vless_link(self.config_url)
            elif self.config_url.startswith("ss://"):
                outbound = self._parse_shadowsocks_link(self.config_url)
            elif self.config_url.startswith("trojan://"):
                outbound = self._parse_trojan_link(self.config_url)
            elif self.config_url.startswith(("hy2://", "hysteria2://")):
                outbound = self._parse_hysteria2_link(self.config_url)
            elif self.config_url.startswith("hysteria://"):
                outbound = self._parse_hysteria_link(self.config_url)
            elif self.config_url.startswith("tuic://"):
                outbound = self._parse_tuic_link(self.config_url)
            elif self.config_url.startswith("wg://"):
                outbound = self._parse_wireguard_link(self.config_url)
            elif self.config_url.startswith("ssh://"):
                outbound = self._parse_ssh_link(self.config_url)
            elif self.config_url.startswith(("socks://", "socks4://", "socks5://")):
                outbound = self._parse_socks_link(self.config_url)
            elif self.config_url.startswith("naive+https://"):
                outbound = self._parse_naiveproxy_link(self.config_url)
            elif self.config_url.startswith(("http://", "https://")):
                outbound = self._parse_http_link(self.config_url)
            else:
                raise ValueError(f"Unsupported link type: {self.config_url[:15]}...")

            # Handle proxy chaining
            outbounds = [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

            if chain_proxy:
                # Add chain proxy outbound
                chain_outbound = (
                    {
                        "type": "socks",
                        "tag": "chain-proxy",
                        "server": "127.0.0.1",
                        "server_port": chain_proxy.socks_port,
                        "version": "5",
                    }
                    if chain_proxy.socks_port
                    else {
                        "type": "http",
                        "tag": "chain-proxy",
                        "server": "127.0.0.1",
                        "server_port": chain_proxy.http_port,
                    }
                )
                outbounds.append(chain_outbound)

                # Configure main proxy to use chain proxy
                outbound["detour"] = "chain-proxy"

            outbounds.insert(0, outbound)

            # Create a basic sing-box configuration with SOCKS and HTTP inbounds
            config = {
                "inbounds": [],
                "outbounds": outbounds,
            }

            if self.socks_port:
                config["inbounds"] += [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": self.socks_port, "users": []}
                ]
            if self.http_port:
                config["inbounds"] += [
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": self.http_port, "users": []}
                ]

            return config
        except Exception as e:
            logger.error(f"Error generating config: {str(e)}")
            raise

    @property
    def config(self) -> dict:
        """Return the current sing-box configuration as a dictionary."""
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to read config file: {str(e)}")
                raise
        else:
            raise FileNotFoundError("Configuration file not found. Please start the proxy first.")

    def create_config_file(self, content: str | dict | None = None) -> str:
        """Create a temporary file with the sing-box configuration."""
        if content is None:
            if self.config_file:
                if not os.path.exists(self.config_file):
                    raise FileNotFoundError(f"Specified config file does not exist: {self.config_file}")
                with open(self.config_file, "r") as f:
                    config = json.load(f)
            else:
                config = self.generate_config(self.chain_proxy)
        elif isinstance(content, str):
            config = json.loads(content)
        elif isinstance(content, dict):
            config = content
        else:
            raise TypeError("content must be None, str, or dict")

        # Log the generated config for debugging
        logger.debug(f"Generated sing-box config: {json.dumps(config, indent=2)}")

        # Create a temporary file for the configuration
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_file:
            temp_file_path = temp_file.name
            json_config = json.dumps(config, indent=2)
            temp_file.write(json_config.encode("utf-8"))
            logger.debug(f"Wrote config to {temp_file_path}")

        self.config_file = temp_file_path
        return temp_file_path

    def _check_proxy_ready(self, timeout=15):
        """Check if the proxy ports are actually accepting connections."""
        start_time = time.time()
        last_error = None

        def is_port_open(port):
            if not port:
                return False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.01)
                return s.connect_ex(("127.0.0.1", port)) == 0

        while time.time() - start_time < timeout:
            # First check if process is still running
            if self.singbox_process.poll() is not None:
                time.sleep(0.001)
                stdout = self.stdout
                stderr = self.stderr
                error_msg = (
                    f"sing-box process terminated early. Exit code: {self.singbox_process.returncode}\nStdout: {stdout}\nStderr: {stderr}"
                )
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            try:
                if is_port_open(self.socks_port) or is_port_open(self.http_port):
                    logger.debug("sing-box proxy is ready and accepting connections")
                    return True

            except Exception as e:
                last_error = str(e)
                logger.debug(f"Proxy not ready yet: {last_error}")

            time.sleep(0.001)

        # If we get here, the proxy didn't become ready in time
        if self.singbox_process.poll() is not None:
            stdout = self.stdout
            stderr = self.stderr
            error_msg = f"sing-box process terminated during initialization. Exit code: {self.singbox_process.returncode}\nStdout: {stdout}\nStderr: {stderr}"
        else:
            error_msg = f"Proxy failed to become ready within {timeout} seconds. Last error: {last_error}"

            # Try to read process output without terminating it
            try:
                # Check if there's any output available
                if self.stdout:
                    error_msg += f"\nStdout (partial): {self.stdout}"

                if self.stderr:
                    error_msg += f"\nStderr (partial): {self.stderr}"
            except Exception as e:
                error_msg += f"\nCould not read process output: {e}"

        logger.error(error_msg)
        raise TimeoutError(error_msg)

    def start(self):
        start_time = time.time()
        """Start the sing-box process with the generated configuration."""
        if self.running:
            logger.warning("sing-box process is already running")
            return

        try:
            if self.config_path:
                config_path = str(self.config_path)
            else:
                config_path = self.create_config_file()

            # Prepare command and environment
            cmd = [self.core.executable, "run", "-c", config_path]

            logger.debug(f"Starting sing-box with command: {' '.join(cmd)}")

            # Set up process creation flags for better process management
            kwargs = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "universal_newlines": True,
            }

            if os.name == "nt":
                kwargs["shell"] = True
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["preexec_fn"] = os.setsid  # Create new process group

            # Start sing-box process
            self.singbox_process = subprocess.Popen(cmd, **kwargs)
            self._process_terminated.clear()

            if self.singbox_process.stdout:
                self._stdout_thread = threading.Thread(
                    target=self._read_stream,
                    args=(self.singbox_process.stdout, self._stdout_lines),
                    daemon=True,
                )
                self._stdout_thread.start()
            if self.singbox_process.stderr:
                self._stderr_thread = threading.Thread(
                    target=self._read_stream,
                    args=(self.singbox_process.stderr, self._stderr_lines),
                    daemon=True,
                )
                self._stderr_thread.start()

            logger.debug(f"sing-box process started with PID {self.singbox_process.pid} in {time.time() - start_time:.2f} seconds")

            # Wait for the proxy to become ready
            try:
                self._check_proxy_ready(timeout=15)
                self.running = True
                logger.info(f"sing-box started successfully on SOCKS port {self.socks_port}, HTTP port {self.http_port}")
            except Exception:
                # If checking fails, terminate the process and raise the exception
                self._terminate_process(timeout=1)
                try:
                    # Wait for reader threads to finish
                    self._stdout_thread.join(timeout=1)
                    self._stderr_thread.join(timeout=1)
                    stdout = self.stdout
                    stderr = self.stderr
                    logger.error(f"sing-box output after failed start: Stdout: {stdout}, Stderr: {stderr}")
                except Exception:
                    pass
                raise
        except Exception as e:
            logger.error(f"Error starting sing-box: {str(e)}")
            self._safe_cleanup()
            raise

    def _join_reader_threads(self, timeout=2):
        """Wait for reader threads to finish."""
        for thread in (self._stdout_thread, self._stderr_thread):
            if thread and thread.is_alive():
                try:
                    thread.join(timeout=timeout)
                except Exception as e:
                    logger.debug(f"Error joining stream thread: {e}")
                if thread.is_alive():
                    logger.warning("stream reader thread did not finish within timeout")

    def stop(self):
        """Stop the sing-box process and clean up resources."""
        start_time = time.time()
        with self._cleanup_lock:
            if not self.running and self.singbox_process is None:
                return

            try:
                if self.singbox_process is not None:
                    success = self._terminate_process(timeout=1)
                    if not success:
                        logger.warning("sing-box process may not have terminated cleanly")

                self._join_reader_threads()

                self.running = False
                logger.info("sing-box process stopped")

            except Exception as e:
                logger.error(f"Error stopping sing-box: {str(e)}")
            finally:
                self._cleanup_internal()
        logger.debug(f"Sing-box stopped in {time.time() - start_time:.2f} seconds")

    def cleanup(self):
        """Clean up temporary files and resources."""
        self._safe_cleanup()

    def _safe_cleanup(self):
        """Thread-safe cleanup method."""
        with self._cleanup_lock:
            self._cleanup_internal()

    def _cleanup_internal(self):
        """Internal cleanup method - should only be called while holding the lock."""
        # Clean up temporary files
        if self.config_file:
            try:
                if os.path.exists(self.config_file):
                    os.unlink(self.config_file)
                    logger.debug(f"Removed config file: {self.config_file}")
            except Exception as e:
                logger.warning(f"Failed to remove config file {self.config_file}: {str(e)}")
            finally:
                self.config_file = None

        # Release allocated ports
        with _port_allocation_lock:
            if hasattr(self, "http_port") and self.http_port:
                _allocated_ports.discard(self.http_port)
            if hasattr(self, "socks_port") and self.socks_port:
                _allocated_ports.discard(self.socks_port)

        # Close std stream threads
        if self._stdout_thread and self._stdout_thread.is_alive():
            try:
                self._stdout_thread.join(timeout=0.5)
            except Exception as e:
                logger.debug(f"Error joining stdout thread during cleanup: {e}")

        if self._stderr_thread and self._stderr_thread.is_alive():
            try:
                self._stderr_thread.join(timeout=0.5)
            except Exception as e:
                logger.debug(f"Error joining stderr thread during cleanup: {e}")

        # Reset process reference
        self.singbox_process = None
        self.running = False
        self._stdout_lines.clear()
        self._stderr_lines.clear()
        self._stdout_thread = None
        self._stderr_thread = None

    def _terminate_process(self, timeout=2) -> bool:
        """
        Fast and reliable process termination with cross-platform support.

        Args:
            timeout (int): Maximum time to wait for graceful termination

        Returns:
            bool: True if process was terminated successfully
        """
        if self.singbox_process is None:
            return True

        try:
            # Check if process is already terminated
            if self.singbox_process.poll() is not None:
                self._process_terminated.set()
                return True

            pid = self.singbox_process.pid
            logger.debug(f"Terminating sing-box process (PID: {pid})")

            if os.name == "nt":
                return self._terminate_windows_process(pid, timeout)
            else:
                return self._terminate_unix_process(pid, timeout)

        except Exception as e:
            logger.error(f"Error terminating sing-box process: {e}")
            return False

    def _terminate_windows_process(self, pid, timeout):
        """Terminate process on Windows."""
        try:
            # Use psutil
            try:
                parent = psutil.Process(pid)
                children = parent.children(recursive=True)

                for child in children:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass

                parent.terminate()

                try:
                    parent.wait(timeout=timeout)
                    self._process_terminated.set()
                    return True
                except psutil.TimeoutExpired:
                    # Force kill if timeout
                    logger.warning("Process didn't terminate gracefully, force killing")
                    for child in children:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    parent.kill()
                    parent.wait(timeout=1)
                    self._process_terminated.set()
                    return True

            except psutil.NoSuchProcess:
                self._process_terminated.set()
                return True

        except ImportError:
            # Fallback to subprocess
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], check=False, capture_output=True, timeout=timeout)
                time.sleep(0.001)
                if self.singbox_process.poll() is not None:
                    self._process_terminated.set()
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Final fallback
            try:
                self.singbox_process.terminate()
                self.singbox_process.wait(timeout=timeout)
                self._process_terminated.set()
                return True
            except subprocess.TimeoutExpired:
                self.singbox_process.kill()
                self.singbox_process.wait(timeout=1)
                self._process_terminated.set()
                return True

    def _terminate_unix_process(self, pid, timeout):
        """Terminate process on Unix-like systems."""
        try:
            try:
                parent = psutil.Process(pid)
                children = parent.children(recursive=True)

                for child in children:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                parent.terminate()

                # Wait for graceful termination
                try:
                    parent.wait(timeout=timeout)
                    self._process_terminated.set()
                    return True
                except psutil.TimeoutExpired:
                    # Force kill if timeout
                    logger.warning("Process didn't terminate gracefully, sending SIGKILL")
                    for child in children:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    parent.kill()
                    parent.wait(timeout=1)
                    self._process_terminated.set()
                    return True

            except psutil.NoSuchProcess:
                # Process already terminated
                self._process_terminated.set()
                return True

        except ImportError:
            # Fallback without psutil
            try:
                # Create process group to manage child processes
                if hasattr(os, "killpg"):
                    try:
                        # Try to kill the entire process group
                        os.killpg(os.getpgid(pid), signal.SIGTERM)

                        # Wait for termination
                        start_time = time.time()
                        while time.time() - start_time < timeout:
                            if self.singbox_process.poll() is not None:
                                self._process_terminated.set()
                                return True
                            time.sleep(0.001)

                        # Force kill if timeout
                        os.killpg(os.getpgid(pid), signal.SIGKILL)
                        self.singbox_process.wait(timeout=1)
                        self._process_terminated.set()
                        return True

                    except (ProcessLookupError, OSError):
                        pass

                # Fallback to individual process termination
                self.singbox_process.terminate()
                try:
                    self.singbox_process.wait(timeout=timeout)
                    self._process_terminated.set()
                    return True
                except subprocess.TimeoutExpired:
                    self.singbox_process.kill()
                    self.singbox_process.wait(timeout=1)
                    self._process_terminated.set()
                    return True

            except (ProcessLookupError, OSError):
                # Process already terminated
                self._process_terminated.set()
                return True

    def _emergency_cleanup(self):
        """Emergency cleanup called by signal handler."""
        try:
            if self.singbox_process and self.singbox_process.poll() is None:
                if os.name == "nt":
                    # Windows - force kill immediately
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(self.singbox_process.pid)], check=False, capture_output=True, timeout=1
                        )
                    except Exception:
                        try:
                            self.singbox_process.kill()
                        except Exception:
                            pass
                elif sys.platform == "darwin":
                    # macOS: try to kill the process group first, fallback to killing the process.
                    try:
                        os.killpg(os.getpgid(self.singbox_process.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            # As an extra fallback, try a direct kill command
                            subprocess.run(
                                ["kill", "-9", str(self.singbox_process.pid)],
                                check=False,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=1,
                            )
                        except Exception:
                            try:
                                self.singbox_process.kill()
                            except Exception:
                                pass
                else:
                    # Unix - force kill process group
                    try:
                        os.killpg(os.getpgid(self.singbox_process.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            self.singbox_process.kill()
                        except Exception:
                            pass

            try:
                if self._stdout_thread and self._stdout_thread.is_alive():
                    self._stdout_thread.join(timeout=0.01)
                if self._stderr_thread and self._stderr_thread.is_alive():
                    self._stderr_thread.join(timeout=0.01)
            except Exception:
                pass
        except Exception:
            pass

    @property
    def socks5_proxy_url(self):
        """Get the SOCKS5 proxy URL."""
        if not self.socks_port:
            return None
        return f"socks5://127.0.0.1:{self.socks_port}"

    @property
    def socks_proxy_url(self):
        """Get the SOCKS5 proxy URL."""
        return self.socks5_proxy_url

    @property
    def http_proxy_url(self):
        """Get the HTTP proxy URL."""
        if not self.http_port:
            return None
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def usage_memory(self):
        """Get the memory usage of the sing-box process."""
        if self.singbox_process and self.singbox_process.pid:
            try:
                process = psutil.Process(self.singbox_process.pid)
                return process.memory_info().rss
            except Exception as exc:
                logger.error(f"Error getting memory usage: {exc}")
        return 0

    @property
    def usage_memory_mb(self):
        """Get the memory usage of the sing-box process in MB."""
        return self.usage_memory / (1024 * 1024)

    @property
    def usage_cpu(self):
        """Get the CPU usage of the sing-box process."""
        if self.singbox_process and self.singbox_process.pid:
            try:
                process = psutil.Process(self.singbox_process.pid)
                return process.cpu_percent(interval=1)
            except Exception as exc:
                logger.error(f"Error getting CPU usage: {exc}")
        return 0

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        try:
            self.stop()
            self.cleanup()
        except Exception as e:
            logger.error(f"Error during context manager cleanup: {e}")
        return False

    def __del__(self):
        """Ensure resources are cleaned up when the object is garbage collected."""
        try:
            if self.singbox_process and self.singbox_process.poll() is None:
                self._emergency_cleanup()
            self._safe_cleanup()
        except Exception:
            pass


def _import_request_module():
    try:
        import curl_cffi

        return curl_cffi
    except ImportError:
        try:
            import requests

            return requests
        except ImportError:
            return None


default_request_module = _import_request_module()


class SingBoxClient:
    "HTTP client for SingBox"

    def __init__(self, client=None, auto_retry: bool = True, retry_times: int = 2, timeout: int = 10, module=None):
        self.client = client
        self.proxy = client.proxy_for_requests if client else None
        self.auto_retry = auto_retry
        self.retry_times = retry_times
        self.timeout = timeout
        self.module = module or default_request_module
        self._session = None
        self._session_lock = threading.RLock()
        self._request_func = None

    def _ensure_request_callable(self):
        if self._request_func is None and self.module is not None:
            request_callable = getattr(self.module, "request", None)
            if request_callable is None:
                nested = getattr(self.module, "requests", None)
                if nested:
                    request_callable = getattr(nested, "request", None)
            self._request_func = request_callable
        return self._request_func

    def _get_session(self):
        if self.module is None:
            return None
        if self._session is not None:
            return self._session
        with self._session_lock:
            if self._session is not None:
                return self._session
            candidates = []
            for attr in ("Session", "session"):
                candidate = getattr(self.module, attr, None)
                if candidate:
                    candidates.append(candidate)
            nested = getattr(self.module, "requests", None)
            if nested:
                for attr in ("Session", "session"):
                    candidate = getattr(nested, attr, None)
                    if candidate:
                        candidates.append(candidate)
            for candidate in candidates:
                try:
                    session = candidate() if callable(candidate) else candidate
                except Exception:
                    continue
                if hasattr(session, "request"):
                    self._session = session
                    break
            return self._session

    def close(self):
        if self._session and hasattr(self._session, "close"):
            try:
                self._session.close()
            except Exception:
                pass
        self._session = None

    def request(self, method: str, url: str, **kwargs):
        "Make an HTTP request with retries"
        start_time = time.time()
        if self.module is None:
            raise ImportError("No HTTP request module available. Please install 'curl-cffi' or 'requests'.")
        request_callable = self._ensure_request_callable()
        if request_callable is None:
            raise ImportError("The configured request module does not expose a request() function.")
        session = self._get_session()
        if session and hasattr(session, "request"):
            request_callable = session.request

        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.timeout
        if kwargs.get("proxies") is None:
            kwargs["proxies"] = self.proxy

        base_kwargs = dict(kwargs)
        retry_times = base_kwargs.pop("retries", self.retry_times if self.auto_retry else 0)
        attempts = 0
        while attempts <= retry_times:
            try:
                response = request_callable(method=method, url=url, **dict(base_kwargs))
                response.raise_for_status()
                logger.debug(f"Request to {url} succeeded in {time.time() - start_time:.2f} seconds")
                return response
            except Exception as e:
                if attempts < retry_times:
                    attempts += 1
                    time.sleep(min(0.2 * attempts, 1))
                    continue
                logger.error(f"Request to {url} failed after {attempts} attempts: {str(e)} and {time.time() - start_time:.2f} seconds")
                raise e

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def __del__(self):
        "Ensure resources are cleaned up when the object is garbage collected."
        try:
            self.close()
        except Exception:
            pass
        if self.client:
            try:
                self.client.stop()
            except Exception:
                pass
