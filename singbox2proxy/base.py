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
import shutil
import sys
import importlib.util
from pathlib import Path
import re


_psutil_module = None
_pysocks_available = None


def _has_pysocks_support() -> bool:
    """Return True if pysocks (socks) is installed/importable."""
    global _pysocks_available
    if _pysocks_available is None:
        _pysocks_available = importlib.util.find_spec("socks") is not None
    return bool(_pysocks_available)


def _get_psutil():
    """Import psutil when needed.

    Returns:
        module | None: psutil module if available, else None.
    """
    global _psutil_module
    if _psutil_module is None:
        try:
            import psutil  # type: ignore

            _psutil_module = psutil
        except ImportError:
            _psutil_module = False
    return _psutil_module if _psutil_module is not False else None


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


class SystemProxyManager:
    """Cross-platform system proxy manager.

    Manages system-wide proxy settings on Windows, macOS, and Linux.
    Automatically saves and restores previous proxy settings.
    """

    def __init__(self):
        self.platform = sys.platform
        self.original_settings = None
        self._enabled = False

    def set_proxy(self, http_proxy: str = None, socks_proxy: str = None, bypass_list: list = None):
        """Set system proxy settings.

        Args:
            http_proxy: HTTP proxy URL (e.g., "http://127.0.0.1:8080")
            socks_proxy: SOCKS5 proxy URL (e.g., "socks5://127.0.0.1:1080")
            bypass_list: List of addresses to bypass (e.g., ["localhost", "127.0.0.1"])

        Returns:
            bool: True if successful, False otherwise
        """
        if self._enabled:
            logger.warning("System proxy already set. Call restore_proxy() first.")
            return False

        # Save current settings
        self.original_settings = self._get_current_settings()

        try:
            if self.platform == "win32":
                return self._set_windows_proxy(http_proxy, socks_proxy, bypass_list)
            elif self.platform == "darwin":
                return self._set_macos_proxy(http_proxy, socks_proxy, bypass_list)
            else:
                return self._set_linux_proxy(http_proxy, socks_proxy, bypass_list)
        except Exception as e:
            logger.error(f"Failed to set system proxy: {e}")
            return False

    def restore_proxy(self):
        """Restore original proxy settings.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self._enabled:
            logger.debug("System proxy not set, nothing to restore.")
            return True

        if self.original_settings is None:
            logger.warning("No original settings saved.")
            return False

        try:
            if self.platform == "win32":
                return self._restore_windows_proxy()
            elif self.platform == "darwin":
                return self._restore_macos_proxy()
            else:  # Linux
                return self._restore_linux_proxy()
        except Exception as e:
            logger.error(f"Failed to restore system proxy: {e}")
            return False
        finally:
            self._enabled = False
            self.original_settings = None

    def _get_current_settings(self):
        """Get current system proxy settings."""
        try:
            if self.platform == "win32":
                return self._get_windows_settings()
            elif self.platform == "darwin":
                return self._get_macos_settings()
            else:  # Linux
                return self._get_linux_settings()
        except Exception as e:
            logger.debug(f"Could not get current settings: {e}")
            return {}

    def _set_windows_proxy(self, http_proxy, socks_proxy, bypass_list):
        """Set Windows proxy via registry."""
        try:
            import winreg
        except ImportError:
            logger.error("winreg module not available (Windows only)")
            return False

        try:
            # Open registry key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE
            )

            # Enable proxy
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)

            # Set proxy server
            if http_proxy:
                # Extract host:port from URL
                proxy_url = urllib.parse.urlparse(http_proxy)
                proxy_addr = f"{proxy_url.hostname}:{proxy_url.port}"
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_addr)

            # Set bypass list
            if bypass_list:
                bypass_str = ";".join(bypass_list)
            else:
                bypass_str = "localhost;127.*;10.*;172.16.*;172.31.*;192.168.*"
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass_str)

            winreg.CloseKey(key)

            # Notify system of settings change
            self._notify_windows_settings_change()

            self._enabled = True
            logger.info(f"Windows system proxy set to {http_proxy}")
            return True

        except Exception as e:
            logger.error(f"Failed to set Windows proxy: {e}")
            return False

    def _restore_windows_proxy(self):
        """Restore Windows proxy settings."""
        try:
            import winreg
        except ImportError:
            return False

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE
            )

            # Restore settings
            if self.original_settings:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, self.original_settings.get("ProxyEnable", 0))
                if "ProxyServer" in self.original_settings:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self.original_settings["ProxyServer"])
                if "ProxyOverride" in self.original_settings:
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self.original_settings["ProxyOverride"])
            else:
                # Disable proxy
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

            winreg.CloseKey(key)
            self._notify_windows_settings_change()

            logger.info("Windows system proxy restored")
            return True

        except Exception as e:
            logger.error(f"Failed to restore Windows proxy: {e}")
            return False

    def _get_windows_settings(self):
        """Get current Windows proxy settings."""
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ
            )

            settings = {}
            try:
                settings["ProxyEnable"] = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                settings["ProxyEnable"] = 0

            try:
                settings["ProxyServer"] = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                pass

            try:
                settings["ProxyOverride"] = winreg.QueryValueEx(key, "ProxyOverride")[0]
            except FileNotFoundError:
                pass

            winreg.CloseKey(key)
            return settings

        except Exception as e:
            logger.debug(f"Could not get Windows settings: {e}")
            return {}

    def _notify_windows_settings_change(self):
        """Notify Windows of Internet settings change."""
        try:
            import ctypes

            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception as e:
            logger.debug(f"Could not notify Windows of settings change: {e}")

    def _set_macos_proxy(self, http_proxy, socks_proxy, bypass_list):
        """Set macOS proxy via networksetup."""
        try:
            # Get active network service
            result = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=True)

            # Find active service (usually Wi-Fi or Ethernet)
            services = [line.strip() for line in result.stdout.split("\n")[1:] if line.strip() and not line.startswith("*")]

            if not services:
                logger.error("No network services found")
                return False

            # Use first available service
            service = services[0]
            logger.debug(f"Using network service: {service}")

            success = True

            if http_proxy:
                proxy_url = urllib.parse.urlparse(http_proxy)
                # Set HTTP proxy
                result = subprocess.run(
                    ["networksetup", "-setwebproxy", service, proxy_url.hostname, str(proxy_url.port)], capture_output=True, text=True
                )
                if result.returncode != 0:
                    logger.error(f"Failed to set HTTP proxy: {result.stderr}")
                    success = False
                else:
                    # Enable HTTP proxy
                    subprocess.run(["networksetup", "-setwebproxystate", service, "on"], capture_output=True, text=True)

                # Set HTTPS proxy (same as HTTP)
                subprocess.run(
                    ["networksetup", "-setsecurewebproxy", service, proxy_url.hostname, str(proxy_url.port)], capture_output=True, text=True
                )
                subprocess.run(["networksetup", "-setsecurewebproxystate", service, "on"], capture_output=True, text=True)

            if socks_proxy:
                proxy_url = urllib.parse.urlparse(socks_proxy)
                result = subprocess.run(
                    ["networksetup", "-setsocksfirewallproxy", service, proxy_url.hostname, str(proxy_url.port)],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    logger.error(f"Failed to set SOCKS proxy: {result.stderr}")
                    success = False
                else:
                    subprocess.run(["networksetup", "-setsocksfirewallproxystate", service, "on"], capture_output=True, text=True)

            # Set bypass domains
            if bypass_list:
                bypass_str = " ".join([f'"{domain}"' for domain in bypass_list])
            else:
                bypass_str = '"localhost" "127.0.0.1" "*.local"'

            subprocess.run(f'networksetup -setproxybypassdomains "{service}" {bypass_str}', shell=True, capture_output=True, text=True)

            if success:
                self._enabled = True
                self.original_settings["service"] = service
                logger.info(f"macOS system proxy set on service: {service}")

            return success

        except Exception as e:
            logger.error(f"Failed to set macOS proxy: {e}")
            return False

    def _restore_macos_proxy(self):
        """Restore macOS proxy settings."""
        try:
            service = self.original_settings.get("service")
            if not service:
                # Try to get current service
                result = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=True)
                services = [line.strip() for line in result.stdout.split("\n")[1:] if line.strip() and not line.startswith("*")]
                if services:
                    service = services[0]
                else:
                    logger.error("No network service found")
                    return False

            # Disable proxies
            subprocess.run(["networksetup", "-setwebproxystate", service, "off"], capture_output=True, text=True)
            subprocess.run(["networksetup", "-setsecurewebproxystate", service, "off"], capture_output=True, text=True)
            subprocess.run(["networksetup", "-setsocksfirewallproxystate", service, "off"], capture_output=True, text=True)

            logger.info(f"macOS system proxy restored on service: {service}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore macOS proxy: {e}")
            return False

    def _get_macos_settings(self):
        """Get current macOS proxy settings."""
        settings = {}
        try:
            result = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=True)
            services = [line.strip() for line in result.stdout.split("\n")[1:] if line.strip() and not line.startswith("*")]
            if services:
                settings["service"] = services[0]
        except Exception as e:
            logger.debug(f"Could not get macOS settings: {e}")

        return settings

    def _set_linux_proxy(self, http_proxy, socks_proxy, bypass_list):
        """Set Linux proxy via environment variables and GNOME/KDE settings."""
        # For Linux, we'll set environment variables and try to configure
        # GNOME/KDE settings if available

        success = False

        # Try GNOME settings (gsettings)
        try:
            if http_proxy:
                proxy_url = urllib.parse.urlparse(http_proxy)

                subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], capture_output=True, text=True, check=True)
                subprocess.run(
                    ["gsettings", "set", "org.gnome.system.proxy.http", "host", proxy_url.hostname],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(proxy_url.port)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.system.proxy.https", "host", proxy_url.hostname],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(proxy_url.port)],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                if bypass_list:
                    bypass_str = str(bypass_list)
                else:
                    bypass_str = "['localhost', '127.0.0.0/8', '::1']"

                subprocess.run(
                    ["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", bypass_str], capture_output=True, text=True, check=True
                )

                success = True
                logger.info("GNOME system proxy set")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug(f"GNOME settings not available or failed: {e}")

        # Try KDE settings (kwriteconfig5)
        try:
            if http_proxy and not success:
                proxy_url = urllib.parse.urlparse(http_proxy)
                proxy_str = f"http://{proxy_url.hostname}:{proxy_url.port}"

                subprocess.run(
                    ["kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    ["kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", proxy_str],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                subprocess.run(
                    ["kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", proxy_str],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                # Notify KDE of changes
                subprocess.run(
                    ["dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''"],
                    capture_output=True,
                    text=True,
                )

                success = True
                logger.info("KDE system proxy set")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug(f"KDE settings not available or failed: {e}")

        if not success:
            logger.warning(
                "Could not set system proxy via GNOME or KDE. "
                "You may need to set environment variables manually: "
                f"export http_proxy={http_proxy} https_proxy={http_proxy}"
            )

        self._enabled = success
        return success

    def _restore_linux_proxy(self):
        """Restore Linux proxy settings."""
        success = False

        # Try GNOME
        try:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], capture_output=True, text=True, check=True)
            success = True
            logger.info("GNOME system proxy restored")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.debug("GNOME settings not available")

        # Try KDE
        try:
            subprocess.run(
                ["kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0"],
                capture_output=True,
                text=True,
                check=True,
            )
            subprocess.run(
                ["dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''"],
                capture_output=True,
                text=True,
            )
            success = True
            logger.info("KDE system proxy restored")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.debug("KDE settings not available")

        return success

    def _get_linux_settings(self):
        """Get current Linux proxy settings."""
        return {}  # Linux settings vary too much to reliably store/restore


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

    if os.name != "nt":
        signal.signal(signal.SIGTERM, cleanup_handler)
        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGHUP, cleanup_handler)
    else:
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
    """Manages the sing-box executable and its lifecycle.

    This class is responsible for locating, installing (if needed), and providing
    access to the sing-box executable. It handles automatic detection of sing-box
    in the system PATH, and can automatically install it via package managers or
    the official installation script if not found.

    The class provides methods to:
    - Check if sing-box is installed and accessible
    - Get version information
    - Run sing-box commands
    - Install sing-box automatically via various methods

    Attributes:
        executable (str): Path or command name of the sing-box executable.

    Example:
        Using default core (auto-detect or install):
        >>> core = SingBoxCore()
        >>> print(core.version)
        1.8.0
        >>> print(core.is_available())
        True

        Using custom executable path:
        >>> core = SingBoxCore(executable="/usr/local/bin/sing-box")
        >>> info = core.get_version_info()
        >>> print(info['version'])

        Running sing-box commands:
        >>> result = core.run_command(["check", "-c", "config.json"])
        >>> print(result.returncode)
    """

    def __init__(self, executable: os.PathLike = None):
        """Initialize a SingBoxCore instance.

        Args:
            executable: Optional path to a specific sing-box executable. If provided,
                       the file must exist. If None, the class will attempt to find
                       sing-box in PATH or install it automatically.

        Raises:
            FileNotFoundError: If a custom executable path is provided but doesn't exist.

        Note:
            When no executable is specified, this will attempt to:
            1. Find sing-box in system PATH
            2. Install via official install.sh script (Unix-like systems)
            3. Install via package managers (apt, dnf, pacman, brew, etc.)
        """
        start_time = time.time()
        if executable and not os.path.exists(executable):
            raise FileNotFoundError(f"Custom set sing-box executable not found: {executable}")
        if executable:
            logger.info(f"Using custom sing-box executable: {executable}")
        self.executable = executable or self._ensure_executable()
        logger.debug(f"SingBoxCore initialized in {time.time() - start_time:.2f} seconds")

    def _ensure_executable(self) -> str:
        """Ensure that the sing-box executable is available.

        This method attempts to locate or install sing-box through multiple strategies:
        1. Check if sing-box is available in system PATH
        2. Install via official install.sh script (Unix-like systems only)
        3. Install via package managers (apt, dnf, pacman, brew, scoop, etc.)

        Returns:
            str: Path or command name to the sing-box executable, or None if not found.

        Note:
            Installation attempts are logged at INFO level. If all methods fail,
            a warning is logged and None is returned.
        """

        def _test_terminal() -> bool:
            """Check if sing-box is accessible from terminal.

            Attempts to run 'sing-box version' command to verify availability.
            On Windows, also checks for 'sing-box.exe'.

            Returns:
                bool: True if sing-box is accessible and working, False otherwise.
            """
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
            Not available on Windows systems.

            Args:
                beta: If True, install the beta version instead of stable.
                version: Specific version to install (e.g., "1.12.8"). If None, installs latest.
                use_sudo: If True, prepends sudo to the install command (for non-root users).
                install_url: URL of the installation script (default: official sing-box script).

            Returns:
                bool: True if installation succeeded, False otherwise.

            Raises:
                RuntimeError: If the installation script cannot be downloaded.
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
            """Attempt to install sing-box using common package managers.

            Supports multiple package managers across different platforms:
            - Windows: scoop, choco, winget
            - macOS: brew
            - Linux: apt, dnf, yum, pacman, yay, paru, apk, nix-env, pkg

            The function will attempt all available package managers until one succeeds.
            Commands requiring root privileges will automatically use sudo if available.

            Returns:
                bool: True if installation succeeded via any package manager, False otherwise.
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

        def _env_bool(*names: str, default: bool = False) -> bool:
            truthy = {"1", "true", "yes", "on", "y", "t"}
            falsy = {"0", "false", "no", "off", "n", "f"}
            for name in names:
                val = os.getenv(name)
                if val is None:
                    continue
                v = val.strip().lower()
                if v in truthy:
                    return True
                if v in falsy:
                    return False
            return default

        def _env_str(*names: str) -> str | None:
            for name in names:
                val = os.getenv(name)
                if val and val.strip():
                    return val.strip()
            return None

        def _get_installed_version() -> str | None:
            """Try to obtain the currently installed sing-box version via CLI."""
            try:
                kwargs = {"capture_output": True, "text": True, "timeout": 2}
                if os.name == "nt":
                    kwargs["shell"] = True
                result = subprocess.run(["sing-box", "version"], **kwargs)
                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.splitlines():
                        if "version" in line.lower():
                            return line.strip()
                    return result.stdout.strip()
            except Exception:
                pass
            return None

        def _normalize_version(ver: str | None) -> str | None:
            if not ver:
                return None
            # extract semantic version like 1.12.9
            m = re.search(r"(\d+\.\d+\.\d+)", ver)
            if m:
                return m.group(1)
            # fallback: strip leading 'v' and whitespace
            return ver.strip().lstrip("vV") if ver else None

        def _uninstall_via_package_manager() -> bool:
            """Attempt to uninstall sing-box using package managers. Returns True if any succeeded."""
            logger.info("Attempting to uninstall existing sing-box via package manager")
            cmds: list[list[str]] = []

            try:
                if os.name == "nt":
                    if shutil.which("scoop"):
                        cmds.append(["scoop", "uninstall", "sing-box"])
                    if shutil.which("choco"):
                        cmds.append(["choco", "uninstall", "sing-box", "-y"])
                    if shutil.which("winget"):
                        cmds.append(["winget", "uninstall", "sing-box", "--accept-package-agreements", "--accept-source-agreements"])
                elif sys.platform == "darwin":
                    if shutil.which("brew"):
                        cmds.append(["brew", "uninstall", "sing-box"])
                else:
                    # Arch family
                    if shutil.which("paru"):
                        cmds.append(["paru", "-Rns", "--noconfirm", "sing-box"])
                    if shutil.which("yay"):
                        cmds.append(["yay", "-Rns", "--noconfirm", "sing-box"])
                    if shutil.which("pacman"):
                        cmds.append(["pacman", "-Rns", "--noconfirm", "sing-box"])

                    # Debian/Ubuntu
                    if shutil.which("apt"):
                        cmds.append(["apt", "remove", "-y", "sing-box"])
                        cmds.append(["apt", "purge", "-y", "sing-box"])
                    if shutil.which("apt-get"):
                        cmds.append(["apt-get", "remove", "-y", "sing-box"])
                        cmds.append(["apt-get", "purge", "-y", "sing-box"])

                    # Alpine
                    if shutil.which("apk"):
                        cmds.append(["apk", "del", "sing-box"])

                    # Fedora / RHEL
                    if shutil.which("dnf"):
                        cmds.append(["dnf", "remove", "-y", "sing-box"])
                    if shutil.which("yum"):
                        cmds.append(["yum", "remove", "-y", "sing-box"])

                    # Nix
                    if shutil.which("nix-env"):
                        # Try both possible names
                        cmds.append(["nix-env", "-e", "sing-box"])
                        cmds.append(["nix-env", "-e", "nixos.sing-box"])

                    # Termux / FreeBSD pkg
                    if shutil.which("pkg"):
                        cmds.append(["pkg", "delete", "-y", "sing-box"])

                    # Linuxbrew
                    if shutil.which("brew"):
                        cmds.append(["brew", "uninstall", "sing-box"])
            except Exception as e:
                logger.warning(f"Error preparing uninstall commands: {e}")
                return False

            any_success = False
            root_required = {"apt", "apt-get", "pacman", "dnf", "yum", "apk", "pkg"}
            for cmd in cmds:
                final_cmd = list(cmd)
                if cmd and cmd[0] in root_required:
                    needs_sudo = False
                    try:
                        if hasattr(os, "geteuid") and os.geteuid() != 0:
                            needs_sudo = True
                    except Exception:
                        needs_sudo = True
                    if needs_sudo:
                        sudo_path = shutil.which("sudo")
                        if sudo_path:
                            final_cmd.insert(0, sudo_path)
                        else:
                            logger.info(f"Skipping uninstall needing root (sudo not found): {' '.join(cmd)}")
                            continue
                try:
                    logger.info(f"Running uninstall: {' '.join(final_cmd)}")
                    proc = subprocess.run(final_cmd, capture_output=True, text=True, timeout=600)
                    if proc.returncode == 0:
                        any_success = True
                        logger.info("Uninstall command reported success")
                        break
                    else:
                        logger.debug(f"Uninstall failed ({proc.returncode}): {proc.stderr or proc.stdout}")
                except Exception as e:
                    logger.debug(f"Error running uninstall {' '.join(final_cmd)}: {e}")
            return any_success

        # Read optional install.sh configuration and force flags from environment
        beta_flag = _env_bool("SINGBOX_BETA_ENABLED", "SINGBOX_BETA", "SINGBOX_INSTALL_BETA", default=False)
        version_str = _env_str("SINGBOX_VERSION", "SINGBOX_INSTALL_VERSION")
        use_sudo_flag = _env_bool("SINGBOX_INSTALL_SUDO", "SINGBOX_SUDO", default=False)
        install_url = _env_str("SINGBOX_INSTALL_URL") or "https://sing-box.app/install.sh"
        force_flag = _env_bool(
            "SINGBOX_FORCE_VERSION",
            "SINGBOX_FORCE_REINSTALL",
            "SINGBOX_FORCE",
            "SINGBOX_FORCE_UPDATE",
            default=False,
        )
        force_beta_flag = _env_bool("SINGBOX_FORCE_BETA", default=False)

        # If already available, optionally enforce desired version/beta
        if _test_terminal():
            if force_flag or force_beta_flag:
                current_raw = _get_installed_version()
                current_norm = _normalize_version(current_raw)
                desired_norm = _normalize_version(version_str) if version_str else None

                should_reinstall = False
                if version_str and desired_norm and current_norm and desired_norm != current_norm:
                    should_reinstall = True
                    logger.info(f"Forcing reinstall to version {version_str} (current: {current_raw or current_norm})")
                elif version_str and desired_norm and not current_norm:
                    should_reinstall = True
                    logger.info(f"Forcing reinstall to version {version_str} (current version unknown)")
                elif not version_str and beta_flag and force_beta_flag:
                    should_reinstall = True
                    logger.info("Forcing reinstall to latest beta version")

                if should_reinstall:
                    # Best-effort uninstall first, then install desired
                    try:
                        _uninstall_via_package_manager()
                    except Exception as e:
                        logger.debug(f"Uninstall attempt skipped/failed: {e}")

                    try:
                        if _install_via_sh(
                            beta=beta_flag and not version_str, version=version_str, use_sudo=use_sudo_flag, install_url=install_url
                        ):
                            # Verify
                            if _test_terminal():
                                new_ver = _normalize_version(_get_installed_version())
                                if (version_str and new_ver == desired_norm) or (not version_str and beta_flag):
                                    return "sing-box"
                    except Exception as e:
                        logger.warning(f"Forced reinstall via install.sh failed: {e}")

                    # If forced and we couldn't ensure, fall through to try package manager install
            return "sing-box"

        # Attempt install via install.sh using env configuration
        try:
            if beta_flag or version_str or use_sudo_flag or os.getenv("SINGBOX_INSTALL_URL"):
                logger.info(
                    "Using install.sh with env overrides: beta=%s, version=%s, sudo=%s, url=%s",
                    beta_flag,
                    version_str,
                    use_sudo_flag,
                    install_url,
                )
            if _install_via_sh(beta=beta_flag and not version_str, version=version_str, use_sudo=use_sudo_flag, install_url=install_url):
                if _test_terminal():
                    # If a specific version was requested, verify match when force is set
                    if version_str and force_flag:
                        installed_norm = _normalize_version(_get_installed_version())
                        desired_norm = _normalize_version(version_str)
                        if installed_norm != desired_norm:
                            logger.warning(f"Requested version {version_str} not detected after install.sh (installed: {installed_norm}).")
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
        """Internal method to retrieve sing-box version string.

        Returns:
            str | None: Version string if available, None otherwise.
        """
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
        """Get the sing-box executable version.

        Returns:
            str | None: Version string (e.g., "1.12.8") or None if unavailable.

        Example:
            >>> core = SingBoxCore()
            >>> print(core.version)
            1.8.0
        """
        return self._version()

    def is_available(self) -> bool:
        """Check if the sing-box executable is available and working.

        Returns:
            bool: True if sing-box can be executed, False otherwise.

        Example:
            >>> core = SingBoxCore()
            >>> if core.is_available():
            ...     print("sing-box is ready to use")
        """
        return self.executable is not None and self._version() is not None

    def get_version_info(self) -> dict:
        """Get detailed version information from sing-box.

        Parses the version output to extract structured information including
        version number, build tags, and other metadata if available.

        Returns:
            dict: Dictionary containing version information with keys:
                  - 'version': Version string
                  - 'raw': Raw version output
                  - 'available': Boolean indicating if sing-box is working

        Example:
            >>> core = SingBoxCore()
            >>> info = core.get_version_info()
            >>> print(f"Version: {info['version']}")
            >>> print(f"Available: {info['available']}")
        """
        version_str = self._version()
        return {
            "version": version_str,
            "raw": version_str,
            "available": version_str is not None,
            "executable": self.executable,
        }

    def run_command(self, args: list[str] | str, timeout: int = 30, **kwargs) -> subprocess.CompletedProcess:
        """Run a sing-box command with the specified arguments.

        Args:
            args: List of command arguments (e.g., ["check", "-c", "config.json"]).
            timeout: Maximum time in seconds to wait for command completion.
            **kwargs: Additional keyword arguments to pass to subprocess.run.

        Returns:
            subprocess.CompletedProcess: Result of the command execution.

        Raises:
            RuntimeError: If sing-box executable is not available.
            subprocess.TimeoutExpired: If the command times out.
            subprocess.CalledProcessError: If check=True and command fails.

        Example:
            >>> core = SingBoxCore()
            >>> result = core.run_command(["check", "-c", "config.json"])
            >>> if result.returncode == 0:
            ...     print("Config is valid")
        """
        if not self.executable:
            raise RuntimeError("sing-box executable is not available")

        if isinstance(args, str):
            args = [args]
        cmd = [self.executable] + args

        # Set defaults for kwargs
        kwargs.setdefault("timeout", timeout)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)

        if os.name == "nt":
            kwargs.setdefault("shell", True)

        return subprocess.run(cmd, **kwargs)

    def run_command_output(self, args: list[str] | str, timeout: int = 30, **kwargs) -> str:
        """Run a sing-box command and return its standard output as a string.

        Args:
            args: List of command arguments (e.g., ["version"]).
            timeout: Maximum time in seconds to wait for command completion.
            **kwargs: Additional keyword arguments to pass to subprocess.run.

        Returns:
            str: Standard output from the command execution.

        Raises:
            RuntimeError: If sing-box executable is not available.
            subprocess.TimeoutExpired: If the command times out.
            subprocess.CalledProcessError: If check=True and command fails.

        Example:
            >>> core = SingBoxCore()
            >>> version_output = core.run_command_output(["version"])
            >>> print(version_output)
        """
        result = self.run_command(args, timeout=timeout, **kwargs)
        return result.stdout if result.stdout else ""

    def check_config(self, config_path: os.PathLike | str) -> tuple[bool, str]:
        """Check if a sing-box configuration file is valid.

        Args:
            config_path: Path to the configuration file to validate.

        Returns:
            tuple[bool, str]: A tuple of (is_valid, message) where is_valid is True
                            if the config is valid, and message contains output or error info.

        Example:
            >>> core = SingBoxCore()
            >>> is_valid, msg = core.check_config("config.json")
            >>> if is_valid:
            ...     print("Configuration is valid")
            >>> else:
            ...     print(f"Configuration error: {msg}")
        """
        if not self.executable:
            return False, "sing-box executable is not available"

        try:
            result = self.run_command(["check", "-c", str(config_path)], timeout=10)
            if result.returncode == 0:
                return True, result.stdout or "Configuration is valid"
            else:
                return False, result.stderr or result.stdout or "Configuration check failed"
        except subprocess.TimeoutExpired:
            return False, "Configuration check timed out"
        except Exception as e:
            return False, f"Error checking configuration: {e}"

    def format_config(self, config_path: os.PathLike | str, output_path: os.PathLike | str = None) -> tuple[bool, str]:
        """Format a sing-box configuration file.

        Args:
            config_path: Path to the configuration file to format.
            output_path: Optional path to write formatted config. If None, formats in-place.

        Returns:
            tuple[bool, str]: A tuple of (success, message).

        Example:
            >>> core = SingBoxCore()
            >>> success, msg = core.format_config("config.json")
            >>> print(msg)
        """
        if not self.executable:
            return False, "sing-box executable is not available"

        try:
            args = ["format", "-c", str(config_path)]
            if output_path:
                args.extend(["-w", str(output_path)])
            else:
                args.append("-w")

            result = self.run_command(args, timeout=10)
            if result.returncode == 0:
                return True, "Configuration formatted successfully"
            else:
                return False, result.stderr or result.stdout or "Format failed"
        except Exception as e:
            return False, f"Error formatting configuration: {e}"

    def __repr__(self) -> str:
        """Return a detailed string representation of the SingBoxCore instance.

        Returns:
            str: String representation showing executable path and version.
        """
        version = self._version()
        return f"<SingBoxCore executable={self.executable!r} version={version!r}>"

    def __str__(self) -> str:
        """Return a readble string representation.

        Returns:
            str: String showing version or unavailable status.
        """
        version = self._version()
        if version:
            return f"SingBoxCore(version={version})"
        return "SingBoxCore(unavailable)"


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
    """A wrapper class for managing sing-box proxy instances.

    This class provides a high-level interface for creating and managing sing-box proxy servers.
    It supports multiple proxy protocols (VMess, VLESS, Shadowsocks, Trojan, Hysteria, etc.) and
    can automatically parse proxy links or use existing configuration files.

    The proxy can operate in two modes:
    - Active mode (default): Automatically starts the sing-box process upon initialization
    - Config-only mode: Only generates configuration without starting the process

    Features:
    - Automatic port allocation for HTTP and SOCKS5 proxies
    - Proxy chaining support (route through another proxy)
    - Built-in HTTP client with automatic proxy configuration
    - Process lifecycle management with signal handling
    - Cross-platform support (Windows, macOS, Linux)

    Example:
        Basic usage with a proxy link:
        >>> proxy = SingBoxProxy("vmess://base64encodedconfig")
        >>> print(proxy.http_proxy_url)
        http://127.0.0.1:12345

        Using with requests library:
        >>> import requests
        >>> proxy = SingBoxProxy("ss://...")
        >>> response = requests.get("https://api.ipify.org", proxies=proxy.proxies)

        Context manager usage:
        >>> with SingBoxProxy("vless://...") as proxy:
        ...     response = proxy.get("https://example.com")

        Custom ports and config file:
        >>> proxy = SingBoxProxy(
        ...     config="/path/to/config.json",
        ...     http_port=8080,
        ...     socks_port=1080
        ... )
    """

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
        tun_enabled: bool = False,
        tun_address: str = "172.19.0.1/30",
        tun_stack: str = "system",
        tun_mtu: int = 9000,
        tun_auto_route: bool = True,
        set_system_proxy: bool = False,
        route: dict = None,
        relay_protocol: str = None,
        relay_host: str = None,
        relay_port: int = None,
        relay_name: str = None,
        uuid_seed: str = None,
    ):
        """Initialize a SingBoxProxy instance.

        Args:
            config: Either a proxy link (vmess://, vless://, ss://, trojan://, etc.) or a path
                   to a sing-box configuration file. Proxy links will be automatically parsed
                   into sing-box configuration format.
            http_port: Port for HTTP proxy server. If None, an unused port is automatically
                      selected. Set to False to disable HTTP proxy.
            socks_port: Port for SOCKS5 proxy server. If None, an unused port is automatically
                       selected. Set to False to disable SOCKS5 proxy.
            chain_proxy: Optional SingBoxProxy instance to chain through. When set, all traffic
                        from this proxy will be routed through the specified chain proxy.
            config_only: If True, only generate configuration without starting the sing-box
                        process. Useful for inspecting or modifying configuration before starting.
            config_file: Path where the generated configuration file should be saved. If None,
                        a temporary file will be created.
            config_directory: Working directory for the sing-box process. If None, uses the
                            system temporary directory.
            client: Custom SingBoxClient instance for HTTP requests. If None, a default client
                   is created. Set to False to disable client creation.
            core: Custom SingBoxCore instance specifying the sing-box executable. If None,
                 uses the default core (which auto-detects or installs sing-box).
            tun_enabled: If True, creates a TUN interface for system-wide VPN. Requires
                        root/administrator privileges. Default is False.
            tun_address: IPv4 address and prefix for the TUN interface. Default is "172.19.0.1/30".
            tun_stack: TUN stack implementation. Options: "system", "gvisor", "mixed". Default is "system".
            tun_mtu: Maximum Transmission Unit for TUN interface. Default is 9000.
            tun_auto_route: If True, automatically configure system routing rules. Default is True.
            set_system_proxy: If True, automatically configure system-wide proxy settings to use
                            this proxy. Settings are restored when the proxy is stopped. Default is False.
            route: Optional dictionary containing sing-box routing rules. This corresponds to the
                  "route" section in the sing-box configuration.
            relay_protocol: If set, enables relay mode using the specified protocol
                            (e.g., "vmess", "ss", "trojan").
            relay_host: Hostname or IP address of the relay server.
            relay_port: Port of the relay server. If None, an unused port is automatically selected
            relay_name: Optional name identifier for the relay connection. Defaults to "nichind.dev|singbox2proxy-relay".
            uuid_seed: Optional seed string for generating consistent UUIDs in relay mode.

        Raises:
            TypeError: If config is not a string or path-like object.
            FileNotFoundError: If a custom executable is specified but doesn't exist.
            RuntimeError: If sing-box fails to start or ports cannot be allocated.
            ValueError: If proxy link format is invalid or unsupported.

        Note:
            When config is a proxy link (e.g., "vmess://..."), self.config_url will be set
            and self.config_path will be None. When config is a file path, self.config_path
            will be set and self.config_url will be None.
        """
        start_time = time.time()
        self._original_config = config

        # Allow None config for direct connection relay
        if config is None:
            self.config_url = None
            self.config_path = None
        # Distinguish between URL and local path
        elif isinstance(config, (str,)):
            parsed = urllib.parse.urlparse(config)
            # Treat strings that parse to a URL with a scheme and a network location as URLs.
            # This handles proxy link schemes like vless://, vmess://, ss://, trojan://, etc.
            # It also avoids misclassifying Windows paths like "C:\\path" which have a scheme but no netloc.
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

        # TUN configuration
        self.tun_enabled = tun_enabled
        self.tun_address = tun_address
        self.tun_stack = tun_stack
        self.tun_mtu = tun_mtu
        self.tun_auto_route = tun_auto_route
        self.set_system_proxy = set_system_proxy
        self.route = route

        # System proxy configuration
        self._system_proxy_manager = None

        # Relay configuration
        self.relay_protocol = relay_protocol
        self.relay_host = relay_host
        self.relay_port = relay_port or (self._pick_unused_port([self.http_port, self.socks_port]) if relay_protocol else None)
        self.relay_url = None
        self.relay_name = relay_name or "nichind.dev|singbox2proxy-relay"
        self.uuid_seed = uuid_seed
        self._relay_credentials = {}  # Store credentials for URL generation

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
        """Return a readable string representation of the proxy instance.

        Returns a formatted string showing the current status and proxy URLs if running,
        or the configured ports if stopped.

        Returns:
            str: Status string.

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> print(proxy)
            SingBoxProxy(running, socks=socks5://127.0.0.1:1080, http=http://127.0.0.1:8080)
        """
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
    def proxy_for_requests(self):
        """Get a proxies dictionary suitable for the requests library.

        Returns a dictionary with 'http' and 'https' keys pointing to the proxy URL,
        formatted for use with the requests library's proxies parameter. Prefers the
        HTTP inbound when available and falls back to the SOCKS inbound.

        Returns:
            dict: Dictionary with 'http' and 'https' keys mapping to proxy URLs.

        Raises:
            RuntimeError: If no proxy ports are available.

        Example:
            >>> proxy = SingBoxProxy("ss://...")
            >>> import requests
            >>> response = requests.get("https://api.ipify.org", proxies=proxy.proxy_for_requests)
            >>> print(response.text)  # Your proxied IP address
        """
        http_url = self.http_proxy_url
        socks_url = self.socks5_proxy_url

        if http_url:
            return {"http": http_url, "https": http_url}
        if socks_url:
            return {"http": socks_url, "https": socks_url}

        raise RuntimeError("No HTTP or SOCKS proxy ports are enabled. Provide http_port or socks_port when creating SingBoxProxy.")

    @property
    def proxies(self):
        """Alias for proxy_for_requests property.

        Returns:
            dict: Dictionary with 'http' and 'https' keys mapping to proxy URLs.

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> requests.get("https://example.com", proxies=proxy.proxies)
        """
        return self.proxy_for_requests

    @property
    def stdout(self) -> str:
        """Get the captured stdout from the sing-box process.

        Returns all standard output text produced by the sing-box process since it started.

        Returns:
            str: All stdout output from the sing-box process.
        """
        return "".join(self._stdout_lines)

    @property
    def stderr(self) -> str:
        """Get the captured stderr from the sing-box process.

        Returns all standard error text produced by the sing-box process since it started.

        Returns:
            str: All stderr output from the sing-box process.
        """
        return "".join(self._stderr_lines)

    def _generate_deterministic_uuid(self, seed: str, suffix: str = "") -> str:
        """Generate a deterministic UUID from a seed string.

        Args:
            seed: The seed string to generate UUID from
            suffix: Optional suffix to append to seed for different UUIDs

        Returns:
            str: A valid UUID v5 string
        """
        import uuid

        # Use UUID5 with a namespace for deterministic generation
        namespace = uuid.NAMESPACE_DNS
        combined_seed = f"{seed}{suffix}"
        return str(uuid.uuid5(namespace, combined_seed))

    def _generate_deterministic_password(self, seed: str, length: int = 16) -> str:
        """Generate a deterministic password from a seed string.

        Args:
            seed: The seed string to generate password from
            length: Length of the password (for shadowsocks compatibility)

        Returns:
            str: A deterministic password
        """
        import hashlib

        # Generate deterministic password from seed
        hash_obj = hashlib.sha256(seed.encode())
        # Take hex digest and truncate to desired length
        return hash_obj.hexdigest()[:length]

    def _get_public_ip(self) -> str:
        """Get the public IP address of this machine.

        Attempts multiple methods to determine the public IP:
        1. Query external IP detection services
        2. Use local network interface IP as fallback

        Returns:
            str: The public or local IP address, defaults to "0.0.0.0" if all methods fail.
        """
        # Try external IP services
        services = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
        ]

        for service in services:
            try:
                response = urllib.request.urlopen(service, timeout=3)
                ip = response.read().decode("utf-8").strip()
                if ip:
                    logger.debug(f"Detected public IP: {ip}")
                    return ip
            except Exception as e:
                logger.debug(f"Failed to get IP from {service}: {e}")
                continue

        # Fallback to local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            logger.debug(f"Using local IP: {ip}")
            return ip
        except Exception as e:
            logger.debug(f"Failed to get local IP: {e}")

        return "0.0.0.0"

    def _generate_relay_url(self, protocol: str, host: str, port: int) -> str:
        """Generate a shareable proxy URL based on the protocol.

        Args:
            protocol: The proxy protocol (vmess, trojan, ss, socks, http)
            host: The host/IP address
            port: The port number

        Returns:
            str: A shareable proxy URL
        """
        if protocol == "vmess":
            # Use stored UUID
            user_id = self._relay_credentials.get("uuid", "")
            vmess_config = {
                "v": "2",
                "ps": self.relay_name,
                "add": host,
                "port": str(port),
                "id": user_id,
                "aid": "0",
                "net": "tcp",
                "type": "none",
                "host": "",
                "path": "",
                "tls": "",
            }
            vmess_json = json.dumps(vmess_config)
            vmess_b64 = base64.b64encode(vmess_json.encode()).decode()
            return f"vmess://{vmess_b64}"

        elif protocol == "trojan":
            # Use stored password
            password = self._relay_credentials.get("password", "")
            name = urllib.parse.quote(self.relay_name)
            return f"trojan://{password}@{host}:{port}#{name}"

        elif protocol in ("ss", "shadowsocks"):
            # Use stored password
            password = self._relay_credentials.get("password", "")
            method = "aes-128-gcm"
            userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
            name = urllib.parse.quote(self.relay_name)
            return f"ss://{userinfo}@{host}:{port}#{name}"

        elif protocol == "socks":
            # Generate SOCKS5 URL: socks5://host:port
            return f"socks5://{host}:{port}"

        elif protocol == "http":
            # Generate HTTP URL: http://host:port
            return f"http://{host}:{port}"

        else:
            raise ValueError(f"Unsupported relay protocol: {protocol}")

    def _generate_relay_inbound(self) -> dict:
        """Generate an inbound configuration for the relay server.

        Returns:
            dict: Sing-box inbound configuration for the relay protocol
        """
        import uuid

        protocol = self.relay_protocol
        port = self.relay_port

        if protocol == "vmess":
            if self.uuid_seed:
                user_id = self._generate_deterministic_uuid(self.uuid_seed, "vmess")
            else:
                user_id = str(uuid.uuid4())
            self._relay_credentials["uuid"] = user_id
            return {
                "type": "vmess",
                "tag": "relay-in",
                "listen": "0.0.0.0",
                "listen_port": port,
                "users": [{"uuid": user_id, "alterId": 0}],
            }

        elif protocol == "trojan":
            if self.uuid_seed:
                password = self._generate_deterministic_password(self.uuid_seed + "trojan", 36)
            else:
                password = str(uuid.uuid4())
            self._relay_credentials["password"] = password
            return {"type": "trojan", "tag": "relay-in", "listen": "0.0.0.0", "listen_port": port, "users": [{"password": password}]}

        elif protocol in ("ss", "shadowsocks"):
            if self.uuid_seed:
                password = self._generate_deterministic_password(self.uuid_seed + "shadowsocks", 16)
            else:
                password = str(uuid.uuid4())[:16]
            self._relay_credentials["password"] = password
            return {
                "type": "shadowsocks",
                "tag": "relay-in",
                "listen": "0.0.0.0",
                "listen_port": port,
                "method": "aes-128-gcm",
                "password": password,
            }

        elif protocol == "socks":
            return {"type": "socks", "tag": "relay-in", "listen": "0.0.0.0", "listen_port": port, "users": []}

        elif protocol == "http":
            return {"type": "http", "tag": "relay-in", "listen": "0.0.0.0", "listen_port": port, "users": []}

        else:
            logger.warning(f"Unsupported relay protocol: {protocol}")
            return None

    def _read_stream(self, stream, collector):
        """Read a stream line by line and append to a collector list.

        Internal method that runs in a background thread to continuously capture
        stdout/stderr from the sing-box process

        Args:
            stream: File-like object to read from.
            collector: List to append captured lines to.
        """
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
        """Check if a TCP port is currently in use by trying to bind to it.

        Args:
            port: Port number to check (1-65535).

        Returns:
            bool: True if the port is in use, False if it's available.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("localhost", port))
                return False
        except (socket.error, OSError):
            return True

    @classmethod
    def _pick_unused_port(cls, exclude_port: int | list = None) -> int:
        """Automatically select an unused TCP port for proxy services.

        First attempts to get a system-assigned ephemeral port, then falls back to
        randomly trying ports in the range 10000-65535 if that fails. Thread-safe
        with global port allocation tracking to prevent conflicts.

        Args:
            exclude_port: Single port number or list of port numbers to avoid.
                         Already allocated ports are automatically excluded.

        Returns:
            int: An available port number.

        Raises:
            RuntimeError: If no unused port could be found after 100 attempts.
        """
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
                    s.bind(("", 0))  # Let OS choose a free port on all interfaces
                    _, port = s.getsockname()
                    if port not in exclude_port:
                        _allocated_ports.add(port)
                        return port
            except Exception as e:
                logger.warning(f"Failed to get system-assigned port: {str(e)}")

            # If that fails, try a few random ports
            for _ in range(100):
                port = random.randint(10000, 65535)
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
        """Generate a sing-box configuration from a proxy link.

        Automatically parses the proxy link provided during initialization and converts it
        into a complete sing-box configuration with appropriate inbound and outbound settings.

        Args:
            chain_proxy: Optional SingBoxProxy instance to chain through. When provided,
                        this proxy will route all traffic through the specified chain proxy.
                        Not all protocols support chaining, refer to the https://sing-box.sagernet.org/configuration/inbound/

        Returns:
            dict: Complete sing-box configuration dictionary ready to be serialized to JSON.

        Raises:
            ValueError: If the proxy link format is invalid or unsupported.
            RuntimeError: If configuration generation fails.

        Supported Protocols:
            - VMess (vmess://)
            - VLESS (vless://)
            - Shadowsocks (ss://)
            - Trojan (trojan://)
            - Hysteria v1 (hysteria://)
            - Hysteria v2 (hy2://, hysteria2://)
            - TUIC (tuic://)
            - WireGuard (wg://)
            - SSH (ssh://)
            - SOCKS (socks://, socks4://, socks5://)
            - HTTP/HTTPS (http://, https://)
            - NaiveProxy (naive+https://)

        Note:
            This method is automatically called during initialization unless config_only=False.
            The generated configuration includes SOCKS5 and/or HTTP inbound servers on the
            configured ports.
        """
        try:
            # Handle direct connection relay (no proxy URL provided)
            if self.config_url is None:
                # Create direct outbound for relay
                outbound = {"type": "direct", "tag": "proxy"}
            # Determine the type of link and parse accordingly
            elif self.config_url.startswith("vmess://"):
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

            # Add route section if provided
            if self.route:
                config["route"] = self.route

            # Add TUN inbound if enabled
            if self.tun_enabled:
                tun_inbound = {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "tun0",
                    "address": [self.tun_address] if isinstance(self.tun_address, str) else self.tun_address,
                    "mtu": self.tun_mtu,
                    "auto_route": self.tun_auto_route,
                    "strict_route": True,
                    "stack": self.tun_stack,
                    "sniff": True,
                    "sniff_override_destination": False,
                }
                config["inbounds"].append(tun_inbound)

            if self.socks_port:
                config["inbounds"] += [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": self.socks_port, "users": []}
                ]
            if self.http_port:
                config["inbounds"] += [
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": self.http_port, "users": []}
                ]

            # Add relay inbound if enabled
            if self.relay_protocol and self.relay_port:
                relay_inbound = self._generate_relay_inbound()
                if relay_inbound:
                    config["inbounds"].append(relay_inbound)

                    # Generate the shareable URL
                    host = self.relay_host or self._get_public_ip()
                    self.relay_url = self._generate_relay_url(self.relay_protocol, host, self.relay_port)

            return config
        except Exception as e:
            logger.error(f"Error generating config: {str(e)}")
            raise

    @property
    def config(self) -> dict:
        """Return the current sing-box configuration as a dictionary.

        Reads and parses the configuration file used by the running sing-box instance.

        Returns:
            dict: The complete sing-box configuration.

        Raises:
            FileNotFoundError: If the configuration file doesn't exist.
            JSONDecodeError: If the configuration file contains invalid JSON.

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> config = proxy.config
            >>> print(config['outbounds'][0]['type'])
            vmess
        """
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
        """Create a temporary file with sing-box configuration.

        Generates a configuration file from the provided content or from the instance's
        config settings. The file is created with a .json extension.

        Args:
            content: Configuration content. Can be:
                    - None: Auto-generate from self.config_file or self.generate_config()
                    - str: JSON string to parse and write
                    - dict: Configuration dictionary to serialize

        Returns:
            str: Absolute path to the created configuration file.

        Raises:
            TypeError: If content is not None, str, or dict.
            JSONDecodeError: If content string is not valid JSON.

        Note:
            The created file is tracked in self.config_file and will be automatically
            cleaned up when the proxy is stopped or destroyed.
        """
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
        """Check if the proxy ports are actually accepting connections.

        Polls the configured proxy ports to verify they're accepting connections,
        indicating that sing-box has successfully started and is ready to proxy traffic.

        Args:
            timeout: Maximum seconds to wait for the proxy to become ready (default: 15).

        Raises:
            RuntimeError: If the sing-box process terminates unexpectedly.
            TimeoutError: If the proxy doesn't become ready within the timeout period.

        Note:
            This method is automatically called by start() and should not normally be
            called directly. It uses rapid polling (1ms intervals) for fast startup detection.
        """
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

    def _setup_system_proxy(self):
        """Setup system-wide proxy settings."""
        try:
            self._system_proxy_manager = SystemProxyManager()

            http_proxy_url = None
            socks_proxy_url = None

            if self.http_port:
                http_proxy_url = f"http://127.0.0.1:{self.http_port}"

            if self.socks_port:
                socks_proxy_url = f"socks5://127.0.0.1:{self.socks_port}"

            # Use HTTP proxy if available, otherwise SOCKS
            if http_proxy_url:
                success = self._system_proxy_manager.set_proxy(
                    http_proxy=http_proxy_url, bypass_list=["localhost", "127.0.0.1", "::1", "*.local"]
                )
            elif socks_proxy_url:
                success = self._system_proxy_manager.set_proxy(
                    socks_proxy=socks_proxy_url, bypass_list=["localhost", "127.0.0.1", "::1", "*.local"]
                )
            else:
                logger.warning("No proxy ports available to set as system proxy")
                return

            if success:
                logger.info(f"System proxy configured: {http_proxy_url or socks_proxy_url}")
            else:
                logger.warning("Failed to configure system proxy")

        except Exception as e:
            logger.error(f"Error setting up system proxy: {e}")

    def _restore_system_proxy(self):
        """Restore original system proxy settings."""
        try:
            if self._system_proxy_manager:
                success = self._system_proxy_manager.restore_proxy()
                if success:
                    logger.info("System proxy settings restored")
                else:
                    logger.warning("Failed to restore system proxy settings")
                self._system_proxy_manager = None
        except Exception as e:
            logger.error(f"Error restoring system proxy: {e}")

    def start(self):
        """Start the sing-box process with the generated configuration.

        Launches the sing-box executable as a subprocess with the appropriate configuration.
        The process is monitored in background threads that capture stdout and stderr.
        This method blocks until the proxy is confirmed to be accepting connections.

        Raises:
            RuntimeError: If sing-box is already running, or if the process fails to start.
            TimeoutError: If the proxy doesn't become ready within 15 seconds.
            FileNotFoundError: If the sing-box executable cannot be found.

        Note:
            This method is automatically called during __init__ unless config_only=True.
            The proxy status can be checked via the 'running' attribute.

        Example:
            >>> proxy = SingBoxProxy("vmess://...", config_only=True)
            >>> # Do something with config
            >>> proxy.start()
            >>> print(proxy.running)
            True
        """
        start_time = time.time()
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

                # Set system proxy if requested
                if self.set_system_proxy:
                    self._setup_system_proxy()

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
        """Wait for reader threads to finish.

        Joins the stdout and stderr reader threads, allowing them to complete their
        cleanup gracefully before proceeding with process termination.

        Args:
            timeout: Maximum seconds to wait for each thread (default: 2).
        """
        for thread in (self._stdout_thread, self._stderr_thread):
            if thread and thread.is_alive():
                try:
                    thread.join(timeout=timeout)
                except Exception as e:
                    logger.debug(f"Error joining stream thread: {e}")
                if thread.is_alive():
                    logger.warning("stream reader thread did not finish within timeout")

    def stop(self):
        """Stop the sing-box process and clean up resources.

        Gracefully terminates the sing-box process, waits for reader threads to finish,
        and performs cleanup. This method is thread-safe and idempotent (safe to call
        multiple times).

        The method will:
        1. Terminate the sing-box process (with escalation to kill if needed)
        2. Join stdout/stderr reader threads
        3. Set running=False
        4. Call internal cleanup

        Note:
            This method is automatically called by __exit__ (context manager) and __del__.
            Manual calls are only needed if you want to stop the proxy before the object
            is destroyed.

        Example:
            >>> proxy = SingBoxProxy("ss://...")
            >>> # Use proxy...
            >>> proxy.stop()
            >>> print(proxy.running)
            False
        """
        start_time = time.time()
        with self._cleanup_lock:
            if not self.running and self.singbox_process is None:
                return

            try:
                # Restore system proxy if it was set
                if self._system_proxy_manager:
                    self._restore_system_proxy()

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
        """Clean up temporary files and resources.

        Public method to trigger cleanup of configuration files and release allocated ports.
        This is a thread-safe wrapper around the internal cleanup method.

        Note:
            Cleanup is automatically performed by stop(), __exit__, and __del__.
            Manual calls are rarely needed.
        """
        self._safe_cleanup()

    def _safe_cleanup(self):
        """Thread-safe cleanup method.

        Acquires the cleanup lock before calling the internal cleanup method to ensure
        thread safety during resource cleanup.
        """
        with self._cleanup_lock:
            self._cleanup_internal()

    def _cleanup_internal(self):
        """Internal cleanup method - should only be called while holding the lock.

        Performs the actual cleanup operations:
        - Removes temporary configuration files
        - Releases allocated ports from the global port registry
        - Joins and cleans up reader threads
        - Resets process references and state

        Warning:
            This method assumes the cleanup lock is already held and should not be
            called directly. Use cleanup() or _safe_cleanup() instead.
        """
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
        """Gracefully terminates the sing-box process using the most appropriate method
        for the current platform. Uses psutil for superior process management when available,
        with fallbacks if psutil is not installed.

        The termination strategy:
        1. Check if process is already terminated
        2. Use platform-specific termination (Windows or Unix)
        3. Attempt graceful termination (SIGTERM)
        4. Escalate to forceful termination (SIGKILL) if needed
        5. Handle child processes recursively

        Args:
            timeout: Maximum time in seconds to wait for graceful termination before
                    escalating to forceful kill (default: 2).

        Returns:
            bool: True if process was terminated successfully, False otherwise.

        Note:
            This method handles process groups to ensure all child processes are also
            terminated. On Windows, uses taskkill for reliable termination.
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
        """Terminate process on Windows.

        Uses psutil if available for better process tree management, otherwise falls
        back to taskkill command and finally to Python's subprocess.terminate().

        Args:
            pid: Process ID to terminate.
            timeout: Maximum seconds to wait for graceful termination.

        Returns:
            bool: True if termination was successful.
        """
        ps = _get_psutil()
        if ps is not None:
            try:
                parent = ps.Process(pid)
                children = parent.children(recursive=True)

                for child in children:
                    try:
                        child.terminate()
                    except ps.NoSuchProcess:
                        pass

                parent.terminate()

                try:
                    parent.wait(timeout=timeout)
                    self._process_terminated.set()
                    return True
                except ps.TimeoutExpired:
                    # Force kill if timeout
                    logger.warning("Process didn't terminate gracefully, force killing")
                    for child in children:
                        try:
                            child.kill()
                        except ps.NoSuchProcess:
                            pass
                    parent.kill()
                    parent.wait(timeout=1)
                    self._process_terminated.set()
                    return True
            except ps.NoSuchProcess:
                self._process_terminated.set()
                return True
            except Exception as e:
                logger.debug(f"psutil termination path failed, falling back: {e}")

        # Fallback to subprocess / default methods
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
        """Terminate process on Unix-like systems.

        Uses psutil if available for better process tree management, otherwise falls
        back to process groups (killpg) and signal-based termination. Handles Linux,
        macOS, BSD, and other Unix-like systems.

        Args:
            pid: Process ID to terminate.
            timeout: Maximum seconds to wait for graceful termination.

        Returns:
            bool: True if termination was successful.
        """
        ps = _get_psutil()
        if ps is not None:
            try:
                parent = ps.Process(pid)
                children = parent.children(recursive=True)

                for child in children:
                    try:
                        child.terminate()
                    except ps.NoSuchProcess:
                        pass
                parent.terminate()

                # Wait for graceful termination
                try:
                    parent.wait(timeout=timeout)
                    self._process_terminated.set()
                    return True
                except ps.TimeoutExpired:
                    # Force kill if timeout
                    logger.warning("Process didn't terminate gracefully, sending SIGKILL")
                    for child in children:
                        try:
                            child.kill()
                        except ps.NoSuchProcess:
                            pass
                    parent.kill()
                    parent.wait(timeout=1)
                    self._process_terminated.set()
                    return True
            except ps.NoSuchProcess:
                self._process_terminated.set()
                return True
            except Exception as e:
                logger.debug(f"psutil unix termination path failed, falling back: {e}")

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
        """Emergency cleanup called by signal handler.

        Performs minimal cleanup operations when the process is being terminated by
        a signal (SIGTERM, SIGINT, SIGHUP). Uses platform-specific methods to force
        terminate the sing-box process without waiting.

        Note:
            Automatically registered as a signal handler during initialization.
            Should not be called directly under normal circumstances.
        """
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
        """Get the SOCKS5 proxy URL.

        Returns:
            str: SOCKS5 URL in the format "socks5://127.0.0.1:port", or None if SOCKS5 is disabled.

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> print(proxy.socks5_proxy_url)
            socks5://127.0.0.1:1080
        """
        if not self.socks_port:
            return None
        return f"socks5://127.0.0.1:{self.socks_port}"

    @property
    def socks_proxy_url(self):
        """Get the SOCKS5 proxy URL.

        Alias for socks5_proxy_url property.

        Returns:
            str: SOCKS5 URL in the format "socks5://127.0.0.1:port", or None if SOCKS5 is disabled.
        """
        return self.socks5_proxy_url

    @property
    def http_proxy_url(self):
        """Get the HTTP proxy URL.

        Returns:
            str: HTTP URL in the format "http://127.0.0.1:port", or None if HTTP proxy is disabled.

        Example:
            >>> proxy = SingBoxProxy("ss://...")
            >>> print(proxy.http_proxy_url)
            http://127.0.0.1:8080
        """
        if not self.http_port:
            return None
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def usage_memory(self):
        """Get the memory usage of the sing-box process in bytes.

        Requires psutil to be installed. Returns 0 if psutil is not available or
        if the process is not running.

        Returns:
            int: Memory usage in bytes (RSS - Resident Set Size).

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> print(f"Memory: {proxy.usage_memory / 1024 / 1024:.2f} MB")
            Memory: 45.23 MB
        """
        try:
            process = self.psutil_process
            if process:
                return process.memory_info().rss
        except Exception as exc:
            logger.debug(f"Error getting memory usage: {exc}")
        return 0

    @property
    def usage_memory_mb(self):
        """Get the memory usage of the sing-box process in megabytes.

        Convenience property that returns memory usage in MB instead of bytes.

        Returns:
            float: Memory usage in megabytes.

        Example:
            >>> proxy = SingBoxProxy("ss://...")
            >>> print(f"Memory: {proxy.usage_memory_mb:.2f} MB")
            Memory: 45.23 MB
        """
        return self.usage_memory / (1024 * 1024)

    @property
    def usage_cpu(self):
        """Get the CPU usage percentage of the sing-box process.

        Requires psutil to be installed. Returns 0 if psutil is not available or
        if the process is not running. The percentage can exceed 100% on multi-core systems.

        Returns:
            float: CPU usage as a percentage (0.0 to N*100.0 where N is the number of cores).

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> print(f"CPU: {proxy.usage_cpu:.1f}%")
            CPU: 2.5%
        """
        try:
            process = self.psutil_process
            if process:
                return process.cpu_percent(interval=1)
        except Exception as exc:
            logger.debug(f"Error getting CPU usage: {exc}")
        return 0

    @property
    def psutil_process(self) -> object | None:
        if self.singbox_process and self.singbox_process.pid:
            ps = _get_psutil()
            if ps is not None:
                try:
                    process = ps.Process(self.singbox_process.pid)
                    return process
                except Exception as exc:
                    logger.debug(f"Error getting psutil process: {exc}")
        logger.debug("psutil not available or process not running")
        return None

    @property
    def latency_ms(self):
        """Measure latency to a known endpoint through the proxy.

        Uses the configured HTTP client to measure the round-trip time to a known
        endpoint (https://api.ipify.org) through the proxy. Requires the HTTP client
        to be properly configured with the proxy settings.

        Returns:
            float: Latency in milliseconds, or None if measurement fails.

        Example:
            >>> proxy = SingBoxProxy("vmess://...")
            >>> latency = proxy.latency_ms
            >>> if latency is not None:
            ...     print(f"Latency: {latency:.2f} ms")
            ... else:
            ...     print("Latency measurement failed")
        """
        if not self.running or not self.client:
            logger.debug("Proxy not running or HTTP client not configured")
            return None
        try:
            start_time = time.time()
            response = self.client.get("https://api.ipify.org", timeout=5)
            if response.status_code == 200:
                latency = (time.time() - start_time) * 1000  # Convert to milliseconds
                return latency
            else:
                logger.debug(f"Unexpected status code during latency check: {response.status_code}")
                return None
        except Exception as e:
            logger.debug(f"Error measuring latency: {e}")
            return None

    def __enter__(self):
        """Context manager entry.

        Allows using SingBoxProxy with the 'with' statement for automatic cleanup.

        Returns:
            SingBoxProxy: Returns self for use in the context.

        Example:
            >>> with SingBoxProxy("vmess://...") as proxy:
            ...     response = proxy.get("https://api.ipify.org")
            ...     print(response.text)
            # Proxy is automatically stopped and cleaned up after the block
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit.

        Automatically stops the proxy and cleans up resources when exiting the 'with' block.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_val: Exception value if an exception occurred, None otherwise.
            exc_tb: Exception traceback if an exception occurred, None otherwise.

        Returns:
            bool: False to propagate any exception that occurred in the context.
        """
        try:
            self.stop()
            self.cleanup()
        except Exception as e:
            logger.error(f"Error during context manager cleanup: {e}")
        return False

    def __del__(self):
        """Ensure resources are cleaned up when the object is garbage collected.

        Automatically called when the object is about to be destroyed. Performs
        emergency cleanup to ensure the sing-box process is terminated and all
        resources are released.

        Note:
            While this provides a safety net, it's better to explicitly call stop()
            or use the context manager pattern for predictable cleanup timing.
        """
        try:
            if self.singbox_process and self.singbox_process.poll() is None:
                self._emergency_cleanup()
            self._safe_cleanup()
        except Exception:
            pass


def _import_request_module():
    try:
        import curl_cffi  # type: ignore

        return curl_cffi
    except ImportError:
        try:
            import requests

            return requests
        except ImportError:
            return None


default_request_module = _import_request_module()


class SingBoxClient:
    """HTTP client for making requests through SingBox proxies.

    This class provides an interface for making HTTP requests through a SingBoxProxy
    instance. It automatically configures proxy settings, handles retries, and supports both
    curl-cffi and requests libraries as backends.

    The client uses connection pooling via sessions and supports
    automatic retry logic with exponential backoff. It can be used standalone or as part
    of a SingBoxProxy instance.

    Example:
        Basic usage with SingBoxProxy:
        >>> proxy = SingBoxProxy("vmess://...")
        >>> client = SingBoxClient(client=proxy)
        >>> response = client.get("https://api.ipify.org")
        >>> print(response.text)

        Standalone usage with custom retry settings:
        >>> client = SingBoxClient(auto_retry=True, retry_times=5, timeout=30)
        >>> response = client.post("https://example.com/api", json={"key": "value"})

        Context manager usage:
        >>> with SingBoxClient(client=proxy) as client:
        ...     response = client.get("https://example.com")
        ...     print(response.status_code)

        Custom module usage:
        >>> import requests
        >>> client = SingBoxClient(module=requests, timeout=20)
    """

    def __init__(
        self,
        client=None,
        auto_retry: bool = True,
        retry_times: int = 2,
        timeout: int = 10,
        module=None,
        proxies: dict | None = None,
    ):
        """Initialize a SingBoxClient instance.

        Args:
            client: Optional SingBoxProxy instance to use for proxy configuration.
                   If provided, the client will automatically use this proxy's settings
                   for all requests.
            auto_retry: Enable automatic retry on failed requests. When True, failed
                       requests will be retried up to retry_times attempts with
                       exponential backoff (default: True).
            retry_times: Maximum number of retry attempts for failed requests. Only
                        applies if auto_retry is True (default: 2).
            timeout: Default timeout in seconds for all requests. Can be overridden
                    per request by passing timeout in kwargs (default: 10).
            module: HTTP library to use for making requests. Can be curl_cffi.requests
                   or requests. If None, will auto-detect available library, preferring
                   curl-cffi (default: None).
            proxies: Explicit proxies mapping to use (same format as requests). When
                     provided, it overrides any proxy provided by the SingBoxProxy instance.

        Raises:
            ImportError: If no suitable HTTP request module is available.

        Note:
            The client preferentially uses curl-cffi if available, falling back to
            requests. Install either 'curl-cffi' or 'requests' package to use this client.
        """
        self.client = client
        self._proxy_override = proxies
        self.proxy = proxies
        self.auto_retry = auto_retry
        self.retry_times = retry_times
        self.timeout = timeout
        self.module = module or default_request_module
        self._session = None
        self._session_lock = threading.RLock()
        self._request_func = None

    def _set_parent(self, proxy: "SingBoxProxy"):
        """Attach this client to a SingBoxProxy instance without re-instantiation."""
        self.client = proxy
        self.proxy = None
        return self

    def _ensure_request_callable(self):
        """Ensure that a request callable function is available from the module.

        Internal method that locates and caches the request function from the configured
        HTTP library module. Handles both direct module attributes and nested attributes
        (e.g., curl_cffi.requests.request).

        Returns:
            callable | None: The request function if found, None otherwise.

        Note:
            This method caches the result in self._request_func for performance.
        """
        if self._request_func is None and self.module is not None:
            request_callable = getattr(self.module, "request", None)
            if request_callable is None:
                nested = getattr(self.module, "requests", None)
                if nested:
                    request_callable = getattr(nested, "request", None)
            self._request_func = request_callable
        return self._request_func

    def _get_session(self):
        """Get or create a session object for connection pooling.

        Internal method that lazily creates and caches a session object from the
        configured HTTP library. Sessions provide connection pooling for better
        performance on multiple requests. This method is thread-safe.

        Returns:
            Session | None: Session object if available, None otherwise.

        Note:
            The session is cached in self._session and reused across requests.
            Supports both requests.Session and curl_cffi.requests.Session.
        """
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

    def _get_proxy_mapping(self):
        """Resolve the proxy configuration for outbound HTTP requests."""
        if self._proxy_override is not None:
            self.proxy = self._proxy_override
            return self._proxy_override
        if self.client:
            mapping = self.client.proxy_for_requests
            self.proxy = mapping
            return mapping
        self.proxy = None
        return None

    @staticmethod
    def _proxies_require_socks(proxies) -> bool:
        if not proxies:
            return False
        for value in proxies.values():
            if isinstance(value, str) and value.lower().startswith("socks"):
                return True
        return False

    def _request_backend_supports_socks(self) -> bool:
        if self.module is None:
            return False
        module_name = getattr(self.module, "__name__", self.module.__class__.__name__).lower()
        if module_name.startswith("curl_cffi"):
            return True
        if "requests" in module_name:
            return self._has_pysocks()
        return True

    @staticmethod
    def _has_pysocks() -> bool:
        return _has_pysocks_support()

    def _validate_proxy_support(self, proxies):
        if not proxies:
            raise RuntimeError("No proxy mapping provided to SingBoxClient.")
        if not self._proxies_require_socks(proxies):
            return
        if not self._request_backend_supports_socks():
            raise RuntimeError(
                "SOCKS proxies require the 'pysocks' package when using requests. "
                "Install pysocks or enable the HTTP inbound port to avoid leaking traffic."
            )

    def close(self):
        """Close the session and release resources.

        Closes the underlying HTTP session if it exists, releasing any pooled
        connections. This method is automatically called by __del__ and __exit__,
        but can be called manually if needed.

        Note:
            After calling close(), a new session will be created on the next request.
            This method is thread-safe.
        """
        if self._session and hasattr(self._session, "close"):
            try:
                self._session.close()
            except Exception:
                pass
        self._session = None

    def request(self, method: str, url: str, **kwargs):
        """Make an HTTP request with automatic retry logic.

        Core method for making HTTP requests through the configured proxy (if any).
        Supports automatic retries with exponential backoff on failures. Automatically
        configures timeout and proxy settings if not explicitly provided.

        Args:
            method: HTTP method to use (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, etc.).
            url: Target URL for the request.
            **kwargs: Additional arguments to pass to the underlying request function.
                     Common arguments include:
                     - headers (dict): HTTP headers
                     - data: Request body (for POST, PUT, etc.)
                     - json: JSON data to send (automatically sets Content-Type)
                     - params (dict): URL query parameters
                     - timeout (int/float): Override default timeout
                     - proxies (dict): Override default proxy settings
                     - retries (int): Override default retry count for this request
                     - verify (bool): SSL certificate verification (default: True)
                     - allow_redirects (bool): Follow redirects (default: True)

        Returns:
            Response: HTTP response object from the underlying library.

        Raises:
            ImportError: If no HTTP request module is available.
            HTTPError: If the request fails after all retry attempts.
            Timeout: If the request times out.
            ConnectionError: If connection to the server fails.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.request("GET", "https://api.ipify.org")
            >>> print(response.text)

            >>> response = client.request("POST", "https://example.com/api",
            ...                          json={"key": "value"},
            ...                          headers={"Authorization": "Bearer token"})

            >>> # Disable retries for a specific request
            >>> response = client.request("GET", "https://example.com", retries=0)

        Note:
            - Retries use exponential backoff: 0.2s, 0.4s, 0.6s, ... up to 1s max
            - The 'retries' kwarg overrides the instance's retry_times setting
            - Failed requests that exhaust retries will raise the last exception
        """
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

        proxies = kwargs.get("proxies")
        if proxies is None:
            proxies = self._get_proxy_mapping()
            if proxies is None:
                raise RuntimeError("No proxy configuration available. Attach a SingBoxProxy instance or pass proxies= explicitly.")
            kwargs["proxies"] = proxies

        self._validate_proxy_support(kwargs["proxies"])

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
        """Make a GET request.

        Method for making GET requests. Equivalent to calling
        request("GET", url, **kwargs).

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.get("https://api.ipify.org")
            >>> print(response.text)

            >>> # With query parameters
            >>> response = client.get("https://example.com/api", params={"key": "value"})
        """
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        """Make a POST request.

        Method for making POST requests. Equivalent to calling
        request("POST", url, **kwargs).

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request(). Common kwargs:
                     - data: Form data or raw body
                     - json: JSON data (automatically sets Content-Type)
                     - files: Files to upload

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.post("https://example.com/api", json={"key": "value"})

            >>> # With form data
            >>> response = client.post("https://example.com/form",
            ...                       data={"field1": "value1", "field2": "value2"})
        """
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        """Make a PUT request.

        Method for making PUT requests. Equivalent to calling
        request("PUT", url, **kwargs).

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.put("https://example.com/api/resource/123",
            ...                       json={"updated": "data"})
        """
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        """Make a DELETE request.

        Method for making DELETE requests. Equivalent to calling
        request("DELETE", url, **kwargs).

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.delete("https://example.com/api/resource/123")
        """
        return self.request("DELETE", url, **kwargs)

    def patch(self, url, **kwargs):
        """Make a PATCH request.

        Method for making PATCH requests. Equivalent to calling
        request("PATCH", url, **kwargs).

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.patch("https://example.com/api/resource/123",
            ...                         json={"field": "updated_value"})
        """
        return self.request("PATCH", url, **kwargs)

    def head(self, url, **kwargs):
        """Make a HEAD request.

        Method for making HEAD requests. Equivalent to calling
        request("HEAD", url, **kwargs). HEAD requests are like GET but only
        return headers without the response body.

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object (without body content).

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.head("https://example.com/large-file.zip")
            >>> print(f"Content-Length: {response.headers.get('Content-Length')}")
        """
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        """Make an OPTIONS request.

        Method for making OPTIONS requests. Equivalent to calling
        request("OPTIONS", url, **kwargs). OPTIONS requests are used to check
        which HTTP methods are supported by a server.

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            Response: HTTP response object.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> response = client.options("https://example.com/api")
            >>> print(f"Allowed methods: {response.headers.get('Allow')}")
        """
        return self.request("OPTIONS", url, **kwargs)

    def download(self, url, destination, chunk_size=8192, **kwargs):
        """Download a file from a URL to a local destination.

        Downloads large files efficiently using streaming to avoid loading
        the entire file into memory. Shows progress if logging is enabled.

        Args:
            url: URL of the file to download.
            destination: Local file path where the file should be saved.
            chunk_size: Size of chunks to read/write at a time in bytes (default: 8192).
            **kwargs: Additional arguments passed to request().

        Returns:
            str: Path to the downloaded file (same as destination).

        Raises:
            IOError: If file cannot be written.
            HTTPError: If download request fails.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> client.download("https://example.com/file.zip", "/tmp/file.zip")
            '/tmp/file.zip'

            >>> # With custom chunk size
            >>> client.download("https://example.com/bigfile.iso",
            ...                "/tmp/bigfile.iso",
            ...                chunk_size=65536)
        """
        kwargs.setdefault("stream", True)
        response = self.request("GET", url, **kwargs)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(destination, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        progress = (downloaded / total_size) * 100
                        logger.debug(f"Download progress: {progress:.1f}% ({downloaded}/{total_size} bytes)")

        logger.info(f"Downloaded {url} to {destination} ({downloaded} bytes)")
        return destination

    def get_json(self, url, **kwargs):
        """Make a GET request and parse JSON response.

        Convenience method that combines a GET request with JSON parsing.

        Args:
            url: Target URL for the request.
            **kwargs: Additional arguments passed to request().

        Returns:
            dict | list: Parsed JSON response.

        Raises:
            JSONDecodeError: If response is not valid JSON.
            HTTPError: If request fails.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> data = client.get_json("https://api.example.com/data")
            >>> print(data["key"])
        """
        response = self.get(url, **kwargs)
        return response.json()

    def post_json(self, url, json_data=None, **kwargs):
        """Make a POST request with JSON data and parse JSON response.

        Convenience method that combines a POST request with JSON input/output.

        Args:
            url: Target URL for the request.
            json_data: JSON-serializable data to send (dict, list, etc.).
            **kwargs: Additional arguments passed to request().

        Returns:
            dict | list: Parsed JSON response.

        Raises:
            JSONDecodeError: If response is not valid JSON.
            HTTPError: If request fails.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> result = client.post_json("https://api.example.com/endpoint",
            ...                          json_data={"key": "value"})
            >>> print(result["status"])
        """
        response = self.post(url, json=json_data, **kwargs)
        return response.json()

    @property
    def is_session_active(self):
        """Check if a session is currently active.

        Returns:
            bool: True if session exists and is not None, False otherwise.

        Example:
            >>> client = SingBoxClient(client=proxy)
            >>> print(client.is_session_active)
            False
            >>> client.get("https://example.com")
            >>> print(client.is_session_active)
            True
        """
        return self._session is not None

    def __repr__(self):
        """Return a detailed string representation of the client.

        Returns:
            str: Representation string with key configuration details.

        Example:
            >>> client = SingBoxClient(client=proxy, timeout=20)
            >>> print(repr(client))
            <SingBoxClient proxy=True timeout=20 auto_retry=True retry_times=2 session=True>
        """
        has_proxy = self.proxy is not None or self._proxy_override is not None or self.client is not None
        return (
            f"<SingBoxClient proxy={has_proxy} "
            f"timeout={self.timeout} auto_retry={self.auto_retry} "
            f"retry_times={self.retry_times} session={self.is_session_active}>"
        )

    def __enter__(self):
        """Context manager entry.

        Allows using SingBoxClient with the 'with' statement for automatic cleanup.

        Returns:
            SingBoxClient: Returns self for use in the context.

        Example:
            >>> with SingBoxClient(client=proxy) as client:
            ...     response = client.get("https://example.com")
            ...     print(response.text)
            # Session is automatically closed after the block
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit.

        Automatically closes the session when exiting the 'with' block.

        Args:
            exc_type: Exception type if an exception occurred, None otherwise.
            exc_val: Exception value if an exception occurred, None otherwise.
            exc_tb: Exception traceback if an exception occurred, None otherwise.

        Returns:
            bool: False to propagate any exception that occurred in the context.
        """
        try:
            self.close()
        except Exception:
            pass
        return False

    def __del__(self):
        """Ensure resources are cleaned up when the object is garbage collected.

        Automatically called when the object is about to be destroyed. Closes
        the session and stops the associated proxy client if any.

        Note:
            While this provides a safety net, it's better to explicitly call close()
            or use the context manager pattern for predictable cleanup timing.
        """
        try:
            self.close()
        except Exception:
            pass
        if self.client:
            try:
                self.client.stop()
            except Exception:
                pass
