from .base import SingBoxCore, SingBoxProxy, enable_logging, disable_logging, default_core

VERSION = "0.1.10"

print(f"singbox2proxy version {VERSION}")

__all__ = ["SingBoxCore", "SingBoxProxy", "VERSION", "enable_logging", "disable_logging", "default_core"]
