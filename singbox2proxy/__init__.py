from .base import SingBoxCore, SingBoxProxy, enable_logging, disable_logging

VERSION = "0.1.5"

print(f"singbox2proxy version {VERSION}")

__all__ = ["SingBoxCore", "SingBoxProxy", "VERSION", "enable_logging", "disable_logging"]
