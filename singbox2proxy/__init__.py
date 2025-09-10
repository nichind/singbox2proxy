from .base import SingBoxCore, SingBoxProxy
from .base import logging as singbox_logging

VERSION = "0.1.3"

print(f"singbox2proxy version {VERSION}")

__all__ = ["SingBoxCore", "SingBoxProxy", "VERSION", "singbox_logging"]
