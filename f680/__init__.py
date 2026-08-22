"""f680 — Python-клиент веб-API роутера ZTE F680 (DST/MGTS).

Публичный API:
    from f680 import F680, PortForward

CLI-команды (отдельные модули):
    python -m f680.cli.api   — базовый API (login, страницы, devices, raw)
    python -m f680.cli.pf    — port forwarding (list/open/close/remove)

После `pip install -e .` доступны и консольные скрипты `f680-api` / `f680-pf`.
"""

from .client import F680, PAGES
from .portforward import PortForward

__all__ = ["F680", "PortForward", "PAGES"]
__version__ = "1.0.0"
