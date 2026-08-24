"""f680 — Python-клиент веб-API роутера ZTE F680 (DST/MGTS).

Публичный API:
    from f680 import F680, PortForward, Dhcp, Firewall, Account

Единый CLI (с версии 1.1):
    f680 <команда> ...          # или: python -m f680 <команда> ...

Команды: status, devices, report, ports (list/add/enable/disable/remove/modify/rename),
dhcp (list/leases/add/remove/modify/rename), firewall (list/enable/disable/level/dos),
account (list/password/timeout/set-timeout),
page, raw, pages, reboot, reset, login, logout. Подробности: `f680 --help`.
"""

from .client import F680, F680Error, LoginFailed, RouterError, PAGES
from .portforward import PortForward
from .dhcp import Dhcp
from .firewall import Firewall
from .account import Account
from .wlan import WLAN
from .macvendor import mac_vendor, hostname_hint, guess_device

__all__ = ["F680", "F680Error", "LoginFailed", "RouterError",
           "PortForward", "Dhcp", "Firewall", "Account", "WLAN", "PAGES",
           "mac_vendor", "hostname_hint", "guess_device"]
__version__ = "1.7.0"
