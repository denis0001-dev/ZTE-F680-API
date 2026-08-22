"""
f680.dhcp — DHCP-резервы (привязка MAC -> IP) на ZTE F680.

«Привязка DHCP» (Static DHCP Binding) из веб-интерфейса:
Локальная сеть → Локальная сеть → IPv4. Изменения, как и для port
forwarding, требуют one-time `_sessionTmpToken` из menuView-страницы
`lanMgrIpv4` и заголовка `Check` (RSA) — см. docs/PORT_FORWARDING.md
и docs/DHCP.md.

Python API:
    from f680 import Dhcp

    with Dhcp() as d:           # авто-login / авто-logout
        d.reservations()
        d.set_reservation("192.168.1.6", "1c:f6:4c:a0:cc:96", name="Macbook")
        d.remove_reservation("192.168.1.6")
"""

import re
import urllib.parse

from .client import F680, F680Error, LoginFailed, RouterError
from .config import BASE as _DEFAULT_BASE, USERNAME as _DEFAULT_USER, \
    PASSWORD as _DEFAULT_PASS
from .portforward import parse_page_token, rsa_check

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "lanMgrIpv4"
DATA_TAG = "Localnet_LanMgrIpv4_DHCPStaticRule_lua.lua"
HOSTINFO_TAG = "Localnet_LanMgrIpv4_DHCPHostInfo_lua.lua"
BIND_ID_PREFIX = "DEV.V4DHCP.Server.Pool1.Bind"
# Роутер принимает поле Name длиной НЕ БОЛЬШЕ 10 символов: при 11+ первый
# POST получает IF_ERRORID -257 (FAIL) и так до бесконечности. Проверено
# эмпирически (len 8/9/10 — OK, len 11/12 — FAIL, независимо от дефиса).
NAME_MAX_LEN = 10


class Dhcp:
    """Static DHCP binding client. Wraps F680 for the session.

    Usage:
        with Dhcp() as d:
            d.reservations()
            d.set_reservation("192.168.1.6", "1c:f6:4c:a0:cc:96", "Macbook")
    """

    def __init__(self, base=_DEFAULT_BASE, username=_DEFAULT_USER,
                 password=_DEFAULT_PASS, verbose=False):
        self.c = F680(base=base, username=username, password=password,
                      verbose=verbose)
        self.token = None

    def login(self):
        if not self.c.login():
            raise LoginFailed("не удалось залогиниться в роутер")

    def logout(self):
        self.c.logout()
        self.token = None

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.logout()
        except Exception:
            pass
        return False

    def _view(self):
        """Fetch the menuView page, grab a fresh one-time token."""
        r = self.c.raw(f"/?_type=menuView&_tag={VIEW_TAG}")
        if "404 Not Found" in r:
            raise F680Error("menuView 404 — страница недоступна?")
        self.token = parse_page_token(r)
        if not self.token:
            raise F680Error("не найден одноразовый токен страницы")
        return self.token

    def _post(self, action, instid="-1", fields=None):
        """Fresh menuView token + signed POST to the data endpoint.

        IF_ERRORID -257 (FAIL) — роутер ещё не завершил предыдущий
        коммит (сразу после ребута, а также при слишком длинных
        именах — см. NAME_MAX_LEN). Каждый FAIL ретраится с бэкоффом
        и свежим токеном.
        """
        import time
        last = None
        for i in range(4):
            self._view()
            body = f"IF_ACTION={action}&_InstID={instid}"
            for k, v in (fields or {}).items():
                body += f"&{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(str(v))}"
            body += f"&_sessionTOKEN={urllib.parse.quote(self.token)}"
            resp = self.c._request(
                f"/?_type=menuData&_tag={DATA_TAG}",
                raw_body=body,
                extra_headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Check": rsa_check(body),
                },
            )
            out = dict(re.findall(r"<(\w+)>([^<]*)</\1>", resp))
            err = out.get("IF_ERRORSTR", "").strip()
            if not err or err.upper() == "SUCC":
                return out
            last = RouterError(
                f"ошибка роутера (IF_ERRORID={out.get('IF_ERRORID')}): {err}")
            if i < 3:
                time.sleep(3)
        raise last

    # -- data -------------------------------------------------------------
    def reservations(self):
        """Все статические DHCP-привязки как список словарей."""
        self._view()
        xml = self.c.get_data(DATA_TAG)
        if self.c.has_error(xml):
            raise F680Error("ошибка при чтении привязок: " + xml[:200])
        out = []
        for d in self.c.parse_instances(xml):
            out.append({
                "id": d.get("_instid", ""),
                "name": d.get("Name", ""),
                "ip": d.get("IPAddr", ""),
                "mac": d.get("MACAddr", "").lower(),
                "raw": d,
            })
        return out

    def active_hosts(self):
        """DHCP-аренды (кто реально получил IP): IP/MAC/hostname."""
        self._view()
        xml = self.c.get_data(HOSTINFO_TAG)
        if self.c.has_error(xml):
            raise F680Error("ошибка при чтении аренд: " + xml[:200])
        out = []
        for d in self.c.parse_instances(xml):
            out.append({
                "id": d.get("_instid", ""),
                "ip": d.get("IPAddr", ""),
                "mac": d.get("MACAddr", "").lower(),
                "hostname": d.get("HostName", ""),
            })
        return out

    def _find(self, ref, snapshot=None):
        """Найти привязку по IP (строка) или по MAC (с ':' или '-').

        snapshot — готовый список из reservations() (чтобы не делать
        лишний GET: каждый GET данных валидирует одноразовый токен
        страницы, и POST после нескольких чтений получает FAIL).
        """
        ref = str(ref).strip().lower()
        for r in (self.reservations() if snapshot is None else snapshot):
            if (r["ip"] == ref or r["mac"] == ref
                    or r["id"].lower() == ref):
                return r
        raise KeyError(f"не найдена привязка '{ref}'")

    def _find_retry(self, ref, tries=3, pause=3):
        """_find с ретраем: роутер до ~5 с не коммитит последнее
        изменение, и свежий GET может ещё не показать объект."""
        import time
        last = None
        for i in range(tries):
            try:
                return self._find(ref)
            except KeyError as e:
                last = e
                if i < tries - 1:
                    time.sleep(pause)
        raise last

    # -- changes ----------------------------------------------------------
    def set_reservation(self, ip, mac, name=None):
        """Создать или обновить привязку IP <-> MAC. Возвращает inst id.

        Если IP или MAC уже заняты другой привязкой — обновляет её
        (фактически переназначает адрес; «вытеснить» прежний occupant
        можно только так, т.к. два правила на один IP невозможны).
        """
        mac = mac.lower()
        if not name:
            name = f"host {ip}"
        if len(name) > NAME_MAX_LEN:
            raise ValueError(
                f"имя привязки {name!r} — {len(name)} символов, "
                f"а роутер принимает не более {NAME_MAX_LEN}")
        fields = {"Name": name, "IPAddr": ip, "MACAddr": mac}
        # Один снимок на всё: GET данных валидирует одноразовый токен,
        # а POST обязан идти сразу после _view() (иначе IF_ERRORID -257).
        snap = self.reservations()
        try:
            existing = self._find(ip, snap)
        except KeyError:
            # IP свободен — не прибит ли MAC к другому IP
            try:
                existing = self._find(mac, snap)
            except KeyError:
                existing = None
        if existing:
            self._post("Apply", instid=existing["id"], fields=fields)
            return existing["id"]

        # Новая привязка. Роутер принимает Apply с _InstID=-1 ТОЛЬКО если
        # _InstNum = max(существующих BindN) + 1 (проверено: 1,2,4,5,6 ->
        # 7; пробелы в нумерации не используются). После FAIL роутер
        # несколько секунд «зависает» (внутренний коммит) и отвечает FAIL
        # на любые последующие изменения — ретраем ждём 3 с.
        import time
        resp = None
        n = None
        for _ in range(4):
            used = set()
            for r in snap:
                m = re.search(r"Bind(\d+)$", r["id"])
                if m:
                    used.add(int(m.group(1)))
            n = (max(used) if used else 0) + 1
            try:
                resp = self._post("Apply", instid="-1",
                                  fields={**fields, "_InstNum": n})
                break
            except RuntimeError as e:
                if "FAIL" in str(e) and _ < 3:
                    time.sleep(3)
                    snap = self.reservations()
                    continue
                raise
        new_id = resp.get("_InstID") or resp.get("INSTIDENTITY")
        if not new_id or "-1" in str(new_id):
            raise F680Error("роутер ответил SUCC, но новый inst id не найден")
        return new_id

    def remove_reservation(self, ref):
        """Удалить привязку (по IP, MAC или inst id)."""
        r = self._find_retry(ref)
        self._post("Delete", instid=r["id"])
        return r

    def rename_reservation(self, ref, new_name):
        """Переименовать привязку, сохранив IP/MAC.

        new_name — не более 10 символов (см. NAME_MAX_LEN)."""
        if len(new_name) > NAME_MAX_LEN:
            raise ValueError(
                f"имя {new_name!r} — {len(new_name)} символов, "
                f"а роутер принимает не более {NAME_MAX_LEN}")
        r = self._find_retry(ref)
        fields = {"Name": new_name, "IPAddr": r["ip"], "MACAddr": r["mac"]}
        self._post("Apply", instid=r["id"], fields=fields)
        return r

    def update_reservation(self, ref, ip=None, mac=None, name=None):
        """Изменить любые поля существующей привязки (modify).

        `ref` — IP, MAC или stable id (см. `_find`). Указанные поля
        заменяются, остальные сохраняются. Возвращает привязку
        ДО изменения. Stable id (BindN) не меняется — та же запись.
        """
        if mac:
            mac = mac.lower()
        if name is not None and len(name) > NAME_MAX_LEN:
            raise ValueError(
                f"имя {name!r} — {len(name)} символов, "
                f"а роутер принимает не более {NAME_MAX_LEN}")
        r = self._find_retry(ref)
        fields = {
            "Name": name if name is not None else r["name"],
            "IPAddr": ip if ip is not None else r["ip"],
            "MACAddr": mac if mac is not None else r["mac"],
        }
        self._post("Apply", instid=r["id"], fields=fields)
        return r
