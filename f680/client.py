"""
f680.client — базовый клиент веб-API роутера ZTE F680 (DST/MGTS).

Веб-интерфейс роутера — не обычная HTML-форма, а небольшой JSON/XML API
по URL вида `/_type=...&_tag=...`. Этот модуль оборачивает API: логин,
logout, чтение и парсинг data-страниц, таблица подключённых клиентов.

Протокол аутентификации и endpoints описаны подробно в docs/API.md.

Python API:
    from f680 import F680

    with F680() as c:                    # авто-login / авто-logout
        devs = c.connected_devices()
        err, insts = c.get_page("wlan")  # (has_error, [dict, ...])
"""

import hashlib
import html as htmlmod
import http.cookiejar
import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request

from .config import BASE as _DEFAULT_BASE, USERNAME as _DEFAULT_USER, \
    PASSWORD as _DEFAULT_PASS


def unescape_stable(s: str) -> str:
    """Роутер дважды экранирует значения (например `a | b` ->
    `a&#32;|&#32;b`) — раскрываем entity'и до устойчивости."""
    for _ in range(5):
        new = htmlmod.unescape(s)
        if new == s:
            break
        s = new
    return s

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126 Safari/537.36"
)


class F680Error(RuntimeError):
    """Базовая ошибка клиента f680.

    Все ошибки, брошенные API (логин, роутер, сеть), — её наследники;
    CLI показывает их красиво. Backward-compat: это подкласс RuntimeError.
    """


class LoginFailed(F680Error):
    """Не удалось залогиниться в роутер."""


class RouterError(F680Error):
    """Роутер ответил ошибкой (IF_ERRORID / IF_ERRORSTR)."""


# Page tags known to exist on this device.
PAGES = {
    "devinfo": "devinfo_homepage_lua.lua",
    "wan": "wan_homepage_lua.lua",
    "wlan": "wlan_homepage_lua.lua",
    "voip": "voip_homepage_lua.lua",
    "firewall": "firewall_homepage_lua.lua",
    "usb": "usb_homepage_lua.lua",
    "accessdev": "accessdev_homepage_lua.lua&InstNum=5",
}


class F680:
    """Client for the ZTE F680 admin web API.

    Usage:
        with F680() as c:            # auto-login / auto-logout
            c.connected_devices()
        # or keep a session alive:
        c = F680(); c.login()
    """

    def __init__(self, base=_DEFAULT_BASE, username=_DEFAULT_USER,
                 password=_DEFAULT_PASS, timeout=20, verbose=False):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        if not self.password:
            raise F680Error(
                "пароль не задан: создай .env (см. .env.example) или "
                "укажи F680_PASSWORD / --pass")
        self.timeout = timeout
        self.verbose = verbose
        self.sess_token = None
        self.cookies = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.headers = {
            "User-Agent": USER_AGENT,
            "Referer": self.base + "/",
        }

    # -- low-level -------------------------------------------------------
    def _request(self, path, data=None, raw_body=None, extra_headers=None,
                 method=None):
        """Perform an HTTP request against the router.

        `data` is a dict, urlencoded automatically; `raw_body` sends an
        already-encoded body string (used for POSTs with custom headers).
        `method` forces a specific HTTP verb (default: GET for bodyless
        requests, POST when a body is present) — e.g. the logout endpoint
        is a GET that still carries a form body.
        """
        url = self.base + path
        body = None
        headers = dict(self.headers)
        if raw_body is not None:
            body = raw_body.encode() if isinstance(raw_body, str) else raw_body
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if extra_headers:
            headers.update(extra_headers)
        if method is None:
            method = "POST" if body is not None else "GET"
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        resp = self.op.open(req, timeout=self.timeout)
        return resp.read().decode("utf-8", errors="replace")

    def _log(self, *a):
        if self.verbose:
            print(*a, file=sys.stderr)

    # -- auth ------------------------------------------------------------
    def login(self, username=None, password=None, retries=3, wait=3):
        """Perform the 3-step SHA256 login. Returns True on success."""
        username = username or self.username
        password = password or self.password

        for attempt in range(1, retries + 1):
            # 1. get session token
            init = json.loads(self._request(
                "/?_type=loginData&_tag=login_entry"))
            self.sess_token = init.get("sess_token")
            self._log("sess_token:", self.sess_token)

            # 2. get one-time hash token
            raw = self._request("/?_type=loginData&_tag=login_token")
            token = re.sub(r"<[^>]+>", "", raw).strip()
            self._log("onetime token:", token)

            # 3. post hashed password
            h = hashlib.sha256((password + token).encode()).hexdigest()
            resp = json.loads(self._request(
                "/?_type=loginData&_tag=login_entry",
                data={
                    "action": "login",
                    "Password": h,
                    "Username": username,
                    "_sessionTOKEN": self.sess_token,
                },
            ))
            self._log("login resp:", resp)

            self.sess_token = resp.get("sess_token", self.sess_token)
            ok = (not resp.get("loginErrMsg")
                  and not resp.get("promptMsg")
                  and not resp.get("lockingTime"))
            if ok:
                # Prime the session the way the browser does.
                self._request("/")
                return True

            err = resp.get("loginErrMsg") or resp.get("promptMsg")
            self._log(f"login failed (attempt {attempt}): {err}")
            time.sleep(wait)
        return False

    def logout(self):
        """Logout and clear the session. Safe to call any number of times.

        The logout endpoint is a GET that still carries a small form body
        (IF_LogOff=1). Errors are swallowed and reported only in verbose
        mode — a half-dead session shouldn't crash the caller.
        """
        try:
            if self.sess_token is not None:
                resp = self._request(
                    "/?_type=loginData&_tag=logout_entry",
                    data={"IF_LogOff": 1},
                    extra_headers={"X-Requested-With": "XMLHttpRequest"},
                    method="GET",
                )
                self._log("logout resp:", resp[:200])
        except Exception as e:  # noqa: BLE001 — best-effort teardown
            self._log("logout failed:", e)
        finally:
            self.sess_token = None
            self.cookies.clear()

    # -- context manager: auto-login / auto-logout -------------------------
    def __enter__(self):
        """Usage: `with F680() as c:` — logs in on entry.

        Always logs out on exit (even if the body raises), so sessions
        don't linger on the router.
        """
        if not self.login():
            raise LoginFailed("не удалось залогиниться в роутер")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.logout()
        return False

    # -- management: reboot / factory reset ------------------------------
    def _admin_action(self, action, data_tag):
        """Получить fresh one-time токен страницы `rebootAndReset` и
        послать управляющее действие (`Restart` / `Reset`) с RSA-подписью.

        Протокол тот же, что и у port forwarding: one-time
        `_sessionTmpToken` из menuView-страницы + заголовок
        `Check: base64(RSA-PKCS1v15(SHA256(body)))`. Без Check роутер
        просто молча игнорирует POST.
        """
        from .portforward import parse_page_token, rsa_check  # локально:
        # порт-форвард от клиента не зависит, а от клиента зависят токены

        view = self.raw("/?_type=menuView&_tag=rebootAndReset")
        if "404 Not Found" in view:
            raise F680Error("menuView 404 — страница недоступна?")
        token = parse_page_token(view)
        if not token:
            raise F680Error("не найден одноразовый токен страницы")

        body = f"IF_ACTION={action}&_sessionTOKEN={urllib.parse.quote(token)}"
        resp = self._request(
            f"/?_type=menuData&_tag={data_tag}",
            raw_body=body,
            extra_headers={
                "X-Requested-With": "XMLHttpRequest",
                "Check": rsa_check(body),
            },
        )
        out = dict(re.findall(r"<(\w+)>([^<]*)</\1>", resp))
        err = out.get("IF_ERRORSTR", "").strip()
        if err and err.upper() != "SUCC":
            raise RouterError(
                f"ошибка роутера (IF_ERRORID={out.get('IF_ERRORID')}): {err}")
        return out

    def reboot(self):
        """Перезагрузить роутер (web → Системное администрирование →
        «Перезагрузка»). Возвращает raw-ответ роутера; после возврата
        роутер через несколько секунд отваливается и поднимается заново
        (~30-60 c). Чтобы дождаться его, вызови `wait_online()`."""
        return self._admin_action("Restart", "devmgr_restartmgr_lua.lua")

    def factory_reset(self):
        """Сбросить настройки к заводским (та же страница, «Сброс
        настроек»). ВНИМАНИЕ: порт-форвардинг, DHCP-привязки, Wi-Fi и
        вся пользовательская конфигурация сотрётся. После сброса
        роутер поднимется с дефолтными параметрами."""
        return self._admin_action("Reset", "db_resetmgr_lua.lua")

    def wait_online(self, timeout=180, poll=2, verbose=True):
        """Подождать, пока роутер снова примет HTTP-запросы (например
        после reboot). Возвращает время ожидания в секундах.

        Считаем «готовым» только живой HTTP-ответ: после перезагрузки
        веб-серв роутера сначала отвечает 400 на всё подряд (boot в
        процессе), поэтому HTTPError — НЕ признак готовности. Бросает
        TimeoutError по истечении `timeout`.
        """
        import urllib.error

        host = urllib.parse.urlsplit(self.base).hostname
        port = urllib.parse.urlsplit(self.base).port or 80
        start = time.time()
        last_log = 0.0
        while True:
            try:
                s = socket.create_connection((host, port), timeout=poll)
                s.close()
                # port открыт — проверим, что веб уже отвечает осмысленно
                try:
                    self._request("/?_type=loginData&_tag=login_entry")
                    return time.time() - start
                except urllib.error.HTTPError:
                    pass  # 400/500 — ещё не готов
                except OSError:
                    pass
            except OSError:
                pass
            if time.time() - start > timeout:
                raise TimeoutError(
                    f"роутер {host}:{port} не вернулся за {timeout} c")
            if self.verbose and time.time() - last_log > 15:
                self._log(f"ожидание {host}... {int(time.time()-start)}s")
                last_log = time.time()
            time.sleep(poll)

    # -- data ------------------------------------------------------------
    def get_data(self, tag, extra=""):
        """Fetch a menuData page and return the raw XML string.

        `tag` may be a bare name ("wlan_homepage_lua.lua") or a short alias
        from the PAGES dict, optionally with query suffixes.
        """
        if tag in PAGES:
            tag = PAGES[tag]
        qs = f"/?_type=menuData&_tag={urllib.parse.quote(tag, safe='=&')}"
        if extra:
            qs += extra
        if self.sess_token:
            qs += f"&_sessionTOKEN={self.sess_token}"
        return self._request(qs)

    @staticmethod
    def parse_instances(xml):
        """Parse XML into a list of dicts (one per <Instance>).

        Each dict maps ParaName -> ParaValue (values are unescaped — the
        router double-escapes them). If an instance carries an `_InstID`
        field it is preserved under key "_instid".
        """
        instances = []
        for block in re.findall(r"<Instance>.*?</Instance>", xml, re.S):
            pairs = re.findall(
                r"<ParaName>([^<]+)</ParaName>"
                r"<ParaValue>([^<]*)</ParaValue>",
                block,
            )
            d = {}
            for name, value in pairs:
                if name == "_InstID":
                    d["_instid"] = value
                else:
                    d[name] = unescape_stable(value)
            if d:
                instances.append(d)
        return instances

    @staticmethod
    def parse_top_values(xml):
        """ParaName/ParaValue pairs OUTSIDE <Instance> blocks (radio
        state, firewall level, ...). Returns a dict, values unescaped."""
        outside = re.sub(r"<Instance>.*?</Instance>", "", xml, flags=re.S)
        pairs = re.findall(
            r"<ParaName>([^<]+)</ParaName>"
            r"<ParaValue>([^<]*)</ParaValue>",
            outside,
        )
        return {k: unescape_stable(v) for k, v in pairs}

    @staticmethod
    def get_error_str(xml):
        """Return the IF_ERRORSTR value (or None). Non-SUCC = error."""
        m = re.search(r"<IF_ERRORSTR>([^<]*)</IF_ERRORSTR>", xml)
        if not m:
            return None
        v = m.group(1).strip()
        return v if v.upper() not in ("", "SUCC") else None

    @staticmethod
    def has_error(xml):
        """A successful response contains IF_ERRORSTR>SUCC, so only a
        non-SUCC IF_ERRORSTR (e.g. SessionTimeout) means an actual error."""
        m = re.search(r"<IF_ERRORSTR>([^<]*)</IF_ERRORSTR>", xml)
        return m is not None and m.group(1).strip().upper() not in ("", "SUCC")

    def get_page(self, tag, extra=""):
        """Convenience: return (has_error, instances) for a data page."""
        xml = self.get_data(tag, extra)
        return self.has_error(xml), self.parse_instances(xml)

    def get_page_full(self, tag, extra=""):
        """Like get_page but also returns top-level (non-instance) values:
        (error_str_or_None, instances, top_values)."""
        xml = self.get_data(tag, extra)
        return (self.get_error_str(xml),
                self.parse_instances(xml),
                self.parse_top_values(xml))

    def raw(self, qs):
        """Fetch any raw `/_type=...&_tag=...` query string and return text."""
        if not qs.startswith("/"):
            qs = "/" + qs
        if self.sess_token and "_sessionTOKEN" not in qs:
            sep = "&" if "?" in qs else "?"
            qs += f"{sep}_sessionTOKEN={self.sess_token}"
        return self._request(qs)

    # -- helpers ---------------------------------------------------------
    def _clients_from(self, xml, keys):
        out = []
        for d in self.parse_instances(xml):
            row = {k: v for k, v in d.items()
                   if k in keys and v.strip()}
            if row.get("IPAddress") or row.get("MACAddress"):
                out.append(row)
        return out

    CLIENT_KEYS = ("IPAddress", "MACAddress", "HostName", "IPV6Address",
                   "AliasName", "RadioSwitch")

    def wifi_clients(self):
        """Wi-Fi clients from the wlan page (IP/IPv6/MAC/hostname)."""
        xml = self.get_data("wlan")
        return self._clients_from(
            xml, ("IPAddress", "IPV6Address", "MACAddress", "HostName"))

    def lan_clients(self):
        """Wired LAN clients from the accessdev page (+ port alias)."""
        xml = self.get_data("accessdev")
        return self._clients_from(
            xml, ("IPAddress", "IPV6Address", "MACAddress", "HostName",
                  "AliasName"))

    def connected_devices(self):
        """Return a tidy list of ALL clients: wired LAN (source=\"wired\")
        and Wi-Fi (source=\"wifi\"), deduplicated by MAC."""
        out = []
        seen = set()
        for row in self.lan_clients():
            row = dict(row)
            row["source"] = "wired"
            mac = row.get("MACAddress", "").lower()
            if mac in seen:
                continue
            seen.add(mac)
            out.append(row)
        for row in self.wifi_clients():
            row = dict(row)
            row["source"] = "wifi"
            mac = row.get("MACAddress", "").lower()
            if mac in seen:
                continue
            seen.add(mac)
            out.append(row)
        return out

    # -- aggregated router status -----------------------------------------
    def status(self):
        """Collect a status snapshot of the router as a dict.

        Sections: wifi (radio state), firewall, usb, voip, wired, wifi_clients,
        plus a list of pages that failed (e.g. devinfo/wan on role mgts).
        """
        st = {"wifi": {}, "firewall": {}, "usb": {}, "voip": {},
              "errors": [], "wired_clients": [], "wifi_clients": []}
        err, insts, top = self.get_page_full("wlan")
        if err:
            st["errors"].append(f"wlan: {err}")
        else:
            # RadioSwitch приходит отдельным Instance'ом (OBJ_WLANRADIO_ID)
            for d in insts:
                if "RadioSwitch" in d:
                    st["wifi"]["RadioSwitch"] = d["RadioSwitch"]
            st["wifi"]["RadioSwitch"] = st["wifi"].get(
                "RadioSwitch") or top.get("RadioSwitch")
            st["wifi_clients"] = [d for d in insts
                                  if d.get("IPAddress")
                                  or d.get("MACAddress")]
        err, insts, _ = self.get_page_full("firewall")
        if err:
            st["errors"].append(f"firewall: {err}")
        else:
            st["firewall"] = {k: v for i in insts for k, v in i.items()
                              if k != "_instid"}
        err, insts, _ = self.get_page_full("usb")
        if err:
            st["errors"].append(f"usb: {err}")
        else:
            st["usb"] = {k: v for i in insts for k, v in i.items()
                         if k != "_instid"}
        err, insts, _ = self.get_page_full("voip")
        if err:
            st["errors"].append(f"voip: {err}")
        else:
            st["voip"] = {k: v for i in insts for k, v in i.items()
                          if k in ("IsOnline", "VoIPRegStatus")}
        st["wired_clients"] = self.lan_clients()
        return st
