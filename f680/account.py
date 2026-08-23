"""
f680.account — учётные записи веб-интерфейса ZTE F680.

«Администрирование → Администрирование учётной записи» (страница
`accountMgr`): список учётных записей, смена пароля, время простоя сессии.
Протокол идентичен port forwarding / firewall: one-time `_sessionTmpToken`
из menuView-страницы + заголовок `Check` (RSA) — см. docs/ACCOUNT.md.

Python API:
    from f680 import Account

    with Account() as a:
        a.accounts()                       # список учётных записей
        a.change_password("mgts", "старый", "новый")
        a.timeout()                        # {'timeout': 5}
        a.set_timeout(10)
"""

import re
import time
import urllib.parse

from .client import F680, F680Error, LoginFailed, RouterError
from .portforward import parse_page_token, rsa_check

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "accountMgr"
ACCOUNT_TAG = "devauth_accountmgr_lua.lua"
TIMEOUT_TAG = "web_login_timeout_lua.lua"

# Права из XML: 1 = администратор, 2 = пользователь
RIGHTS = {"1": "admin", "2": "user"}


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class Account:
    """Account client. Wraps F680 for the session.

    Usage:
        with Account() as a:
            a.accounts()
            a.change_password("mgts", "old", "new")
    """

    def __init__(self, base=None, username=None, password=None, verbose=False):
        from .config import BASE, USERNAME, PASSWORD
        self.c = F680(base=base or BASE, username=username or USERNAME,
                      password=password or PASSWORD, verbose=verbose)

    def login(self):
        if not self.c.login():
            raise LoginFailed("не удалось залогиниться в роутер")

    def logout(self):
        self.c.logout()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.logout()
        except Exception:
            pass
        return False

    # -- протокол ---------------------------------------------------------
    def _view(self):
        """Fetch the menuView page, grab a fresh one-time token."""
        r = self.c.raw(f"/?_type=menuView&_tag={VIEW_TAG}")
        if "404 Not Found" in r:
            raise F680Error("menuView 404 — страница недоступна?")
        self.token = parse_page_token(r)
        if not self.token:
            raise F680Error("не найден одноразовый токен страницы")
        return self.token

    def _get(self, tag):
        """Чтение блока: один menuView-токен на один GET."""
        self._view()
        body = (f"/?_type=menuData&_tag={tag}"
                f"&_sessionTOKEN={urllib.parse.quote(self.token)}")
        xml = self.c._request(body)
        if self.c.has_error(xml):
            raise F680Error("ошибка при чтении: "
                            + self.c.get_error_str(xml))
        return self.c.parse_instances(xml)

    def _post(self, tag, fields):
        """Fresh menuView token + signed POST."""
        last = None
        for i in range(3):
            self._view()
            body = "IF_ACTION=Apply"
            for k, v in fields.items():
                body += (f"&{urllib.parse.quote_plus(k)}="
                         f"{urllib.parse.quote_plus(str(v))}")
            body += f"&_sessionTOKEN={urllib.parse.quote(self.token)}"
            resp = self.c._request(
                f"/?_type=menuData&_tag={tag}",
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
            from .client import unescape_stable
            last = RouterError(
                f"ошибка роутера (IF_ERRORID={out.get('IF_ERRORID')}): "
                f"{unescape_stable(err)}")
            if i < 2:
                time.sleep(3)
        raise last

    # -- чтение -----------------------------------------------------------
    def accounts(self):
        """Список учётных записей.

        list[dict]: username, inst_id, right ('admin'/'user'), enabled.
        Пароли в ответ не отдаются.
        """
        out = []
        for d in self._get(ACCOUNT_TAG):
            if d.get("Enable", "0") != "1":
                continue
            out.append({
                "username": d.get("Username", ""),
                "inst_id": d.get("_instid", ""),
                "right": RIGHTS.get(d.get("Right", ""),
                                    d.get("Right", "")),
                "enabled": True,
            })
        return out

    def _find_account(self, username):
        """Машинный record (сырое Right, _instid) по имени."""
        all_recs = self._get(ACCOUNT_TAG)
        for d in all_recs:
            if d.get("Username") == username:
                if d.get("Enable", "0") != "1":
                    raise F680Error(
                        f"учётная запись '{username}' отключена (Enable=0)")
                return d
        raise F680Error(
            f"учётная запись '{username}' не найдена "
            f"(есть: {', '.join(d.get('Username', '') for d in all_recs)})")

    def timeout(self):
        """Время простоя сессии веб-интерфейса: {'timeout': int} (мин)."""
        insts = self._get(TIMEOUT_TAG)
        if not insts:
            raise F680Error("блок времени простоя пуст")
        return {"timeout": int(insts[0].get("Timeout", "5"))}

    # -- изменения --------------------------------------------------------
    def change_password(self, username, old_password, new_password):
        """Сменить пароль учётной записи.

        `username` — имя (например, 'mgts'), `old_password` — текущий
        пароль, `new_password` — новый. Сессия НЕ разрывается: после
        успеха работают и старый, и новый логин. Но ОДНОВРЕМЕННЫЙ
        новый логин может «выдавить» старую сессию — для следующих
        операций залогиньтесь заново. Возвращает True.
        """
        if not new_password:
            raise ValueError("новый пароль не может быть пустым")
        rec = self._find_account(username)
        self._post(ACCOUNT_TAG, {
            "_InstID": rec["_instid"],
            "Right": rec.get("Right", "1"),
            "Enable": "1",
            "Username": username,
            "Password": old_password,
            "NewPassword": new_password,
            "Keyword": rec.get("Keyword", ""),
        })
        return True

    def set_timeout(self, minutes):
        """Изменить время простоя сессии (1..30 мин). Возвращает новое."""
        m = int(minutes)
        if not 1 <= m <= 30:
            raise ValueError("время простоя: 1..30 минут")
        self._post(TIMEOUT_TAG, {"_InstID": "IGD", "Timeout": m})
        return self.timeout()
