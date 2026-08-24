"""
f680.firewall — межсетевой экран (firewall + anti-DoS) на ZTE F680.

«Безопасность → Межсетевой экран» из веб-интерфейса: два блока —
уровень FW (Enable/Level) и anti-DoS (Enable/Threshold). Изменения, как
и для port forwarding / DHCP, требуют one-time `_sessionTmpToken` из
menuView-страницы `firewall` и заголовка `Check` (RSA) — см.
docs/PORT_FORWARDING.md, docs/DHCP.md, docs/FIREWALL.md.

Python API:
    from f680 import Firewall

    with Firewall() as fw:
        fw.config()          # {'enabled': True, 'level': 'low'}
        fw.dos()             # {'enabled': True, 'threshold': 100}
        fw.set_level("high")
        fw.disable_dos()
"""

import time
import urllib.parse

from .client import F680, F680Error, LoginFailed, RouterError
from .portforward import parse_page_token, rsa_check

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "firewall"
CONFIG_TAG = "firewall_config_lua.lua"
DOS_TAG = "firewall_dos_lua.lua"
INST_ID = "IGD"  # оба блока — одиночный инстанс с id "IGD"

LEVELS = {"low": "Low", "middle": "Middle", "high": "High"}


def _norm_level(level):
    key = str(level).strip().lower()
    if key not in LEVELS:
        raise ValueError(
            f"неизвестный уровень '{level}' — варианты: low, middle, high")
    return LEVELS[key]


def _norm_enable(enabled):
    return 1 if str(enabled).strip() not in ("", "0", "0.0", "False",
                                             "false", "off", "Off") else 0


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class Firewall:
    """Firewall client. Wraps F680 for the session.

    Usage:
        with Firewall() as fw:
            fw.config()
            fw.set_level("high")
            fw.disable_dos()
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
        """Чтение блока: один menuView-токен на один GET.

        Значения лежат ВНУТРИ <Instance> (parse_top_values их отбрасывает).
        """
        self._view()
        body = (f"/?_type=menuData&_tag={tag}"
                f"&_sessionTOKEN={urllib.parse.quote(self.token)}")
        xml = self.c._request(body)
        if self.c.has_error(xml):
            raise F680Error(
                "ошибка при чтении: " + self.c.get_error_str(xml))
        insts = self.c.parse_instances(xml)
        if not insts:
            raise F680Error(f"блок {tag} пуст — данные не получены")
        return insts[0]

    def _post(self, tag, fields):
        """Fresh menuView token + signed POST к одному из двух блоков.

        IF_ERRORID -257 (FAIL) — роутер ещё не завершил предыдущий
        коммит (сразу после ребута и т.п.): ретраим с бэкоффом, как в
        f680.dhcp.
        """
        import re
        last = None
        for i in range(4):
            self._view()
            body = f"IF_ACTION=Apply&_InstID={INST_ID}"
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
            last = RouterError(
                f"ошибка роутера (IF_ERRORID={out.get('IF_ERRORID')}): {err}")
            if "sessiontimeout" in err.lower():
                # сессия роутера протухла, а cookie жив: перезалогиниться
                self.c.login()
            if i < 3:
                time.sleep(3)
        raise last

    # -- чтение -----------------------------------------------------------
    def config(self):
        """Уровень межсетевого экрана: {'enabled': bool, 'level': str}."""
        d = self._get(CONFIG_TAG)
        return {
            "enabled": d.get("Enable", "0") == "1",
            "level": d.get("Level", "").lower() or None,
        }

    def dos(self):
        """Anti-DoS: {'enabled': bool, 'threshold': int}."""
        d = self._get(DOS_TAG)
        return {
            "enabled": d.get("Enable", "0") == "1",
            "threshold": int(d["Threshold"]) if d.get("Threshold") else None,
        }

    def _raw_block(self, tag):
        """Машинные значения блока (Enable 0/1, Level как в XML) для
        точечного изменения через `update_*`."""
        return self._get(tag)

    # -- изменения --------------------------------------------------------
    def set_config(self, enabled=True, level=None):
        """Изменить уровень/состояние межсетевого экрана.

        `enabled` — вкл/выкл FW, `level` — low/middle/high (если задан
        только enabled, уровень сохраняется). Возвращает новое
        состояние.
        """
        if level is None and enabled is None:
            raise ValueError("нечего изменять: enabled и/или level")
        cur = self.config()
        fields = {
            "Enable": _norm_enable(enabled if enabled is not None
                                   else cur["enabled"]),
            "Level": _norm_level(level if level is not None
                                 else (cur["level"] or "low")),
        }
        self._post(CONFIG_TAG, fields)
        return self.config()

    def set_level(self, level):
        """Изменить только уровень (FW остаётся в текущем состоянии)."""
        cur = self.config()
        self._post(CONFIG_TAG, {"Enable": 1 if cur["enabled"] else 0,
                                "Level": _norm_level(level)})
        return self.config()

    def enable(self):
        """Включить межсетевой экран (уровень сохраняется)."""
        cur = self.config()
        self._post(CONFIG_TAG, {"Enable": 1,
                                "Level": _norm_level(cur["level"] or "low")})
        return self.config()

    def disable(self):
        """Выключить межсетевой экран (уровень сохраняется)."""
        cur = self.config()
        self._post(CONFIG_TAG, {"Enable": 0,
                                "Level": _norm_level(cur["level"] or "low")})
        return self.config()

    def set_dos(self, enabled=None, threshold=None):
        """Изменить anti-DoS (состояние и/или порог). Возвращает новое
        состояние."""
        if enabled is None and threshold is None:
            raise ValueError("нечего изменять: enabled и/или threshold")
        cur = self.dos()
        fields = {
            "Enable": _norm_enable(enabled if enabled is not None
                                   else cur["enabled"]),
            "Threshold": int(threshold if threshold is not None
                             else (cur["threshold"] if cur["threshold"]
                                   is not None else 100)),
        }
        if not 0 < fields["Threshold"] < 1000:
            raise ValueError("порог должен быть 1..999")
        self._post(DOS_TAG, fields)
        return self.dos()

    def enable_dos(self):
        cur = self.dos()
        self._post(DOS_TAG, {"Enable": 1,
                             "Threshold": cur["threshold"] or 100})
        return self.dos()

    def disable_dos(self):
        cur = self.dos()
        self._post(DOS_TAG, {"Enable": 0,
                             "Threshold": cur["threshold"] or 100})
        return self.dos()

    def set_threshold(self, n):
        """Изменить только порог anti-DoS."""
        cur = self.dos()
        n = int(n)
        if not 0 < n < 1000:
            raise ValueError("порог должен быть 1..999")
        self._post(DOS_TAG, {"Enable": 1 if cur["enabled"] else 0,
                             "Threshold": n})
        return self.dos()
