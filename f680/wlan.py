"""
f680.wlan — настройка Wi-Fi (WLAN) на ZTE F680.

«Безопасность → Wi-Fi» (страница `wlanBasic`): три data-блока —
2.4 GHz (DEV.WIFI.RD1), 5 GHz (DEV.WIFI.RD2) и список SSID/шифрование
(DEV.WIFI.AP1..AP8 + PSK/WEP-инстансы). Протокол идентичен
port forwarding / firewall: one-time `_sessionTmpToken` из
menuView-страницы + заголовок `Check` (RSA) — см. docs/WLAN.md.

Python API:
    from f680 import WLAN

    with WLAN() as w:
        w.radios()            # {'DEV.WIFI.RD1': {...}, 'DEV.WIFI.RD2': {...}}
        w.ssids()             # список всех 8 SSID с параметрами
        w.set_radio("2.4", enabled=False)
        w.set_ssid("DEV.WIFI.AP1", "NewName")
        w.set_channel("5", 36, auto=False)
"""

import re
import time
import urllib.parse

from .client import F680, F680Error, LoginFailed, RouterError
from .portforward import parse_page_token, rsa_check

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "wlanBasic"
RADIO_TAG = "wlan_wlanbasiconoff_lua.lua"        # включение/выключение радио
ADCONF_TAG = "wlan_wlanbasicadconf_lua.lua"       # канал, скорость, power
SSID_TAG = "wlan_wlansssidconf_lua.lua"           # SSID + шифрование

BANDS = {"2.4": "DEV.WIFI.RD1", "5": "DEV.WIFI.RD2",
         "2.4ghz": "DEV.WIFI.RD1", "5ghz": "DEV.WIFI.RD2",
         "DEV.WIFI.RD1": "DEV.WIFI.RD1", "DEV.WIFI.RD2": "DEV.WIFI.RD2"}


def _norm_band(band):
    key = str(band).strip()
    if key in BANDS:
        return BANDS[key]
    raise ValueError(f"неизвестная полоса '{band}' — варианты: 2.4, 5")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class WLAN:
    """Wi-Fi client. Wraps F680 for the session.

    Usage:
        with WLAN() as w:
            w.radios()
            w.set_ssid("DEV.WIFI.AP1", "NewName")
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

        Возвращает список всех инстансов (радио, SSID, WEP/PSK-ключи).
        """
        self._view()
        body = (f"/?_type=menuData&_tag={tag}"
                f"&_sessionTOKEN={urllib.parse.quote(self.token)}")
        xml = self.c._request(body)
        if self.c.has_error(xml):
            raise F680Error(
                "ошибка при чтении: " + self.c.get_error_str(xml))
        return self.c.parse_instances(xml)

    def _post(self, tag, instid, fields, token=None):
        """Signed POST к блоку.

        Токен menuView одноразовый: если `token` не задан — берётся
        свежий; при ретрае всегда берётся новый.

        IF_ERRORID -257 (FAIL) — роутер ещё не завершил предыдущий
        коммит (сразу после ребута и т.п.): ретраим с бэкоффом, как в
        f680.firewall.
        """
        last = None
        for i in range(4):
            if token is None or i > 0:
                self._view()
            body = "IF_ACTION=Apply&_InstID={}".format(instid)
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
    def radios(self):
        """Состояние радио: dict по инстансам.

        {'DEV.WIFI.RD1': {'band': '2.4GHz', 'enabled': True,
                          'channel': int, 'auto_channel': bool}, ...}
        """
        data = self._get(ADCONF_TAG)
        out = {}
        for d in data:
            instid = d.get("_instid", "")
            if instid not in ("DEV.WIFI.RD1", "DEV.WIFI.RD2"):
                continue
            out[instid] = {
                "band": d.get("Band", ""),
                "enabled": d.get("RadioStatus", "0") == "1",
                "channel": int(d["Channel"]) if d.get("Channel") else None,
                "auto_channel": d.get("AutoChannelEnabled", "0") == "1",
                "raw": d,
            }
        return out

    def ssids(self):
        """Все 8 SSID: список dicts (AP1..AP8).

        Каждый: {'id': 'DEV.WIFI.AP1', 'alias': 'SSID1', 'ssid': str,
                 'enabled': bool, 'band': '2.4'|'5',
                 'hidden': bool, 'max_users': int, 'raw': dict}
        """
        data = self._get(SSID_TAG)
        out = []
        for d in data:
            instid = d.get("_instid", "")
            m = re.fullmatch(r"DEV\.WIFI\.AP(\d)", instid)
            if not m:
                continue
            rd = d.get("WLANViewName", "")
            band = "2.4" if rd == "DEV.WIFI.RD1" else \
                   ("5" if rd == "DEV.WIFI.RD2" else rd)
            out.append({
                "id": instid,
                "n": int(m.group(1)),
                "alias": d.get("Alias", ""),
                "ssid": d.get("ESSID", ""),
                "enabled": d.get("Enable", "0") == "1",
                "band": band,
                "hidden": d.get("ESSIDHideEnable", "0") == "1",
                "max_users": int(d["MaxUserNum"]) if d.get("MaxUserNum") else None,
                "raw": d,
            })
        out.sort(key=lambda s: s["n"])
        return out

    def _find_ap(self, ref):
        """Найти AP по id (DEV.WIFI.APn), номеру (1..8) или SSID."""
        ssids = self.ssids()
        ref = str(ref).strip()
        for s in ssids:
            if ref == s["id"]:
                return s
            if ref.isdigit() and int(ref) == s["n"]:
                return s
            if ref and ref == s["ssid"]:
                return s
        raise KeyError(f"не найдено SSID '{ref}'")

    def _find_radio(self, band):
        rd = _norm_band(band)
        data = self._get(ADCONF_TAG)
        for d in data:
            if d.get("_instid") == rd:
                return d
        raise KeyError(f"не найдено радио {rd}")

    # -- изменения --------------------------------------------------------
    def set_radio(self, band, enabled):
        """Включить/выключить радио 2.4 GHz или 5 GHz.

        Нюанс: блок `wlan_wlanbasiconoff_lua.lua` (InstSwitch/Apply)
        отвечает SUCC, но RadioStatus НЕ меняет (no-op) — роутер
        принимает переключение только через полный Apply на
        `wlan_wlanbasicadconf_lua.lua` со ВСЕМИ полями радио (так
        шлёт веб-форма). Поэтому здесь берём полный raw-снимок
        инстанса и меняем только RadioStatus.

        Возвращает новое состояние {'band': ..., 'enabled': bool}.
        """
        rd = _norm_band(band)
        cur = self.radios()[rd]
        fields = {k: v for k, v in cur["raw"].items() if k != "_instid"}
        fields["RadioStatus"] = int(bool(enabled))
        self._post(ADCONF_TAG, rd, fields)
        return self.radios()[rd]

    def enable_radio(self, band):
        return self.set_radio(band, True)

    def disable_radio(self, band):
        return self.set_radio(band, False)

    def set_channel(self, band, channel=None, auto=None):
        """Изменить канал радио (канал 1..14 для 2.4, 36..165 для 5).

        `auto=None` — оставить автоканал как есть (тогда обязательно
        задать `channel`). При `auto=True` поле Channel роутер
        принимает как "NULL" (так шлёт веб-форма), поэтому явный
        канал в этом случае игнорируется. Возвращает новое
        состояние радио.
        """
        rd = _norm_band(band)
        cur = self.radios()[rd]
        if auto is None and channel is None:
            raise ValueError("нечего изменять: channel и/или auto")
        fields = {k: v for k, v in cur["raw"].items() if k != "_instid"}
        if auto is not None:
            fields["AutoChannelEnabled"] = int(bool(auto))
            if fields["AutoChannelEnabled"]:
                fields["Channel"] = "NULL"
            elif channel is None:
                fields["Channel"] = cur["channel"] or "NULL"
        elif channel is not None:
            ch = int(channel)
            lo, hi = (1, 14) if cur["band"] == "2.4GHz" else (36, 165)
            if not lo <= ch <= hi:
                raise ValueError(f"канал {ch} вне диапазона {lo}..{hi}")
            fields["Channel"] = ch
            fields["AutoChannelEnabled"] = 0
        self._post(ADCONF_TAG, rd, fields)
        return self.radios()[rd]

    def set_ssid(self, ap, ssid):
        """Переименовать SSID (AP1..AP8, номер 1..8 или текущее имя).

        Возвращает обновлённый dict SSID.
        """
        s = self._find_ap(ap)
        if not 1 <= len(ssid) <= 32:
            raise ValueError("имя SSID: 1..32 символа")
        fields = {k: v for k, v in s["raw"].items() if k != "_instid"}
        fields["ESSID"] = ssid
        self._post(SSID_TAG, s["id"], fields)
        return next(x for x in self.ssids() if x["id"] == s["id"])

    def set_passphrase(self, ap, password):
        """Сменить WPA-PSK пароль SSID (8..63 символа, ASCII).

        Роутер принимает пароль только как часть комбинированного POST
        на AP-инстанс (как веб-форма: все поля AP + `_InstID_PSK` +
        `KeyPassphrase`). Отдельный POST на суб-инстанс `APn.PSK1`
        отклоняется с IF_ERRORID -8.

        Флаг `_PSKCONIG=Y` (из веб-формы) НЕ нужен: с ним роутер
        применяет пароль, но отвечает 404/SessionTimeout вместо XML.
        Возвращает обновлённый dict SSID.
        """
        s = self._find_ap(ap)
        if not 8 <= len(password) <= 63 or not all(ord(c) < 128 for c in password):
            raise ValueError("пароль: 8..63 символа, только ASCII")
        fields = {k: v for k, v in s["raw"].items() if k != "_instid"}
        fields["_InstID_PSK"] = s["id"] + ".PSK1"
        fields["KeyPassphrase"] = password
        self._post(SSID_TAG, s["id"], fields)
        return next(x for x in self.ssids() if x["id"] == s["id"])

    def set_ap(self, ap, enabled=None, hidden=None, max_users=None):
        """Изменить параметры SSID: включение, скрытие, макс. клиентов.

        Возвращает обновлённый dict SSID.
        """
        s = self._find_ap(ap)
        if all(v is None for v in (enabled, hidden, max_users)):
            raise ValueError("нечего изменять: enabled и/или hidden и/или max_users")
        fields = {k: v for k, v in s["raw"].items() if k != "_instid"}
        if enabled is not None:
            fields["Enable"] = int(bool(enabled))
        if hidden is not None:
            fields["ESSIDHideEnable"] = int(bool(hidden))
        if max_users is not None:
            if not 1 <= int(max_users) <= 32:
                raise ValueError("макс. клиентов: 1..32")
            fields["MaxUserNum"] = int(max_users)
        self._post(SSID_TAG, s["id"], fields)
        return next(x for x in self.ssids() if x["id"] == s["id"])
