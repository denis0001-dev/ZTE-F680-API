"""
f680.macvendor — определение вендора устройства по MAC-адресу.

Оффлайн-таблица OUI (первые 3 байта) + эвристики по hostname.
Собрано из данных реального сканирования домашней сети (2026-08)
и типовых префиксов. Таблицу легко дополнять: OUI[name] = "Вендор".
"""

import re

# ---------------------------------------------------------------------------
# OUI-таблица (первые 24 бита MAC). Только то, что реально встречается
# или интересно; при желании можно подключить mactype/oui.txt целиком.
# ---------------------------------------------------------------------------
OUI = {
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi (RPi3/4/5)",
    "50:8b:b9": "Raspberry Pi (RPi4)",
    # Apple
    "1c:f6:4c": "Apple",
    # Samsung
    "5c:dc:49": "Samsung",
    # Xiaomi / Realtek (Xiaomi часто использует Realtek Wi-Fi)
    "66:98:0b": "Xiaomi (Realtek Wi-Fi)",
    "2a:8a:9c": "Xiaomi (Realtek Wi-Fi)",
    # Realtek
    "3c:0b:4f": "Realtek (IoT/SBC)",
    # Intel / Realtek — SBC, IoT-модули
    "b8:87:6e": "Intel/Realtek (SBC/IoT)",
    # Bosch / BlitzWolf / Bambu Lab
    "ac:ba:c0": "Bosch/BlitzWolf/Bambu Lab",
    # Bambu Lab (бренд Bl606a0 — чип BL606, напр. A1 mini)
    "b4:e8:42": "Bambu Lab (BL606)",
}

# ---------------------------------------------------------------------------
# Эвристики по hostname — иногда говорят больше, чем OUI.
# ---------------------------------------------------------------------------
HOSTNAME_HINTS = [
    (r"^wlan0$", "Raspberry Pi (Wi-Fi)"),
    (r"^bl606", "Bambu Lab (устройство на чипе BL606, напр. A1 mini)"),
    (r"^air", "Apple (AirDrop-устройство)"),
    (r"galaxy", "Samsung Galaxy"),
    (r"^(poco|redmi|xiaomi)", "Xiaomi"),
    (r"iphone", "Apple iPhone"),
    (r"ipad", "Apple iPad"),
    (r"^mac", "Apple Mac"),
]


def mac_vendor(mac: str) -> str:
    """Вернуть имя вендора по MAC ('' если неизвестно)."""
    if not mac:
        return ""
    m = re.sub(r"[:-]", ":", mac.lower())
    if len(m) != 17:
        return ""
    prefix = m[:8]  # "xx:xx:xx"
    return OUI.get(prefix, "")


def hostname_hint(hostname: str) -> str:
    """Вернуть подсказку по hostname ('' если ничего не совпало)."""
    if not hostname:
        return ""
    for pattern, hint in HOSTNAME_HINTS:
        if re.search(pattern, hostname, re.I):
            return hint
    return ""


def _first_word(s: str) -> str:
    """Первое (главное) слово строки, нижний регистр: 'Raspberry Pi …' -> 'raspberry'."""
    return s.split(None, 1)[0].lower() if s.split() else ""


def guess_device(mac: str, hostname: str = "") -> str:
    """Комбинированный вердикт: вендор по MAC + подсказка по hostname.

    Возвращает строку вида "Bambu Lab (BL606); устройство на чипе BL606…"
    или "" если ничего не удалось определить.

    Дедуп: если одна часть содержит другую (подстрока) или они начинаются
    с одного главного слова — оставляем только более полную.
    """
    parts = [p for p in (mac_vendor(mac), hostname_hint(hostname)) if p]
    out = []
    for p in parts:
        clash = any(p.lower() in q.lower() or q.lower() in p.lower()
                    or _first_word(p) == _first_word(q)
                    for q in out)
        if clash:
            # оставляем более длинную/подробную
            if len(p) > len(max(out, key=len)):
                out = [q for q in out
                       if p.lower() not in q.lower()
                       and _first_word(p) != _first_word(q)] + [p]
        else:
            out.append(p)
    return "; ".join(out)
