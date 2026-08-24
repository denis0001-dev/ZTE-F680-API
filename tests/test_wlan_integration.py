#!/usr/bin/env python3
"""Test: read + modify + restore WLAN on the F680.

Тест трогает РЕАЛЬНЫЙ роутер. Чтобы не ломать живую сеть, все
«болтающиеся» изменения делаем на ВЫКЛЮЧЕННЫХ SSID:

  - AP4 (2.4 GHz, выкл) — смена пароля WPA-PSK + смена SSID + вкл/выкл;
  - AP8 (5 GHz, выкл)   — смена SSID;
  - 5 GHz радио         — вкл/выкл (set_radio) + round-trip автоканала.

Нюанс set_radio: блок onoff (wlan_wlanbasiconoff_lua.lua) отвечает
SUCC, но RadioStatus не меняет — переключение применяется полным
Apply на wlan_wlanbasicadconf_lua.lua со всеми полями радио.

Важные нюансы:
  * роутеру нужно ~3 секунды между изменениями (иначе IF_ERRORID -257) —
    между операциями стоят паузы; ретраи живут внутри WLAN._post;
  * старый WPA-PSK роутер НЕ отдаёт при чтении — «restore» пароля AP4
    невозможен, после теста остаётся известный пароль "TestPsw123"
    (AP4 выключен, на сеть это не влияет);
  * SessionTimeout внутри _post/релога — норм, клиент сам перезалогинится.

Запуск:
    python3 tests/test_wlan_integration.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680.wlan import WLAN

PAUSE = 3        # сек между изменениями
NEW_AP4_SSID = "SSID_FREE_TEST"
NEW_AP8_SSID = "SSID_FREE5_TEST"
TEST_PASS = "TestPsw123"


def main():
    orig = None
    with WLAN(verbose=True) as w:
        print("== original state ==")
        radios = w.radios()
        ssids = {s["id"]: s for s in w.ssids()}
        orig = {"radios": radios, "ssids": {k: dict(v) for k, v in ssids.items()}}
        for inst, r in radios.items():
            print(f"  {inst}: enabled={r['enabled']} channel={r['channel']} "
                  f"auto={r['auto_channel']}")
        for s in sorted(ssids.values(), key=lambda x: x["n"]):
            print(f"  {s['id']}: enabled={s['enabled']} ssid={s['ssid']!r}")

        ap4, ap8 = ssids["DEV.WIFI.AP4"], ssids["DEV.WIFI.AP8"]
        assert not ap4["enabled"] and not ap8["enabled"], \
            "AP4/AP8 должны быть выключены, иначе тест рвёт живую сеть"

        # 1. пароль AP4 (2.4, выкл) ---------------------------------------
        print("== set_passphrase AP4 ->", TEST_PASS, "==")
        res = w.set_passphrase("4", TEST_PASS)
        if res["ssid"] != ap4["ssid"]:
            print("PASSPHRASE POST CHANGED SSID:", res)
            return 1
        print("  OK (пароль принят, SSID не тронут)")
        time.sleep(PAUSE)

        # 2. смена SSID AP4 ------------------------------------------------
        print("== set_ssid AP4 ->", NEW_AP4_SSID, "==")
        res = w.set_ssid("4", NEW_AP4_SSID)
        if res["ssid"] != NEW_AP4_SSID:
            print("AP4 SSID CHANGED FAILED:", res)
            return 1
        print("  ", res["ssid"])
        time.sleep(PAUSE)

        # 3. вкл/выкл AP4 ---------------------------------------------------
        print("== enable AP4 ==")
        res = w.set_ap("4", enabled=True)
        if not res["enabled"]:
            print("AP4 ENABLE FAILED:", res)
            return 1
        time.sleep(PAUSE)
        print("== disable AP4 ==")
        res = w.set_ap("4", enabled=False)
        if res["enabled"]:
            print("AP4 DISABLE FAILED:", res)
            return 1
        time.sleep(PAUSE)

        # 4. смена SSID AP8 (5 GHz, выкл) ----------------------------------
        print("== set_ssid AP8 ->", NEW_AP8_SSID, "==")
        res = w.set_ssid("8", NEW_AP8_SSID)
        if res["ssid"] != NEW_AP8_SSID:
            print("AP8 SSID CHANGED FAILED:", res)
            return 1
        print("  ", res["ssid"])
        time.sleep(PAUSE)

        # 5. 5 GHz радио: вкл/выкл (set_radio) ------------------------------
        print("== set_radio 5 off ==")
        after = w.set_radio("5", False)
        if after["enabled"] is not False:
            print("5G RADIO OFF FAILED:", after)
            return 1
        time.sleep(PAUSE)
        print("== set_radio 5 on ==")
        after = w.set_radio("5", True)
        if after["enabled"] is not True:
            print("5G RADIO ON FAILED:", after)
            return 1
        print("  5G radio round-trip OK")
        time.sleep(PAUSE)

        # 6. 5 GHz радио: round-trip автоканала -----------------------------
        r5 = radios["DEV.WIFI.RD2"]
        print("== set_channel 5 (auto, round-trip) ==")
        after = w.set_channel("5", auto=r5["auto_channel"])
        if not after["enabled"] or after["auto_channel"] != r5["auto_channel"]:
            print("5G ROUND-TRIP MISMATCH:", r5, "->", after)
            return 1
        print("  auto=", after["auto_channel"], "channel=", after["channel"])
        time.sleep(PAUSE)

        # 7. restore --------------------------------------------------------
        print("== restore ==")
        w.set_ssid("4", ap4["ssid"])
        time.sleep(PAUSE)
        w.set_ssid("8", ap8["ssid"])
        time.sleep(PAUSE)

        final_s = {s["id"]: s for s in w.ssids()}
        final_r = w.radios()
        ok = (final_s["DEV.WIFI.AP4"]["ssid"] == ap4["ssid"]
              and final_s["DEV.WIFI.AP4"]["enabled"] is False
              and final_s["DEV.WIFI.AP8"]["ssid"] == ap8["ssid"]
              and final_r["DEV.WIFI.RD2"]["enabled"] == r5["enabled"]
              and final_r["DEV.WIFI.RD2"]["auto_channel"] == r5["auto_channel"])
        if not ok:
            print("RESTORE MISMATCH:")
            print("  AP4:", final_s["DEV.WIFI.AP4"])
            print("  AP8:", final_s["DEV.WIFI.AP8"])
            print("  RD2:", final_r["DEV.WIFI.RD2"])
            return 1
        print("  AP4/AP8 SSID restored, 5G radio restored")
        print("  (AP4 passphrase теперь 'TestPsw123' — старый нечитаем)")
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
