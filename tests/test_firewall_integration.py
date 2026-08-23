#!/usr/bin/env python3
"""Test: read + modify + restore firewall and anti-DoS on the F680.

Тест трогает РЕАЛЬНЫЙ роутер: снимает исходное состояние обоих блоков,
прогоняет изменения (уровень FW, вкл/выкл FW, порог anti-DoS,
вкл/выкл anti-DoS) и в конце восстанавливает исходное состояние.

ВАЖНО: роутеру нужно ~3 секунды между изменениями (иначе IF_ERRORID -257),
поэтому между операциями стоят паузы. Ретраи FAIL-ов живут внутри
Firewall._post (f680/firewall.py). Запуск:

    python3 tests/test_firewall_integration.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680.firewall import Firewall

PAUSE = 3  # сек между изменениями — роутер «зависает» на коммит
TEST_THRESHOLD = 200  # 1..999


def restore(fw, cur):
    """Вернуть блоки к исходному состоянию (см. main)."""
    if cur["fw"]:
        if cur["fw"]["level"]:
            fw.set_level(cur["fw"]["level"])
            time.sleep(PAUSE)
    # порядок не важен: enable/disable не сбрасывает уровень (см. docs/FIREWALL.md 3.3)
    (fw.enable if cur["fw"]["enabled"] else fw.disable)()
    time.sleep(PAUSE)
    fw.set_dos(enabled=cur["dos"]["enabled"],
               threshold=cur["dos"]["threshold"] or 100)
    time.sleep(PAUSE)


def main():
    orig = None
    with Firewall(verbose=True) as fw:
        print("== original state ==")
        cur = {"fw": fw.config(), "dos": fw.dos()}
        orig = cur
        print("  firewall:", cur["fw"])
        print("  anti-dos:", cur["dos"])

        print("== set level to middle ==")
        after = fw.set_level("middle")
        if after["level"] != "middle":
            print("LEVEL CHANGED FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)

        print("== toggle firewall off/on ==")
        after = fw.disable()
        if after["enabled"]:
            print("DISABLE FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)
        after = fw.enable()
        if not after["enabled"]:
            print("ENABLE FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)

        print(f"== set anti-DoS threshold to {TEST_THRESHOLD} ==")
        after = fw.set_threshold(TEST_THRESHOLD)
        if after["threshold"] != TEST_THRESHOLD:
            print("THRESHOLD CHANGED FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)

        print("== toggle anti-DoS off/on ==")
        after = fw.disable_dos()
        if after["enabled"]:
            print("DOS DISABLE FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)
        after = fw.enable_dos()
        if not after["enabled"]:
            print("DOS ENABLE FAILED:", after)
            return 1
        print("  ", after)
        time.sleep(PAUSE)

        print("== restore original state ==")
        restore(fw, cur)
        time.sleep(PAUSE)

        final = {"fw": fw.config(), "dos": fw.dos()}
        print("  final:", final)
        ok = (final["fw"]["enabled"] == orig["fw"]["enabled"]
              and final["fw"]["level"] == orig["fw"]["level"]
              and final["dos"]["enabled"] == orig["dos"]["enabled"]
              and final["dos"]["threshold"] == orig["dos"]["threshold"])
        if not ok:
            print("RESTORE MISMATCH:", orig, "->", final)
            return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
