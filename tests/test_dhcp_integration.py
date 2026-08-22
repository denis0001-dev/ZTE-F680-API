#!/usr/bin/env python3
"""Test: read + create + delete a static DHCP reservation on the F680.

Тест трогает РЕАЛЬНЫЙ роутер: создаёт временную привязку
192.168.1.199 -> 00:00:00:00:00:ff (мак не должен быть занят) и удаляет её.

ВАЖНО: роутеру нужно ~3 секунды между изменениями (иначе IF_ERRORID -257),
поэтому между операциями стоят паузы. Запуск:

    python3 tests/test_dhcp_integration.py

ВНИМАНИЕ: каждый GET данных (reservations/active_hosts) валидирует
одноразовый токен страницы — после нескольких GET-ов подряд первый POST
получает -257. Поэтому тест держит один снимок на всё и не делает
лишних GET-ов. Ретраи FAIL-ов живут внутри Dhcp._post (f680/dhcp.py).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680.dhcp import Dhcp

TEST_IP = "192.168.1.199"
TEST_MAC = "00:00:00:00:00:ff"
TEST_NAME = "pytestdhcp"  # <= 10 символов: роутер отклоняет более длинные (см. dhcp.NAME_MAX_LEN)
PAUSE = 3  # сек между изменениями — роутер «зависает» на коммит


def cleanup(d, snap):
    """Убрать мусор из СНИМКА (дополнительный GET сюда нельзя:
    каждый GET данных валидирует одноразовый токен страницы, а после
    ~4 GET-ов роутер отвечает -257 на первый POST — см. dhcp.py)."""
    for r in snap:
        if r["ip"] == TEST_IP or r["mac"] == TEST_MAC:
            d._post("Delete", instid=r["id"])
            print("  removed leftover:", r["id"], r["name"])


def main():
    with Dhcp(verbose=True) as d:
        print("== current reservations ==")
        snap = d.reservations()  # ОДИН снимок на всё (см. cleanup)
        for r in snap:
            print("  ", r["ip"], r["mac"], r["name"])
        cleanup(d, snap)
        time.sleep(PAUSE)

        print("== create test reservation ==")
        rid = d.set_reservation(TEST_IP, TEST_MAC, name=TEST_NAME)
        print("  created:", rid)
        time.sleep(PAUSE)

        print("== reservations after add ==")
        found = next((r for r in d.reservations() if r["ip"] == TEST_IP), None)
        if found is None:
            print("ADD FAILED - aborting")
            return 1
        print("  ", found["ip"], found["mac"], found["name"])
        if found["id"] != rid:
            print("ID MISMATCH:", found["id"], "!=", rid)
            return 1

        print("== remove reservation ==", found["id"])
        time.sleep(PAUSE)
        d.remove_reservation(found["id"])
        time.sleep(PAUSE)

        print("== reservations after remove ==")
        leftovers = [r for r in d.reservations() if r["ip"] == TEST_IP]
        if leftovers:
            print("REMOVAL FAILED, still present:", leftovers)
            return 1
        for r in d.reservations():
            print("  ", r["ip"], r["mac"], r["name"])

    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
