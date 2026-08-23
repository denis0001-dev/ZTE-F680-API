#!/usr/bin/env python3
"""Test: read accounts, change password, change back on the F680.

Тест трогает РЕАЛЬНЫЙ роутер: читает список учётных записей и таймаут
сессии, меняет пароль `mgts` на временный, проверяет логин с новым
паролем, меняет обратно и проверяет логин с исходным паролем.

Важно: смена пароля НЕ рвёт текущую сессию, но неудачный логин ставит
паузу (lockingTime) — если логин с новым паролем с первого раза не
прошёл (случайный FAIL при коммите), клиент внутри F680.login уже
ретраит. Запуск:

    python3 tests/test_account_integration.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680 import F680
from f680.account import Account
from f680.config import BASE, PASSWORD, USERNAME

TEST_PW = "tempPw@123"


def main():
    with Account(verbose=True) as a:
        print("== accounts ==")
        accs = a.accounts()
        print("  ", accs)
        assert any(x["username"] == "mgts" for x in accs), "нет mgts"

        print("== timeout ==")
        t = a.timeout()
        print("  ", t)

        print("== set timeout to 10, then back ==")
        after = a.set_timeout(10)
        if after["timeout"] != 10:
            print("SET TIMEOUT FAILED:", after)
            return 1
        print("  ", after)
        a.set_timeout(t["timeout"])
        after = a.timeout()
        if after["timeout"] != t["timeout"]:
            print("TIMEOUT RESTORE FAILED:", after)
            return 1
        print("  ", after)

        print("== change password mgts ==")
        a.change_password(USERNAME, PASSWORD, TEST_PW)
        print("  changed")

        print("== login with new password ==")
        a2 = Account(base=BASE, username=USERNAME, password=TEST_PW,
                     verbose=True)
        a2.login()
        print("  login OK")

        print("== change password back (new session — old one is killed) ==")
        a2.change_password(USERNAME, TEST_PW, PASSWORD)
        a2.logout()
        print("  changed back")

    print("== final: login with original password ==")
    c3 = F680(base=BASE, username=USERNAME, password=PASSWORD, verbose=True)
    if not c3.login():
        print("LOGIN WITH ORIGINAL PW FAILED")
        return 1
    c3.logout()
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
