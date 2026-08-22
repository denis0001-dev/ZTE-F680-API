"""f680.cli.compat — deprecated-обёртки для старых команд f680-api /
f680-pf / f680-dhcp / f680-net.

Каждая старая команда транслируется в новый синтаксис `f680 ...` и
вызывает единый CLI из f680.cli.main. Печатает в stderr напоминание,
что старый вариант устарел.

Старый → новый:
    f680-api <cmd> [args]     →  f680 <cmd> [args]
    f680-pf <cmd> [args]      →  f680 pf <cmd> [args]
    f680-dhcp <cmd> [args]    →  f680 dhcp <cmd> [args]
    f680-net status           →  f680 status
    f680-net devices [--json] →  f680 devices [--json]
    f680-net pf               →  f680 pf list
    f680-net all [--json]     →  f680 report [--json]
    f680-net reboot [...]     →  f680 reboot [...]
"""

import sys

from f680.cli.main import main as _new_main

NET_MAP = {"status": "status", "devices": "devices",
           "pf": "pf list", "all": "report", "reboot": "reboot"}


def legacy_main(prog, transform, argv=None):
    """Общий вход для старьёвых CLI-обёрток.

    `prog` — имя старого бинаря (для сообщения), `transform` — функция
    (old_argv) -> new_argv.
    """
    old = list(sys.argv[1:] if argv is None else argv)
    new = transform(old)
    print(f"{prog} — deprecated, используйте: f680 {' '.join(new)}",
          file=sys.stderr)
    return _new_main(new)


def _identity(argv):
    return list(argv)


def _group(prefix):
    def t(argv):
        return [prefix] + list(argv)
    return t


def _net(argv):
    argv = list(argv)
    if argv and argv[0] in NET_MAP:
        return NET_MAP[argv[0]].split() + argv[1:]
    return argv


main_api = lambda argv=None: legacy_main("f680-api", _identity, argv)
main_pf = lambda argv=None: legacy_main("f680-pf", _group("pf"), argv)
main_dhcp = lambda argv=None: legacy_main("f680-dhcp", _group("dhcp"), argv)
main_net = lambda argv=None: legacy_main("f680-net", _net, argv)
