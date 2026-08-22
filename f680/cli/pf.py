#!/usr/bin/env python3
"""
f680.cli.pf — CLI для управления пробросом портов на ZTE F680.

Синтаксис:
    python -m f680.cli.pf list
    python -m f680.cli.pf open <порт> <ip> <порт> [название] [--proto tcp|udp|both]
    python -m f680.cli.pf close <порт или название>
    python -m f680.cli.pf remove <порт или название>
    python -m f680.cli.pf logout

Примеры:
    python -m f680.cli.pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
    python -m f680.cli.pf close 3000
    python -m f680.cli.pf remove "PC | Open WebUI"

Порт может быть диапазоном, напр. 50000-60000 (через --ext-end / --int-end).
"""

import argparse
import sys

from f680.portforward import PortForward, PROTOS
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2


def _fmt_range(a, b):
    return str(a) if b == a else f"{a}-{b}"


def print_rules(rules):
    print(f"{'ПОРТ':<12} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} {'-> IP:ПОРТ':<22} СОСТОЯНИЕ")
    for r in rules:
        ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
        inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
        state = "" if r["enabled"] else " [выкл]"
        print(f"{ext:<12} {r['protocol'].lower():<6} {r['alias']:<22} "
              f"{r['int_ip']}:{inp:<13}{state}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="f680-pf",
        description="Проброс портов на ZTE F680",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "примеры:\n"
            "  f680-pf list\n"
            '  f680-pf open 3000 192.168.1.3 3000 "PC | Open WebUI"\n'
            "  f680-pf close 3000\n"
            '  f680-pf remove "PC | Open WebUI"\n'
            "\nопции для open:\n"
            "  --proto tcp|udp|both (по умолчанию both)\n"
            "  --ext-end N  конец диапазона внешних портов\n"
            "  --int-end N  конец диапазона внутренних портов\n"
            "  --from IP    ограничить внешний IP (по умолчанию любой)"
        ))
    ap.add_argument("--base", default=BASE, help=argparse.SUPPRESS)
    ap.add_argument("--user", default=USERNAME, help=argparse.SUPPRESS)
    ap.add_argument("--pass", dest="password", default=PASSWORD,
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="показать все правила")
    sub.add_parser("logout", help="логин + явный logout (тест)")

    p_open = sub.add_parser("open", help="создать/обновить и включить правило")
    p_open.add_argument("port", type=int, help="внешний порт")
    p_open.add_argument("ip", help="IP устройства в локальной сети")
    p_open.add_argument("int_port", type=int, help="внутренний порт")
    p_open.add_argument("name", nargs="?", default=None, help="название правила")
    p_open.add_argument("--proto", default="both", choices=sorted(PROTOS))
    p_open.add_argument("--ext-end", type=int)
    p_open.add_argument("--int-end", type=int)
    p_open.add_argument("--from", dest="remote_host", default="0.0.0.0")

    p_close = sub.add_parser("close", help="отключить правило (оставить)")
    p_close.add_argument("ref", help="порт или название")
    p_remove = sub.add_parser("remove", help="удалить правило")
    p_remove.add_argument("ref", help="порт или название")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    pf = PortForward(base=args.base, username=args.user,
                     password=args.password)

    try:
        with pf:
            if args.cmd == "list":
                print_rules(pf.rules())
            elif args.cmd == "logout":
                pf.logout()  # уже залогинены через __enter__
                print("logout OK")
            elif args.cmd == "open":
                rid = pf.open_port(args.port, args.ip, args.int_port,
                                   proto=args.proto, alias=args.name,
                                   ext_port_end=args.ext_end,
                                   int_port_end=args.int_end,
                                   remote_host=args.remote_host)
                print(f"OK: правило порта {args.port} создано/обновлено "
                      f"(id: {rid})")
                print_rules(pf.rules())
            elif args.cmd == "close":
                r = pf.close_port(args.ref)
                print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) "
                      f"отключено")
            elif args.cmd == "remove":
                r = pf.remove_port(args.ref)
                print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) "
                      f"удалено")
        return 0
    except (KeyError, RuntimeError) as e:
        if "login failed" in str(e).lower():
            print("ОШИБКА ВХОДА", file=sys.stderr)
            return EXIT_LOGIN_FAILED
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
