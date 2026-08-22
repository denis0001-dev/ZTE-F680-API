#!/usr/bin/env python3
"""
f680.cli.dhcp — CLI для статических DHCP-привязок (MAC -> IP) на ZTE F680.

Синтаксис:
    python -m f680.cli.dhcp list
    python -m f680.cli.dhcp leases
    python -m f680.cli.dhcp set <IP> <MAC> [название]
    python -m f680.cli.dhcp remove <IP или MAC>
    python -m f680.cli.dhcp rename <IP или MAC> <новое название>

Примеры:
    python -m f680.cli.dhcp set 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
    python -m f680.cli.dhcp remove 192.168.1.6
"""

import argparse
import sys

from f680.dhcp import Dhcp
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2


def print_reservations(rules):
    print(f"{'IP':<16} {'MAC':<18} {'НАЗВАНИЕ':<24} ID")
    for r in rules:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['name']:<24} {r['id']}")


def print_leases(rows):
    print(f"{'IP':<16} {'MAC':<18} HOSTNAME")
    for r in rows:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['hostname']}")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="f680-dhcp",
        description="Статические DHCP-привязки (MAC -> IP) на ZTE F680",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "примеры:\n"
            "  f680-dhcp list\n"
            "  f680-dhcp leases\n"
            "  f680-dhcp set 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook\n"
            "  f680-dhcp remove 192.168.1.6\n"
            "  f680-dhcp rename 192.168.1.6 Mac-new\n"
        ))
    ap.add_argument("--base", default=BASE, help=argparse.SUPPRESS)
    ap.add_argument("--user", default=USERNAME, help=argparse.SUPPRESS)
    ap.add_argument("--pass", dest="password", default=PASSWORD,
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="все статические привязки")
    sub.add_parser("leases", help="DHCP-аренды (кто реально онлайн)")
    sub.add_parser("logout", help="логин + явный logout (тест)")

    p_set = sub.add_parser("set", help="создать/обновить привязку IP<->MAC")
    p_set.add_argument("ip", help="IP-адрес, напр. 192.168.1.6")
    p_set.add_argument("mac", help="MAC-адрес, напр. 1c:f6:4c:a0:cc:96")
    p_set.add_argument("name", nargs="?", default=None, help="название")

    p_rm = sub.add_parser("remove", help="удалить привязку")
    p_rm.add_argument("ref", help="IP или MAC")
    p_ren = sub.add_parser("rename", help="переименовать привязку")
    p_ren.add_argument("ref", help="IP или MAC")
    p_ren.add_argument("name", help="новое название")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    d = Dhcp(base=args.base, username=args.user, password=args.password)

    try:
        with d:
            if args.cmd == "list":
                print_reservations(d.reservations())
            elif args.cmd == "leases":
                print_leases(d.active_hosts())
            elif args.cmd == "logout":
                d.logout()  # уже залогинены через __enter__
                print("logout OK")
            elif args.cmd == "set":
                rid = d.set_reservation(args.ip, args.mac, name=args.name)
                print(f"OK: привязка {args.ip} -> {args.mac.lower()} "
                      f"создана/обновлена (id: {rid})")
                print_reservations(d.reservations())
            elif args.cmd == "remove":
                r = d.remove_reservation(args.ref)
                print(f"OK: привязка '{r['name']}' ({r['ip']}) удалена")
            elif args.cmd == "rename":
                r = d.rename_reservation(args.ref, args.name)
                print(f"OK: привязка переименована в '{args.name}' "
                      f"({r['ip']})")
        return 0
    except (KeyError, ValueError, RuntimeError) as e:
        if "login failed" in str(e).lower():
            print("ОШИБКА ВХОДА", file=sys.stderr)
            return EXIT_LOGIN_FAILED
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
