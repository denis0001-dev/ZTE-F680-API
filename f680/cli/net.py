#!/usr/bin/env python3
"""
f680.cli.net — «одной кнопкой» обзор домашней сети через ZTE F680.

Тот набор команд, которым пользуются при сканировании сети:

    python -m f680.cli.net status   # состояние роутера (wifi/firewall/usb/voip)
    python -m f680.cli.net devices  # все клиенты + вендоры по MAC
    python -m f680.cli.net pf       # правила проброса портов
    python -m f680.cli.net all      # всё вместе (отчёт)

Глобальные опции:
    --base URL   [default: из .env]
    --user U     [default: из .env]
    --pass P     [default: из .env]
    -v           verbose

После `pip install -e .` доступен и консольный скрипт `f680-net`.
"""

import argparse
import json
import sys
import time

from f680.client import F680
from f680.portforward import PortForward
from f680.macvendor import guess_device
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2

# ---------------------------------------------------------------------------
# Fmt helpers
# ---------------------------------------------------------------------------

def _col(*cols, total=0):
    """Build a format string from (text, min_width) pairs."""
    return "".join(f"{{:<{w}}}" for _, w in cols)


def fmt_devices(devs, title="УСТРОЙСТВА"):
    if not devs:
        print(f"(не найдено {title.lower()})")
        return
    cols = [("IP", 15), ("MAC", 19), ("HOST", 20), ("ВЕНДОР/ПОДСКАЗКА", 34), ("СЕТЬ", 7)]
    fmt = _col(*cols)
    print(fmt.format(*[c for c, _ in cols]))
    print(fmt.format(*["-" * w for _, w in cols]))
    for d in sorted(devs, key=lambda x: x.get("IPAddress", "")):
        ip = d.get("IPAddress", "")
        mac = d.get("MACAddress", "")
        host = d.get("HostName", "") or "(без имени)"
        src = d.get("source", "")
        vendor = guess_device(mac, host)
        if host in ("(без имени)",) and not vendor:
            vendor = ""
        print(fmt.format(ip, mac, host, vendor, src))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(c: F680, args):
    st = c.status()
    print("=== РОУТЕР: СОСТОЯНИЕ ===")
    radio = st["wifi"].get("RadioSwitch")
    print(f"  Wi-Fi radio:  {'ВКЛ' if radio == '1' else 'ВЫКЛ' if radio == '0' else 'неизвестно'}")
    fw = st["firewall"]
    print(f"  Firewall:     Level={fw.get('Level', '?')}, "
          f"AntiAttack={'вкл' if fw.get('AntiAttack') == '1' else 'выкл'}")
    usb = st["usb"]
    print(f"  USB FTP:      {'вкл' if usb.get('FtpEnable') == '1' else 'выкл'}"
          f" (порт {usb.get('ServerPort', '21')})")
    voip = st["voip"]
    print(f"  VoIP:         {'online' if voip.get('IsOnline') == '1' else 'offline'}"
          f" (RegStatus={voip.get('VoIPRegStatus', '?')})")
    if st["errors"]:
        print("  Ошибки страниц: " + "; ".join(st["errors"]))
    else:
        print("  Все страницы прочитаны без ошибок")


def cmd_devices(c: F680, args):
    devs = c.connected_devices()
    n_wired = sum(1 for d in devs if d.get("source") == "wired")
    n_wifi = sum(1 for d in devs if d.get("source") == "wifi")
    print(f"=== КЛИЕНТЫ СЕТИ: всего {len(devs)} "
          f"(wired: {n_wired}, wifi: {n_wifi}) ===")
    fmt = "  {:<15} {:<19} {:<20} {:<34} {}"
    print(fmt.format("IP", "MAC", "HOST", "ВЕНДОР/ПОДСКАЗКА", "СЕТЬ"))
    print("  " + "-" * 95)
    for d in sorted(devs, key=lambda x: x.get("IPAddress", "")):
        ip = d.get("IPAddress", "")
        mac = d.get("MACAddress", "")
        host = d.get("HostName", "") or "(без имени)"
        src = d.get("source", "")
        vendor = guess_device(mac, host)
        print(fmt.format(ip, mac, host, vendor, src))


def cmd_pf(pf: PortForward, args):
    rules = pf.rules()
    print(f"=== PORT FORWARDING: {len(rules)} правил ===")
    if not rules:
        print("(пусто)")
        return
    print(f"  {'ВН. ПОРТ':<14} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} -> ВНУТРЕННИЙ")
    print("  " + "-" * 70)

    def rng(a, b):
        return str(a) if b == a else f"{a}-{b}"

    for r in rules:
        ext = rng(r["ext_port"], r["ext_port_end"] or r["ext_port"])
        inp = rng(r["int_port"], r["int_port_end"] or r["int_port"])
        state = "" if r["enabled"] else " [выкл]"
        print(f"  {ext:<14} {r['protocol'].lower():<6} {r['alias']:<22} "
              f"{r['int_ip']}:{inp}{state}")


def cmd_all(c: F680, args):
    cmd_status(c, args)
    print()
    cmd_devices(c, args)
    print()
    with PortForward(base=c.base, username=c.username,
                     password=c.password) as pf:
        cmd_pf(pf, args)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="f680-net",
        description="Обзор домашней сети через ZTE F680 "
                    "(статус роутера, клиенты, port forwarding)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "примеры:\n"
            "  f680-net status    # состояние роутера\n"
            "  f680-net devices   # все клиенты + вендоры\n"
            "  f680-net pf        # правила проброса портов\n"
            "  f680-net all       # полный отчёт\n"
            "  f680-net reboot    # перезагрузить роутер (и дождаться подъёма)\n"
            "  f680-net devices --json\n"
        ))
    ap.add_argument("--base", default=BASE, help=argparse.SUPPRESS)
    ap.add_argument("--user", default=USERNAME, help=argparse.SUPPRESS)
    ap.add_argument("--pass", dest="password", default=PASSWORD,
                    help=argparse.SUPPRESS)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="состояние роутера (wifi/firewall/usb/voip)")
    p_dev = sub.add_parser("devices", help="все клиенты + вендоры по MAC")
    p_dev.add_argument("--json", action="store_true",
                       help="вывод в JSON (с вендорами)")
    sub.add_parser("pf", help="правила проброса портов")
    sub.add_parser("all", help="полный отчёт: status + devices + pf")
    p_reboot = sub.add_parser("reboot", help="перезагрузить роутер")
    p_reboot.add_argument("--no-wait", action="store_true",
                         help="не ждать, пока роутер поднимется")
    p_reboot.add_argument("--timeout", type=int, default=180)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)

    c = F680(base=args.base, username=args.user,
             password=args.password, verbose=args.verbose)
    try:
        with c:
            if args.cmd == "status":
                cmd_status(c, args)
            elif args.cmd == "devices":
                devs = c.connected_devices()
                if args.json:
                    for d in devs:
                        d["vendor_guess"] = guess_device(
                            d.get("MACAddress", ""), d.get("HostName", ""))
                    print(json.dumps(devs, ensure_ascii=False, indent=2))
                else:
                    cmd_devices(c, args)
            elif args.cmd == "pf":
                with PortForward(base=args.base, username=args.user,
                                 password=args.password,
                                 verbose=args.verbose) as pf:
                    cmd_pf(pf, args)
            elif args.cmd == "all":
                cmd_all(c, args)
            elif args.cmd == "reboot":
                c.reboot()
                print("reboot запрошен — роутер перезагружается...")
                if not args.no_wait:
                    t0 = time.time()
                    try:
                        c.wait_online(timeout=args.timeout)
                    finally:
                        print(f"роутер снова в сети через {int(time.time()-t0)} c")
        return 0
    except RuntimeError as e:
        if "login failed" in str(e).lower():
            print("ОШИБКА ВХОДА", file=sys.stderr)
            return EXIT_LOGIN_FAILED
        raise


if __name__ == "__main__":
    sys.exit(main())
