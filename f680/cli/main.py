#!/usr/bin/env python3
"""
f680 — единый CLI для роутера ZTE F680 (DST/MGTS).

Запуск:

    f680 <команда> [аргументы] [опции]
    python -m f680 <команда> [аргументы] [опции]

Команды:
    status                     состояние роутера (wifi/firewall/usb/voip)
    devices                    все клиенты + вендоры по MAC
    report / all               полный отчёт: status + devices + ports + dhcp
    ports  list|add|enable|disable|remove|rename      проброс портов (NAT)
    dhcp   list|leases|add|remove|rename             статические DHCP-привязки (MAC -> IP)
    page <tag>                 дамп data-страницы
    raw <qs>                   сырой запрос
    pages                      список известных страниц
    reboot                     перезагрузить роутер (подтверждение / -y)
    reset                      сброс к заводским (подтверждение / -y)
    login / logout             проверка сессии

Деструктивные действия (reboot, reset, ports remove, dhcp remove)
просят подтверждение в терминале: нажать `y` (без Enter).
Для автоматизации: -y / --yes. В Python API подтверждений нет.

Глобальные опции (ставятся ПЕРЕД командой):
    --base URL    адрес роутера   [из .env / F680_BASE, default http://192.168.1.1]
    --user U      логин           [из .env / F680_USERNAME, default mgts]
    --pass P      пароль          [из .env / F680_PASSWORD]
    -v, --verbose                debug-вывод в stderr
    -j, --json                   вывод в JSON (у команд, которые его поддерживают)

Примеры:
    f680 devices
    f680 devices --json
    f680 report
    f680 ports list
    f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"
    f680 ports add 22 192.168.1.2 22 --proto tcp
    f680 ports disable 3000
    f680 ports remove "PC | Open WebUI"
    f680 dhcp add 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
    f680 dhcp rename 192.168.1.6 Mac
    f680 dhcp remove 192.168.1.6
    f680 reboot -y
    f680 reset -y

Все команды работают через context manager: авто-login при входе и
авто-logout при выходе (даже при ошибке) — на роутере не остаётся
мёртвая сессия.
"""

import argparse
import json
import os
import re
import sys
import termios
import time
import tty

from f680.client import F680, PAGES
from f680.portforward import PortForward, PROTOS
from f680.dhcp import Dhcp
from f680.macvendor import guess_device
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2
EXIT_NOT_CONFIRMED = 3


# ---------------------------------------------------------------------------
# Подтверждение деструктивных действий
# ---------------------------------------------------------------------------

def confirm(prompt, assume_yes=False):
    """Интерактивное подтверждение через tty: нажать `y` (без Enter).

    `n`/Enter/любая другая клавиша — отмена. Без tty: нужен --yes.
    Python API подтверждений не знает — это чисто CLI-механика.
    """
    if assume_yes:
        return True
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        print(f"{prompt}\n"
              "нет tty для интерактивного подтверждения — используйте -y / --yes",
              file=sys.stderr)
        return False
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        os.write(fd, f"{prompt} [y/n] ".encode("utf-8"))
        ch = os.read(fd, 1).decode("utf-8", "replace").lower()
        os.write(fd, b"\n")
        return ch in ("y", "у")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        os.close(fd)


# ---------------------------------------------------------------------------
# Форматирование (общее для текстового вывода)
# ---------------------------------------------------------------------------

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


def print_reservations(rules):
    print(f"{'IP':<16} {'MAC':<18} {'НАЗВАНИЕ':<24} ID")
    for r in rules:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['name']:<24} {r['id']}")


def print_leases(rows):
    print(f"{'IP':<16} {'MAC':<18} HOSTNAME")
    for r in rows:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['hostname']}")


def print_devices_table(devs, title="КЛИЕНТЫ СЕТИ"):
    n_wired = sum(1 for d in devs if d.get("source") == "wired")
    n_wifi = sum(1 for d in devs if d.get("source") == "wifi")
    print(f"=== {title}: всего {len(devs)} (wired: {n_wired}, wifi: {n_wifi}) ===")
    if not devs:
        print("(не найдено)")
        return
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


def devices_as_dicts(devs):
    """Клиенты в dict'ах + поле vendor_guess (для --json)."""
    out = []
    for d in devs:
        d = dict(d)
        d["vendor_guess"] = guess_device(d.get("MACAddress", ""),
                                         d.get("HostName", ""))
        out.append(d)
    return out


def _print_status_text(st):
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


def _print_ports_section(rules):
    print(f"=== PORT FORWARDING: {len(rules)} правил ===")
    if not rules:
        print("(пусто)")
        return
    print(f"  {'ВН. ПОРТ':<14} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} -> ВНУТРЕННИЙ")
    print("  " + "-" * 70)
    for r in rules:
        ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
        inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
        state = "" if r["enabled"] else " [выкл]"
        print(f"  {ext:<14} {r['protocol'].lower():<6} {r['alias']:<22} "
              f"{r['int_ip']}:{inp}{state}")


def _print_dhcp_section(d):
    rs = d.reservations()
    print(f"=== DHCP-ПРИВЯЗКИ: {len(rs)} ===")
    if not rs:
        print("(пусто)")
    else:
        print_reservations(rs)


# ---------------------------------------------------------------------------
# Обработчики корневых команд
# ---------------------------------------------------------------------------

def _cmd_page(c, args):
    xml = c.get_data(args.tag, args.extra)
    has_err = c.has_error(xml)
    if has_err:
        m = re.search(r"<IF_ERRORSTR>([^<]+)</IF_ERRORSTR>", xml)
        err = m.group(1) if m else "unknown"
        if args.json:
            print(json.dumps({"tag": args.tag, "error": err},
                             ensure_ascii=False))
        else:
            print(f"[error on {args.tag}]")
            print("  IF_ERRORSTR:", err)
        sys.exit(1)
    if args.json:
        print(json.dumps(
            {"tag": args.tag,
             "instances": c.parse_instances(xml),
             "top": c.parse_top_values(xml)},
            ensure_ascii=False, indent=2))
        return
    insts = c.parse_instances(xml)
    if not insts:
        print("(no data instances)")
    for i, d in enumerate(insts):
        print(f"--- instance {i} {d.pop('_instid', '')}")
        for k, v in d.items():
            print(f"    {k}: {v}")


def _cmd_status(c, args):
    st = c.status()
    if args.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
    else:
        _print_status_text(st)


def _cmd_devices(c, args):
    devs = c.connected_devices()
    if args.json:
        print(json.dumps(devices_as_dicts(devs), ensure_ascii=False, indent=2))
    else:
        print_devices_table(devs)


def _cmd_report(c, args):
    if args.json:
        report = {
            "status": c.status(),
            "devices": devices_as_dicts(c.connected_devices()),
        }
        with PortForward(base=c.base, username=c.username,
                         password=c.password, verbose=c.verbose) as pf:
            report["ports"] = pf.rules()
        with Dhcp(base=c.base, username=c.username,
                  password=c.password, verbose=c.verbose) as d:
            report["dhcp_reservations"] = d.reservations()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return
    _cmd_status(c, args)
    print()
    _cmd_devices(c, args)
    print()
    with PortForward(base=c.base, username=c.username,
                     password=c.password, verbose=c.verbose) as pf:
        _print_ports_section(pf.rules())
    print()
    with Dhcp(base=c.base, username=c.username,
              password=c.password, verbose=c.verbose) as d:
        _print_dhcp_section(d)


def _cmd_reboot(c, args):
    if not confirm(f"Перезагрузить роутер {c.base}?", args.yes):
        print("Отменено.")
        return EXIT_NOT_CONFIRMED
    c.reboot()
    print("reboot запрошен — роутер перезагружается...")
    if not args.no_wait:
        t0 = time.time()
        try:
            c.wait_online(timeout=args.timeout)
        finally:
            print(f"роутер снова в сети через {int(time.time()-t0)} c")
    return 0


def _cmd_reset(c, args):
    if not confirm(f"Сбросить ВСЕ настройки роутера {c.base} к заводским?",
                   args.yes):
        print("Отменено.")
        return EXIT_NOT_CONFIRMED
    c.factory_reset()
    print("factory reset запрошен — роутер перезагружается "
          "с дефолтной конфигурацией...")
    if not args.no_wait:
        t0 = time.time()
        try:
            c.wait_online(timeout=args.timeout)
        finally:
            print(f"роутер снова в сети через {int(time.time()-t0)} c")
    return 0


def _cmd_root(c, args):
    """Команды, работающие на базовом клиенте F680."""
    if args.cmd == "login":
        print("login OK")
    elif args.cmd == "logout":
        c.logout()  # уже залогинены через __enter__
        print("logout OK")
    elif args.cmd == "page":
        _cmd_page(c, args)
    elif args.cmd == "raw":
        print(c.raw(args.qs))
    elif args.cmd == "status":
        _cmd_status(c, args)
    elif args.cmd == "devices":
        _cmd_devices(c, args)
    elif args.cmd in ("report", "all"):
        _cmd_report(c, args)
    elif args.cmd == "reboot":
        return _cmd_reboot(c, args)
    elif args.cmd == "reset":
        return _cmd_reset(c, args)
    return 0


# ---------------------------------------------------------------------------
# Обработчики групп ports / dhcp
# ---------------------------------------------------------------------------

def _cmd_ports(pf, args):
    sub = args.action
    if sub == "list":
        rules = pf.rules()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            print_rules(rules)
    elif sub == "add":
        rid = pf.open_port(args.port, args.ip, args.int_port,
                           proto=args.proto, alias=args.name,
                           ext_port_end=args.ext_end,
                           int_port_end=args.int_end,
                           remote_host=args.remote_host)
        print(f"OK: правило порта {args.port} создано/обновлено (id: {rid})")
        rules = pf.rules()
        if args.json:
            print(json.dumps([r for r in rules if r["id"] == rid],
                             ensure_ascii=False, indent=2))
        else:
            print_rules(rules)
    elif sub == "disable":
        r = pf.close_port(args.ref)
        print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) отключено")
    elif sub == "enable":
        r = pf.enable_port(args.ref)
        print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) включено")
    elif sub == "remove":
        if not confirm(f"Удалить правило '{args.ref}'?", args.yes):
            print("Отменено.")
            return EXIT_NOT_CONFIRMED
        r = pf.remove_port(args.ref)
        print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) удалено")
    elif sub == "rename":
        r = pf.set_alias(args.ref, args.name)
        print(f"OK: правило переименовано в '{args.name}' "
              f"(порт {r['ext_port']})")
    return 0


def _cmd_dhcp(d, args):
    sub = args.action
    if sub == "list":
        rules = d.reservations()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            print_reservations(rules)
    elif sub == "leases":
        rows = d.active_hosts()
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            print_leases(rows)
    elif sub == "add":
        rid = d.set_reservation(args.ip, args.mac, name=args.name)
        print(f"OK: привязка {args.ip} -> {args.mac.lower()} "
              f"создана/обновлена (id: {rid})")
        rules = d.reservations()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            print_reservations(rules)
    elif sub == "remove":
        if not confirm(f"Удалить DHCP-привязку '{args.ref}'?", args.yes):
            print("Отменено.")
            return EXIT_NOT_CONFIRMED
        r = d.remove_reservation(args.ref)
        print(f"OK: привязка '{r['name']}' ({r['ip']}) удалена")
    elif sub == "rename":
        r = d.rename_reservation(args.ref, args.name)
        print(f"OK: привязка переименована в '{args.name}' ({r['ip']})")
    return 0


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

EPILOG = """
примеры:
  f680 devices                          # все клиенты + вендоры
  f680 devices --json
  f680 report                           # полный отчёт одним заходом
  f680 ports list                       # правила проброса портов
  f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"
  f680 ports disable 3000
  f680 ports remove "PC | Open WebUI"   # спросит y/n
  f680 ports remove "PC | Open WebUI" -y
  f680 dhcp list                        # статические DHCP-привязки
  f680 dhcp add 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
  f680 dhcp remove 192.168.1.6 -y
  f680 reboot                           # перезагрузить и дождаться подъёма
  f680 reset -y                         # СБРОС к заводским (осторожно!)

деструктивные действия (reboot, reset, ports remove, dhcp remove)
просят подтверждение: нажать y (без Enter). -y / --yes — пропустить
подтверждение (для скриптов).

опции для ports add:
  --proto tcp|udp|both   протокол (по умолчанию both)
  --ext-end N            конец диапазона внешних портов
  --int-end N            конец диапазона внутренних портов
  --from IP              ограничить внешний IP (по умолчанию любой)

настройки: .env (F680_BASE / F680_USERNAME / F680_PASSWORD) или флаги
--base / --user / --pass (ставятся ПЕРЕД командой).
"""


def _add_yes(p):
    p.add_argument("-y", "--yes", action="store_true",
                   help="не спрашивать подтверждение")


def build_parser():
    ap = argparse.ArgumentParser(
        prog="f680",
        description="Единый CLI для роутера ZTE F680 (DST/MGTS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG)
    ap.add_argument("--base", default=BASE,
                    help=f"адрес роутера [default: {BASE}]")
    ap.add_argument("--user", default=USERNAME,
                    help=f"логин [default: {USERNAME}]")
    ap.add_argument("--pass", dest="password", default=PASSWORD,
                    help="пароль [default: из .env / F680_PASSWORD]")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="debug-вывод в stderr")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="КОМАНДА")

    # -- обзор сети -------------------------------------------------------
    p = sub.add_parser("status",
                       help="состояние роутера (wifi/firewall/usb/voip)")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    p = sub.add_parser("devices", help="все клиенты + вендоры по MAC")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    p = sub.add_parser("report",
                       help="полный отчёт: status + devices + ports + dhcp")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")
    p = sub.add_parser("all",
                       help="alias для `report`")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    # -- ports -------------------------------------------------------------
    p = sub.add_parser("ports", help="проброс портов (NAT)")
    ps = p.add_subparsers(dest="action", required=True, metavar="ДЕЙСТВИЕ")

    psl = ps.add_parser("list", help="показать все правила")
    psl.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    psa = ps.add_parser("add", help="создать/обновить и включить правило")
    psa.add_argument("port", type=int, help="внешний порт")
    psa.add_argument("ip", help="IP устройства в локальной сети")
    psa.add_argument("int_port", type=int, help="внутренний порт")
    psa.add_argument("name", nargs="?", default=None, help="название правила")
    psa.add_argument("--proto", default="both", choices=sorted(PROTOS),
                     help="протокол [default: both]")
    psa.add_argument("--ext-end", type=int,
                     help="конец диапазона внешних портов")
    psa.add_argument("--int-end", type=int,
                     help="конец диапазона внутренних портов")
    psa.add_argument("--from", dest="remote_host", default="0.0.0.0",
                     help="ограничить внешний IP [default: 0.0.0.0]")
    psa.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pfd = ps.add_parser("disable", help="отключить правило (оставить)")
    pfd.add_argument("ref", help="внешний порт или название")

    pen = ps.add_parser("enable", help="включить отключённое правило")
    pen.add_argument("ref", help="внешний порт или название")

    psr = ps.add_parser("remove", help="удалить правило")
    psr.add_argument("ref", help="внешний порт или название")
    _add_yes(psr)

    psrn = ps.add_parser("rename", help="переименовать правило")
    psrn.add_argument("ref", help="внешний порт или название")
    psrn.add_argument("name", help="новое название")

    # -- dhcp ----------------------------------------------------------------
    p = sub.add_parser("dhcp", help="статические DHCP-привязки (MAC -> IP)")
    ds = p.add_subparsers(dest="action", required=True, metavar="ДЕЙСТВИЕ")

    dsl = ds.add_parser("list", help="все статические привязки")
    dsl.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    dsl2 = ds.add_parser("leases",
                         help="DHCP-аренды (кто реально получил IP)")
    dsl2.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    dsa = ds.add_parser("add", help="создать/обновить привязку IP<->MAC")
    dsa.add_argument("ip", help="IP-адрес, напр. 192.168.1.6")
    dsa.add_argument("mac", help="MAC-адрес, напр. 1c:f6:4c:a0:cc:96")
    dsa.add_argument("name", nargs="?", default=None,
                     help="название (<= 10 символов)")
    dsa.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    dsr = ds.add_parser("remove", help="удалить привязку")
    dsr.add_argument("ref", help="IP или MAC")
    _add_yes(dsr)

    dsrn = ds.add_parser("rename", help="переименовать привязку")
    dsrn.add_argument("ref", help="IP или MAC")
    dsrn.add_argument("name", help="новое название (<= 10 символов)")

    # -- базовый API ----------------------------------------------------------
    p = sub.add_parser("page", help="дамп data-страницы (key/values)")
    p.add_argument("tag", help="страница или alias (wlan, wan, firewall, ...)")
    p.add_argument("--extra", default="",
                   help="доп. query-хвост, напр. &InstNum=5")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    p = sub.add_parser("raw", help="сырой fetch запроса ?_type=...")
    p.add_argument("qs",
                   help="query string, напр. "
                        "?_type=menuData&_tag=wan_homepage_lua.lua")

    sub.add_parser("pages", help="список известных page-тагов")

    p = sub.add_parser("login", help="тест логина")
    p = sub.add_parser("logout",
                       help="логин + явный logout (тест разборки сессии)")

    p = sub.add_parser("reboot", help="перезагрузить роутер")
    _add_yes(p)
    p.add_argument("--no-wait", action="store_true",
                   help="не ждать, пока роутер поднимется")
    p.add_argument("--timeout", type=int, default=180,
                   help="сколько секунд ждать восстановления [180]")

    p = sub.add_parser("reset",
                       help="СБРОС настроек к заводским (осторожно!)")
    _add_yes(p)
    p.add_argument("--no-wait", action="store_true",
                   help="не ждать, пока роутер поднимется")
    p.add_argument("--timeout", type=int, default=180,
                   help="сколько секунд ждать восстановления [180]")
    return ap


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        if args.cmd == "pages":
            for k, v in PAGES.items():
                print(f"{k:12s} {v}")
            return 0

        if args.cmd == "ports":
            with PortForward(base=args.base, username=args.user,
                             password=args.password,
                             verbose=args.verbose) as pf:
                return _cmd_ports(pf, args) or 0
        elif args.cmd == "dhcp":
            with Dhcp(base=args.base, username=args.user,
                      password=args.password, verbose=args.verbose) as d:
                return _cmd_dhcp(d, args) or 0
        else:
            with F680(base=args.base, username=args.user,
                      password=args.password,
                      verbose=args.verbose) as c:
                return _cmd_root(c, args) or 0
    except (KeyError, ValueError, RuntimeError) as e:
        if "login failed" in str(e).lower():
            print("ОШИБКА ВХОДА", file=sys.stderr)
            return EXIT_LOGIN_FAILED
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 1
    except TimeoutError as e:
        print(f"ОШИБКА: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
