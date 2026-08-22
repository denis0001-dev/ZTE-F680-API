#!/usr/bin/env python3
"""
f680 — единый CLI для роутера ZTE F680 (DST/MGTS).

Запуск:

    f680 <команда> [аргументы] [опции]
    python -m f680 <команда> [аргументы] [опции]

Команды:
    status                     состояние роутера (wifi/firewall/usb/voip)
    devices                    все клиенты + вендоры по MAC
    report / all               полный отчёт: status + devices + pf + dhcp
    pf   list|open|close|remove|rename      проброс портов
    dhcp list|leases|set|remove|rename     статические DHCP-привязки (MAC -> IP)
    page <tag>                 дамп data-страницы
    raw <qs>                   сырой запрос
    pages                      список известных страниц
    reboot                     перезагрузить роутер
    reset                      сброс к заводским (нужен --yes)
    login / logout             проверка сессии

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
    f680 pf list
    f680 pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
    f680 pf open 22 192.168.1.2 22 --proto tcp
    f680 pf close 3000
    f680 pf remove "PC | Open WebUI"
    f680 dhcp set 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
    f680 dhcp rename 192.168.1.6 Mac
    f680 dhcp remove 192.168.1.6
    f680 reboot
    f680 reset --yes

Все команды работают через context manager: авто-login при входе и
авто-logout при выходе (даже при ошибке) — на роутере не остаётся
мёртвая сессия.
"""

import argparse
import json
import re
import sys
import time

from f680.client import F680, PAGES
from f680.portforward import PortForward, PROTOS
from f680.dhcp import Dhcp
from f680.macvendor import guess_device
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2


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


def _print_pf_section(rules):
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
            report["port_forwarding"] = pf.rules()
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
        _print_pf_section(pf.rules())
    print()
    with Dhcp(base=c.base, username=c.username,
              password=c.password, verbose=c.verbose) as d:
        _print_dhcp_section(d)


def _cmd_reboot(c, args):
    c.reboot()
    print("reboot запрошен — роутер перезагружается...")
    if not args.no_wait:
        t0 = time.time()
        try:
            c.wait_online(timeout=args.timeout)
        finally:
            print(f"роутер снова в сети через {int(time.time()-t0)} c")


def _cmd_reset(c, args):
    if not args.yes:
        print("Сброс ВСЕХ настроек к заводским? "
              "Запусти с --yes, чтобы подтвердить.")
        return 1
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
        _cmd_reboot(c, args)
    elif args.cmd == "reset":
        return _cmd_reset(c, args)
    return 0


# ---------------------------------------------------------------------------
# Обработчики групп pf / dhcp
# ---------------------------------------------------------------------------

def _cmd_pf(pf, args):
    sub = args.pf
    if sub == "list":
        rules = pf.rules()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            print_rules(rules)
    elif sub == "open":
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
    elif sub == "close":
        r = pf.close_port(args.ref)
        print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) отключено")
    elif sub == "remove":
        r = pf.remove_port(args.ref)
        print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) удалено")
    elif sub == "rename":
        r = pf.set_alias(args.ref, args.name)
        print(f"OK: правило переименовано в '{args.name}' "
              f"(порт {r['ext_port']})")


def _cmd_dhcp(d, args):
    sub = args.dhcp
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
    elif sub == "set":
        rid = d.set_reservation(args.ip, args.mac, name=args.name)
        print(f"OK: привязка {args.ip} -> {args.mac.lower()} "
              f"создана/обновлена (id: {rid})")
        rules = d.reservations()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            print_reservations(rules)
    elif sub == "remove":
        r = d.remove_reservation(args.ref)
        print(f"OK: привязка '{r['name']}' ({r['ip']}) удалена")
    elif sub == "rename":
        r = d.rename_reservation(args.ref, args.name)
        print(f"OK: привязка переименована в '{args.name}' ({r['ip']})")


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

EPILOG = """
примеры:
  f680 devices                          # все клиенты + вендоры
  f680 devices --json
  f680 report                           # полный отчёт одним заходом
  f680 pf list                          # правила проброса портов
  f680 pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
  f680 pf close 3000
  f680 pf remove "PC | Open WebUI"
  f680 dhcp list                        # статические DHCP-привязки
  f680 dhcp set 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
  f680 dhcp remove 192.168.1.6
  f680 reboot                           # перезагрузить и дождаться подъёма
  f680 reset --yes                      # СБРОС к заводским (осторожно!)

опции для pf open:
  --proto tcp|udp|both   протокол (по умолчанию both)
  --ext-end N            конец диапазона внешних портов
  --int-end N            конец диапазона внутренних портов
  --from IP              ограничить внешний IP (по умолчанию любой)

настройки: .env (F680_BASE / F680_USERNAME / F680_PASSWORD) или флаги
--base / --user / --pass (ставятся ПЕРЕД командой).
"""


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
                       help="полный отчёт: status + devices + pf + dhcp")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")
    p = sub.add_parser("all",
                       help="alias для `report`")
    p.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    # -- pf ----------------------------------------------------------------
    p = sub.add_parser("pf", help="проброс портов (NAT)")
    pfs = p.add_subparsers(dest="pf", required=True, metavar="ДЕЙСТВИЕ")

    pfl = pfs.add_parser("list", help="показать все правила")
    pfl.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pfo = pfs.add_parser("open", help="создать/обновить и включить правило")
    pfo.add_argument("port", type=int, help="внешний порт")
    pfo.add_argument("ip", help="IP устройства в локальной сети")
    pfo.add_argument("int_port", type=int, help="внутренний порт")
    pfo.add_argument("name", nargs="?", default=None, help="название правила")
    pfo.add_argument("--proto", default="both", choices=sorted(PROTOS),
                     help="протокол [default: both]")
    pfo.add_argument("--ext-end", type=int,
                     help="конец диапазона внешних портов")
    pfo.add_argument("--int-end", type=int,
                     help="конец диапазона внутренних портов")
    pfo.add_argument("--from", dest="remote_host", default="0.0.0.0",
                     help="ограничить внешний IP [default: 0.0.0.0]")
    pfo.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pfc = pfs.add_parser("close", help="отключить правило (оставить)")
    pfc.add_argument("ref", help="внешний порт или название")

    pfr = pfs.add_parser("remove", help="удалить правило")
    pfr.add_argument("ref", help="внешний порт или название")

    pfn = pfs.add_parser("rename", help="переименовать правило")
    pfn.add_argument("ref", help="внешний порт или название")
    pfn.add_argument("name", help="новое название")

    # -- dhcp ----------------------------------------------------------------
    p = sub.add_parser("dhcp", help="статические DHCP-привязки (MAC -> IP)")
    pds = p.add_subparsers(dest="dhcp", required=True, metavar="ДЕЙСТВИЕ")

    pdl = pds.add_parser("list", help="все статические привязки")
    pdl.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pdl2 = pds.add_parser("leases",
                          help="DHCP-аренды (кто реально получил IP)")
    pdl2.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pds3 = pds.add_parser("set", help="создать/обновить привязку IP<->MAC")
    pds3.add_argument("ip", help="IP-адрес, напр. 192.168.1.6")
    pds3.add_argument("mac", help="MAC-адрес, напр. 1c:f6:4c:a0:cc:96")
    pds3.add_argument("name", nargs="?", default=None,
                      help="название (<= 10 символов)")
    pds3.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pdr = pds.add_parser("remove", help="удалить привязку")
    pdr.add_argument("ref", help="IP или MAC")

    pdrn = pds.add_parser("rename", help="переименовать привязку")
    pdrn.add_argument("ref", help="IP или MAC")
    pdrn.add_argument("name", help="новое название (<= 10 символов)")

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
    p.add_argument("--no-wait", action="store_true",
                   help="не ждать, пока роутер поднимется")
    p.add_argument("--timeout", type=int, default=180,
                   help="сколько секунд ждать восстановления [180]")

    p = sub.add_parser("reset",
                       help="СБРОС настроек к заводским (осторожно!)")
    p.add_argument("--yes", action="store_true",
                   help="подтвердить (без --yes ничего не произойдёт)")
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

        if args.cmd == "pf":
            with PortForward(base=args.base, username=args.user,
                             password=args.password,
                             verbose=args.verbose) as pf:
                _cmd_pf(pf, args)
        elif args.cmd == "dhcp":
            with Dhcp(base=args.base, username=args.user,
                      password=args.password, verbose=args.verbose) as d:
                _cmd_dhcp(d, args)
        else:
            with F680(base=args.base, username=args.user,
                      password=args.password,
                      verbose=args.verbose) as c:
                return _cmd_root(c, args) or 0
        return 0
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
