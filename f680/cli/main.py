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
    ports  list|add|enable|disable|remove|modify|rename   проброс портов (NAT)
    dhcp   list|leases|add|remove|modify|rename           статические DHCP-привязки (MAC -> IP)
    help <команда> [подкоманда]                          справка (f680 help ports add)
    page <tag>                 дамп data-страницы
    raw <qs>                   сырой запрос
    pages                      список известных страниц
    reboot                     перезагрузить роутер (подтверждение / -y)
    reset                      сброс к заводским (подтверждение / -y)
    login / logout             проверка сессии

Ссылки на правила (enable/disable/remove/modify/rename):
    №      порядковый номер из списка (1..N)
    80     внешний порт (для ports)
    IP/MAC (для dhcp)
    id     стабильный id правила (DEV.NAT.PtMapping1, ...Bind3)
    name   название правила
Перед изменением CLI показывает правило и после — проверяет по
стабильному id, что изменена именно та запись.

Деструктивные действия (reboot, reset, ports remove, dhcp remove,
ports modify, dhcp modify) просят подтверждение в терминале:
нажать `y` (без Enter). Для автоматизации: -y / --yes.

Цвета включаются только в терминале (TTY); в трубе/пайпе вывод
чистый. F680_COLOR=0/1 — принудительно выкл/вкл, NO_COLOR — выкл.

Глобальные опции (ставятся ПЕРЕД командой):
    --base URL    адрес роутера   [из .env / F680_BASE, default http://192.168.1.1]
    --user U      логин           [из .env / F680_USERNAME, default mgts]
    --pass P      пароль          [из .env / F680_PASSWORD]
    -v, --verbose                debug-вывод в stderr
    -j, --json                   вывод в JSON (у команд, которые его поддерживают)

Примеры:
    f680 devices
    f680 ports list
    f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"
    f680 ports add --port 3000 --ip 192.168.1.3 --in-port 3000 --name "PC | Open WebUI"  # то же флагами
    f680 ports modify 1 --proto tcp --name "PC | SSH2"
    f680 ports modify 2222 --in-port 2223
    f680 ports disable 2
    f680 ports remove "RPI | SSH"
    f680 help ports add
    f680 dhcp list
    f680 dhcp modify 192.168.1.6 --name Mac
    f680 dhcp add 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
    f680 dhcp remove 1
    f680 reboot -y
    f680 reset -y

Exit codes:
    0   успех
    1   ошибка
    2   не удалось залогиниться
    3   действие отменено (нет подтверждения)
    130 прервано (Ctrl+C)

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

from f680.client import F680, F680Error, LoginFailed, RouterError, PAGES
from f680.portforward import PortForward, PROTOS
from f680.dhcp import Dhcp
from f680.macvendor import guess_device
from f680.config import BASE, USERNAME, PASSWORD
from f680.cli import ui

EXIT_LOGIN_FAILED = 2
EXIT_NOT_CONFIRMED = 3
EXIT_INTERRUPTED = 130


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
        print(ui.red("✗ ") + f"{prompt}\n"
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


def _state(r):
    """«включено»/«выключено» с цветом (зелёный/красный)."""
    return ui.green("включено") if r["enabled"] else ui.red("выключено")


def _describe_port(r):
    ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
    inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
    return (f"{ext:<10} {r['protocol'].lower():<6} '{r['alias']}' -> "
            f"{r['int_ip']}:{inp} {_state(r)}  {ui.dim(r['id'])}")


def print_rules(rules, numbered=False):
    if numbered:
        print(f"{'№':<4} " + f"{'ПОРТ':<12} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} {'-> IP:ПОРТ':<25} СОСТОЯНИЕ")
        for i, r in enumerate(rules, 1):
            ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
            inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
            line = (f"{i:<4} {ext:<12} {r['protocol'].lower():<6} "
                    f"{r['alias']:<22} {r['int_ip']}:{inp:<13}{_state(r)}")
            print(line)
    else:
        print(ui.bold(f"{'ПОРТ':<12} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} {'-> IP:ПОРТ':<25} СОСТОЯНИЕ"))
        for r in rules:
            ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
            inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
            line = (f"{ext:<12} {r['protocol'].lower():<6} {r['alias']:<22} "
                    f"{r['int_ip']}:{inp:<13}{_state(r)}")
            print(line)


def print_reservations(rules, numbered=False):
    if numbered:
        print(f"{'№':<4} " + f"{'IP':<16} {'MAC':<18} {'НАЗВАНИЕ':<24} ID")
        for i, r in enumerate(rules, 1):
            print(f"{i:<4} {r['ip']:<16} {r['mac']:<18} {r['name']:<24} "
                  f"{ui.dim(r['id'])}")
    else:
        print(ui.bold(f"{'IP':<16} {'MAC':<18} {'НАЗВАНИЕ':<24} ID"))
        for r in rules:
            print(f"{r['ip']:<16} {r['mac']:<18} {r['name']:<24} {ui.dim(r['id'])}")


def print_leases(rows):
    print(ui.bold(f"{'IP':<16} {'MAC':<18} HOSTNAME"))
    for r in rows:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['hostname']}")


def print_devices_table(devs, title="КЛИЕНТЫ СЕТИ"):
    n_wired = sum(1 for d in devs if d.get("source") == "wired")
    n_wifi = sum(1 for d in devs if d.get("source") == "wifi")
    print(ui.bold(f"=== {title}: всего {len(devs)} "
                  f"(wired: {n_wired}, wifi: {n_wifi}) ==="))
    if not devs:
        print("(не найдено)")
        return
    fmt = "  {:<15} {:<19} {:<20} {:<34} {}"
    print(ui.bold(fmt.format("IP", "MAC", "HOST", "ВЕНДОР/ПОДСКАЗКА", "СЕТЬ")))
    print(ui.dim("  " + "-" * 95))
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
    print(ui.bold("=== РОУТЕР: СОСТОЯНИЕ ==="))
    radio = st["wifi"].get("RadioSwitch")
    wifi_state = ("ВКЛ" if radio == "1" else
                  "ВЫКЛ" if radio == "0" else "неизвестно")
    print(f"  Wi-Fi radio:  {ui.green(wifi_state) if radio == '1' else wifi_state}")
    fw = st["firewall"]
    print(f"  Firewall:     Level={fw.get('Level', '?')}, "
          f"AntiAttack={'вкл' if fw.get('AntiAttack') == '1' else 'выкл'}")
    usb = st["usb"]
    print(f"  USB FTP:      {'вкл' if usb.get('FtpEnable') == '1' else 'выкл'}"
          f" (порт {usb.get('ServerPort', '21')})")
    voip = st["voip"]
    voip_state = "online" if voip.get("IsOnline") == "1" else "offline"
    print(f"  VoIP:         {ui.green(voip_state) if voip_state == 'online' else voip_state}"
          f" (RegStatus={voip.get('VoIPRegStatus', '?')})")
    if st["errors"]:
        print("  Ошибки страниц: " + ui.red("; ".join(st["errors"])))
    else:
        print("  Все страницы прочитаны без ошибок")


def _print_ports_section(rules):
    print(ui.bold(f"=== PORT FORWARDING: {len(rules)} правил ==="))
    if not rules:
        print("(пусто)")
        return
    print(ui.dim(f"  {'ВН. ПОРТ':<14} {'ПРОТО':<6} {'НАЗВАНИЕ':<22} -> ВНУТРЕННИЙ"))
    print(ui.dim("  " + "-" * 70))
    for r in rules:
        ext = _fmt_range(r["ext_port"], r["ext_port_end"] or r["ext_port"])
        inp = _fmt_range(r["int_port"], r["int_port_end"] or r["int_port"])
        line = (f"  {ext:<14} {r['protocol'].lower():<6} {r['alias']:<22} "
                f"{r['int_ip']}:{inp} {_state(r)}")
        print(line)


def _print_dhcp_section(d):
    rs = d.reservations()
    print(ui.bold(f"=== DHCP-ПРИВЯЗКИ: {len(rs)} ==="))
    if not rs:
        print("(пусто)")
    else:
        print_reservations(rs)


# ---------------------------------------------------------------------------
# Разрешение ссылок: № / порт / id / имя
# ---------------------------------------------------------------------------

def _resolve_port(ref, rules):
    """Rule по № (1..N), внешнему порту, stable id или названию.

    Числовый аргумент в пределах списка трактуется как порядковый
    номер; любое другое число — как внешний порт.
    """
    ref = str(ref).strip()
    if ref.isdigit():
        n = int(ref)
        if 1 <= n <= len(rules):
            return rules[n - 1]
        for r in rules:
            if r["ext_port"] is None:
                continue
            if r["ext_port"] == n or \
               (r["ext_port"] <= n <= (r["ext_port_end"] or r["ext_port"])):
                return r
        raise ui.RefError(f"не найдено правило с портом {n}")
    for r in rules:
        if ref == r["id"]:
            return r
    for r in rules:
        if ref.upper() == r["alias"].upper():
            return r
    raise ui.RefError(
        f"не найдено правило '{ref}' — см. `f680 ports list` "
        f"(№: 1-{len(rules)}, внешний порт, id или название)")


def _resolve_dhcp(ref, rules):
    """Rule по № (1..N), IP, MAC, stable id или названию."""
    ref = str(ref).strip().lower()
    if ref.isdigit():
        n = int(ref)
        if 1 <= n <= len(rules):
            return rules[n - 1]
        raise ui.RefError(f"привязки №{n} нет — см. `f680 dhcp list` "
                          f"(№: 1-{len(rules)})")
    for r in rules:
        if (r["ip"] == ref or r["mac"] == ref
                or r["id"].lower() == ref
                or r["name"].lower() == ref):
            return r
    raise ui.RefError(
        f"не найдена привязка '{ref}' — см. `f680 dhcp list` "
        f"(№: 1-{len(rules)}, IP, MAC, id или название)")


def _verify_port(pf, rid, expected=None):
    """После мутации: перечесть правила, найти по стабильному id и
    (опц.) сверить поля. Возвращает правило или None."""
    try:
        for r in pf.rules():
            if r["id"] == rid:
                if expected:
                    for k, v in expected.items():
                        if r.get(k) != v:
                            return None
                return r
    except F680Error:
        return None
    return None


def _verify_dhcp(d, rid, expected=None):
    try:
        for r in d.reservations():
            if r["id"] == rid:
                if expected:
                    for k, v in expected.items():
                        if r.get(k) != v:
                            return None
                return r
    except F680Error:
        return None
    return None


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
            print(ui.red(f"[error on {args.tag}]"))
            print("  IF_ERRORSTR:", err)
        return 1
    if args.json:
        print(json.dumps(
            {"tag": args.tag,
             "instances": c.parse_instances(xml),
             "top": c.parse_top_values(xml)},
            ensure_ascii=False, indent=2))
        return 0
    insts = c.parse_instances(xml)
    if not insts:
        print("(no data instances)")
    for i, d in enumerate(insts):
        print(ui.bold(f"--- instance {i} {d.pop('_instid', '')}"))
        for k, v in d.items():
            print(f"    {k}: {v}")
    return 0


def _cmd_status(c, args):
    st = c.status()
    if args.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
    else:
        _print_status_text(st)
    return 0


def _cmd_devices(c, args):
    devs = c.connected_devices()
    if args.json:
        print(json.dumps(devices_as_dicts(devs), ensure_ascii=False, indent=2))
    else:
        print_devices_table(devs)
    return 0


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
        return 0
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
    return 0


def _cmd_reboot(c, args):
    if not confirm(f"Перезагрузить роутер {c.base}?", args.yes):
        print(ui.yellow("Отменено."))
        return EXIT_NOT_CONFIRMED
    c.reboot()
    print(ui.green("✓ ") + "reboot запрошен — роутер перезагружается...")
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
        print(ui.yellow("Отменено."))
        return EXIT_NOT_CONFIRMED
    c.factory_reset()
    print(ui.green("✓ ") + "factory reset запрошен — роутер перезагружается "
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
        print(ui.green("✓ ") + "login OK")
    elif args.cmd == "logout":
        c.logout()  # уже залогинены через __enter__
        print(ui.green("✓ ") + "logout OK")
    elif args.cmd == "page":
        return _cmd_page(c, args)
    elif args.cmd == "raw":
        print(c.raw(args.qs))
    elif args.cmd == "status":
        return _cmd_status(c, args)
    elif args.cmd == "devices":
        return _cmd_devices(c, args)
    elif args.cmd in ("report", "all"):
        return _cmd_report(c, args)
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
            if not rules:
                print(ui.dim("(пусто)"))
            else:
                print_rules(rules, numbered=True)
                print(ui.dim("№ — порядковый номер, подходит для "
                             "enable/disable/remove/modify"))
    elif sub == "add":
        if args.port is None or args.ip is None or args.in_port is None:
            ui.fail("не хватает обязательных аргументов",
                    "формат: f680 ports add PORT IP IN_PORT [NAME] [--proto tcp|udp|both] "
                    "[--port-end N] [--in-port-end N] [--from IP] "
                    "(диапазоны: PORT 1000-2000; то же можно записать флагами: "
                    "--port N --ip IP --in-port N)")
            return 1
        rid = pf.open_port(args.port, args.ip, args.in_port,
                           proto=args.proto, alias=args.name,
                           ext_port_end=args.port_end,
                           int_port_end=args.in_port_end,
                           remote_host=args.remote_host)
        if args.json:
            for r in pf.rules():
                if r["id"] == rid:
                    print(json.dumps(r, ensure_ascii=False, indent=2))
                    break
        else:
            print(ui.green("✓ ") + f"правило порта {args.port} "
                  f"создано/обновлено (id: {rid})")
    elif sub in ("enable", "disable"):
        rules = pf.rules()
        r = _resolve_port(args.ref, rules)
        print(ui.bold(f"> " + _describe_port(r)))
        if sub == "disable":
            pf.close_port(r["id"])
            msg, expected = "отключено", {"enabled": False}
        else:
            pf.enable_port(r["id"])
            msg, expected = "включено", {"enabled": True}
        after = _verify_port(pf, r["id"], expected)
        if after is None:
            ui.warn(f"не удалось подтвердить: правило {r['id']} "
                    f"не показывает ожидаемое состояние")
            return 1
        print(ui.green("✓ ") + f"правило '{r['alias']}' "
              f"(порт {r['ext_port']}) {msg}")
    elif sub == "remove":
        rules = pf.rules()
        r = _resolve_port(args.ref, rules)
        print(ui.bold(f"> " + _describe_port(r)))
        if not confirm(f"Удалить правило '{r['alias']}' ({r['ext_port']})?",
                       args.yes):
            print(ui.yellow("Отменено."))
            return EXIT_NOT_CONFIRMED
        pf.remove_port(r["id"])
        after = _verify_port(pf, r["id"])
        if after is not None:
            ui.warn(f"правило {r['id']} всё ещё на месте — "
                    f"возможно, роутер ещё коммитит")
            return 1
        print(ui.green("✓ ") + f"правило '{r['alias']}' "
              f"(порт {r['ext_port']}) удалено")
    elif sub == "modify":
        rules = pf.rules()
        r = _resolve_port(args.ref, rules)
        print(ui.bold(f"> " + _describe_port(r)))

        expected = {}
        changes = {}
        if args.name is not None:
            changes["alias"] = args.name
            expected["alias"] = args.name
        if args.proto is not None:
            changes["proto"] = args.proto
            expected["protocol"] = PROTOS[args.proto]
        if args.port is not None:
            changes["ext_port"] = args.port
            expected["ext_port"] = args.port
        if args.port_end is not None:
            changes["ext_port_end"] = args.port_end
        elif args.port is not None:
            expected["ext_port_end"] = args.port
        if args.ip is not None:
            changes["int_ip"] = args.ip
            expected["int_ip"] = args.ip
        if args.in_port is not None:
            changes["int_port"] = args.in_port
            expected["int_port"] = args.in_port
        if args.in_port_end is not None:
            changes["int_port_end"] = args.in_port_end
        elif args.in_port is not None:
            expected["int_port_end"] = args.in_port
        if args.remote_host is not None:
            changes["remote_host"] = args.remote_host
        if args.enable is not None:
            expected["enabled"] = args.enable

        if not changes:
            ui.fail("нечего изменять",
                    "укажите хотя бы один из: --name --proto --port "
                    "--port-end --ip --in-port --in-port-end --from "
                    "--enable/--disable")
            return 1
        what = ", ".join(f"{k}={v}" for k, v in changes.items())
        if not confirm(f"Изменить правило '{r['alias']}'? {what}", args.yes):
            print(ui.yellow("Отменено."))
            return EXIT_NOT_CONFIRMED
        pf.update_port(r["id"], **changes)
        after = _verify_port(pf, r["id"], expected)
        if after is None:
            ui.warn(f"не удалось подтвердить: правило {r['id']} "
                    f"не содержит ожидаемые значения")
            return 1
        print(ui.green("✓ ") + f"правило '{after['alias']}' изменено: {what}")
    elif sub == "rename":
        rules = pf.rules()
        r = _resolve_port(args.ref, rules)
        print(ui.bold(f"> '{r['alias']}' -> '{args.name}' "
                      f"(порт {r['ext_port']})"))
        pf.set_alias(r["id"], args.name)
        after = _verify_port(pf, r["id"], {"alias": args.name})
        if after is None:
            ui.warn(f"не удалось подтвердить: правило {r['id']} "
                    f"не переименовано?")
            return 1
        print(ui.green("✓ ") + f"правило переименовано в '{args.name}'")
    return 0


def _cmd_dhcp(d, args):
    sub = args.action
    if sub == "list":
        rules = d.reservations()
        if args.json:
            print(json.dumps(rules, ensure_ascii=False, indent=2))
        else:
            if not rules:
                print(ui.dim("(пусто)"))
            else:
                print_reservations(rules, numbered=True)
                print(ui.dim("№ — порядковый номер, подходит для "
                             "remove/modify/rename"))
    elif sub == "leases":
        rows = d.active_hosts()
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            if not rows:
                print(ui.dim("(пусто)"))
            else:
                print_leases(rows)
    elif sub == "add":
        rid = d.set_reservation(args.ip, args.mac, name=args.name)
        if args.json:
            for r in d.reservations():
                if r["id"] == rid:
                    print(json.dumps(r, ensure_ascii=False, indent=2))
                    break
        else:
            print(ui.green("✓ ") + f"привязка {args.ip} -> {args.mac.lower()} "
                  f"создана/обновлена (id: {rid})")
    elif sub == "remove":
        rules = d.reservations()
        r = _resolve_dhcp(args.ref, rules)
        print(ui.bold(f"> {r['ip']:<16} {r['mac']:<18} '{r['name']}' "
                      f"{ui.dim(r['id'])}"))
        if not confirm(f"Удалить DHCP-привязку '{r['name']}' ({r['ip']})?",
                       args.yes):
            print(ui.yellow("Отменено."))
            return EXIT_NOT_CONFIRMED
        d.remove_reservation(r["id"])
        after = _verify_dhcp(d, r["id"])
        if after is not None:
            ui.warn(f"привязка {r['id']} всё ещё на месте — "
                    f"возможно, роутер ещё коммитит")
            return 1
        print(ui.green("✓ ") + f"привязка '{r['name']}' ({r['ip']}) удалена")
    elif sub == "modify":
        rules = d.reservations()
        r = _resolve_dhcp(args.ref, rules)
        print(ui.bold(f"> {r['ip']:<16} {r['mac']:<18} '{r['name']}' "
                      f"{ui.dim(r['id'])}"))
        changes, expected = {}, {}
        if args.ip is not None:
            changes["ip"] = args.ip
            expected["ip"] = args.ip
        if args.mac is not None:
            changes["mac"] = args.mac.lower()
            expected["mac"] = args.mac.lower()
        if args.name is not None:
            changes["name"] = args.name
            expected["name"] = args.name
        if not changes:
            ui.fail("нечего изменять",
                    "укажите хотя бы один из: --ip --mac --name")
            return 1
        what = ", ".join(f"{k}={v}" for k, v in changes.items())
        if not confirm(f"Изменить привязку '{r['name']}'? {what}", args.yes):
            print(ui.yellow("Отменено."))
            return EXIT_NOT_CONFIRMED
        d.update_reservation(r["id"], **changes)
        after = _verify_dhcp(d, r["id"], expected)
        if after is None:
            ui.warn(f"не удалось подтвердить: привязка {r['id']} "
                    f"не содержит ожидаемые значения")
            return 1
        print(ui.green("✓ ") + f"привязка '{after['name']}' изменена: {what}")
    elif sub == "rename":
        rules = d.reservations()
        r = _resolve_dhcp(args.ref, rules)
        print(ui.bold(f"> '{r['name']}' -> '{args.name}' ({r['ip']})"))
        d.rename_reservation(r["id"], args.name)
        after = _verify_dhcp(d, r["id"], {"name": args.name})
        if after is None:
            ui.warn(f"не удалось подтвердить: привязка {r['id']} "
                    f"не переименована?")
            return 1
        print(ui.green("✓ ") + f"привязка переименована в '{args.name}' "
              f"({r['ip']})")
    return 0


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

REF_PORT = "№ из списка, внешний порт, id (DEV.NAT...) или название"
REF_DHCP = "№ из списка, IP, MAC, id (DEV.V4DHCP...) или название"

PORT_ARG = ("порт или диапазон 1000-2000 "
            "(одно значение = и начало, и конец диапазона)")
INPORT_ARG = ("внутренний порт или диапазон 1000-2000 "
              "(одно значение = и начало, и конец диапазона)")


def parse_port_range(s):
    """`'3000'` -> (3000, None); `'1000-2000'` -> (1000, 2000)."""
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", str(s).strip())
    if not m:
        raise ValueError(f"нестандартный формат порта: {s!r} "
                         f"(ожидается 3000 или 1000-2000)")
    a, b = int(m.group(1)), m.group(2)
    b = int(b) if b else None
    if b is not None and b < a:
        raise ValueError(f"конец диапазона {b} < начало {a}")
    return a, b


def _merge_positional_add(args):
    """Позиционный синтаксис `ports add`:

        f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"

    Позиционные аргументы (внешний порт, IP, внутренний порт, название)
    приравниваются к флагам --port / --ip / --in-port / --name.
    Смешивать позиции и флаги нельзя.
    """
    pairs = (("pos_port", "port", "--port"),
             ("pos_ip", "ip", "--ip"),
             ("pos_in_port", "in_port", "--in-port"),
             ("pos_name", "name", "--name"))
    for pos_attr, flag_attr, flag_name in pairs:
        pos = getattr(args, pos_attr, None)
        flag = getattr(args, flag_attr, None)
        if pos is not None and flag is not None:
            raise ValueError(
                f"позиционный аргумент и флаг {flag_name} заданы одновременно — "
                f"используйте только один из синтаксисов")
        if pos is not None:
            setattr(args, flag_attr, pos)


def _apply_port_ranges(args):
    """Распаковать '1000-2000' из --port/--in-port в *_end, если --port-end
    / --in-port-end не заданы явно. Работает для add и modify."""
    for flag, end_attr in (("port", "port_end"),
                           ("in_port", "in_port_end")):
        raw = getattr(args, flag, None)
        if raw is None:
            continue
        if isinstance(raw, str):
            start, end = parse_port_range(raw)
            setattr(args, flag, start)
            if getattr(args, end_attr, None) is None:
                setattr(args, end_attr, end)
        elif getattr(args, end_attr, None) is None:
            setattr(args, end_attr, raw)

EPILOG = """
примеры:
  f680 devices                          # все клиенты + вендоры
  f680 devices --json
  f680 report                           # полный отчёт одним заходом
  f680 ports list                       # правила проброса портов
  f680 ports add 3000 192.168.1.3 3000 "PC | Open WebUI"   # позиции: ПОРТ IP ВНУТР. ПОРТ [ИМЯ]
  f680 ports add --port 3000 --ip 192.168.1.3 --in-port 3000 --name "PC | Open WebUI"
  f680 ports add 1000-2000 192.168.1.3 1000-2000           # диапазоны
  f680 ports modify 1 --proto tcp      # № из списка
  f680 ports modify 2222 --in-port 2223
  f680 ports disable 2
  f680 ports remove "RPI | SSH"        # спросит y/n
  f680 ports remove "RPI | SSH" -y
  f680 help ports add                  # подробная справка по команде
  f680 dhcp list                        # статические DHCP-привязки
  f680 dhcp modify 192.168.1.6 --name Mac
  f680 dhcp add 192.168.1.6 1c:f6:4c:a0:cc:96 Macbook
  f680 dhcp remove 1 -y
  f680 reboot                           # перезагрузить и дождаться подъёма
  f680 reset -y                         # СБРОС к заводским (осторожно!)

деструктивные действия (reboot, reset, * remove, * modify) просят
подтверждение: нажать y (без Enter). -y / --yes — пропустить
подтверждение (для скриптов).

ссылки на правило: порядковый номер из списка (1..N), или
  ports:  внешний порт, id (DEV.NAT.PtMapping1...), название
  dhcp:   IP, MAC, id (DEV.V4DHCP...Bind1...), название
Перед изменением показывается правило, после — проверяется по
стабильному id, что изменена именно та запись.

ports add — позиции или флаги (смешивать нельзя):
  f680 ports add ПОРТ IP ВНУТР_ПОРТ [ИМЯ]
  f680 ports add --port N --ip IP --in-port N --name TEXT
  ПОРТ / ВНУТР_ПОРТ: N или диапазон N-M (обязательно); --port-end / --in-port-end
  — конец диапазона, если не встроен; --proto tcp|udp|both (default both);
  --from IP — ограничить внешний IP (по умолчанию любой)

опции для ports modify REF (задаётся только то, что меняется):
  --name TEXT --proto tcp|udp|both --port N | N-M --port-end N
  --ip IP --in-port N | N-M --in-port-end N --from IP --enable/--disable

опции для dhcp modify REF:
  --ip IP --mac MAC --name TEXT  (имя <= 10 символов)

подробная справка по любой команде: f680 help <команда> [подкоманда].

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
    p = sub.add_parser("ports", help="проброс портов (NAT)",
                       description="Проброс портов (NAT). "
                       "Подкоманды: list, add, enable, disable, remove, "
                       "modify, rename. Подробности: f680 help ports add.")
    ps = p.add_subparsers(dest="action", required=True, metavar="ДЕЙСТВИЕ")

    psl = ps.add_parser("list", help="показать все правила")
    psl.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    psa = ps.add_parser(
        "add", help="создать/обновить и включить правило",
        description=("Создать (или заменить) и включить правило проброса.\n\n"
                     "f680 ports add PORT IP IN_PORT [NAME]\n"
                     "              [--proto tcp|udp|both] [--port-end N] "
                     "[--in-port-end N]\n"
                     "              [--from IP] [-y]\n\n"
                     "PORT / IN_PORT принимают одно значение (3000) или\n"
                     "диапазон (1000-2000) — конец диапазона из него "
                     "заполняется автоматически, если --port-end / --in-port-end "
                     "не заданы явно.\n\n"
                     "То же самое флагами: f680 ports add --port 3000 "
                     "--ip 192.168.1.3 --in-port 3000 --name 'ИМЯ'.\n"
                     "Смешивать позиционные аргументы и флаги нельзя."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    psa.add_argument("pos_port", nargs="?", default=None, metavar="ПОРТ",
                     help=f"внешний порт: {PORT_ARG}")
    psa.add_argument("pos_ip", nargs="?", default=None, metavar="IP",
                     help="IP устройства в локальной сети, напр. 192.168.1.2")
    psa.add_argument("pos_in_port", nargs="?", default=None, metavar="ИН_ПОРТ",
                     help=f"внутренний порт: {INPORT_ARG}")
    psa.add_argument("pos_name", nargs="?", default=None, metavar="ИМЯ",
                     help="название правила")
    psa.add_argument("--port", help=f"внешний порт (флаговый вариант): {PORT_ARG}")
    psa.add_argument("--port-end", type=int,
                     help="конец диапазона внешних портов (если --port — один порт, равняется ему)")
    psa.add_argument("--ip", help="IP устройства в локальной сети, напр. 192.168.1.2")
    psa.add_argument("--in-port", help=f"внутренний порт: {INPORT_ARG}")
    psa.add_argument("--in-port-end", type=int,
                     help="конец диапазона внутренних портов")
    psa.add_argument("--name", help="название правила (по умолчанию 'port N')")
    psa.add_argument("--proto", default="both", choices=sorted(PROTOS),
                     help="протокол [default: both]")
    psa.add_argument("--from", dest="remote_host", default="0.0.0.0",
                     help="ограничить внешний IP [default: 0.0.0.0 — любой]")
    psa.add_argument("-j", "--json", action="store_true", help="вывод в JSON")

    pfd = ps.add_parser("disable", help="отключить правило (оставить)")
    pfd.add_argument("ref", help=REF_PORT)

    pen = ps.add_parser("enable", help="включить отключённое правило")
    pen.add_argument("ref", help=REF_PORT)

    psr = ps.add_parser("remove", help="удалить правило")
    psr.add_argument("ref", help=REF_PORT)
    _add_yes(psr)

    psm = ps.add_parser(
        "modify", help="изменить поля существующего правила",
        description=("Изменить один или несколько полей существующего правила.\n\n"
                     "f680 ports modify REF [--name TEXT] [--proto tcp|udp|both]"
                     "\n                   [--port N | N-M] [--port-end N]"
                     "\n                   [--ip IP] [--in-port N | N-M] [--in-port-end N]"
                     "\n                   [--from IP] [--enable | --disable] [-y]\n\n"
                     "REF — № из списка, внешний порт, id (DEV.NAT...) или название.\n"
                     "Задаётся только то, что меняется; остальное сохраняется."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    psm.add_argument("ref", help=REF_PORT)
    psm.add_argument("--name", help="новое название")
    psm.add_argument("--proto", choices=sorted(PROTOS), help="протокол")
    psm.add_argument("--port", help=f"внешний порт: {PORT_ARG}")
    psm.add_argument("--port-end", type=int, help="конец диапазона внешних портов")
    psm.add_argument("--ip", help="внутренний IP")
    psm.add_argument("--in-port", help=f"внутренний порт: {INPORT_ARG}")
    psm.add_argument("--in-port-end", type=int,
                     help="конец диапазона внутренних портов")
    psm.add_argument("--from", dest="remote_host",
                     help="ограничить внешний IP")
    psm.add_argument("--enable", dest="enable", action="store_true",
                     default=None, help="включить правило")
    psm.add_argument("--disable", dest="enable", action="store_false",
                     help="отключить правило")
    _add_yes(psm)

    psrn = ps.add_parser("rename", help="переименовать правило")
    psrn.add_argument("ref", help=REF_PORT)
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
    dsr.add_argument("ref", help=REF_DHCP)
    _add_yes(dsr)

    dsm = ds.add_parser("modify", help="изменить поля существующей привязки")
    dsm.add_argument("ref", help=REF_DHCP)
    dsm.add_argument("--ip", help="новый IP")
    dsm.add_argument("--mac", help="новый MAC")
    dsm.add_argument("--name", help="новое название (<= 10 символов)")
    _add_yes(dsm)

    dsrn = ds.add_parser("rename", help="переименовать привязку")
    dsrn.add_argument("ref", help=REF_DHCP)
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
    p = sub.add_parser("help",
                       help="справка: f680 help [команда [подкоманда]]")
    p.add_argument("topic", nargs="*", metavar="КОМАНДА",
                   help="напр. `f680 help ports add`")
    return ap


# ---------------------------------------------------------------------------
# Ошибки
# ---------------------------------------------------------------------------

def _handle_error(e):
    """Красивый вывод ошибки. Возвращает exit code."""
    if isinstance(e, LoginFailed):
        ui.fail(f"{e}", "проверьте --base / --user / --pass и .env")
        return EXIT_LOGIN_FAILED
    if isinstance(e, RouterError):
        ui.fail(f"{e}", "попробуйте повторить; если повторяется — "
                        "откройте веб-интерфейс роутера")
        return 1
    if isinstance(e, ui.RefError):
        ui.fail(f"{e}")
        return 1
    if isinstance(e, ValueError):
        ui.fail(f"{e}")
        return 1
    if isinstance(e, F680Error):
        ui.fail(f"{e}")
        return 1
    if isinstance(e, TimeoutError):
        ui.fail(f"таймаут: {e}", "роутер отвечает медленно — увеличьте "
                        "таймаут или проверьте сеть")
        return 1
    if isinstance(e, OSError):
        ui.fail(f"сеть: {e}", "роутер недоступен — проверьте --base "
                        "и подключение")
        return 1
    ui.fail(f"{type(e).__name__}: {e}")
    return 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _subparser_map(p):
    """dict имя -> parser для вложенных subparser'ов."""
    for a in getattr(p, "_actions", []):
        if type(a).__name__ == "_SubParsersAction":
            return a.choices
    return None


def _cmd_help(parser, args):
    """`f680 help`, `f680 help ports`, `f680 help ports add`."""
    topic = args.topic or []
    p = parser
    for t in topic:
        sp = _subparser_map(p)
        if not sp or t not in sp:
            ui.fail(f"неизвестная команда '{t}'",
                    "список команд: f680 help (без аргументов)")
            return 1
        p = sp[t]
    p.print_help()
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "help":
            return _cmd_help(parser, args)
        if args.cmd in ("ports", "dhcp"):
            if args.cmd == "ports" and args.action == "add":
                _merge_positional_add(args)
            _apply_port_ranges(args)
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
    except KeyboardInterrupt:
        print()
        print(ui.yellow("⚠ ") + "прервано (Ctrl+C)", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (KeyError, ValueError, F680Error, ui.RefError, TimeoutError,
            OSError) as e:
        return _handle_error(e)


if __name__ == "__main__":
    sys.exit(main())
