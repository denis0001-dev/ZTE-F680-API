#!/usr/bin/env python3
"""
f680.cli.api — CLI для базового веб-API ZTE F680.

Примеры:
    python -m f680.cli.api login
    python -m f680.cli.api page wlan
    python -m f680.cli.api devices
    python -m f680.cli.api raw "?_type=menuData&_tag=wan_homepage_lua.lua"
    python -m f680.cli.api logout
    python -m f680.cli.api pages

Все команды (кроме `pages`) работают через context manager: авто-login
при входе, авто-logout при выходе (даже при ошибке) — на роутере не
осталась мёртвая сессия.
"""

import argparse
import re
import sys

from f680.client import F680, PAGES
from f680.config import BASE, USERNAME, PASSWORD

EXIT_LOGIN_FAILED = 2


def build_parser():
    ap = argparse.ArgumentParser(
        prog="f680-api",
        description="ZTE F680 admin web API client")
    ap.add_argument("--base", default=BASE, help=f"[default: {BASE}]")
    ap.add_argument("--user", default=USERNAME)
    ap.add_argument("--pass", dest="password", default=PASSWORD,
                    help="пароль (по умолчанию из F680_PASSWORD/.env)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("login", help="test login")
    sub.add_parser("logout", help="login then explicitly logout (teardown test)")
    p_page = sub.add_parser("page", help="dump a data page's key/values")
    p_page.add_argument("tag", help="page tag or alias (e.g. wlan, wan, ...)")
    p_page.add_argument("--extra", default="")
    sub.add_parser("devices", help="list connected clients")
    p_raw = sub.add_parser("raw", help="raw fetch of a ?_type=... query")
    p_raw.add_argument("qs",
                       help="query string, e.g. ?_type=menuData&_tag=wan_homepage_lua.lua")
    sub.add_parser("pages", help="list known page tags")
    return ap


def cmd_page(c, args):
    xml = c.get_data(args.tag, args.extra)
    has_err, insts = c.has_error(xml), c.parse_instances(xml)
    if has_err:
        print(f"[error on {args.tag}]")
        m = re.search(r"<IF_ERRORSTR>([^<]+)</IF_ERRORSTR>", xml)
        if m:
            print("  IF_ERRORSTR:", m.group(1))
        sys.exit(1)
    if not insts:
        print("(no data instances)")
    for i, d in enumerate(insts):
        print(f"--- instance {i} {d.pop('_instid', '')}")
        for k, v in d.items():
            print(f"    {k}: {v}")


def cmd_devices(c):
    devs = c.connected_devices()
    if not devs:
        print("(no devices found)")
        return
    print(f"{'IP':<16} {'MAC':<18} HOSTNAME")
    for d in devs:
        print(f"{d.get('IPAddress',''):<16} "
              f"{d.get('MACAddress',''):<18} {d.get('HostName','')}")


def main(argv=None):
    args = build_parser().parse_args(argv)
    c = F680(base=args.base, username=args.user, password=args.password,
             verbose=args.verbose)

    if args.cmd == "pages":
        for k, v in PAGES.items():
            print(f"{k:12s} {v}")
        return 0

    try:
        with c:
            if args.cmd == "login":
                print("login OK")
            elif args.cmd == "logout":
                c.logout()  # already logged in by __enter__
                print("logout OK")
            elif args.cmd == "page":
                cmd_page(c, args)
            elif args.cmd == "devices":
                cmd_devices(c)
            elif args.cmd == "raw":
                print(c.raw(args.qs))
        return 0
    except RuntimeError as e:
        if "login failed" in str(e).lower():
            print("LOGIN FAILED", file=sys.stderr)
            return EXIT_LOGIN_FAILED
        raise


if __name__ == "__main__":
    sys.exit(main())
