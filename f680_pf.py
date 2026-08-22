#!/usr/bin/env python3
"""
f680_pf.py — управление пробросом портов на роутере ZTE F680.

Синтаксис:
  pf list                    — список правил
  pf open <порт> <ip> <порт> [название] [--proto tcp|udp|both]
  pf close <порт или название>    — отключить правило (но оставить)
  pf remove <порт или название>   — удалить правило

Примеры:
  pf open 3000 192.168.1.3 3000 "PC | Open WebUI"
  pf close 3000
  pf remove "PC | Open WebUI"

Порт может быть диапазоном, напр. 50000-60000 (через --ext-end / --int-end).

Python API:
  from f680_pf import PortForward
  with PortForward() as pf:
      pf.rules()
      pf.open_port(8080, "192.168.1.2", 8080, proto="both")
"""

import argparse
import base64
import hashlib
import html as htmlmod
import re
import sys
import urllib.parse

from f680_api import F680
import f680_config as config
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "portForwarding"
DATA_TAG = "firewall_portforwarding_lua.lua"

PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV\n"
    "7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb\n"
    "1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9\n"
    "hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc\n"
    "fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb\n"
    "GH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w\n"
    "nwIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)

PROTOS = {"tcp": "TCP", "udp": "UDP", "both": "BOTH"}


# ---------------------------------------------------------------------------
# Криптография
# ---------------------------------------------------------------------------
def rsa_check(body: str) -> str:
    digest = hashlib.sha256(body.encode()).hexdigest()
    cipher = PKCS1_v1_5.new(RSA.import_key(PUBKEY))
    return base64.b64encode(cipher.encrypt(digest.encode())).decode()


def unescape_stable(s: str) -> str:
    """Роутер дважды экранирует значения — раскрываем до устойчивости."""
    for _ in range(5):
        new = htmlmod.unescape(s)
        if new == s:
            break
        s = new
    return s


def aes_zero_pad_b64(src: str, key: str, iv: str) -> str:
    data = src.encode()
    data += b"\x00" * (-len(data) % 16)
    enc = AES.new(hashlib.sha256(key.encode()).digest(),
                  AES.MODE_CBC, hashlib.sha256(iv.encode()).digest()).encrypt(data)
    return base64.b64encode(enc).decode()


def parse_page_token(view_html: str):
    m = re.search(r'_sessionTmpToken = "((?:\\x[0-9a-f]{2})+)"', view_html)
    return m.group(1).encode().decode("unicode_escape") if m else None


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class PortForward:
    def __init__(self, base=config.BASE, username=config.USERNAME,
                 password=config.PASSWORD, verbose=False):
        self.c = F680(base=base, username=username, password=password,
                      verbose=verbose)
        self.token = None

    def login(self):
        if not self.c.login():
            raise RuntimeError("login failed")

    def logout(self):
        self.c.logout()
        self.token = None

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.logout()
        except Exception:
            pass
        return False

    def _view(self):
        r = self.c.raw(f"/?_type=menuView&_tag={VIEW_TAG}")
        if "404 Not Found" in r:
            raise RuntimeError("menuView 404 — страница недоступна?")
        self.token = parse_page_token(r)
        if not self.token:
            raise RuntimeError("не найден одноразовый токен страницы")
        return self.token

    def _post(self, action, instid="-1", fields=None):
        self._view()
        body = "IF_ACTION={}&_InstID={}".format(action, instid)
        for k, v in (fields or {}).items():
            body += f"&{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(str(v))}"
        body += f"&_sessionTOKEN={urllib.parse.quote(self.token)}"
        resp = self.c._request(
            f"/?_type=menuData&_tag={DATA_TAG}",
            raw_body=body,
            extra_headers={
                "X-Requested-With": "XMLHttpRequest",
                "Check": rsa_check(body),
            },
        )
        out = dict(re.findall(r"<(\w+)>([^<]*)</\1>", resp))
        err = htmlmod.unescape(out.get("IF_ERRORSTR", "")).strip()
        if err and err.upper() != "SUCC":
            raise RuntimeError(
                f"ошибка роутера (IF_ERRORID={out.get('IF_ERRORID')}): {err}")
        return out

    def rules(self):
        self._view()
        xml = self.c.get_data(DATA_TAG)
        if self.c.has_error(xml):
            raise RuntimeError("ошибка при чтении правил: " + xml[:200])
        out = []
        for d in self.c.parse_instances(xml):
            alias = unescape_stable(d.get("Alias", ""))
            out.append({
                "id": d.get("_instid", ""),
                "alias": alias,
                "protocol": d.get("Protocol", ""),
                "ext_port": int(d["ExternalPort"]) if d.get("ExternalPort") else None,
                "ext_port_end": int(d["ExternalPortEndRange"]) if d.get("ExternalPortEndRange") else None,
                "int_ip": d.get("InternalClient", ""),
                "int_port": int(d["InternalPort"]) if d.get("InternalPort") else None,
                "int_port_end": int(d["InternalPortEndRange"]) if d.get("InternalPortEndRange") else None,
                "remote_host": d.get("RemoteHost", "0.0.0.0") or "0.0.0.0",
                "enabled": d.get("Enable", "1") == "1",
                "raw": d,
            })
        return out

    def _find(self, ref):
        """Найти правило по внешнему порту (число) или по названию."""
        rules = self.rules()
        if isinstance(ref, int) or str(ref).isdigit():
            n = int(ref)
            for r in rules:
                if r["ext_port"] is None:
                    continue
                if r["ext_port"] == n or \
                   (r["ext_port"] <= n <= (r["ext_port_end"] or r["ext_port"])):
                    return r
            raise KeyError(f"не найдено правило с портом {n}")
        ref = str(ref)
        for r in rules:
            if ref.upper() == r["alias"].upper():
                return r
        raise KeyError(f"не найдено правило '{ref}'")

    @staticmethod
    def _default_fields(ext_port, int_ip, int_port, proto, alias=None,
                        ext_port_end=None, int_port_end=None,
                        remote_host="0.0.0.0"):
        return {
            "Enable": 1,
            "Alias": alias or f"port {ext_port}",
            "Protocol": proto,
            "RemoteHost": remote_host,
            "RemoteHostEndRange": remote_host,
            "AllInterface": 1,
            "ExternalPort": ext_port,
            "ExternalPortEndRange": ext_port_end or ext_port,
            "InternalClient": int_ip,
            "InternalPort": int_port,
            "InternalPortEndRange": int_port_end or int_port,
        }

    def open_port(self, ext_port, int_ip, int_port, proto="both",
                  alias=None, ext_port_end=None, int_port_end=None,
                  remote_host="0.0.0.0"):
        proto = PROTOS[proto.lower()]
        fields = self._default_fields(ext_port, int_ip, int_port, proto,
                                      alias, ext_port_end, int_port_end,
                                      remote_host)
        try:
            existing = self._find(int(ext_port))
            resp = self._post("Apply", instid=existing["id"], fields=fields)
        except KeyError:
            resp = self._post("Apply", instid="-1", fields=fields)
        return resp.get("_InstID") or resp.get("INSTIDENTITY")

    def close_port(self, ref):
        r = self._find(ref)
        fields = {k: unescape_stable(str(v)) for k, v in r["raw"].items()}
        fields.pop("_instid", None)
        fields.update({"Enable": 0})
        self._post("Apply", instid=r["id"], fields=fields)
        return r

    def remove_port(self, ref):
        r = self._find(ref)
        self._post("Delete", instid=r["id"])
        return r

    def set_alias(self, ref, new_alias):
        r = self._find(ref)
        fields = {k: unescape_stable(str(v)) for k, v in r["raw"].items()}
        fields.pop("_instid", None)
        fields["Alias"] = new_alias
        self._post("Apply", instid=r["id"], fields=fields)
        return r


# ---------------------------------------------------------------------------
# CLI
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


def main():
    ap = argparse.ArgumentParser(
        description="Проброс портов на ZTE F680",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "примеры:\n"
            "  pf list\n"
            '  pf open 3000 192.168.1.3 3000 "PC | Open WebUI"\n'
            "  pf close 3000\n"
            '  pf remove "PC | Open WebUI"\n'
            "\nопции для open:\n"
            "  --proto tcp|udp|both (по умолчанию both)\n"
            "  --ext-end N  конец диапазона внешних портов\n"
            "  --int-end N  конец диапазона внутренних портов\n"
            "  --from IP    ограничить внешний IP (по умолчанию любой)"
        ))
    ap.add_argument("--base", default=config.BASE, help=argparse.SUPPRESS)
    ap.add_argument("--user", default=config.USERNAME, help=argparse.SUPPRESS)
    ap.add_argument("--pass", dest="password", default=config.PASSWORD,
                    help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="показать все правила")

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

    args = ap.parse_args()
    pf = PortForward(base=args.base, username=args.user, password=args.password)

    try:
        with pf:
            if args.cmd == "list":
                print_rules(pf.rules())
            elif args.cmd == "open":
                rid = pf.open_port(args.port, args.ip, args.int_port,
                                   proto=args.proto, alias=args.name,
                                   ext_port_end=args.ext_end, int_port_end=args.int_end,
                                   remote_host=args.remote_host)
                print(f"OK: правило порта {args.port} создано/обновлено")
                print_rules(pf.rules())
            elif args.cmd == "close":
                r = pf.close_port(args.ref)
                print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) отключено")
            elif args.cmd == "remove":
                r = pf.remove_port(args.ref)
                print(f"OK: правило '{r['alias']}' (порт {r['ext_port']}) удалено")
    except RuntimeError as e:
        if "login failed" in str(e).lower():
            print("ОШИБКА ВХОДА", file=sys.stderr)
            sys.exit(2)
        raise


if __name__ == "__main__":
    try:
        main()
    except (KeyError, RuntimeError) as e:
        print(f"ОШИБКА: {e}", file=sys.stderr)
        sys.exit(1)
