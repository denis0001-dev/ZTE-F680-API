"""
f680.portforward — управление пробросом портов (NAT) на ZTE F680.

Реверс-инжиниринг веб-интерфейса: изменения правил требуют one-time
`_sessionTmpToken` из menuView-страницы и заголовка
`Check: base64(RSA-PKCS1v15(SHA256(body)))` — подробности в
docs/PORT_FORWARDING.md.

Python API:
    from f680 import PortForward

    with PortForward() as pf:      # авто-login / авто-logout
        pf.rules()
        pf.open_port(8080, "192.168.1.2", 8080, proto="both")
        pf.close_port(8080)
        pf.remove_port(8080)
"""

import base64
import hashlib
import html as htmlmod
import re
import urllib.parse

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

from .client import F680
from .config import BASE as _DEFAULT_BASE, USERNAME as _DEFAULT_USER, \
    PASSWORD as _DEFAULT_PASS

# ---------------------------------------------------------------------------
# Константы веб-интерфейса роутера
# ---------------------------------------------------------------------------
VIEW_TAG = "portForwarding"
DATA_TAG = "firewall_portforwarding_lua.lua"

# Hardcoded public key of the router (see docs/PORT_FORWARDING.md).
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
    """Заголовок `Check`: RSA-PKCS1v15(SHA256(body)), base64."""
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
    """CryptoJS-совместимый AES-CBC с ZeroPadding (не нужен для port
    forwarding, оставлен для полей с `encode="1"`)."""
    data = src.encode()
    data += b"\x00" * (-len(data) % 16)
    enc = AES.new(hashlib.sha256(key.encode()).digest(),
                  AES.MODE_CBC, hashlib.sha256(iv.encode()).digest()).encrypt(data)
    return base64.b64encode(enc).decode()


def parse_page_token(view_html: str):
    """Вытащить one-time `_sessionTmpToken` из HTML menuView-страницы."""
    m = re.search(r'_sessionTmpToken = "((?:\\x[0-9a-f]{2})+)"', view_html)
    return m.group(1).encode().decode("unicode_escape") if m else None


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
class PortForward:
    """Port-forwarding client. Wraps F680 for the session.

    Usage:
        with PortForward() as pf:
            pf.open_port(3000, "192.168.1.3", 3000, alias="web")
    """

    def __init__(self, base=_DEFAULT_BASE, username=_DEFAULT_USER,
                 password=_DEFAULT_PASS, verbose=False):
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
        """Fetch the menuView page, grab a fresh one-time token."""
        r = self.c.raw(f"/?_type=menuView&_tag={VIEW_TAG}")
        if "404 Not Found" in r:
            raise RuntimeError("menuView 404 — страница недоступна?")
        self.token = parse_page_token(r)
        if not self.token:
            raise RuntimeError("не найден одноразовый токен страницы")
        return self.token

    def _post(self, action, instid="-1", fields=None):
        """Fresh menuView token + signed POST to the data endpoint."""
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
        """All port-forwarding rules as a list of dicts."""
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
        """Create (or replace) and enable a rule. Returns the rule id."""
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
        """Disable a rule (Enable=0), it stays in the list."""
        return self._set_enabled(ref, 0)

    def enable_port(self, ref):
        """Enable a rule (Enable=1), it stays in the list."""
        return self._set_enabled(ref, 1)

    def _set_enabled(self, ref, enabled):
        r = self._find(ref)
        fields = {k: unescape_stable(str(v)) for k, v in r["raw"].items()}
        fields.pop("_instid", None)
        fields.update({"Enable": enabled})
        self._post("Apply", instid=r["id"], fields=fields)
        return r

    def remove_port(self, ref):
        """Delete a rule entirely."""
        r = self._find(ref)
        self._post("Delete", instid=r["id"])
        return r

    def set_alias(self, ref, new_alias):
        """Rename a rule (preserves all other fields)."""
        r = self._find(ref)
        fields = {k: unescape_stable(str(v)) for k, v in r["raw"].items()}
        fields.pop("_instid", None)
        fields["Alias"] = new_alias
        self._post("Apply", instid=r["id"], fields=fields)
        return r
