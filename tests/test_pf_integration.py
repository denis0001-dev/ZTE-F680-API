#!/usr/bin/env python3
"""Test: read + create + delete a port-forwarding rule on the F680."""
import base64
import hashlib
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from f680_api import F680
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

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

VIEW_TAG = "portForwarding"
DATA_TAG = "firewall_portforwarding_lua.lua"


def rsa_b64(plaintext: str) -> str:
    key = RSA.import_key(PUBKEY)
    cipher = PKCS1_v1_5.new(key)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()


def aes_zero_pad_b64(src: str, key: str, iv: str) -> str:
    """CryptoJS.AES.encrypt with key=SHA256(key), iv=SHA256(iv), CBC, ZeroPadding."""
    bkey = hashlib.sha256(key.encode()).digest()
    biv = hashlib.sha256(iv.encode()).digest()
    data = src.encode()
    data += b"\x00" * (-len(data) % 16)
    enc = AES.new(bkey, AES.MODE_CBC, biv).encrypt(data)
    return base64.b64encode(enc).decode()


import re

def view(c: F680):
    """GET the menuView page; returns the page-embedded _sessionTmpToken.

    Each menuView page issues its own one-time token which must be used as
    _sessionTOKEN in the POST body (not the login sess_token).
    """
    r = c.raw(f"/?_type=menuView&_tag={VIEW_TAG}")
    if "404 Not Found" in r:
        print("  menuView 404!")
        return None
    m = re.search(r'_sessionTmpToken = "((?:\\x[0-9a-f]{2})+)"', r)
    if m:
        tok = m.group(1).encode().decode("unicode_escape")
    else:
        tok = None
    print("  menuView token:", tok)
    return tok


def get_rules(c: F680):
    view(c)
    xml = c.get_data(DATA_TAG)
    if c.has_error(xml):
        print("  [error]", xml[:200])
        return []
    return c.parse_instances(xml)


def post(c: F680, params: dict, action: str, instid: str = "-1", token: str = None):
    """Build the form body the way the page JS does, add Check header, POST."""
    params = dict(params)
    body = urllib.parse.urlencode(
        {"IF_ACTION": action, "_InstID": instid, **params},
        doseq=False,
    )
    body += "&_sessionTOKEN=" + (token or "")
    digest = hashlib.sha256(body.encode()).hexdigest()
    check = rsa_b64(digest)
    print("  POST body:", body[:300])
    print("  Check:", check[:60], "...")
    resp = c._request(
        f"/?_type=menuData&_tag={DATA_TAG}",
        data=None,
        raw_body=body,
        extra_headers={
            "Check": check,
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    print("  RESP:", resp[:400].replace("\r", " "))
    return resp


def main():
    c = F680(verbose=True)
    assert c.login(), "login failed"

    print("== current rules ==")
    rules = get_rules(c)
    for r in rules:
        print("  ", {k: v for k, v in r.items() if k in
                      ("Alias", "Protocol", "ExternalPort", "InternalClient",
                       "InternalPort", "_instid", "Enable")})

    tok = view(c)
    print("== add test rule ==")
    post(c, {
        "Enable": "1",
        "Alias": "pytest-rule",
        "Protocol": "TCP",
        "RemoteHost": "0.0.0.0",
        "RemoteHostEndRange": "0.0.0.0",
        "AllInterface": "1",
        "ExternalPort": "18080",
        "ExternalPortEndRange": "18080",
        "InternalClient": "192.168.1.2",
        "InternalPort": "2222",
        "InternalPortEndRange": "2222",
    }, action="Apply", token=tok)

    print("== rules after add ==")
    rules = get_rules(c)
    new_id = None
    for r in rules:
        if r.get("Alias") == "pytest-rule":
            new_id = r.get("_instid")
            print("  created:", r)
    if new_id is None:
        print("ADD FAILED - aborting")
        sys.exit(1)

    tok = view(c)
    print("== delete rule", new_id, "==")
    post(c, {}, action="Delete", instid=str(new_id), token=tok)

    print("== rules after delete ==")
    rules = get_rules(c)
    for r in rules:
        print("  ", {k: v for k, v in r.items() if k in
                      ("Alias", "Protocol", "ExternalPort", "InternalClient",
                       "InternalPort", "_instid", "Enable")})


if __name__ == "__main__":
    main()
