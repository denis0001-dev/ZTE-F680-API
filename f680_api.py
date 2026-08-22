#!/usr/bin/env python3
"""
f680_api.py — minimal client for the ZTE F680 (DST/MGTS) admin web API.

The router's web UI is not a plain HTML form; it talks to a small JSON/XML
API over `/_type=...&_tag=...` URLs. This module wraps that API so you can
log in and pull structured data programmatically.

Endpoints / usage are documented in the note "ZTE F680 router — admin web API".

Quick CLI usage:
    python3 f680_api.py login
    python3 f680_api.py page wlan_homepage_lua.lua
    python3 f680_api.py page devinfo_homepage_lua.lua
    python3 f680_api.py devices            # nice table of connected clients
    python3 f680_api.py raw "?_type=menuData&_tag=wlan_homepage_lua.lua"
    python3 f680_api.py logout             # explicit logout

Every command uses the context manager, so it auto-logs-out afterwards
(even on error), and no session is left hanging on the router.
`logout()` can also be called manually any time.
"""

import argparse
import hashlib
import http.cookiejar
import json
import re
import sys
import time
import urllib.parse
import urllib.request

import f680_config as config

# ---------------------------------------------------------------------------
# Configuration (.env / env — см. f680_config.py)
# ---------------------------------------------------------------------------
BASE = config.BASE
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126 Safari/537.36"
)

# Page tags known to exist on this device.
PAGES = {
    "devinfo": "devinfo_homepage_lua.lua",
    "wan": "wan_homepage_lua.lua",
    "wlan": "wlan_homepage_lua.lua",
    "voip": "voip_homepage_lua.lua",
    "firewall": "firewall_homepage_lua.lua",
    "usb": "usb_homepage_lua.lua",
    "accessdev": "accessdev_homepage_lua.lua&InstNum=5",
}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
class F680:
    def __init__(self, base=BASE, username=USERNAME, password=PASSWORD,
                 timeout=20, verbose=False):
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        if not self.password:
            raise RuntimeError(
                "пароль не задан: создай .env (см. .env.example) или "
                "укажи F680_PASSWORD / --pass")
        self.timeout = timeout
        self.verbose = verbose
        self.sess_token = None
        self.cookies = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.headers = {
            "User-Agent": USER_AGENT,
            "Referer": self.base + "/",
        }

    # -- low-level -------------------------------------------------------
    def _request(self, path, data=None, raw_body=None, extra_headers=None,
                 method=None):
        """Perform an HTTP request against the router.

        `data` is a dict, urlencoded automatically; `raw_body` sends an
        already-encoded body string (used for POSTs with custom headers).
        `method` forces a specific HTTP verb (default: GET for bodyless
        requests, POST when a body is present) — e.g. the logout endpoint
        is a GET that still carries a form body.
        """
        url = self.base + path
        body = None
        headers = dict(self.headers)
        if raw_body is not None:
            body = raw_body.encode() if isinstance(raw_body, str) else raw_body
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if extra_headers:
            headers.update(extra_headers)
        if method is None:
            method = "POST" if body is not None else "GET"
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        resp = self.op.open(req, timeout=self.timeout)
        return resp.read().decode("utf-8", errors="replace")

    def _log(self, *a):
        if self.verbose:
            print(*a, file=sys.stderr)

    # -- auth ------------------------------------------------------------
    def login(self, username=None, password=None, retries=3, wait=3):
        """Perform the 3-step SHA256 login. Returns True on success."""
        username = username or self.username
        password = password or self.password

        for attempt in range(1, retries + 1):
            # 1. get session token
            init = json.loads(self._request("/?_type=loginData&_tag=login_entry"))
            self.sess_token = init.get("sess_token")
            self._log("sess_token:", self.sess_token)

            # 2. get one-time hash token
            raw = self._request("/?_type=loginData&_tag=login_token")
            token = re.sub(r"<[^>]+>", "", raw).strip()
            self._log("onetime token:", token)

            # 3. post hashed password
            h = hashlib.sha256((password + token).encode()).hexdigest()
            resp = json.loads(self._request(
                "/?_type=loginData&_tag=login_entry",
                data={
                    "action": "login",
                    "Password": h,
                    "Username": username,
                    "_sessionTOKEN": self.sess_token,
                },
            ))
            self._log("login resp:", resp)

            self.sess_token = resp.get("sess_token", self.sess_token)
            ok = (not resp.get("loginErrMsg")
                  and not resp.get("promptMsg")
                  and not resp.get("lockingTime"))
            if ok:
                # Prime the session the way the browser does.
                self._request("/")
                return True

            err = resp.get("loginErrMsg") or resp.get("promptMsg")
            self._log(f"login failed (attempt {attempt}): {err}")
            time.sleep(wait)
        return False

    def logout(self):
        """Logout and clear the session. Safe to call any number of times.

        The logout endpoint is a GET that still carries a small form body
        (IF_LogOff=1). Errors are swallowed and reported only in verbose
        mode — a half-dead session shouldn't crash the caller.
        """
        try:
            if self.sess_token is not None:
                resp = self._request(
                    "/?_type=loginData&_tag=logout_entry",
                    data={"IF_LogOff": 1},
                    extra_headers={"X-Requested-With": "XMLHttpRequest"},
                    method="GET",
                )
                self._log("logout resp:", resp[:200])
        except Exception as e:  # noqa: BLE001 — best-effort teardown
            self._log("logout failed:", e)
        finally:
            self.sess_token = None
            self.cookies.clear()

    # -- context manager: auto-login / auto-logout -------------------------
    def __enter__(self):
        """Usage: `with F680() as c:` — logs in on entry.

        Always logs out on exit (even if the body raises), so sessions
        don't linger on the router.
        """
        if not self.login():
            raise RuntimeError("login failed")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.logout()
        return False

    # -- data ------------------------------------------------------------
    def get_data(self, tag, extra=""):
        """Fetch a menuData page and return the raw XML string.

        `tag` may be a bare name ("wlan_homepage_lua.lua") or a short alias
        from the PAGES dict, optionally with query suffixes.
        """
        if tag in PAGES:
            tag = PAGES[tag]
        qs = f"/?_type=menuData&_tag={urllib.parse.quote(tag, safe='=&')}"
        if extra:
            qs += extra
        if self.sess_token:
            qs += f"&_sessionTOKEN={self.sess_token}"
        return self._request(qs)

    @staticmethod
    def parse_instances(xml):
        """Parse XML into a list of dicts (one per <Instance>).

        Each dict maps ParaName -> ParaValue. If an instance carries an
        `_InstID` field it is preserved under key "_instid".
        """
        instances = []
        for block in re.findall(r"<Instance>.*?</Instance>", xml, re.S):
            pairs = re.findall(
                r"<ParaName>([^<]+)</ParaName>"
                r"<ParaValue>([^<]*)</ParaValue>",
                block,
            )
            d = {}
            for name, value in pairs:
                if name == "_InstID":
                    d["_instid"] = value
                else:
                    d[name] = value
            if d:
                instances.append(d)
        return instances

    @staticmethod
    def has_error(xml):
        """A successful response contains IF_ERRORSTR>SUCC, so only a
        non-SUCC IF_ERRORSTR (e.g. SessionTimeout) means an actual error."""
        m = re.search(r"<IF_ERRORSTR>([^<]*)</IF_ERRORSTR>", xml)
        return m is not None and m.group(1).strip().upper() not in ("", "SUCC")

    def get_page(self, tag, extra=""):
        """Convenience: return (has_error, instances) for a data page."""
        xml = self.get_data(tag, extra)
        return self.has_error(xml), self.parse_instances(xml)

    def raw(self, qs):
        """Fetch any raw `/_type=...&_tag=...` query string and return text."""
        if not qs.startswith("/"):
            qs = "/" + qs
        if self.sess_token and "_sessionTOKEN" not in qs:
            sep = "&" if "?" in qs else "?"
            qs += f"{sep}_sessionTOKEN={self.sess_token}"
        return self._request(qs)

    # -- helpers ---------------------------------------------------------
    def connected_devices(self):
        """Return a tidy list of clients from the accessdev page."""
        xml = self.get_data("accessdev")
        out = []
        # Walk instances; collect contiguous ParaName/ParaValue triples.
        blocks = re.findall(r"<Instance>.*?</Instance>", xml, re.S)
        cur = {}
        for block in blocks:
            pairs = re.findall(
                r"<ParaName>([^<]+)</ParaName>"
                r"<ParaValue>([^<]*)</ParaValue>",
                block,
            )
            row = {}
            for name, value in pairs:
                if name in ("IPAddress", "MACAddress", "HostName",
                            "IPV6Address"):
                    row[name] = value
            if row.get("IPAddress") or row.get("MACAddress"):
                out.append(row)
        return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ZTE F680 admin web API client")
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
    p_raw.add_argument("qs", help="query string, e.g. ?_type=menuData&_tag=wan_homepage_lua.lua")
    sub.add_parser("pages", help="list known page tags")

    args = ap.parse_args()
    c = F680(base=args.base, username=args.user, password=args.password,
             verbose=args.verbose)

    if args.cmd == "pages":
        for k, v in PAGES.items():
            print(f"{k:12s} {v}")
        return

    # All commands below use the context manager: auto-login on entry,
    # auto-logout on exit (even when the body raises or sys.exit is called).
    try:
        with c:
            if args.cmd == "login":
                print("login OK")

            elif args.cmd == "logout":
                # already logged in by __enter__; now do the explicit logout
                c.logout()
                print("logout OK")

            elif args.cmd == "page":
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

            elif args.cmd == "devices":
                devs = c.connected_devices()
                if not devs:
                    print("(no devices found)")
                    return
                print(f"{'IP':<16} {'MAC':<18} HOSTNAME")
                for d in devs:
                    print(f"{d.get('IPAddress',''):<16} "
                          f"{d.get('MACAddress',''):<18} {d.get('HostName','')}")

            elif args.cmd == "raw":
                print(c.raw(args.qs))
    except RuntimeError as e:
        if "login failed" in str(e).lower():
            print("LOGIN FAILED", file=sys.stderr)
            sys.exit(2)
        raise


if __name__ == "__main__":
    main()
