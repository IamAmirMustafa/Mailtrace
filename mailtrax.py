#!/usr/bin/env python3
"""
MailTrax 3.1 - advanced email header & phishing analyzer (defensive tool)
Developed by DEVJIX - www.devjix.com

Give it the raw message (Gmail "Show original", Outlook "View message source",
or a saved .eml file). It reports the real sender, the route, the sending IP
with location and reputation, SPF/DKIM/DMARC (from the headers AND re-checked
live in DNS), domain age, link and attachment analysis, threat-intel hits and
a 0-100 risk score.

Quick start:
  mailtrax mail.eml
  mailtrax                      (paste raw mail, then Ctrl+D)
  mailtrax inbox_dump/ --html report.html
  mailtrax --help

Standard library only. Optional extras: python3-dnspython, python3-dkim.
"""
import argparse
import datetime as dt
import difflib
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

VERSION = "3.1"
VENDOR = "DEVJIX"
SITE = "www.devjix.com"
CONFIG = os.path.expanduser("~/.config/mailtrax/config.json")
SERVICES = ("abuseipdb", "virustotal", "urlhaus")
TIMEOUT = 8
UA = {"User-Agent": f"MailTrax/{VERSION}"}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "proton.me", "protonmail.com", "icloud.com", "aol.com",
    "gmx.com", "yandex.com", "mail.com", "zoho.com",
}
BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "whatsapp", "linkedin", "binance", "dhl", "fedex", "dropbox",
    "docusign", "outlook", "office365", "meezan", "easypaisa", "jazzcash",
    "hbl", "ubl", "daraz", "coinbase", "metamask", "adobe", "wetransfer",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "t.ly", "qrco.de",
}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq",
              "work", "country", "kim", "loan", "icu", "cfd", "sbs", "rest", "quest"}
RISKY_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "ps1", "hta",
             "lnk", "iso", "img", "jar", "msi", "com", "pif", "wsf", "docm",
             "xlsm", "pptm", "html", "htm", "shtml", "svg", "one", "dll", "apk"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace"}
SUBJECT_BAIT = ["urgent", "verify your", "suspend", "password", "unusual activity",
                "confirm your", "action required", "invoice", "payment failed",
                "locked", "security alert", "final notice", "lottery",
                "inheritance", "gift card", "overdue"]
BODY_BAIT = ["verify your account", "confirm your password", "your account will be",
             "click here immediately", "within 24 hours", "wire transfer",
             "gift card", "bitcoin", "update your payment", "login to avoid",
             "unusual sign-in", "account has been limited", "kindly"]
MULTI_SUFFIX = {"co.uk", "ac.uk", "gov.uk", "org.uk", "com.pk", "org.pk",
                "net.pk", "edu.pk", "gov.pk", "com.au", "co.in", "com.br",
                "co.za", "com.cn", "co.jp", "com.sg", "com.tr", "com.mx",
                "co.nz", "com.sa", "com.bd", "com.ng", "co.ke", "com.my"}
DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org"]

_cache = {}


# ================================================================= helpers
class C:
    R = "\033[91m"; Y = "\033[93m"; G = "\033[92m"; B = "\033[96m"; M = "\033[95m"
    D = "\033[2m"; W = "\033[1m"; X = "\033[0m"
    HI = "\033[1;30;106m"          # highlighted sender IP (black on bright cyan)
    ON = True

    @classmethod
    def off(cls):
        for k in ("R", "Y", "G", "B", "M", "D", "W", "X", "HI"):
            setattr(cls, k, "")
        cls.ON = False


ANIM = False                        # switched on in main() for interactive terminals
BANNER = r"""
███╗   ███╗ █████╗ ██╗██╗  ████████╗██████╗  █████╗ ██╗  ██╗
████╗ ████║██╔══██╗██║██║  ╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝
██╔████╔██║███████║██║██║     ██║   ██████╔╝███████║ ╚███╔╝
██║╚██╔╝██║██╔══██║██║██║     ██║   ██╔══██╗██╔══██║ ██╔██╗
██║ ╚═╝ ██║██║  ██║██║███████╗██║   ██║  ██║██║  ██║██╔╝ ██╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
""".strip("\n").split("\n")
GRADIENT = (51, 45, 39, 33, 63, 93)


def width():
    return max(60, min(shutil.get_terminal_size((80, 24)).columns - 1, 78))


def vlen(text):
    """Visible length of a string that may contain colour codes."""
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def emit(text="", delay=0.012):
    print(text)
    if ANIM:
        sys.stdout.flush()
        time.sleep(delay)


def typewrite(text, delay=0.012):
    if not ANIM:
        print(text)
        return
    for part in re.findall(r"\033\[[0-9;]*m|.", text):
        sys.stdout.write(part)
        if not part.startswith("\033"):
            sys.stdout.flush()
            time.sleep(delay)
    print()


def banner():
    print()
    for n, line in enumerate(BANNER):
        col = f"\033[1;38;5;{GRADIENT[n]}m" if C.ON else ""
        emit(f"  {col}{line}{C.X}", 0.06)
    typewrite(f"  {C.W}Email Tracker & Phishing Detector{C.X}  {C.D}v{VERSION}{C.X}")
    typewrite(f"  {C.D}Developed by{C.X} {C.M}{C.W}{VENDOR}{C.X}  {C.D}|{C.X}  {C.B}{SITE}{C.X}")
    emit(f"  {C.D}{'━' * (width() - 4)}{C.X}")


class Spinner:
    """Animated status line on stderr while network lookups run."""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.text, self.active, self._stop, self._t = "", False, None, None

    def start(self, text):
        self.text = text
        if not ANIM or self.active:
            return
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self.active = True
        self._t.start()

    def set(self, text):
        self.text = text

    def _run(self):
        i = 0
        while not self._stop.is_set():
            f = self.FRAMES[i % len(self.FRAMES)]
            sys.stderr.write(f"\r\033[K  {C.B}{f}{C.X} {self.text} {C.D}...{C.X}")
            sys.stderr.flush()
            i += 1
            self._stop.wait(0.08)

    def stop(self):
        if self.active:
            self._stop.set()
            self._t.join()
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
            self.active = False


SPIN = Spinner()


def note(text):
    if not ANIM and sys.stderr.isatty():
        print(f"{C.D}[*] {text}{C.X}", file=sys.stderr)


def dec(value):
    if value is None:
        return ""
    try:
        value = str(make_header(decode_header(str(value))))
    except Exception:
        value = str(value)
    return re.sub(r"\s+", " ", value).strip()


def domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(" >.") if "@" in addr else ""


def org_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def find_ips(text):
    out = []
    text = re.sub(r"(?i)\bipv6:", " ", text)          # "[IPv6:2407:...]" literals
    cands = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)", text)
    cands += re.findall(r"(?<![\w:])[0-9A-Fa-f:]{3,39}(?![\w:])", text)
    for c in cands:
        try:
            ip = ipaddress.ip_address(c)
        except ValueError:
            continue
        if ip.version == 6 and c.count(":") < 2:
            continue
        if str(ip) not in out:
            out.append(str(ip))
    return out


def defang(text):
    """Make a URL/host unclickable so reports are safe to share."""
    return text.replace("http", "hxxp").replace(".", "[.]")


def load_keys():
    keys = {}
    try:
        with open(CONFIG) as f:
            keys = json.load(f)
    except Exception:
        pass
    for s in SERVICES:
        env = os.environ.get("MAILTRAX_" + s.upper())
        if env:
            keys[s] = env
    return keys


def save_key(service, key):
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    keys = {}
    try:
        with open(CONFIG) as f:
            keys = json.load(f)
    except Exception:
        pass
    keys[service] = key
    with open(CONFIG, "w") as f:
        json.dump(keys, f, indent=2)
    os.chmod(CONFIG, 0o600)


def http_json(url, headers=None, data=None):
    """Return (json_object, error_string)."""
    h = dict(UA)
    h.update(headers or {})
    body = urllib.parse.urlencode(data).encode() if data else None
    try:
        req = urllib.request.Request(url, headers=h, data=body)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace")), ""
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)[:80]


# ===================================================================== DNS
def dns_query(name, rtype):
    """Return a list of strings. dnspython if installed, else DNS-over-HTTPS."""
    key = ("dns", name, rtype)
    if key in _cache:
        return _cache[key]
    out = []
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = 5
        try:
            for rd in res.resolve(name, rtype):
                if rtype == "TXT":
                    out.append(b"".join(rd.strings).decode("utf-8", "replace"))
                elif rtype == "MX":
                    out.append(str(rd.exchange).rstrip("."))
                else:
                    out.append(rd.address)
        except Exception:
            pass
    except ImportError:
        code = {"A": 1, "MX": 15, "TXT": 16, "AAAA": 28}[rtype]
        url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": rtype})
        data, _ = http_json(url)
        for ans in (data or {}).get("Answer", []) or []:
            if ans.get("type") != code:
                continue
            d = ans.get("data", "")
            if rtype == "TXT":
                d = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', d)) or d
            elif rtype == "MX":
                d = d.split()[-1].rstrip(".")
            out.append(d)
    _cache[key] = out
    return out


def host_ips(host):
    return dns_query(host, "A") + dns_query(host, "AAAA")


def spf_eval(ip, domain, state=None):
    """Small SPF evaluator: ip4, ip6, a, mx, include, redirect, all."""
    state = state if state is not None else {"n": 0, "unknown": False}
    state["n"] += 1
    if state["n"] > 10:
        return "permerror"
    recs = [t for t in dns_query(domain, "TXT") if t.lower().startswith("v=spf1")]
    if not recs:
        return "none"
    addr = ipaddress.ip_address(ip)
    qmap = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
    redirect = ""

    def in_net(target, cidr):
        try:
            net = ipaddress.ip_network(f"{target}/{cidr}" if cidr else target, strict=False)
            return addr.version == net.version and addr in net
        except ValueError:
            return False

    for term in recs[0].split()[1:]:
        q = "+"
        if term[0] in qmap:
            q, term = term[0], term[1:]
        low = term.lower()
        if "%" in low or low.startswith(("exists", "ptr")):
            state["unknown"] = True
            continue
        if low.startswith(("ip4:", "ip6:")):
            if in_net(term[4:], ""):
                return qmap[q]
        elif low.startswith("include:"):
            if spf_eval(ip, term[8:], state) == "pass":
                return qmap[q]
        elif low.startswith("redirect="):
            redirect = term[9:]
        elif low == "all":
            return qmap[q]
        else:
            m = re.match(r"^(a|mx)(?::([^/]+))?(?:/(\d+))?", low)
            if not m:
                continue
            target = m.group(2) or domain
            hosts = [target] if m.group(1) == "a" else dns_query(target, "MX")
            state["n"] += 1
            for h in hosts[:10]:
                for a in host_ips(h):
                    cidr = m.group(3) if (m.group(3) and ":" not in a) else ""
                    if in_net(a, cidr):
                        return qmap[q]
    if redirect:
        return spf_eval(ip, redirect, state)
    return "unknown" if state["unknown"] else "neutral"


def dmarc_record(domain):
    for d in dict.fromkeys([domain, org_domain(domain)]):
        for t in dns_query("_dmarc." + d, "TXT"):
            if t.lower().startswith("v=dmarc1"):
                m = re.search(r"\bp\s*=\s*(\w+)", t, re.I)
                return {"domain": d, "policy": m.group(1).lower() if m else "?", "record": t}
    return {}


# =========================================================== route and IPs
def parse_received(msg):
    hops = []
    for raw in msg.get_all("Received") or []:
        line = re.sub(r"\s+", " ", str(raw)).strip()
        head, _, date_part = line.rpartition(";")
        if not head:
            head, date_part = line, ""
        from_clause = re.split(r"\sby\s", " " + head, maxsplit=1)[0]
        m_from = re.search(r"\bfrom\s+(\S+)", from_clause)
        plain = re.sub(r"\([^()]*\)", " ", head)        # drop (comments)
        m_by = re.search(r"\bby\s+(\S+)", plain)
        m_with = re.search(r"\bwith\s+(\S+)", plain)
        submitted = bool(re.search(r"Authenticated sender|\bwith\s+E?SMTPS?A\b", head, re.I))
        when = None
        try:
            when = parsedate_to_datetime(date_part.strip())
        except Exception:
            pass
        ips = find_ips(from_clause) if m_from else []
        hops.append({
            "from": m_from.group(1) if m_from else "",
            "by": m_by.group(1) if m_by else "",
            "with": m_with.group(1) if m_with else "",
            "tls": bool(re.search(r"TLS|ESMTPS", head)), "submitted": submitted,
            "ips": ips, "public_ips": [i for i in ips if is_public(i)],
            "time": when.isoformat() if when else "", "_dt": when,
        })
    hops.reverse()
    prev = None
    for h in hops:
        h["delay_s"] = None
        if h["_dt"] and prev:
            try:
                h["delay_s"] = int((h["_dt"] - prev).total_seconds())
            except TypeError:
                pass
        if h["_dt"]:
            prev = h["_dt"]
    return hops


def pick_ips(msg, hops):
    """
    handoff        = IP that delivered the mail to the recipient's provider.
                     Written by the recipient's own server, so not forgeable.
    claimed_origin = earliest public IP. Written by the sender's side; may be fake.
    """
    handoff = claimed = ""
    with_ip = [h for h in hops if h["public_ips"]]
    for h in reversed(with_ip):                       # newest first
        f, b = h["from"].strip("[]"), h["by"]
        if is_ip(f) or not b or org_domain(f) != org_domain(b):
            handoff = h["public_ips"][0]              # crossed an organisation
            break
    if not handoff and with_ip:
        handoff = with_ip[-1]["public_ips"][0]
    origin_is_client = False
    if with_ip:
        claimed = with_ip[0]["public_ips"][0]
        first = with_ip[0]
        # the sender's own device: a bare IP that logged in to its mail provider
        origin_is_client = first["submitted"] or is_ip(re.sub(r"(?i)ipv6:", "", first["from"].strip("[]")))
    spf_ip = ""
    for name in ("Received-SPF", "Authentication-Results", "ARC-Authentication-Results"):
        for v in msg.get_all(name) or []:
            m = re.search(r"client-ip=([0-9A-Fa-f:.]+)", str(v)) or \
                re.search(r"designates\s+([0-9A-Fa-f:.]+)\s+as", str(v))
            if m and is_public(m.group(1).rstrip(".")):
                spf_ip = m.group(1).rstrip(".")
                break
        if spf_ip:
            break
    x_orig = ""
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        v = msg.get(name)
        found = [i for i in find_ips(str(v or "")) if is_public(i)]
        if found:
            x_orig = found[0]
            break
    return {"handoff": spf_ip or handoff, "claimed_origin": claimed, "x_originating": x_orig,
            "origin_is_client": origin_is_client}


# ==================================================================== auth
def parse_auth(msg):
    res = {"spf": "none", "dkim": "none", "dmarc": "none", "dkim_domains": [],
           "dkim_pass_domains": [], "spf_mailfrom": "", "present": False}
    ar = msg.get_all("Authentication-Results") or \
        msg.get_all("ARC-Authentication-Results") or []
    if not ar:
        return res
    res["present"] = True
    text = re.sub(r"\s+", " ", str(ar[0]))
    dkim_results = []
    for seg in text.split(";"):
        m = re.match(r"\s*(spf|dkim|dmarc)=(\w+)", seg, re.I)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if method == "spf":
            res["spf"] = result
            mf = re.search(r"smtp\.mailfrom=(\S+)", seg)
            if mf:
                res["spf_mailfrom"] = mf.group(1)
        elif method == "dmarc":
            res["dmarc"] = result
        else:
            dkim_results.append(result)
            d = re.search(r"header\.d=(\S+)", seg) or re.search(r"header\.i=\S*@(\S+)", seg)
            if d:
                dname = d.group(1).lower().strip(".")
                res["dkim_domains"].append(dname)
                if result == "pass":
                    res["dkim_pass_domains"].append(dname)
    if dkim_results:
        res["dkim"] = "pass" if "pass" in dkim_results else dkim_results[0]
    return res


def check_auth(auth, add):
    if not auth["present"]:
        add("MED", 10, "No Authentication-Results header - SPF/DKIM/DMARC not confirmed by the receiver")
        return
    table = {
        "spf": {"fail": 25, "softfail": 15, "none": 10, "neutral": 8, "permerror": 10, "temperror": 5},
        "dkim": {"fail": 25, "none": 10, "neutral": 8, "permerror": 10, "temperror": 5},
        "dmarc": {"fail": 30, "none": 5, "permerror": 8, "temperror": 5},
    }
    for k in ("spf", "dkim", "dmarc"):
        r = auth[k]
        if r == "pass":
            add("OK", 0, f"{k.upper()} passed")
        else:
            pts = table[k].get(r, 8)
            add("HIGH" if pts >= 20 else "MED", pts, f"{k.upper()} result: {r}")


# =================================================================== body
class BodyParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []
        self.text, self.forms, self._skip = [], 0, 0

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []
        elif tag == "form":
            self.forms += 1
        elif tag in ("script", "style"):
            self._skip += 1

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join(self._text).strip()))
            self._href = None
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1


def extract_body(msg):
    links, attachments, text, forms = [], [], [], 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = dec(part.get_filename()) if part.get_filename() else ""
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if fname:
            attachments.append({"name": fname, "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "magic": payload[:4].hex(), "type": part.get_content_type()})
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        body = payload.decode(part.get_content_charset() or "utf-8", "replace")
        if ctype == "text/html":
            p = BodyParser()
            try:
                p.feed(body)
            except Exception:
                pass
            links += p.links
            forms += p.forms
            text.append(" ".join(p.text))
        else:
            text.append(body)
            links += [(u.rstrip(".,)>"), "") for u in re.findall(r"https?://[^\s<>\"']+", body)]
    return links, attachments, re.sub(r"\s+", " ", " ".join(text)).lower(), forms


def check_links(links, add):
    hosts, urls, seen = {}, [], set()
    for href, text in links:
        low = href.lower()
        if low.startswith(("javascript:", "data:")):
            if "js" not in seen:
                seen.add("js")
                add("HIGH", 20, "Link uses a javascript:/data: URL (hides its real action)")
            continue
        if not low.startswith(("http://", "https://")):
            continue
        u = urlparse(href)
        host = (u.hostname or "").lower()
        if not host:
            continue
        hosts[host] = hosts.get(host, 0) + 1
        if href not in urls:
            urls.append(href)

        def flag(key, sev, pts, msg):
            if (key, host) not in seen:
                seen.add((key, host))
                add(sev, pts, msg)

        dh = defang(host)
        if is_ip(host):
            flag("ip", "HIGH", 15, f"Link points to a raw IP address: {dh}")
        if "xn--" in host:
            flag("puny", "HIGH", 15, f"Link uses a punycode (look-alike) domain: {dh}")
        if "@" in u.netloc:
            flag("at", "HIGH", 15, f"Link hides its real host with '@': {defang(href[:80])}")
        if host in SHORTENERS:
            flag("short", "LOW", 5, f"Shortened link hides the destination: {dh}")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            flag("tld", "MED", 8, f"Link uses a frequently abused TLD: {dh}")
        if host.count(".") >= 4 and not is_ip(host):
            flag("deep", "LOW", 4, f"Link host has unusually many subdomains: {dh}")
        b = lookalike(host)
        if b:
            flag("brand", "HIGH", 20, f"Link domain {dh} imitates the brand '{b}'")
        m = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", text.lower())
        if m and org_domain(m.group(1)) != org_domain(host):
            flag("mismatch", "HIGH", 20,
                 f"Link text shows '{m.group(1)}' but really opens '{dh}'")
    return hosts, urls


def check_attachments(atts, body_text, add):
    for a in atts:
        n = a["name"]
        parts = n.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        a["flags"] = []
        if ext in RISKY_EXT:
            a["flags"].append("risky type")
            add("HIGH", 25, f"Risky attachment type: {n}")
        if len(parts) > 2 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            a["flags"].append("double extension")
            add("HIGH", 15, f"Attachment with a double extension: {n}")
        if a["magic"].startswith("4d5a") and ext not in {"exe", "dll", "scr", "com", "msi"}:
            a["flags"].append("hidden executable")
            add("HIGH", 30, f"Attachment is a Windows executable disguised as .{ext or '?'}: {n}")
        if ext in ARCHIVE_EXT and "password" in body_text:
            a["flags"].append("password archive")
            add("MED", 10, f"Archive attachment with a password given in the mail body: {n}")


# ================================================================ identity
def lookalike(domain):
    label = org_domain(domain).split(".")[0]
    for tok in [label] + label.split("-"):
        if tok in BRANDS:
            continue
        norm = (tok.replace("0", "o").replace("1", "l").replace("3", "e")
                .replace("5", "s").replace("rn", "m").replace("vv", "w"))
        for b in BRANDS:
            if norm == b or (len(b) > 4 and
                             difflib.SequenceMatcher(None, tok, b).ratio() >= 0.85):
                return b
    return ""


def check_identity(info, auth, add):
    fd = info["from_domain"]
    f_org = org_domain(fd) if fd else ""
    name = info["from_name"].lower()
    if not fd:
        add("HIGH", 20, "From header has no valid address")
        return
    if "xn--" in fd or not fd.isascii():
        add("HIGH", 20, f"Sender domain uses non-standard characters: {fd}")
    b = lookalike(fd)
    if b:
        add("HIGH", 30, f"Sender domain '{fd}' imitates the brand '{b}'")
    inner = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if inner and org_domain(inner.group(1)) != f_org:
        add("HIGH", 25, "Display name shows a different email address than the real sender")
    for br in BRANDS:
        if re.search(rf"\b{re.escape(br)}\b", name) and br not in fd:
            sev, pts = ("HIGH", 25) if fd in FREEMAIL else ("MED", 12)
            add(sev, pts, f"Display name mentions '{br}' but the sender domain is {fd}")
            break
    rp = info["return_path_domain"]
    aligned = any(org_domain(d) == f_org for d in auth["dkim_pass_domains"])
    info["dkim_aligned"] = aligned
    if rp and org_domain(rp) != f_org:
        if aligned:
            add("INFO", 0, f"Return-Path domain ({rp}) differs from From, but DKIM is "
                           "aligned - normal for a bulk mail service")
        else:
            add("MED", 15, f"Return-Path domain ({rp}) differs from From domain ({fd})")
    for rt in info["reply_to_domains"]:
        if org_domain(rt) != f_org:
            pts = 30 if rt in FREEMAIL and fd not in FREEMAIL else 20
            add("HIGH", pts, f"Replies go to a different domain ({rt}) than the sender ({fd})")
            break
    mid = info["message_id_domain"]
    if mid and org_domain(mid) != f_org and not aligned:
        add("LOW", 5, f"Message-ID domain ({mid}) differs from From domain")
    hits = [w for w in SUBJECT_BAIT if w in info["subject"].lower()]
    if hits:
        add("LOW", min(10, 5 * len(hits)), "Pressure / bait wording in subject: " + ", ".join(hits))


# ================================================================== intel
def geo_lookup(ip):
    url = (f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,"
           "city,zip,lat,lon,timezone,isp,org,as,proxy,hosting")
    data, err = http_json(url)
    if data and data.get("status") == "success":
        return data
    return {"error": (data or {}).get("message") or err or "lookup failed"}


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def dnsbl(ip):
    listed = []
    if not is_ip(ip) or ipaddress.ip_address(ip).version != 4:
        return listed
    rev = ".".join(reversed(ip.split(".")))
    for zone in DNSBLS:
        try:
            if socket.gethostbyname(f"{rev}.{zone}").startswith("127.0.0."):
                listed.append(zone)
        except Exception:
            pass
    return listed


def abuseipdb(ip, key):
    data, err = http_json("https://api.abuseipdb.com/api/v2/check?" +
                          urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
                          {"Key": key, "Accept": "application/json"})
    if not data:
        return {"error": err}
    d = data.get("data", {})
    return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
            "usage": d.get("usageType") or "", "tor": bool(d.get("isTor"))}


def virustotal(kind, ident, key):
    data, err = http_json(f"https://www.virustotal.com/api/v3/{kind}/{ident}", {"x-apikey": key})
    if not data:
        return {"error": "not in VirusTotal" if err == "HTTP 404" else err}
    st = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
            "engines": sum(st.values()) if st else 0}


def urlhaus(host, key):
    data, err = http_json("https://urlhaus-api.abuse.ch/v1/host/", {"Auth-Key": key}, {"host": host})
    if not data:
        return {"error": err}
    if data.get("query_status") == "ok":
        return {"listed": True, "urls": int(data.get("url_count") or 0)}
    return {"listed": False}


def domain_age(domain):
    """Days since registration via RDAP, or None when the registry has no RDAP."""
    key = ("age", domain)
    if key in _cache:
        return _cache[key]
    days = None
    data, _ = http_json("https://rdap.org/domain/" + domain)
    for ev in (data or {}).get("events", []) or []:
        if ev.get("eventAction") == "registration":
            try:
                when = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                days = (dt.datetime.now(dt.timezone.utc) - when).days
            except Exception:
                pass
    _cache[key] = days
    return days


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def expand_url(url):
    """Follow redirects with HEAD requests only. Contacts the remote server."""
    opener = urllib.request.build_opener(NoRedirect)
    chain = [url]
    for _ in range(6):
        try:
            req = urllib.request.Request(chain[-1], method="HEAD", headers=UA)
            opener.open(req, timeout=TIMEOUT)
            break
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if e.code in (301, 302, 303, 307, 308) and loc:
                chain.append(urllib.parse.urljoin(chain[-1], loc))
            else:
                break
        except Exception:
            break
    return chain


def run_intel(r, add, keys, opts, raw):
    info, auth, ips = r["info"], r["auth"], r["ips"]
    fd = info["from_domain"]
    f_org = org_domain(fd) if fd else ""
    socket.setdefaulttimeout(5)
    intel = {"ip": {}, "dns": {}, "domain_age": {}, "virustotal": {}, "urlhaus": {}, "expanded": {}}
    note("running network lookups (use --no-net to skip)")
    SPIN.start("Tracing sender IP and location")

    dns_ok = bool(dns_query("gmail.com", "MX"))       # sanity check: is DNS reachable?
    # ---- IPs
    for key in ("handoff", "claimed_origin", "x_originating"):
        ip = ips[key]
        if not ip or ip in intel["ip"]:
            continue
        rep = {"reverse_dns": rdns(ip), "geo": geo_lookup(ip), "blacklists": dnsbl(ip)}
        if keys.get("abuseipdb"):
            rep["abuseipdb"] = abuseipdb(ip, keys["abuseipdb"])
        intel["ip"][ip] = rep
        if rep["blacklists"]:
            add("HIGH", 20, f"Sending IP {ip} is on blacklist(s): " + ", ".join(rep["blacklists"]))
        if rep["geo"].get("proxy"):
            add("MED", 10, f"IP {ip} is a known proxy / VPN / Tor exit")
        if dns_ok and not rep["reverse_dns"] and key == "handoff":
            add("LOW", 5, f"Sending IP {ip} has no reverse DNS (unusual for a real mail server)")
        ab = rep.get("abuseipdb") or {}
        if ab.get("score", 0) >= 50:
            add("HIGH", 20, f"AbuseIPDB: {ip} has abuse score {ab['score']}% ({ab['reports']} reports)")
        elif ab.get("score", 0) >= 15:
            add("MED", 10, f"AbuseIPDB: {ip} has abuse score {ab['score']}% ({ab['reports']} reports)")

    SPIN.set("Checking live DNS records (SPF / DMARC / MX)")
    # ---- live DNS re-check of the sender domain
    if not dns_ok:
        intel["dns_error"] = "DNS lookups unavailable - live DNS checks skipped"
    if fd and dns_ok:
        d = intel["dns"]
        d["mx"] = dns_query(fd, "MX")
        if not d["mx"] and not host_ips(fd):
            add("HIGH", 20, f"Sender domain {fd} has no MX or A record (cannot receive mail / may not exist)")
        d["dmarc"] = dmarc_record(fd)
        if not d["dmarc"]:
            add("LOW", 5, f"{fd} publishes no DMARC record, so anyone can spoof it easily")
        env = domain_of(auth["spf_mailfrom"]) or info["return_path_domain"] or fd
        if ips["handoff"]:
            d["spf_domain"] = env
            d["spf_live"] = spf_eval(ips["handoff"], env)
            live = d["spf_live"]
            if auth["present"] and auth["spf"] == "pass" and live in ("fail", "softfail"):
                add("MED", 15, f"Header claims SPF pass, but {ips['handoff']} is NOT authorised in the live "
                               f"SPF record of {env} (forged header or changed record)")
            elif not auth["present"]:
                if live == "pass":
                    add("OK", 0, f"Live SPF check: {ips['handoff']} is authorised to send for {env}")
                elif live in ("fail", "softfail"):
                    add("HIGH", 20, f"Live SPF check: {ips['handoff']} is not authorised to send for {env} ({live})")
                elif live == "none":
                    add("LOW", 5, f"{env} publishes no SPF record")

    SPIN.set("Checking domain age")
    # ---- domain age
    link_orgs = []
    for host in sorted(r["link_hosts"], key=lambda h: -r["link_hosts"][h]):
        o = org_domain(host)
        if not is_ip(host) and o != f_org and o not in FREEMAIL and o not in link_orgs:
            link_orgs.append(o)
    for dom in ([f_org] if f_org and f_org not in FREEMAIL else []) + link_orgs[:3]:
        age = domain_age(dom)
        intel["domain_age"][dom] = age
        if age is None:
            continue
        if age < 30:
            add("HIGH", 25, f"Domain {defang(dom)} was registered only {age} days ago")
        elif age < 180:
            add("MED", 10, f"Domain {defang(dom)} is young ({age} days old)")

    SPIN.set("Checking threat-intelligence feeds")
    # ---- URLhaus
    if keys.get("urlhaus"):
        for host in list(r["link_hosts"])[:5]:
            res = urlhaus(host, keys["urlhaus"])
            intel["urlhaus"][host] = res
            if res.get("listed"):
                add("HIGH", 30, f"URLhaus: {defang(host)} is a known malware host ({res['urls']} URLs)")

    # ---- VirusTotal (free API = 4 requests/min, so only 4 per mail)
    if keys.get("virustotal"):
        jobs = [("files", a["sha256"], a["name"]) for a in r["attachments"]]
        jobs += [("domains", o, o) for o in link_orgs]
        if ips["handoff"]:
            jobs.append(("ip_addresses", ips["handoff"], ips["handoff"]))
        for kind, ident, label in jobs[:4]:
            res = virustotal(kind, ident, keys["virustotal"])
            intel["virustotal"][label] = res
            mal = res.get("malicious", 0)
            shown = label if kind == "files" else defang(label)
            if kind == "files" and mal >= 1:
                add("HIGH", 30, f"VirusTotal: attachment {shown} flagged by {mal} engines")
            elif mal >= 3:
                add("HIGH", 25, f"VirusTotal: {shown} flagged malicious by {mal} engines")
            elif mal >= 1:
                add("MED", 10, f"VirusTotal: {shown} flagged by {mal} engine(s)")

    # ---- optional: follow short links
    if opts.get("expand"):
        short = [u for u in r["urls"] if (urlparse(u).hostname or "").lower() in SHORTENERS]
        for u in short[:3]:
            chain = expand_url(u)
            intel["expanded"][u] = chain
            if len(chain) > 1:
                final = (urlparse(chain[-1]).hostname or "").lower()
                bad = is_ip(final) or final.rsplit(".", 1)[-1] in RISKY_TLDS or lookalike(final)
                add("HIGH" if bad else "INFO", 15 if bad else 0,
                    f"Short link {defang(u)} really leads to {defang(final)}")

    # ---- optional: cryptographic DKIM verification
    if opts.get("verify_dkim"):
        try:
            import dkim
            ok = dkim.verify(raw)
            intel["dkim_crypto"] = "valid" if ok else "invalid"
            if ok:
                add("OK", 0, "DKIM signature verified cryptographically (message not altered)")
            else:
                add("LOW", 5, "DKIM signature did not verify locally (message altered, "
                              "or the file was re-formatted when saved)")
        except ImportError:
            intel["dkim_crypto"] = "dkimpy not installed (sudo apt install python3-dkim)"
        except Exception as e:
            intel["dkim_crypto"] = f"error: {e}"
    return intel


# ================================================================= analyze
def analyze(raw, keys=None, opts=None):
    keys, opts = keys or {}, opts or {}
    raw = raw.lstrip(b"\xef\xbb\xbf\r\n \t")
    msg = message_from_bytes(raw)
    if not msg.keys():
        raise ValueError("No email headers found. Use the full 'Show original' text or a .eml file.")

    from_name, from_addr = parseaddr(dec(msg.get("From")))
    rp = parseaddr(dec(msg.get("Return-Path")))[1]
    reply_tos = [a for _, a in getaddresses([dec(v) for v in msg.get_all("Reply-To") or []]) if a]
    mid = dec(msg.get("Message-ID"))
    info = {
        "from_name": from_name, "from_address": from_addr, "from_domain": domain_of(from_addr),
        "return_path": rp, "return_path_domain": domain_of(rp),
        "reply_to": reply_tos,
        "reply_to_domains": [domain_of(a) for a in reply_tos if domain_of(a)],
        "to": dec(msg.get("To")), "subject": dec(msg.get("Subject")),
        "date": dec(msg.get("Date")), "message_id": mid,
        "message_id_domain": domain_of(mid.strip("<>")),
        "mailer": dec(msg.get("X-Mailer") or msg.get("User-Agent")),
    }
    findings = []

    def add(sev, pts, text):
        if not any(f["text"] == text for f in findings):
            findings.append({"severity": sev, "points": pts, "text": text})

    auth = parse_auth(msg)
    hops = parse_received(msg)
    ips = pick_ips(msg, hops)
    check_auth(auth, add)
    check_identity(info, auth, add)
    links, attachments, body_text, forms = extract_body(msg)
    link_hosts, urls = check_links(links, add)
    check_attachments(attachments, body_text, add)

    if forms:
        add("HIGH", 15, "The mail contains an HTML form (asks for data inside the email itself)")
    hits = [w for w in BODY_BAIT if w in body_text]
    if hits:
        add("LOW", min(10, 4 * len(hits)), "Pressure / bait wording in body: " + ", ".join(hits[:5]))
    if not hops:
        add("MED", 10, "No Received headers - the route cannot be traced")
    if any(h["delay_s"] is not None and h["delay_s"] < -300 for h in hops):
        add("LOW", 5, "Timestamps in the route go backwards (possible forged hop)")
    try:
        sent = parsedate_to_datetime(info["date"])
        first = next(h["_dt"] for h in hops if h["_dt"])
        if abs((first - sent).total_seconds()) > 86400:
            add("LOW", 5, "Date header differs from the first server timestamp by more than a day")
    except Exception:
        pass
    for h in hops:
        h.pop("_dt", None)

    r = {"info": info, "auth": auth, "ips": ips, "hops": hops, "link_hosts": link_hosts,
         "urls": urls, "attachments": attachments, "findings": findings, "intel": {}}
    if not opts.get("no_net"):
        try:
            r["intel"] = run_intel(r, add, keys, opts, raw)
        finally:
            SPIN.stop()

    r["score"] = min(100, sum(f["points"] for f in findings))
    r["verdict"] = ("HIGH RISK - likely phishing / spoofed" if r["score"] >= 50 else
                    "SUSPICIOUS - verify before trusting" if r["score"] >= 20 else
                    "LOW RISK - no strong phishing signs")
    def ip_summary(ip):
        g = ((r["intel"].get("ip") or {}).get(ip) or {}).get("geo") or {}
        has = g.get("lat") is not None
        return {"ip": ip, "city": g.get("city"), "region": g.get("regionName"),
                "country": g.get("country"), "latitude": g.get("lat"), "longitude": g.get("lon"),
                "timezone": g.get("timezone"), "isp": g.get("isp"),
                "map": f"https://www.google.com/maps?q={g['lat']},{g['lon']}" if has else None}

    # sender_ip  = mail server that handed the message to the recipient (verified)
    # origin_ip  = where the message was first submitted from (sender's device/network)
    r["sender_ip"] = ip_summary(ips["handoff"] or ips["claimed_origin"])
    origin = ips["x_originating"] or ips["claimed_origin"]
    r["origin_ip"] = None
    if origin and origin != r["sender_ip"]["ip"]:
        r["origin_ip"] = ip_summary(origin)
        r["origin_ip"]["is_sender_device"] = bool(ips["x_originating"] or ips["origin_is_client"])
        r["origin_ip"]["trusted"] = auth["dmarc"] == "pass" or info.get("dkim_aligned", False)
    r["iocs"] = {
        "ips": sorted({ips[k] for k in ("handoff", "claimed_origin", "x_originating") if ips[k]}),
        "domains": sorted({org_domain(h) for h in link_hosts if not is_ip(h)} |
                          ({info["from_domain"]} if info["from_domain"] else set())),
        "urls": urls, "sha256": [a["sha256"] for a in attachments],
    }
    return r


# ================================================================== output
IP_LABELS = [("handoff", "Verified sending IP (recorded by your mail provider)"),
             ("claimed_origin", "Earliest IP in headers (can be forged)"),
             ("x_originating", "X-Originating-IP (sender's device, if provided)")]
ORDER = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3, "OK": 4}


ICON = {"HIGH": "✖", "MED": "▲", "LOW": "●", "INFO": "ℹ", "OK": "✔"}


def panel(title, lines, colour):
    """Draw a boxed panel; lines may contain colour codes."""
    w = width() - 4
    emit(f"  {colour}╔═ {C.W}{title}{C.X}{colour} {'═' * max(0, w - vlen(title) - 4)}╗{C.X}", 0.03)
    for ln in lines:
        while vlen(ln) > w - 2:                       # trim over-long lines
            ln = ln[:-1]
        emit(f"  {colour}║{C.X} {ln}{' ' * (w - 2 - vlen(ln))} {colour}║{C.X}", 0.03)
    emit(f"  {colour}╚{'═' * w}╝{C.X}", 0.03)


def risk_meter(score, verdict):
    vc = C.R if score >= 50 else C.Y if score >= 20 else C.G
    cells = 30
    steps = range(0, score + 1, 2) if ANIM else [score]
    for val in list(steps) + [score]:
        filled = round(cells * val / 100)
        bar = f"{vc}{'█' * filled}{C.D}{'░' * (cells - filled)}{C.X}"
        line = f"  {C.W}RISK{C.X} {bar} {vc}{C.W}{val:>3}/100{C.X}"
        if ANIM:
            sys.stdout.write("\r\033[K" + line)
            sys.stdout.flush()
            time.sleep(0.02)
    if not ANIM:
        sys.stdout.write(line)
    print()
    typewrite(f"  {vc}{C.W}▶ {verdict}{C.X}", 0.02)


def show(r, source="", want_ioc=False):
    i, a, intel = r["info"], r["auth"], r["intel"]

    def sec(t):
        emit()
        emit(f"  {C.B}{C.W}▌ {t}{C.X} {C.D}{'─' * max(0, width() - vlen(t) - 7)}{C.X}", 0.04)

    def row(k, v):
        if v not in ("", None):
            emit(f"    {C.D}{k:<17}{C.X}{v}")

    if source:
        emit(f"\n  {C.D}File: {source}{C.X}")

    # ---------------- highlighted IPs: sender's device first, then the delivering server
    def ip_lines(sm, hi):
        rep = (intel.get("ip") or {}).get(sm["ip"], {})
        g = rep.get("geo") or {}
        lines = [f"{C.W}IP ADDRESS{C.X}   {hi} {sm['ip']} {C.X}"]
        if sm["latitude"] is not None:
            place = ", ".join(dict.fromkeys(x for x in (sm["city"], sm["region"], sm["country"]) if x))
            lines += [
                f"{C.D}Location{C.X}      {C.W}{place}{C.X}",
                f"{C.D}Latitude{C.X}      {C.G}{sm['latitude']}{C.X}      "
                f"{C.D}Longitude{C.X}  {C.G}{sm['longitude']}{C.X}",
                f"{C.D}Timezone{C.X}      {sm['timezone'] or '-'}",
                f"{C.D}ISP{C.X}           {sm['isp'] or '-'}",
                f"{C.D}Map{C.X}           {C.B}{sm['map']}{C.X}",
            ]
        elif g.get("error"):
            lines.append(f"{C.D}Location{C.X}      {C.Y}lookup failed ({g['error']}){C.X}")
        else:
            lines.append(f"{C.D}Location{C.X}      {C.Y}not looked up (offline mode){C.X}")
        if rep.get("reverse_dns"):
            lines.append(f"{C.D}Server name{C.X}   {rep['reverse_dns']}")
        return lines

    sip, oip = r["sender_ip"], r.get("origin_ip")
    emit()
    if oip and oip["is_sender_device"]:
        panel("◉ SENDER'S DEVICE / NETWORK", ip_lines(oip, C.HI), C.G if oip["trusted"] else C.Y)
        if oip["trusted"]:
            emit(f"  {C.D}The network the sender was connected to (WiFi / mobile data) when sending.{C.X}")
            emit(f"  {C.D}Location is the ISP's area for that IP: usually the right city, never a street address.{C.X}")
        else:
            emit(f"  {C.Y}Unverified: this mail failed authentication, so this IP may be forged.{C.X}")
        emit()
        panel("◉ DELIVERED BY MAIL SERVER", ip_lines(sip, C.W), C.B)
        emit(f"  {C.D}The relay that handed the mail to your provider. This is not the sender's location.{C.X}")
    elif sip["ip"]:
        panel("◉ THIS MAIL CAME FROM", ip_lines(sip, C.HI), C.B)
        emit(f"  {C.D}This is the mail server that delivered the message, not the sender's device.{C.X}")
        emit(f"  {C.D}The sender's provider (e.g. Gmail, Outlook) does not reveal the device IP.{C.X}")
    else:
        panel("◉ THIS MAIL CAME FROM", [f"{C.Y}No public IP address found in the headers{C.X}"], C.Y)

    sec("SENDER")
    row("From name", i["from_name"])
    row("From address", f"{C.W}{i['from_address']}{C.X}")
    row("Return-Path", i["return_path"]); row("Reply-To", ", ".join(i["reply_to"]))
    row("To", i["to"]); row("Subject", i["subject"]); row("Date", i["date"])
    row("Message-ID", i["message_id"]); row("Mail client", i["mailer"])

    sec("AUTHENTICATION")
    badges = []
    for k in ("spf", "dkim", "dmarc"):
        v = a[k]
        col = C.G if v == "pass" else C.R if v in ("fail", "softfail") else C.Y
        mark = "✔" if v == "pass" else "✖" if v in ("fail", "softfail") else "?"
        badges.append(f"{col}{C.W}{mark} {k.upper()} {v.upper()}{C.X}")
    emit("    " + "     ".join(badges))
    row("Signed by", ", ".join(sorted(set(a["dkim_domains"]))))
    row("Envelope sender", a["spf_mailfrom"])
    dns = intel.get("dns") or {}
    if intel.get("dns_error"):
        emit(f"    {C.Y}{intel['dns_error']}{C.X}")
    if dns:
        row("MX servers", ", ".join(dns.get("mx", [])[:3]) or "none")
        if "spf_live" in dns:
            row("SPF (live DNS)", f"{dns['spf_live'].upper()} for {r['ips']['handoff']} on {dns['spf_domain']}")
        dm = dns.get("dmarc") or {}
        row("DMARC policy", f"p={dm['policy']} ({dm['domain']})" if dm else "no record")
    row("DKIM (crypto)", intel.get("dkim_crypto"))

    sec("IP DETAILS")
    shown = set()
    for key, label in IP_LABELS:
        ip = r["ips"][key]
        if not ip or ip in shown:
            continue
        shown.add(ip)
        rep = (intel.get("ip") or {}).get(ip, {})
        if key == "claimed_origin" and r["ips"].get("origin_is_client"):
            label = "Sender's device / network IP (reported by the sender's mail provider)"
        emit(f"    {C.W}{ip}{C.X}  {C.D}{label}{C.X}")
        g = rep.get("geo") or {}
        if g and "error" not in g:
            row("  Location", ", ".join(dict.fromkeys(str(x) for x in (g.get("city"), g.get("regionName"), g.get("country")) if x)))
            row("  Lat / Long", f"{g.get('lat')}, {g.get('lon')}")
            row("  ISP / Org", " / ".join(x for x in (g.get("isp"), g.get("org")) if x))
            row("  ASN", g.get("as"))
            row("  Type", "hosting / datacenter" if g.get("hosting") else "")
        row("  Reverse DNS", rep.get("reverse_dns"))
        if "blacklists" in rep:
            bl = rep["blacklists"]
            row("  Blacklists", f"{C.R}{', '.join(bl)}{C.X}" if bl else f"{C.G}not listed{C.X}")
        ab = rep.get("abuseipdb")
        if ab:
            row("  AbuseIPDB", ab.get("error") or f"score {ab['score']}%, {ab['reports']} reports, {ab['usage']}")
    if not shown:
        emit("    no public IP found in the headers")

    sec("ROUTE  (sender → you)")
    for n, h in enumerate(r["hops"], 1):
        d = "" if h["delay_s"] is None else f"  {C.D}+{h['delay_s']}s{C.X}"
        extra = [x for x in h["ips"] if x not in h["from"]]
        ip = f" {C.B}[{', '.join(extra)}]{C.X}" if extra else ""
        tls = f" {C.G}TLS{C.X}" if h["tls"] else ""
        emit(f"    {C.B}{n}{C.X} {h['from'] or '(internal)'}{ip}", 0.05)
        emit(f"      {C.D}└─▶{C.X} {h['by'] or '?'} {C.D}{h['with']}{C.X}{tls}{d}", 0.05)
    if not r["hops"]:
        emit("    no Received headers")

    ages = intel.get("domain_age") or {}
    if ages:
        sec("DOMAIN AGE")
        for dom, age in ages.items():
            if age is None:
                txt = f"{C.D}unknown (registry has no RDAP){C.X}"
            else:
                col = C.R if age < 30 else C.Y if age < 180 else C.G
                txt = f"{col}{age} days{C.X} {C.D}({age // 365} years){C.X}"
            emit(f"    {C.D}{dom}{C.X}  {txt}")
    if r["link_hosts"]:
        sec("LINK DOMAINS")
        for host, n in sorted(r["link_hosts"].items(), key=lambda x: -x[1])[:15]:
            tags = []
            uh = (intel.get("urlhaus") or {}).get(host)
            if uh:
                tags.append("URLhaus: " + ("LISTED" if uh.get("listed") else uh.get("error") or "clean"))
            vt = (intel.get("virustotal") or {}).get(org_domain(host))
            if vt:
                tags.append("VT: " + (vt.get("error") or f"{vt['malicious']}/{vt['engines']}"))
            emit(f"    {host}  {C.D}x{n}  {'  '.join(tags)}{C.X}")
        for u, chain in (intel.get("expanded") or {}).items():
            emit(f"    {C.D}{defang(u)} → {defang(chain[-1])}{C.X}")
    if r["attachments"]:
        sec("ATTACHMENTS")
        for at in r["attachments"]:
            vt = (intel.get("virustotal") or {}).get(at["name"])
            vtxt = f"  VT: {vt.get('error') or str(vt['malicious']) + '/' + str(vt['engines'])}" if vt else ""
            flags = f"  {C.R}{', '.join(at.get('flags', []))}{C.X}" if at.get("flags") else ""
            emit(f"    {C.W}{at['name']}{C.X}  {C.D}{at['size']} bytes{vtxt}{C.X}{flags}")
            emit(f"      {C.D}sha256 {at['sha256']}{C.X}")

    sec("FINDINGS")
    col = {"HIGH": C.R, "MED": C.Y, "LOW": C.Y, "INFO": C.D, "OK": C.G}
    for f in sorted(r["findings"], key=lambda f: ORDER[f["severity"]]):
        pts = f" {C.D}(+{f['points']}){C.X}" if f["points"] else ""
        emit(f"    {col[f['severity']]}{ICON[f['severity']]} {f['severity']:<4}{C.X} {f['text']}{pts}", 0.03)

    if want_ioc:
        sec("IOCs  (block or report these)")
        for k, vals in r["iocs"].items():
            for v in vals:
                emit(f"    {C.D}{k:<8}{C.X} {defang(v) if k in ('domains', 'urls') else v}")

    emit()
    emit(f"  {C.D}{'━' * (width() - 4)}{C.X}")
    risk_meter(r["score"], r["verdict"])
    emit(f"  {C.D}A low score is not a guarantee: a hacked real account passes every check.{C.X}")


def footer():
    emit(f"\n  {C.D}MailTrax v{VERSION}  •  Developed by{C.X} {C.M}{C.W}{VENDOR}{C.X}  {C.D}•{C.X}  {C.B}{SITE}{C.X}\n")


def html_report(results):
    e = html.escape
    css = ("body{font-family:system-ui,sans-serif;background:#11151c;color:#dde3ea;max-width:960px;"
           "margin:24px auto;padding:0 16px}h1{font-size:22px}h2{font-size:17px;margin-top:36px;"
           "border-bottom:1px solid #2c3440;padding-bottom:6px}h3{font-size:13px;color:#7fb4ff;"
           "text-transform:uppercase;letter-spacing:.06em;margin:20px 0 6px}table{border-collapse:collapse;"
           "width:100%;font-size:14px}td{padding:4px 8px;border-bottom:1px solid #222a35;vertical-align:top;"
           "word-break:break-word}td:first-child{color:#8b97a6;width:170px}.HIGH{color:#ff6b6b}"
           ".MED,.LOW{color:#ffcc66}.OK{color:#6fdc8c}.INFO{color:#8b97a6}.score{font-size:20px;"
           "font-weight:700;padding:10px 14px;border-radius:8px;background:#1a212b;display:inline-block}"
           "code{font-size:12px;color:#8b97a6}")
    out = [f"<!doctype html><meta charset='utf-8'><title>MailTrax report</title><style>{css}</style>",
           f"<h1>MailTrax {VERSION} report</h1><p class='INFO'>Generated "
           f"{dt.datetime.now().strftime('%Y-%m-%d %H:%M')} &middot; {len(results)} message(s). "
           "Links and domains are defanged.</p>"]

    def table(rows):
        return "<table>" + "".join(f"<tr><td>{e(str(k))}</td><td>{v}</td></tr>"
                                   for k, v in rows if v not in ("", None)) + "</table>"

    for src, r in results:
        i, a, intel = r["info"], r["auth"], r["intel"]
        cls = "HIGH" if r["score"] >= 50 else "MED" if r["score"] >= 20 else "OK"
        out.append(f"<h2>{e(src)} &mdash; {e(i['subject'] or '(no subject)')}</h2>")
        out.append(f"<div class='score {cls}'>{r['score']}/100 &middot; {e(r['verdict'])}</div>")
        out.append("<h3>Sender</h3>" + table([
            ("From", e(f"{i['from_name']} <{i['from_address']}>")), ("Return-Path", e(i["return_path"])),
            ("Reply-To", e(", ".join(i["reply_to"]))), ("To", e(i["to"])), ("Date", e(i["date"])),
            ("Message-ID", e(i["message_id"]))]))
        dns = intel.get("dns") or {}
        dm = dns.get("dmarc") or {}
        out.append("<h3>Authentication</h3>" + table(
            [(k.upper(), f"<span class='{'OK' if a[k] == 'pass' else 'HIGH' if a[k] in ('fail', 'softfail') else 'MED'}'>"
                         f"{e(a[k].upper())}</span>") for k in ("spf", "dkim", "dmarc")] +
            [("SPF (live DNS)", e(dns.get("spf_live", "").upper())),
             ("DMARC policy", e(f"p={dm['policy']}") if dm else ("no record" if dns else ""))]))
        rows = []
        for key, label in IP_LABELS:
            ip = r["ips"][key]
            if not ip:
                continue
            rep = (intel.get("ip") or {}).get(ip, {})
            g = rep.get("geo") or {}
            bits = [label]
            if g and "error" not in g:
                bits.append(", ".join(x for x in (g.get("city"), g.get("country"), g.get("isp")) if x))
                bits.append(f"lat {g.get('lat')}, long {g.get('lon')}")
            if rep.get("reverse_dns"):
                bits.append("rDNS " + rep["reverse_dns"])
            if rep.get("blacklists"):
                bits.append("BLACKLISTED: " + ", ".join(rep["blacklists"]))
            rows.append((ip, e(" | ".join(bits))))
        out.append("<h3>Sending IP</h3>" + (table(rows) if rows else "<p>none found</p>"))
        out.append("<h3>Route</h3>" + table(
            [(n, e(f"{h['from'] or '(internal)'} {' '.join(h['ips'])} -> {h['by']} {h['with']}"))
             for n, h in enumerate(r["hops"], 1)]))
        out.append("<h3>Findings</h3>" + table(
            [(f["severity"], f"<span class='{f['severity']}'>{e(f['text'])}</span>"
              + (f" <code>+{f['points']}</code>" if f["points"] else ""))
             for f in sorted(r["findings"], key=lambda f: ORDER[f["severity"]])]))
        ioc = [(k, "<br>".join(e(defang(v) if k in ("domains", "urls") else v) for v in vals[:40]))
               for k, vals in r["iocs"].items() if vals]
        out.append("<h3>IOCs</h3>" + table(ioc))
    out.append(f"<p class='INFO' style='margin-top:40px;text-align:center'>MailTrax v{VERSION} "
               f"&middot; Developed by <b>{VENDOR}</b> &middot; {SITE}</p>")
    return "\n".join(out)


# ==================================================================== main
def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in sorted(names)
                          if n.lower().endswith((".eml", ".txt", ".msg.txt"))]
        else:
            files.append(p)
    return files


def main():
    ap = argparse.ArgumentParser(
        prog="mailtrax", description="MailTrax - advanced email header & phishing analyzer, developed by DEVJIX (www.devjix.com)",
        epilog="Exit code: 0 = low risk, 1 = suspicious, 2 = high risk (highest of all files).")
    ap.add_argument("paths", nargs="*", help=".eml/.txt files or folders; '-' or nothing = paste / stdin")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the report")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report")
    ap.add_argument("--ioc", action="store_true", help="list IPs, domains, URLs and hashes (defanged)")
    ap.add_argument("-q", "--quiet", action="store_true", help="one summary line per mail")
    ap.add_argument("--no-net", action="store_true", help="offline: no DNS, location or reputation lookups")
    ap.add_argument("--expand", action="store_true",
                    help="follow shortened links (HEAD only). CONTACTS THE SENDER'S SERVER")
    ap.add_argument("--verify-dkim", action="store_true",
                    help="verify the DKIM signature cryptographically (needs python3-dkim, use a .eml file)")
    ap.add_argument("--set-key", nargs=2, metavar=("SERVICE", "KEY"),
                    help="save an API key: " + ", ".join(SERVICES))
    ap.add_argument("--show-keys", action="store_true", help="show which API keys are configured")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-anim", action="store_true", help="no animations or banner art delays")
    ap.add_argument("--version", action="version", version=f"MailTrax {VERSION}")
    args = ap.parse_args()

    if args.no_color or args.json or not sys.stdout.isatty():
        C.off()
    if args.set_key:
        svc = args.set_key[0].lower()
        if svc not in SERVICES:
            sys.exit("Unknown service. Choose from: " + ", ".join(SERVICES))
        save_key(svc, args.set_key[1])
        print(f"Saved {svc} key to {CONFIG}")
        return
    global ANIM
    pretty = not args.json and not args.quiet
    ANIM = pretty and not args.no_anim and sys.stdout.isatty() and sys.stderr.isatty()
    if pretty:
        banner()
    keys = load_keys()
    if args.show_keys:
        for s in SERVICES:
            print(f"  {s:<12} {'configured' if keys.get(s) else 'not set'}")
        return

    inputs = []
    if not args.paths or args.paths == ["-"]:
        if sys.stdin.isatty():
            print("Paste the full 'Show original' text, then press Ctrl+D:\n", file=sys.stderr)
        inputs.append(("pasted message", sys.stdin.buffer.read()))
    else:
        for f in collect(args.paths):
            try:
                with open(f, "rb") as fh:
                    inputs.append((f, fh.read()))
            except OSError as e:
                print(f"Cannot read {f}: {e}", file=sys.stderr)
    if not inputs:
        sys.exit("No input files found.")

    opts = {"no_net": args.no_net, "expand": args.expand, "verify_dkim": args.verify_dkim}
    results = []
    for src, raw in inputs:
        try:
            results.append((src, analyze(raw, keys, opts)))
        except ValueError as e:
            print(f"{src}: {e}", file=sys.stderr)
    if not results:
        sys.exit(3)

    if args.json:
        print(json.dumps([dict(r, source=s) for s, r in results] if len(results) > 1
                         else results[0][1], indent=2, ensure_ascii=False))
    elif args.quiet or len(results) > 1:
        if not args.quiet:
            for n, (src, r) in enumerate(results):
                if n:
                    print("\n" + "-" * 72)
                show(r, src, args.ioc)
            print(f"\n{C.B}{C.W}== SUMMARY =={C.X}")
        for src, r in sorted(results, key=lambda x: -x[1]["score"]):
            vc = C.R if r["score"] >= 50 else C.Y if r["score"] >= 20 else C.G
            print(f"  {vc}{r['score']:>3}/100{C.X}  {r['info']['from_address'][:34]:<34}  "
                  f"{r['info']['subject'][:40]:<40}  {C.D}{os.path.basename(src)}{C.X}")
    else:
        show(results[0][1], results[0][0], args.ioc)
    if pretty:
        footer()

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_report(results))
        print(f"\nHTML report written to {args.html}", file=sys.stderr)

    top = max(r["score"] for _, r in results)
    sys.exit(2 if top >= 50 else 1 if top >= 20 else 0)


if __name__ == "__main__":
    main()
