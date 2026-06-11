#!/usr/bin/env python3
"""
Warren - Advanced Subdomain Discovery Framework v3.1
Multi-source passive + active + permutation + probing recon.

v3.1 additions (on top of v3.0's resilience layer):
  - Permutation/alteration phase: alterx > gotator > dnsgen > built-in generator,
    then resolves the candidates (puredns if present, else built-in resolver).
  - Recursive enumeration (--recursive): re-queries key-less sources against
    discovered subdomains, one level deep, with a hard parent cap.
  - Live-host probing: httpx if present, else a built-in async HTTP prober
    (status code + title) over resolved hosts.
  - Real wildcard filtering: samples wildcard IPs and drops hosts that only
    resolve to them (built-in resolver path).
  - New sources: github-subdomains, gitlab-subdomains (token-gated),
    tlsx cert-SAN enrichment.
  - Every phase isolated; one failure never aborts the run.
"""

import asyncio
import argparse
import base64
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Set, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import aiohttp
except ImportError:
    print("[FATAL] aiohttp is required:  pip install aiohttp", file=sys.stderr)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[FATAL] PyYAML is required:  pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ─── Terminal Colors ─────────────────────────────────────────────────────────
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    WHITE = "\033[97m"; BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


if not sys.stdout.isatty():
    for _a in ("RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE",
               "BOLD", "DIM", "RESET"):
        setattr(C, _a, "")


def tag_info(msg):     print(f"{C.CYAN}[INFO]{C.RESET}    {msg}")
def tag_run(msg):      print(f"{C.BLUE}[RUNNING]{C.RESET} {msg}")
def tag_ok(msg):       print(f"{C.GREEN}[SUCCESS]{C.RESET} {msg}")
def tag_err(msg):      print(f"{C.RED}[ERROR]{C.RESET}   {msg}")
def tag_warn(msg):     print(f"{C.YELLOW}[WARN]{C.RESET}    {msg}")
def tag_found(n, src): print(f"{C.MAGENTA}[FOUND]{C.RESET}   {C.BOLD}{n}{C.RESET} subdomains \u2190 {C.CYAN}{src}{C.RESET}")


BANNER = f"""{C.CYAN}{C.BOLD}
\u2588\u2588\u2557    \u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2557   \u2588\u2588\u2557
\u2588\u2588\u2551    \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255d\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2551
\u2588\u2588\u2551 \u2588\u2557 \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2557  \u2588\u2588\u2554\u2588\u2588\u2557 \u2588\u2588\u2551
\u2588\u2588\u2551\u2588\u2588\u2588\u2557\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2554\u2550\u2550\u255d  \u2588\u2588\u2551\u255a\u2588\u2588\u2557\u2588\u2588\u2551
\u255a\u2588\u2588\u2588\u2554\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2551 \u255a\u2588\u2588\u2588\u2588\u2551
 \u255a\u2550\u2550\u255d\u255a\u2550\u2550\u255d \u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d\u255a\u2550\u255d  \u255a\u2550\u2550\u2550\u255d
{C.RESET}{C.DIM}
        \u2501\u2501\u2501  Resilient Subdomain Discovery Framework v3.1  \u2501\u2501\u2501
        \u2501\u2501\u2501  Passive \u2502 Active \u2502 Permute \u2502 Probe \u2502 Resilient    \u2501\u2501\u2501
{C.RESET}"""


# ─── Config ──────────────────────────────────────────────────────────────────
DEFAULT_CONFIG: Dict[str, Any] = {
    "securitytrails": "",
    "virustotal": "",
    "shodan": "",
    "censys_id": "",
    "censys_secret": "",
    "zoomeye": "",
    "binaryedge": "",
    "chaos": "",
    "urlscan": "",
    "github_token": "",
    "gitlab_token": "",
    "rate_limit_delay": 1,
    "tool_timeout": 300,
    "http_retries": 3,
    "http_timeout": 30,
    "resolve_concurrency": 100,
    "probe_concurrency": 50,
    "probe_timeout": 8,
    "permutation_cap": 50000,
    "permutation_builtin_resolve_cap": 8000,
    "recursive_limit": 25,
    "resolvers_file": "/tmp/warren_resolvers.txt",
    "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
}


def load_config(config_path: str = "config.yaml") -> dict:
    config = DEFAULT_CONFIG.copy()
    if not os.path.exists(config_path):
        tag_warn("No config.yaml found \u2014 API-key sources will be skipped")
        return config
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        if not isinstance(user_cfg, dict):
            tag_warn("config.yaml is not a mapping \u2014 using defaults")
            return config
        config.update({k: v for k, v in user_cfg.items() if v is not None})
        tag_info(f"Config loaded from {C.BOLD}{config_path}{C.RESET}")
    except yaml.YAMLError as e:
        tag_warn(f"config.yaml parse error ({e}) \u2014 using defaults")
    except Exception as e:
        tag_warn(f"Could not read config ({e}) \u2014 using defaults")
    return config


# ─── Output / Logging ────────────────────────────────────────────────────────
class OutputManager:
    def __init__(self, domain: str, base_dir: str = "output"):
        self.domain = domain
        self.dir = Path(base_dir) / domain
        self.dir.mkdir(parents=True, exist_ok=True)
        self.raw_file = self.dir / "raw.txt"
        self.resolved_file = self.dir / "resolved.txt"
        self.final_file = self.dir / "final.txt"
        self.live_file = self.dir / "live.txt"
        self.json_file = self.dir / "results.json"
        self.log_file = self.dir / "warren.log"
        self._logger = logging.getLogger(f"warren.{domain}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        if not self._logger.handlers:
            try:
                fh = logging.FileHandler(self.log_file, encoding="utf-8")
                fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
                self._logger.addHandler(fh)
            except Exception:
                pass

    def _write(self, path: Path, data: set):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(("\n".join(sorted(data)) + "\n") if data else "")
        except Exception as e:
            self.log(f"write failed for {path}: {e}")

    def write_raw(self, s: set):      self._write(self.raw_file, s)
    def write_resolved(self, s: set): self._write(self.resolved_file, s)
    def write_final(self, s: set):    self._write(self.final_file, s)

    def write_live(self, records: list):
        try:
            with open(self.live_file, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(f"{r.get('url','')}\t{r.get('status','')}\t{r.get('title','')}\n")
        except Exception as e:
            self.log(f"live write failed: {e}")

    def log(self, msg: str):
        try:
            self._logger.info(msg)
        except Exception:
            pass


# ─── Normalization ───────────────────────────────────────────────────────────
_LABEL = r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,}}$", re.IGNORECASE)


def normalize(host: str, base: str) -> Optional[str]:
    if not host:
        return None
    d = host.strip().lower().strip(".")
    if "//" in d:
        d = d.split("//", 1)[1]
    d = d.lstrip("*.")
    d = d.split("/")[0].split("?")[0]
    d = d.split(":")[0]
    d = d.split("@")[-1]
    if not d or len(d) > 253 or not _DOMAIN_RE.match(d):
        return None
    if d != base and not d.endswith("." + base):
        return None
    return d


def normalize_set(raw: set, base: str) -> set:
    out = set()
    for d in raw:
        try:
            n = normalize(d, base)
            if n:
                out.add(n)
        except Exception:
            continue
    return out


def extract_hosts(text: str, base: str) -> set:
    if not text:
        return set()
    try:
        pat = re.compile(r"([a-z0-9_\-\.\*]+\." + re.escape(base) + r")", re.IGNORECASE)
        return set(pat.findall(text))
    except Exception:
        return set()


# ─── External CLI helpers ────────────────────────────────────────────────────
def available(tool: str) -> bool:
    try:
        return shutil.which(tool) is not None
    except Exception:
        return False


def run_cmd(cmd: list, timeout: int = 300, env: dict = None) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def parse_lines(text: str) -> set:
    return {l.strip() for l in (text or "").splitlines() if l.strip()}


def write_tmp(lines, prefix="warren_"):
    try:
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(lines)) + "\n")
        return path
    except Exception:
        return None


# ─── Passive CLI modules ─────────────────────────────────────────────────────
def _cli_source(name, bin_name, cmd, cfg, out, env=None, key=None, key_name=None) -> set:
    if not available(bin_name):
        tag_warn(f"{name}: not installed, skipping")
        return set()
    if key_name and not key:
        tag_warn(f"{name}: {key_name} not set, skipping")
        return set()
    tag_run(name)
    try:
        rc, stdout, stderr = run_cmd(cmd, cfg.get("tool_timeout", 300), env)
        if rc == -2:
            tag_warn(f"{name}: binary vanished, skipping")
            return set()
        if rc != 0:
            out.log(f"{name} rc={rc} stderr={stderr.strip()[:500]}")
            if rc == -1:
                tag_warn(f"{name}: timed out")
        results = parse_lines(stdout)
        tag_found(len(results), name)
        return results
    except Exception as e:
        out.log(f"{name} crashed: {e}")
        tag_err(f"{name}: {e}")
        return set()


def mod_subfinder(domain, cfg, out):
    return _cli_source("subfinder", "subfinder",
                       ["subfinder", "-d", domain, "-silent", "-all"], cfg, out)

def mod_amass(domain, cfg, out):
    return _cli_source("amass", "amass",
                       ["amass", "enum", "-passive", "-d", domain, "-silent"], cfg, out)

def mod_assetfinder(domain, cfg, out):
    return _cli_source("assetfinder", "assetfinder",
                       ["assetfinder", "--subs-only", domain], cfg, out)

def mod_findomain(domain, cfg, out):
    return _cli_source("findomain", "findomain",
                       ["findomain", "-t", domain, "-q"], cfg, out)

def mod_chaos(domain, cfg, out):
    key = cfg.get("chaos", "")
    return _cli_source("chaos", "chaos",
                       ["chaos", "-d", domain, "-silent"], cfg, out,
                       env={"CHAOS_KEY": key} if key else None,
                       key=key, key_name="chaos key")

def mod_github(domain, cfg, out):
    tok = cfg.get("github_token", "")
    return _cli_source("github-subdomains", "github-subdomains",
                       ["github-subdomains", "-d", domain, "-t", tok], cfg, out,
                       key=tok, key_name="github_token")

def mod_gitlab(domain, cfg, out):
    tok = cfg.get("gitlab_token", "")
    return _cli_source("gitlab-subdomains", "gitlab-subdomains",
                       ["gitlab-subdomains", "-d", domain, "-t", tok], cfg, out,
                       key=tok, key_name="gitlab_token")


PASSIVE_MODULES = [mod_subfinder, mod_amass, mod_assetfinder, mod_findomain,
                   mod_chaos, mod_github, mod_gitlab]


def collect_passive_results(domain, cfg, out) -> set:
    all_results = set()
    workers = max(1, len(PASSIVE_MODULES))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fn, domain, cfg, out): fn.__name__
                       for fn in PASSIVE_MODULES}
            for fut in as_completed(futures):
                try:
                    all_results.update(fut.result())
                except Exception as e:
                    out.log(f"{futures[fut]} future error: {e}")
                    tag_err(f"{futures[fut]}: {e}")
    except Exception as e:
        out.log(f"passive pool error: {e}")
        tag_err(f"passive phase: {e}")
    return all_results


# ─── HTTP layer ──────────────────────────────────────────────────────────────
async def fetch(sess, method, url, *, retries=3, timeout=30, **kw):
    last_exc = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            async with sess.request(
                method, url, timeout=aiohttp.ClientTimeout(total=timeout), **kw
            ) as r:
                body = await r.text()
                if r.status in (429, 502, 503, 504) and attempt < retries:
                    await asyncio.sleep(min(2 ** attempt, 10))
                    continue
                return r.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_exc = e
            await asyncio.sleep(min(2 ** attempt, 8))
        except Exception as e:
            last_exc = e
            break
    return None, (f"__exc__:{last_exc}" if last_exc else None)


def jloads(body):
    if not body or body.startswith("__exc__:"):
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


# ─── API source modules ──────────────────────────────────────────────────────
async def api_crtsh(domain, cfg, sess, out):
    tag_run("crt.sh")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET", f"https://crt.sh/?q=%.{domain}&output=json",
            retries=4, timeout=60)
        data = jloads(body)
        if data:
            for entry in data:
                nv = entry.get("name_value", "") if isinstance(entry, dict) else ""
                for name in nv.split("\n"):
                    results.update(extract_hosts(name, domain))
        elif status not in (200, None):
            out.log(f"crt.sh HTTP {status}")
        tag_found(len(results), "crt.sh")
    except Exception as e:
        out.log(f"crt.sh: {e}"); tag_err(f"crt.sh: {e}")
    return results


async def api_hackertarget(domain, cfg, sess, out):
    tag_run("HackerTarget")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET", f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if body and not body.startswith("__exc__:"):
            low = body.lower()[:60]
            if "api count exceeded" in low or "error" in low:
                out.log(f"HackerTarget throttled: {body.strip()[:120]}")
            else:
                for line in body.splitlines():
                    results.update(extract_hosts(line.split(",")[0], domain))
        tag_found(len(results), "HackerTarget")
    except Exception as e:
        out.log(f"HackerTarget: {e}"); tag_err(f"HackerTarget: {e}")
    return results


async def api_securitytrails(domain, cfg, sess, out):
    key = cfg.get("securitytrails", "")
    if not key:
        return set()
    tag_run("SecurityTrails")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET",
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": key})
        data = jloads(body)
        if data and isinstance(data, dict):
            for s in data.get("subdomains", []):
                results.add(f"{s}.{domain}")
        elif status and status != 200:
            out.log(f"SecurityTrails HTTP {status}")
            tag_warn(f"SecurityTrails: HTTP {status}")
        results = {h for h in results if normalize(h, domain)}
        tag_found(len(results), "SecurityTrails")
    except Exception as e:
        out.log(f"SecurityTrails: {e}"); tag_err(f"SecurityTrails: {e}")
    return results


async def api_virustotal(domain, cfg, sess, out):
    key = cfg.get("virustotal", "")
    if not key:
        return set()
    tag_run("VirusTotal")
    results = set()
    headers = {"x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    cursor, pages = None, 0
    try:
        while pages < 25:
            params = {"limit": 40}
            if cursor:
                params["cursor"] = cursor
            status, body = await fetch(sess, "GET", url, headers=headers,
                                       params=params, retries=4)
            if status == 401:
                tag_warn("VirusTotal: invalid API key"); break
            data = jloads(body)
            if not data:
                if status and status != 200:
                    out.log(f"VirusTotal HTTP {status}")
                break
            for item in data.get("data", []):
                if isinstance(item, dict) and item.get("id"):
                    results.add(item["id"])
            cursor = (data.get("meta") or {}).get("cursor")
            pages += 1
            if not cursor:
                break
            await asyncio.sleep(cfg.get("rate_limit_delay", 1))
        tag_found(len(results), "VirusTotal")
    except Exception as e:
        out.log(f"VirusTotal: {e}"); tag_err(f"VirusTotal: {e}")
    return results


async def api_shodan(domain, cfg, sess, out):
    key = cfg.get("shodan", "")
    if not key:
        return set()
    tag_run("Shodan")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET", f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": key})
        data = jloads(body)
        if data and isinstance(data, dict):
            for sub in data.get("subdomains", []):
                results.add(f"{sub}.{domain}")
        elif status and status != 200:
            out.log(f"Shodan HTTP {status}")
        tag_found(len(results), "Shodan")
    except Exception as e:
        out.log(f"Shodan: {e}"); tag_err(f"Shodan: {e}")
    return results


async def api_binaryedge(domain, cfg, sess, out):
    key = cfg.get("binaryedge", "")
    if not key:
        return set()
    tag_run("BinaryEdge")
    results = set()
    headers = {"X-Key": key}
    url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
    try:
        page = 1
        while page <= 10:
            status, body = await fetch(sess, "GET", url, headers=headers,
                                       params={"page": page})
            data = jloads(body)
            if not data:
                if status and status != 200:
                    out.log(f"BinaryEdge HTTP {status}")
                break
            events = data.get("events", []) or []
            if not events:
                break
            results.update(events)
            total = data.get("total", 0) or 0
            pagesize = data.get("pagesize", 100) or 100
            if page >= max(1, (total // pagesize) + 1):
                break
            page += 1
            await asyncio.sleep(cfg.get("rate_limit_delay", 1))
        tag_found(len(results), "BinaryEdge")
    except Exception as e:
        out.log(f"BinaryEdge: {e}"); tag_err(f"BinaryEdge: {e}")
    return results


async def api_censys(domain, cfg, sess, out):
    uid, secret = cfg.get("censys_id", ""), cfg.get("censys_secret", "")
    if not uid or not secret:
        return set()
    tag_run("Censys")
    results = set()
    try:
        creds = base64.b64encode(f"{uid}:{secret}".encode()).decode()
        headers = {"Authorization": f"Basic {creds}",
                   "Content-Type": "application/json"}
        payload = {"q": f"parsed.names: {domain}", "per_page": 100,
                   "fields": ["parsed.names"]}
        status, body = await fetch(
            sess, "POST", "https://search.censys.io/api/v2/certificates/search",
            headers=headers, json=payload)
        data = jloads(body)
        if data and isinstance(data, dict):
            hits = (data.get("result") or {}).get("hits", [])
            for hit in hits:
                for name in (hit.get("parsed.names") or []):
                    results.update(extract_hosts(name, domain))
        elif status and status != 200:
            out.log(f"Censys HTTP {status}"); tag_warn(f"Censys: HTTP {status}")
        tag_found(len(results), "Censys")
    except Exception as e:
        out.log(f"Censys: {e}"); tag_err(f"Censys: {e}")
    return results


async def api_zoomeye(domain, cfg, sess, out):
    key = cfg.get("zoomeye", "")
    if not key:
        return set()
    tag_run("ZoomEye")
    results = set()
    try:
        headers = {"API-KEY": key, "Content-Type": "application/json"}
        qb = base64.b64encode(f'domain="{domain}"'.encode()).decode()
        for page in range(1, 6):
            status, body = await fetch(
                sess, "POST", "https://api.zoomeye.ai/v2/search",
                headers=headers, json={"qbase64": qb, "page": page})
            if status in (401, 403):
                tag_warn("ZoomEye: auth failed (check API-KEY)"); break
            data = jloads(body)
            if not data or not isinstance(data, dict):
                if status and status != 200:
                    out.log(f"ZoomEye HTTP {status}")
                break
            rows = data.get("data", []) or []
            if not rows:
                break
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for cand in (row.get("domain"),
                             (row.get("current") or {}).get("domain")):
                    results.update(extract_hosts(cand or "", domain))
            await asyncio.sleep(cfg.get("rate_limit_delay", 1))
        tag_found(len(results), "ZoomEye")
    except Exception as e:
        out.log(f"ZoomEye: {e}"); tag_err(f"ZoomEye: {e}")
    return results


async def api_otx(domain, cfg, sess, out):
    tag_run("AlienVault OTX")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        data = jloads(body)
        if data and isinstance(data, dict):
            for rec in data.get("passive_dns", []) or []:
                results.update(extract_hosts(rec.get("hostname", ""), domain))
        tag_found(len(results), "AlienVault OTX")
    except Exception as e:
        out.log(f"OTX: {e}"); tag_err(f"OTX: {e}")
    return results


async def api_anubis(domain, cfg, sess, out):
    tag_run("Anubis (jldc)")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET", f"https://jldc.me/anubis/subdomains/{domain}")
        data = jloads(body)
        if data and isinstance(data, list):
            for h in data:
                results.update(extract_hosts(h, domain))
        tag_found(len(results), "Anubis (jldc)")
    except Exception as e:
        out.log(f"Anubis: {e}"); tag_err(f"Anubis: {e}")
    return results


async def api_rapiddns(domain, cfg, sess, out):
    tag_run("RapidDNS")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET", f"https://rapiddns.io/subdomain/{domain}?full=1")
        if body and not body.startswith("__exc__:"):
            results.update(extract_hosts(body, domain))
        tag_found(len(results), "RapidDNS")
    except Exception as e:
        out.log(f"RapidDNS: {e}"); tag_err(f"RapidDNS: {e}")
    return results


async def api_wayback(domain, cfg, sess, out):
    tag_run("Wayback Machine")
    results = set()
    try:
        status, body = await fetch(
            sess, "GET",
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
            f"&output=text&fl=original&collapse=urlkey&limit=50000",
            timeout=45)
        if body and not body.startswith("__exc__:"):
            results.update(extract_hosts(body, domain))
        tag_found(len(results), "Wayback Machine")
    except Exception as e:
        out.log(f"Wayback: {e}"); tag_err(f"Wayback: {e}")
    return results


async def api_urlscan(domain, cfg, sess, out):
    tag_run("urlscan.io")
    results = set()
    headers = {}
    if cfg.get("urlscan"):
        headers["API-Key"] = cfg["urlscan"]
    try:
        status, body = await fetch(
            sess, "GET",
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
            headers=headers)
        data = jloads(body)
        if data and isinstance(data, dict):
            for r in data.get("results", []) or []:
                page = (r.get("page") or {})
                results.update(extract_hosts(page.get("domain", ""), domain))
        tag_found(len(results), "urlscan.io")
    except Exception as e:
        out.log(f"urlscan: {e}"); tag_err(f"urlscan: {e}")
    return results


API_MODULES = [
    api_crtsh, api_hackertarget, api_securitytrails, api_virustotal,
    api_shodan, api_binaryedge, api_censys, api_zoomeye,
    api_otx, api_anubis, api_rapiddns, api_wayback, api_urlscan,
]
RECURSIVE_SOURCES = [api_crtsh, api_anubis, api_otx]


async def collect_api_results(domain, cfg, out) -> set:
    all_results = set()
    connector = aiohttp.TCPConnector(limit=20, ssl=False, ttl_dns_cache=300)
    headers = {"User-Agent": "warren/3.1 (+security-research)"}
    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as sess:
            tasks = [m(domain, cfg, sess, out) for m in API_MODULES]
            done = await asyncio.gather(*tasks, return_exceptions=True)
            for idx, r in enumerate(done):
                if isinstance(r, set):
                    all_results.update(r)
                elif isinstance(r, Exception):
                    out.log(f"{API_MODULES[idx].__name__} raised: {r}")
    except Exception as e:
        out.log(f"api session error: {e}"); tag_err(f"API phase: {e}")
    return all_results


async def recursive_enum(base, parents, cfg, out, limit) -> set:
    found = set()
    targets = sorted(p for p in parents if p != base)[:max(0, limit)]
    if not targets:
        return found
    tag_info(f"Recursive expansion on {C.BOLD}{len(targets)}{C.RESET} subdomains")
    connector = aiohttp.TCPConnector(limit=15, ssl=False, ttl_dns_cache=300)
    headers = {"User-Agent": "warren/3.1 (+security-research)"}
    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as sess:
            for sub in targets:
                tasks = [m(sub, cfg, sess, out) for m in RECURSIVE_SOURCES]
                done = await asyncio.gather(*tasks, return_exceptions=True)
                for r in done:
                    if isinstance(r, set):
                        found.update(normalize_set(r, base))
    except Exception as e:
        out.log(f"recursive error: {e}"); tag_err(f"Recursive: {e}")
    return found


# ─── Permutation generation ──────────────────────────────────────────────────
PERM_WORDS = [
    "dev", "development", "staging", "stage", "stg", "test", "testing", "qa",
    "uat", "preprod", "prod", "production", "admin", "api", "api2", "app",
    "apps", "portal", "internal", "intranet", "corp", "vpn", "gw", "gateway",
    "beta", "alpha", "demo", "new", "old", "legacy", "backup", "bak", "db",
    "database", "ftp", "sftp", "git", "gitlab", "jenkins", "ci", "cd", "build",
    "cdn", "static", "assets", "media", "img", "secure", "login", "auth", "sso",
    "dashboard", "monitor", "monitoring", "grafana", "kibana", "metrics",
    "status", "mail", "smtp", "webmail", "ns", "ns1", "ns2", "mx", "remote",
    "cloud", "k8s", "docker", "registry", "proxy", "edge", "lb", "node",
]


def generate_permutations_builtin(known, base, words, cap) -> set:
    labels = set()
    for h in known:
        if h == base or not h.endswith("." + base):
            continue
        prefix = h[:-(len(base) + 1)]
        if not prefix:
            continue
        labels.add(prefix)
        for part in prefix.split("."):
            if part:
                labels.add(part)
    out = set()
    for lab in sorted(labels):
        for w in words:
            for cand in (f"{w}-{lab}", f"{lab}-{w}", f"{w}.{lab}",
                         f"{lab}.{w}", f"{w}{lab}", f"{lab}{w}"):
                out.add(f"{cand}.{base}")
                if len(out) >= cap:
                    return out
        for n in range(1, 6):
            for cand in (f"{lab}{n}", f"{lab}-{n}", f"{lab}0{n}"):
                out.add(f"{cand}.{base}")
                if len(out) >= cap:
                    return out
    return out


def generate_permutations(known, base, cfg, out) -> Tuple[set, str]:
    cap = int(cfg.get("permutation_cap", 50000))
    hosts_file = write_tmp(known, "warren_hosts_")
    words_file = write_tmp(PERM_WORDS, "warren_words_")
    try:
        if available("alterx") and hosts_file:
            rc, o, e = run_cmd(["alterx", "-l", hosts_file, "-silent"],
                               cfg.get("tool_timeout", 300))
            if rc == 0:
                return set(list(parse_lines(o))[:cap]), "alterx"
            out.log(f"alterx rc={rc} {e.strip()[:300]}")
        if available("gotator") and hosts_file and words_file:
            rc, o, e = run_cmd(
                ["gotator", "-sub", hosts_file, "-perm", words_file,
                 "-depth", "1", "-numbers", "3", "-silent"],
                cfg.get("tool_timeout", 300))
            if rc == 0:
                return set(list(parse_lines(o))[:cap]), "gotator"
            out.log(f"gotator rc={rc} {e.strip()[:300]}")
        if available("dnsgen") and hosts_file:
            rc, o, e = run_cmd(["dnsgen", hosts_file], cfg.get("tool_timeout", 300))
            if rc == 0:
                return set(list(parse_lines(o))[:cap]), "dnsgen"
            out.log(f"dnsgen rc={rc} {e.strip()[:300]}")
        return generate_permutations_builtin(known, base, PERM_WORDS, cap), "built-in"
    except Exception as e:
        out.log(f"permutation gen crashed: {e}")
        tag_err(f"permutation gen: {e}")
        return set(), "error"
    finally:
        for p in (hosts_file, words_file):
            try:
                if p and os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass


# ─── Active resolution / brute-force ─────────────────────────────────────────
DEFAULT_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "77.88.8.8", "74.82.42.42", "76.76.2.0",
]


def ensure_resolvers(path: str) -> str:
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_RESOLVERS) + "\n")
        return path
    except Exception:
        alt = os.path.join("/tmp", "warren_resolvers_fallback.txt")
        try:
            with open(alt, "w", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_RESOLVERS) + "\n")
        except Exception:
            pass
        return alt


def run_puredns(domain, wordlist, resolvers, output_file, cfg, out) -> set:
    if not available("puredns"):
        tag_warn("puredns: not installed, skipping active brute-force")
        return set()
    if not os.path.exists(wordlist):
        tag_warn(f"puredns: wordlist not found ({wordlist}), skipping")
        return set()
    tag_run("puredns (active brute-force)")
    try:
        rc, o, e = run_cmd(
            ["puredns", "bruteforce", wordlist, domain,
             "-r", resolvers, "-w", output_file, "--quiet"],
            cfg.get("tool_timeout", 300) * 3)
        if rc != 0:
            out.log(f"puredns rc={rc} stderr={e.strip()[:500]}")
            if rc != -2:
                tag_warn(f"puredns exited rc={rc}")
        results = set()
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                results = {l.strip() for l in f if l.strip()}
        tag_found(len(results), "puredns (brute)")
        return results
    except Exception as e:
        out.log(f"puredns crashed: {e}"); tag_err(f"puredns: {e}")
        return set()


def puredns_resolve(hosts, resolvers, output_file, cfg, out) -> Optional[set]:
    if not available("puredns") or not hosts:
        return None
    hosts_file = write_tmp(hosts, "warren_perm_")
    if not hosts_file:
        return None
    tag_run("puredns (resolve candidates)")
    try:
        rc, o, e = run_cmd(
            ["puredns", "resolve", hosts_file, "-r", resolvers,
             "-w", output_file, "--quiet"],
            cfg.get("tool_timeout", 300) * 2)
        if rc != 0:
            out.log(f"puredns resolve rc={rc} stderr={e.strip()[:500]}")
        results = set()
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                results = {l.strip() for l in f if l.strip()}
        return results
    except Exception as e:
        out.log(f"puredns resolve crashed: {e}")
        return set()
    finally:
        try:
            if os.path.exists(hosts_file):
                os.remove(hosts_file)
        except Exception:
            pass


def run_dnsx(input_file, output_file, cfg, out) -> set:
    if not available("dnsx"):
        return set()
    tag_run("dnsx (resolution)")
    try:
        rc, o, e = run_cmd(
            ["dnsx", "-l", input_file, "-silent", "-o", output_file,
             "-t", "100", "-retry", "3"],
            cfg.get("tool_timeout", 300) * 2)
        if rc != 0:
            out.log(f"dnsx rc={rc} stderr={e.strip()[:500]}")
        results = set()
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                results = {l.strip() for l in f if l.strip()}
        if results:
            tag_ok(f"dnsx resolved {C.BOLD}{len(results)}{C.RESET} subdomains")
        return results
    except Exception as e:
        out.log(f"dnsx crashed: {e}"); tag_err(f"dnsx: {e}")
        return set()


def run_tlsx(hosts, cfg, out) -> set:
    if not available("tlsx") or not hosts:
        return set()
    hosts_file = write_tmp(hosts, "warren_tlsx_")
    if not hosts_file:
        return set()
    tag_run("tlsx (cert SAN enrichment)")
    try:
        rc, o, e = run_cmd(
            ["tlsx", "-l", hosts_file, "-san", "-silent", "-resp-only"],
            cfg.get("tool_timeout", 300))
        if rc != 0:
            out.log(f"tlsx rc={rc} stderr={e.strip()[:300]}")
        return parse_lines(o)
    except Exception as e:
        out.log(f"tlsx crashed: {e}"); tag_err(f"tlsx: {e}")
        return set()
    finally:
        try:
            if os.path.exists(hosts_file):
                os.remove(hosts_file)
        except Exception:
            pass


# ─── Built-in async resolver (fallback) ──────────────────────────────────────
def _sync_resolve(host):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return host, frozenset(i[4][0] for i in infos)
    except Exception:
        return host, None


async def get_wildcard_ips(domain, samples=3) -> set:
    probes = ["".join(random.choices(string.ascii_lowercase + string.digits, k=20))
              + f".{domain}" for _ in range(samples)]
    loop = asyncio.get_event_loop()
    ex = ThreadPoolExecutor(max_workers=max(2, samples))
    ips = set()
    try:
        tasks = [loop.run_in_executor(ex, _sync_resolve, p) for p in probes]
        for fut in asyncio.as_completed(tasks):
            _, got = await fut
            if got:
                ips |= set(got)
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    return ips


async def resolve_hosts(hosts, concurrency=100, wildcard_ips=None) -> set:
    if not hosts:
        return set()
    loop = asyncio.get_event_loop()
    ex = ThreadPoolExecutor(max_workers=max(8, min(int(concurrency), 256)))
    out = set()
    try:
        tasks = [loop.run_in_executor(ex, _sync_resolve, h) for h in hosts]
        for fut in asyncio.as_completed(tasks):
            try:
                host, ips = await fut
            except Exception:
                continue
            if ips:
                if wildcard_ips and ips <= wildcard_ips:
                    continue
                out.add(host)
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False)
    return out


# ─── Built-in live-host prober (fallback for httpx) ──────────────────────────
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def _probe_one(sess, sem, host, timeout):
    async with sem:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                async with sess.get(
                    url, timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True, ssl=False
                ) as r:
                    title = ""
                    try:
                        chunk = await r.content.read(8192)
                        m = _TITLE_RE.search(chunk.decode("utf-8", "ignore"))
                        if m:
                            title = " ".join(m.group(1).split())[:120]
                    except Exception:
                        pass
                    return {"input": host, "url": str(r.url),
                            "status": r.status, "title": title}
            except Exception:
                continue
        return None


async def probe_builtin(hosts, concurrency, timeout) -> list:
    if not hosts:
        return []
    sem = asyncio.Semaphore(max(1, concurrency))
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    records = []
    try:
        async with aiohttp.ClientSession(
            connector=connector, headers={"User-Agent": "warren/3.1"}
        ) as sess:
            tasks = [_probe_one(sess, sem, h, timeout) for h in hosts]
            for fut in asyncio.as_completed(tasks):
                try:
                    r = await fut
                    if r:
                        records.append(r)
                except Exception:
                    continue
    except Exception:
        pass
    return records


def probe_httpx(hosts, output_json, cfg, out) -> Optional[list]:
    if not available("httpx") or not hosts:
        return None
    hosts_file = write_tmp(hosts, "warren_httpx_")
    if not hosts_file:
        return None
    tag_run("httpx (live-host probing)")
    try:
        rc, o, e = run_cmd(
            ["httpx", "-l", hosts_file, "-silent", "-json",
             "-status-code", "-title", "-tech-detect", "-o", output_json],
            cfg.get("tool_timeout", 300) * 2)
        if rc != 0:
            out.log(f"httpx rc={rc} stderr={e.strip()[:300]}")
        records = []
        if os.path.exists(output_json):
            with open(output_json, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    d = jloads(line.strip())
                    if d:
                        records.append({
                            "input": d.get("input", ""),
                            "url": d.get("url", ""),
                            "status": d.get("status_code", d.get("status-code", "")),
                            "title": d.get("title", ""),
                            "tech": d.get("tech", d.get("technologies", [])),
                        })
        return records
    except Exception as e:
        out.log(f"httpx crashed: {e}"); tag_err(f"httpx: {e}")
        return []
    finally:
        try:
            if os.path.exists(hosts_file):
                os.remove(hosts_file)
        except Exception:
            pass


async def detect_wildcard(domain: str) -> bool:
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    loop = asyncio.get_event_loop()
    try:
        await loop.getaddrinfo(f"{rand}.{domain}", None, proto=socket.IPPROTO_TCP)
        return True
    except Exception:
        return False


# ─── Orchestration ───────────────────────────────────────────────────────────
async def enumerate_domain(domain: str, cfg: dict, args) -> set:
    t0 = time.time()
    out = OutputManager(domain)
    sep = f"{C.CYAN}{'\u2501' * 62}{C.RESET}"
    print(f"\n{sep}")
    tag_info(f"Target : {C.BOLD}{C.WHITE}{domain}{C.RESET}")
    tag_info(f"Output : {C.DIM}{out.dir}{C.RESET}")
    print(sep + "\n")

    all_raw: Set[str] = set()
    stats = {"permute": 0, "recursive": 0, "tls": 0, "live": 0}

    # Phase 1 — Passive CLI
    if not args.no_passive:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 1]{C.RESET} Passive Tool Enumeration\n")
        try:
            passive = collect_passive_results(domain, cfg, out)
            all_raw.update(passive)
            tag_ok(f"Passive tools: {C.BOLD}{len(passive)}{C.RESET} raw results")
        except Exception as e:
            out.log(f"phase1: {e}"); tag_err(f"Phase 1: {e}")

    # Phase 2 — API sources
    if not args.no_api:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 2]{C.RESET} API-Based Enumeration\n")
        try:
            api_res = await collect_api_results(domain, cfg, out)
            all_raw.update(api_res)
            tag_ok(f"API sources: {C.BOLD}{len(api_res)}{C.RESET} raw results")
        except Exception as e:
            out.log(f"phase2: {e}"); tag_err(f"Phase 2: {e}")

    # Phase 3 — Normalize & dedupe
    print(f"\n{C.YELLOW}{C.BOLD}[PHASE 3]{C.RESET} Normalization & Deduplication\n")
    normalized = normalize_set(all_raw, domain)
    tag_ok(f"Unique after normalization: {C.BOLD}{len(normalized)}{C.RESET}")
    out.write_raw(normalized)

    # Phase 4 — Recursive (optional)
    if args.recursive and normalized:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 4]{C.RESET} Recursive Enumeration\n")
        try:
            rec = await recursive_enum(domain, normalized, cfg, out,
                                       int(cfg.get("recursive_limit", 25)))
            before = len(normalized)
            normalized.update(rec)
            stats["recursive"] = len(normalized) - before
            tag_ok(f"Recursion added {C.BOLD}{stats['recursive']}{C.RESET} new subdomains")
            out.write_raw(normalized)
        except Exception as e:
            out.log(f"phase4: {e}"); tag_err(f"Phase 4: {e}")

    # Phase 5 — Active brute-force
    resolvers = ensure_resolvers(cfg.get("resolvers_file", "/tmp/warren_resolvers.txt"))
    if not args.no_brute:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 5]{C.RESET} Active DNS Brute-Force\n")
        try:
            brute_out = str(out.dir / "brute_raw.txt")
            brute = run_puredns(domain, cfg.get("wordlist", ""),
                                resolvers, brute_out, cfg, out)
            before = len(normalized)
            normalized.update(normalize_set(brute, domain))
            tag_ok(f"Brute-force added {C.BOLD}{len(normalized) - before}{C.RESET} new subdomains")
            out.write_raw(normalized)
        except Exception as e:
            out.log(f"phase5: {e}"); tag_err(f"Phase 5: {e}")

    # Wildcard sampling (used by the built-in resolver path)
    wildcard_ips = set()
    try:
        wildcard_ips = await get_wildcard_ips(domain)
        if wildcard_ips:
            tag_warn(f"Wildcard DNS detected ({len(wildcard_ips)} IP(s)) "
                     f"\u2014 filtering matching responses")
    except Exception as e:
        out.log(f"wildcard sample: {e}")

    # Phase 6 — Resolution
    resolved: Set[str] = set()
    method = "skipped"
    if not args.no_resolve:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 6]{C.RESET} DNS Resolution\n")
        try:
            resolved = run_dnsx(str(out.raw_file), str(out.resolved_file), cfg, out)
            if resolved:
                method = "dnsx"
            else:
                tag_info("dnsx unavailable \u2014 using built-in async resolver")
                resolved = await resolve_hosts(
                    normalized, cfg.get("resolve_concurrency", 100), wildcard_ips)
                method = "builtin"
                tag_ok(f"Resolved {C.BOLD}{len(resolved)}{C.RESET} / {len(normalized)} hosts")
            out.write_resolved(resolved)
        except Exception as e:
            out.log(f"phase6: {e}"); tag_err(f"Phase 6: {e}")
        if not resolved:
            tag_warn("Resolution produced 0 \u2014 keeping normalized set (unresolved)")
            resolved = set(normalized); method = "unresolved-fallback"
            out.write_resolved(resolved)
    else:
        resolved = set(normalized)
        out.write_resolved(resolved)

    # Phase 7 — Permutation generation + resolution
    if not args.no_permute and resolved:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 7]{C.RESET} Permutation / Alteration\n")
        try:
            cands, gen = generate_permutations(resolved, domain, cfg, out)
            cands = normalize_set(cands, domain) - resolved
            tag_info(f"Generated {C.BOLD}{len(cands)}{C.RESET} candidates via {gen}")
            new_resolved = set()
            if cands:
                perm_out = str(out.dir / "perm_resolved.txt")
                pr = puredns_resolve(cands, resolvers, perm_out, cfg, out)
                if pr is not None:
                    new_resolved = normalize_set(pr, domain)
                else:
                    cap = int(cfg.get("permutation_builtin_resolve_cap", 8000))
                    if len(cands) > cap:
                        tag_warn(f"No puredns \u2014 capping built-in resolve to {cap}")
                        cands = set(list(cands)[:cap])
                    new_resolved = await resolve_hosts(
                        cands, cfg.get("resolve_concurrency", 100), wildcard_ips)
            new_resolved -= resolved
            stats["permute"] = len(new_resolved)
            resolved.update(new_resolved)
            normalized.update(new_resolved)
            tag_ok(f"Permutation added {C.BOLD}{len(new_resolved)}{C.RESET} new live subdomains")
            out.write_resolved(resolved)
        except Exception as e:
            out.log(f"phase7: {e}"); tag_err(f"Phase 7: {e}")

    # Phase 8 — TLS SAN enrichment (best-effort, needs tlsx)
    if not args.no_tls and resolved and available("tlsx"):
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 8]{C.RESET} TLS Certificate SAN Enrichment\n")
        try:
            sans = run_tlsx(resolved, cfg, out)
            collected = set()
            for s in sans:
                collected |= extract_hosts(s, domain)
            new_names = normalize_set(collected, domain) - normalized
            if new_names:
                add = await resolve_hosts(
                    new_names, cfg.get("resolve_concurrency", 100), wildcard_ips)
                stats["tls"] = len(add)
                resolved.update(add)
                normalized.update(add)
                out.write_resolved(resolved)
            tag_ok(f"TLS SANs added {C.BOLD}{stats['tls']}{C.RESET} new live subdomains")
        except Exception as e:
            out.log(f"phase8: {e}"); tag_err(f"Phase 8: {e}")

    out.write_final(resolved)

    # Phase 9 — Live-host probing
    live_records = []
    if not args.no_probe and resolved:
        print(f"\n{C.YELLOW}{C.BOLD}[PHASE 9]{C.RESET} Live-Host Probing\n")
        try:
            httpx_json = str(out.dir / "httpx.json")
            live_records = probe_httpx(resolved, httpx_json, cfg, out)
            if live_records is None:
                tag_info("httpx unavailable \u2014 using built-in HTTP prober")
                live_records = await probe_builtin(
                    resolved, cfg.get("probe_concurrency", 50),
                    cfg.get("probe_timeout", 8))
            stats["live"] = len(live_records)
            out.write_live(live_records)
            tag_ok(f"Live hosts: {C.BOLD}{stats['live']}{C.RESET} / {len(resolved)} responded")
        except Exception as e:
            out.log(f"phase9: {e}"); tag_err(f"Phase 9: {e}")

    elapsed = time.time() - t0
    out.log(f"complete raw={len(all_raw)} norm={len(normalized)} "
            f"resolved={len(resolved)} live={stats['live']} method={method} "
            f"perm+{stats['permute']} rec+{stats['recursive']} tls+{stats['tls']} "
            f"time={elapsed:.1f}s")

    # Summary
    bar = f"{C.GREEN}{'\u2501' * 62}{C.RESET}"
    print(f"\n{bar}")
    print(f"{C.GREEN}{C.BOLD}  RESULTS \u2014 {domain}{C.RESET}")
    print(bar)
    print(f"  {C.CYAN}Raw Collected   {C.RESET}: {len(all_raw)}")
    print(f"  {C.CYAN}Unique/Normed   {C.RESET}: {len(normalized)}")
    print(f"  {C.CYAN}DNS Resolved    {C.RESET}: {C.BOLD}{len(resolved)}{C.RESET}  ({method})")
    print(f"  {C.CYAN}  \u2514 recursion   {C.RESET}: +{stats['recursive']}")
    print(f"  {C.CYAN}  \u2514 permutation {C.RESET}: +{stats['permute']}")
    print(f"  {C.CYAN}  \u2514 tls SANs    {C.RESET}: +{stats['tls']}")
    print(f"  {C.CYAN}Live Hosts      {C.RESET}: {stats['live']}")
    print(f"  {C.CYAN}Time Elapsed    {C.RESET}: {elapsed:.1f}s")
    print(f"  {C.CYAN}Output Dir      {C.RESET}: {out.dir}")
    print(f"{bar}\n")

    if args.json:
        try:
            data = {
                "domain": domain,
                "raw_count": len(all_raw),
                "normalized_count": len(normalized),
                "resolved_count": len(resolved),
                "resolution_method": method,
                "added": {"recursion": stats["recursive"],
                          "permutation": stats["permute"], "tls_san": stats["tls"]},
                "live_count": stats["live"],
                "resolved": sorted(resolved),
                "live_hosts": live_records,
                "elapsed_seconds": round(elapsed, 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(out.json_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            tag_ok(f"JSON: {out.json_file}")
        except Exception as e:
            out.log(f"json: {e}"); tag_err(f"JSON output: {e}")

    if not args.silent:
        for sub in sorted(resolved):
            print(f"  {C.DIM}\u21b3{C.RESET} {sub}")

    return resolved


# ─── CLI ─────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="warren",
        description="warren \u2014 Advanced Subdomain Discovery Framework v3.1")
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-d", "--domain", help="Single target domain")
    tgt.add_argument("-l", "--list", help="File with one domain per line")
    p.add_argument("-c", "--config", default="config.yaml", help="Config YAML path")
    p.add_argument("--silent", action="store_true", help="Suppress subdomain list output")
    p.add_argument("--json", action="store_true", help="Write JSON output per domain")
    p.add_argument("--recursive", action="store_true", help="One-level recursive enumeration")
    p.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution")
    p.add_argument("--no-brute", action="store_true", help="Skip active brute-force")
    p.add_argument("--no-passive", action="store_true", help="Skip passive CLI tools")
    p.add_argument("--no-api", action="store_true", help="Skip API sources")
    p.add_argument("--no-permute", action="store_true", help="Skip permutation phase")
    p.add_argument("--no-probe", action="store_true", help="Skip live-host probing")
    p.add_argument("--no-tls", action="store_true", help="Skip tlsx SAN enrichment")
    return p


def load_targets(args) -> List[str]:
    if args.domain:
        d = args.domain.strip().lower().lstrip("*.")
        return [d] if d else []
    targets = []
    if not os.path.exists(args.list):
        tag_err(f"Target file not found: {args.list}")
        return []
    try:
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    targets.append(line.lstrip("*."))
    except Exception as e:
        tag_err(f"Could not read target list: {e}")
    return targets


async def main():
    print(BANNER)
    args = build_parser().parse_args()
    cfg = load_config(args.config)
    domains = load_targets(args)
    if not domains:
        tag_err("No valid targets provided.")
        sys.exit(1)

    tag_info(f"Loaded {C.BOLD}{len(domains)}{C.RESET} target(s)\n")

    def _sigint(sig, frame):
        print(f"\n{C.RED}[!] Interrupted \u2014 partial results saved in output/{C.RESET}")
        os._exit(0)
    try:
        signal.signal(signal.SIGINT, _sigint)
    except Exception:
        pass

    for domain in domains:
        try:
            await enumerate_domain(domain, cfg, args)
        except KeyboardInterrupt:
            print(f"\n{C.RED}[!] Interrupted{C.RESET}")
            break
        except Exception as e:
            tag_err(f"Fatal error on {domain}: {e}")
            try:
                OutputManager(domain).log(f"fatal: {e}")
            except Exception:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"{C.RED}[FATAL]{C.RESET} {e}", file=sys.stderr)
        sys.exit(1)
