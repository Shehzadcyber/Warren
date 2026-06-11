# Warren

**A resilient, multi-source subdomain discovery framework.**
Passive sources, active brute-force, permutation generation, and live-host probing in one pipeline — where any single source failing never takes down the run.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](#contributing)

---

## Why Warren?

Most enumeration scripts stop at "query a few sources and print the union." Warren goes further and, more importantly, is built so that a dead API, a missing binary, a rate-limit, or a malformed key degrades gracefully instead of crashing the scan. Every phase is isolated; every external tool has a built-in fallback.

- **13 passive API sources** — crt.sh, HackerTarget, SecurityTrails, VirusTotal, Shodan, BinaryEdge, Censys, ZoomEye, AlienVault OTX, Anubis (jldc), RapidDNS, Wayback, urlscan. Seven need no API key at all.
- **Passive CLI tools** — subfinder, amass, assetfinder, findomain, chaos, plus github-subdomains / gitlab-subdomains for code-host scraping.
- **Active brute-force** — puredns + massdns against a wordlist, with wildcard-safe resolution.
- **Permutation / alteration** — alterx → gotator → dnsgen → a built-in generator, then resolves the candidates to surface names that live in no public dataset.
- **Recursive enumeration** — optionally expands discovered subdomains one level deep.
- **Live-host probing** — httpx if installed, otherwise a built-in async HTTP prober (status code + page title).
- **Real wildcard filtering** — samples wildcard IPs and drops hosts that only resolve to them.
- **Graceful everything** — no key? skipped. tool missing? fallback. source down? logged and the run continues.

External binaries are *optional*. With none installed, Warren still runs every key-less API source, its built-in resolver, built-in permutation generator, and built-in prober.

---

## Install

```bash
git clone https://github.com/<you>/warren.git
cd warren
pip install -r requirements.txt        # aiohttp, pyyaml
```

### Optional external tools (recommended)

Warren auto-detects these on `$PATH` and uses them when present:

| Capability        | Tools                                                        |
|-------------------|-------------------------------------------------------------|
| Passive discovery | `subfinder` `amass` `assetfinder` `findomain` `chaos`       |
| Code-host scrape  | `github-subdomains` `gitlab-subdomains`                     |
| Resolution        | `dnsx` `puredns` (+ `massdns`)                              |
| Permutation       | `alterx` `gotator` `dnsgen`                                 |
| Probing / certs   | `httpx` `tlsx`                                              |

Most are from [ProjectDiscovery](https://github.com/projectdiscovery). On Kali, `seclists` provides the default wordlist.

---

## Configuration

```bash
cp config.example.yaml config.yaml
# then edit config.yaml and add whatever keys you have
```

> ⚠️ **Never commit `config.yaml`.** It holds your API keys. The included `.gitignore` already excludes it — keep it that way, and if a key has ever been pasted or pushed anywhere, rotate it.

Every key is optional. Leave blank what you don't have; those sources are simply skipped.

---

## Usage

```bash
# Single domain, full pipeline
python warren.py -d example.com

# Quiet, machine-readable output
python warren.py -d example.com --silent --json

# Add one level of recursion
python warren.py -d example.com --recursive

# Many targets
python warren.py -l domains.txt

# Passive-only (no brute-force, permutation, or probing)
python warren.py -d example.com --no-brute --no-permute --no-probe
```

### Flags

| Flag           | Effect                                  |
|----------------|-----------------------------------------|
| `-d, --domain` | Single target domain                    |
| `-l, --list`   | File with one domain per line           |
| `-c, --config` | Config path (default `config.yaml`)     |
| `--recursive`  | One-level recursive enumeration         |
| `--json`       | Write `results.json` per domain         |
| `--silent`     | Suppress the printed subdomain list     |
| `--no-passive` `--no-api` `--no-brute` `--no-permute` `--no-probe` `--no-tls` `--no-resolve` | Skip individual phases |

---

## Output

Results are written under `output/<domain>/`:

```
output/example.com/
├── raw.txt         # everything found, normalized + deduped
├── resolved.txt    # hosts that resolve in DNS
├── final.txt       # the canonical result set
├── live.txt        # responding HTTP(S) hosts  (url  status  title)
├── results.json    # full structured output (with --json)
└── warren.log      # per-source diagnostics
```

---

## Pipeline

```
Passive CLI → API sources → Normalize → Recursive(opt)
  → Brute-force → Resolve(+wildcard filter) → Permute → TLS-SAN → Probe
```

Each stage feeds the next; each is wrapped so a failure is logged and skipped rather than fatal.

---

## Legal

Warren is for **authorized security testing only** — assets you own or have explicit written permission to assess (e.g. an in-scope bug-bounty target). Unauthorized scanning may be illegal in your jurisdiction. You are solely responsible for how you use it.

---

## Contributing

Issues and PRs welcome — new sources, permutation strategies, and resolver improvements especially. Keep the resilience contract: a new source must fail closed (log + skip), never crash the run.

## License

MIT — see [LICENSE](LICENSE).
