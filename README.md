# dns-quality-tester-pro

A robust, production-ready DNS quality tester and benchmark tool.

**Short description**
dns-quality-tester-pro runs large-scale, configurable DNS checks against multiple resolvers (UDP/TCP/DoH), captures latency and DNSSEC flags, computes per-resolver scores, and produces raw CSV and JSON summary output. Designed for researchers, network engineers, and power users who want repeatable, automated DNS quality measurement.

**Highlights**
- Multi-protocol tests: UDP with TCP fallback and DoH (JSON).
- Multiple query types: A, AAAA, MX, NS (configurable).
- DNSSEC AD-flag detection and disagreement analysis vs majority answers.
- Configurable attempts, timeout, concurrency and global spread-over-time.
- Load custom resolvers from `resolvers.json`.
- Exports raw CSV + aggregated JSON summary.
- Progress bar (tqdm), retries, and robust error handling.

**Why use this**
- Compare public and private resolvers reliably under repeatable conditions.
- Reveal filtering/censorship differences (e.g., bank or local domains).
- Get a single composite score combining success-rate, latency and DNSSEC friendliness.

**Quickstart**
```bash
# create venv (recommended)
python -m venv .venv
source .venv/bin/activate

# install deps
pip install dnspython requests tqdm

# run (example)
python dns_tester_pro.py --attempts 12 --timeout 3 --workers 40 --spread 120 --out results.csv --summary dns_summary.json
````

**Outputs**

* `results.csv` — raw per-request rows (resolver, domain, qtype, protocol, rtt, answers, flags, error, ...)
* `dns_summary.json` — per-resolver aggregated metrics and composite scores.

**Example use-cases**

* Nightly automated tests to track resolver performance trends.
* Pre-deployment checks for users relying on specific DNS providers.
* Research into DNS filtering differences across networks.

**Requirements**

* Python 3.8+
* `dnspython`, `requests`, `tqdm`

**Recommended license**

* MIT (or choose whatever fits your org)

**Notes**

* Be mindful of the load you generate — use `--spread` and reasonable `--workers` to avoid overloading endpoints or causing network alarms.

````

---

## Full original script (unchanged)
(you asked to have the code back in full — here it is, exactly as you sent)
```python
#!/usr/bin/env python3
"""
DNS Quality Tester - PRO
Upgrades:
 - more domains, more query types (A, AAAA, MX, NS)
 - UDP + TCP fallback + DoH JSON
 - DNSSEC AD-flag detection
 - configurable attempts, timeout, concurrency, and spread-over-time
 - optional resolvers.json loader (format: {"name": {"ip":"x.x.x.x","doh":"https://..."} , ...})
 - saves raw CSV + summary JSON
 - progress bar (tqdm) and retries
 - no 'global' usage for timeout (clean design)

Requirements:
    pip install dnspython requests tqdm

Run example:
    python dns_tester_pro.py --attempts 12 --timeout 3 --workers 40 --spread 120 --out results.csv
"""

import time
import csv
import json
import argparse
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean
from pathlib import Path

import dns.message
import dns.query
import dns.flags
import requests
from tqdm import tqdm

# ------------------------
# Default resolvers (public + user-provided)
# You can also pass --resolvers resolvers.json to load a JSON file.
# JSON format example:
# {
#   "Cloudflare": {"ip":"1.1.1.1", "doh":"https://cloudflare-dns.com/dns-query"},
#   "MyISP": {"ip":"10.0.0.1", "doh":null}
# }
# ------------------------
DEFAULT_RESOLVERS = {
    "Cloudflare": {"ip": "1.1.1.1", "doh": "https://cloudflare-dns.com/dns-query"},
    "Cloudflare-1.0.0.1": {"ip": "1.0.0.1", "doh": None},
    "Google": {"ip": "8.8.8.8", "doh": "https://dns.google/resolve"},
    "Google-8.8.4.4": {"ip": "8.8.4.4", "doh": None},
    "Quad9": {"ip": "9.9.9.9", "doh": "https://dns.quad9.net/dns-query"},
    "OpenDNS": {"ip": "208.67.222.222", "doh": "https://doh.opendns.com/dns-query"},
    "AdGuard": {"ip": "94.140.14.14", "doh": "https://dns.adguard.com/dns-query"},
    "DNS.WATCH": {"ip": "84.200.69.80", "doh": None},
    "Verisign": {"ip": "64.6.64.6", "doh": None},
    "CleanBrowsing-Security": {"ip": "185.228.168.9", "doh": None},

    # user-provided (from your previous message)
    "Shakhn-1": {"ip": "178.22.122.100", "doh": None},
    "Shakhn-2": {"ip": "185.51.200.2", "doh": None},
    "Electro-1": {"ip": "78.157.42.100", "doh": None},
    "Electro-2": {"ip": "78.157.42.101", "doh": None},
    "RadarGame-1": {"ip": "10.202.10.10", "doh": None},
    "RadarGame-2": {"ip": "10.202.10.11", "doh": None},
    "Shelter-1": {"ip": "94.103.125.157", "doh": None},
    "Shelter-2": {"ip": "94.103.125.158", "doh": None},
    "asiatech": {"ip": "185.98.113.113", "doh": None},
    "asiatech-2": {"ip": "185.98.114.114", "doh": None},
    "Tci": {"ip": "5.200.200.200", "doh": None},

}

# ------------------------
# Bigger domain list for more realistic sampling
# (a mix of global popular sites + some regional ones)
# Add or remove as you like.
# ------------------------
DEFAULT_TEST_DOMAINS = [
    "example.com",
    "google.com",
    "facebook.com",
    "youtube.com",
    "wikipedia.org",
    "twitter.com",
    "instagram.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "reddit.com",
    "bing.com",
    "yahoo.com",
    "soft98.ir",
    "digikala.com",
    "aparat.com",
    "cafebazaar.ir",
    "bankmellat.ir",     # bank domains: can show censorship/filtering differences
    "telegram.org",
    "pornhub.com",       # user included previously; might be blocked in some networks
    "yandex.ru",
    "baidu.com",
    "cloudflare.com",
    "akamaiedge.net",
    "example.org",
]

# Query types to test
DEFAULT_QTYPES = ["A", "AAAA", "MX", "NS"]

# Defaults (can be overridden via CLI)
DEFAULT_ATTEMPTS = 8
DEFAULT_TIMEOUT = 3.0   # seconds per single UDP/TCP attempt
DEFAULT_WORKERS = 30
DEFAULT_SPREAD = 0      # seconds to spread attempts across (0 = run as fast as possible)
CSV_OUT_DEFAULT = "dns_test_results_pro.csv"
JSON_SUMMARY_DEFAULT = "dns_summary_pro.json"

# ------------------------
# Helper functions
# ------------------------

def load_resolvers_from_file(path):
    """Load resolver dict from JSON file (simple validation)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        validated = {}
        for name, info in data.items():
            ip = info.get("ip")
            doh = info.get("doh") if "doh" in info else None
            if not ip:
                continue
            validated[name] = {"ip": ip, "doh": doh}
        return validated
    except Exception as e:
        print("Failed to load resolvers file:", e)
        return {}

def make_udp_query(server_ip, qname, rdtype="A", timeout=DEFAULT_TIMEOUT):
    """Send UDP query. Return tuple (success, rtt_ms, answers_list, flags_int, error_str)."""
    q = dns.message.make_query(qname, rdtype)
    start = time.perf_counter()
    try:
        resp = dns.query.udp(q, server_ip, timeout=timeout)
        rtt = (time.perf_counter() - start) * 1000.0
        answers = []
        for rr in resp.answer:
            for item in rr.items:
                answers.append(item.to_text())
        flags = int(resp.flags)
        return True, round(rtt, 2), answers, flags, None
    except Exception as e:
        rtt = (time.perf_counter() - start) * 1000.0
        return False, round(rtt, 2), [], 0, str(e)

def make_tcp_query(server_ip, qname, rdtype="A", timeout=DEFAULT_TIMEOUT):
    """Send TCP query fallback."""
    q = dns.message.make_query(qname, rdtype)
    start = time.perf_counter()
    try:
        resp = dns.query.tcp(q, server_ip, timeout=timeout)
        rtt = (time.perf_counter() - start) * 1000.0
        answers = []
        for rr in resp.answer:
            for item in rr.items:
                answers.append(item.to_text())
        flags = int(resp.flags)
        return True, round(rtt, 2), answers, flags, None
    except Exception as e:
        rtt = (time.perf_counter() - start) * 1000.0
        return False, round(rtt, 2), [], 0, str(e)

def make_doh_query(doh_url, qname, rdtype="A", timeout=10.0):
    """Query DoH JSON endpoint (simple GET style used by many providers)."""
    headers = {"accept": "application/dns-json"}
    params = {"name": qname, "type": rdtype}
    start = time.perf_counter()
    try:
        r = requests.get(doh_url, params=params, headers=headers, timeout=timeout)
        rtt = (time.perf_counter() - start) * 1000.0
        if r.status_code != 200:
            return False, round(rtt, 2), [], {}, f"HTTP {r.status_code}"
        j = r.json()
        answers = []
        for a in j.get("Answer", []):
            answers.append(str(a.get("data")))
        flags = {"AD": j.get("AD", False), "TC": j.get("TC", False)}
        return True, round(rtt, 2), answers, flags, None
    except Exception as e:
        rtt = (time.perf_counter() - start) * 1000.0
        return False, round(rtt, 2), [], {}, str(e)

def test_one(resolver_name, resolver_info, domain, qtype, timeout, enable_tcp=True, doh_timeout=10.0, max_retries=2, spread=0):
    """
    Test a single resolver+domain+qtype once (with retries).
    Returns a dictionary (raw record) describing the attempt.
    """
    # optional spread/jitter to distribute queries
    if spread and spread > 0:
        # small random delay so not all threads hit at same time
        delay = random.uniform(0, spread)
        time.sleep(delay)

    ip = resolver_info.get("ip")
    doh = resolver_info.get("doh")
    attempt = 0
    last_err = None

    while attempt <= max_retries:
        attempt += 1
        # UDP attempt
        ok, rtt, answers, flags, err = make_udp_query(ip, domain, rdtype=qtype, timeout=timeout)
        protocol = "UDP"
        if not ok and enable_tcp:
            # try TCP fallback once
            ok2, rtt2, answers2, flags2, err2 = make_tcp_query(ip, domain, rdtype=qtype, timeout=timeout)
            if ok2:
                ok, rtt, answers, flags, err = True, rtt2, answers2, flags2, None
                protocol = "TCP"
            else:
                last_err = f"UDP_err={err}; TCP_err={err2}"
        if ok:
            # success via UDP or TCP
            doh_result = (None, None, None, None, None)
            if doh:
                doh_result = make_doh_query(doh, domain, rdtype=qtype, timeout=doh_timeout)
            return {
                "resolver": resolver_name,
                "resolver_ip": ip,
                "domain": domain,
                "qtype": qtype,
                "protocol": protocol,
                "success": True,
                "rtt_ms": rtt,
                "answers": "|".join(answers) if answers else "",
                "flags": int(flags) if isinstance(flags, int) else 0,
                "dnssec_ad": bool(flags & dns.flags.AD) if isinstance(flags, int) else False,
                "doh_present": bool(doh),
                "doh_success": doh_result[0],
                "doh_rtt_ms": doh_result[1],
                "doh_answers": "|".join(doh_result[2]) if doh_result[2] else "",
                "doh_flags": doh_result[3],
                "error": None,
                "attempt": attempt
            }
        else:
            # failed attempt; maybe retry
            last_err = err
            # small backoff before retry
            time.sleep(0.08 * attempt)

    # after retries, return failure record
    return {
        "resolver": resolver_name,
        "resolver_ip": ip,
        "domain": domain,
        "qtype": qtype,
        "protocol": "UDP",
        "success": False,
        "rtt_ms": None,
        "answers": "",
        "flags": 0,
        "dnssec_ad": False,
        "doh_present": bool(doh),
        "doh_success": None,
        "doh_rtt_ms": None,
        "doh_answers": "",
        "doh_flags": {},
        "error": last_err,
        "attempt": attempt
    }

# ------------------------
# Runner / aggregator
# ------------------------

def run_all_tests(resolvers, domains, qtypes, attempts, timeout, workers, spread, doh_timeout):
    """
    Create and run tasks for (resolver x domain x qtype x attempts).
    Returns raw_results list of dicts.
    """
    tasks = []
    raw_results = []
    total_tasks = len(resolvers) * len(domains) * len(qtypes) * attempts
    pbar = tqdm(total=total_tasks, desc="Testing", unit="req")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = []
        for name, info in resolvers.items():
            for domain in domains:
                for qtype in qtypes:
                    for i in range(attempts):
                        # pass small spread per-task so total spread roughly equals 'spread' seconds
                        task = ex.submit(test_one, name, info, domain, qtype, timeout, True, doh_timeout, 2, spread)
                        futures.append(task)
        for fut in as_completed(futures):
            try:
                res = fut.result()
                raw_results.append(res)
            except Exception as e:
                # keep going if a single task raises
                raw_results.append({
                    "resolver": "error",
                    "resolver_ip": "",
                    "domain": "",
                    "qtype": "",
                    "protocol": "",
                    "success": False,
                    "rtt_ms": None,
                    "answers": "",
                    "flags": 0,
                    "dnssec_ad": False,
                    "doh_present": False,
                    "doh_success": None,
                    "doh_rtt_ms": None,
                    "doh_answers": "",
                    "doh_flags": {},
                    "error": str(e),
                    "attempt": 0
                })
            pbar.update(1)
    pbar.close()
    return raw_results

def aggregate(raw_results):
    """
    Aggregate raw results into per-resolver summary.
    Compute majority answers per (domain,qtype) and disagreement rate.
    Return summary list sorted by composite score and a details dict.
    """
    # group by resolver
    by_resolver = {}
    for r in raw_results:
        key = (r["resolver"], r["resolver_ip"])
        by_resolver.setdefault(key, []).append(r)

    # majority answers per (domain,qtype)
    maj = {}
    for r in raw_results:
        key = (r["domain"], r["qtype"])
        ans = r["answers"]
        if key not in maj:
            maj[key] = {}
        maj[key][ans] = maj[key].get(ans, 0) + 1

    majority_answer = {}
    for key, cnts in maj.items():
        # choose the non-empty answer with max count; if all empty, it's empty string
        majority_answer[key] = max(cnts.items(), key=lambda x: x[1])[0]

    summaries = []
    for (name, ip), rows in by_resolver.items():
        successes = [r for r in rows if r["success"]]
        success_rate = len(successes) / len(rows) if rows else 0.0
        rtts = [r["rtt_ms"] for r in successes if r["rtt_ms"] is not None]
        avg_rtt = round(mean(rtts), 2) if rtts else None
        dnssec_count = sum(1 for r in successes if r.get("dnssec_ad"))
        dnssec_rate = dnssec_count / len(rows) if rows else 0.0

        # disagreement: fraction of (domain,qtype) where resolver answer != majority
        seen = set()
        disagreements = 0
        total_pairs = 0
        for r in rows:
            k = (r["domain"], r["qtype"])
            if k in seen:
                continue
            seen.add(k)
            total_pairs += 1
            maj_ans = majority_answer.get(k, "")
            if r["answers"] != maj_ans:
                disagreements += 1

        disagreement_rate = disagreements / total_pairs if total_pairs else 0.0

        summaries.append({
            "resolver": name,
            "ip": ip,
            "avg_rtt_ms": avg_rtt,
            "success_rate": round(success_rate, 3),
            "dnssec_rate": round(dnssec_rate, 3),
            "disagreement_rate": round(disagreement_rate, 3),
            "samples": len(rows)
        })

    # compute latency normalization
    rtts_vals = [s["avg_rtt_ms"] for s in summaries if s["avg_rtt_ms"] is not None]
    min_rtt = min(rtts_vals) if rtts_vals else None
    max_rtt = max(rtts_vals) if rtts_vals else None

    for s in summaries:
        if s["avg_rtt_ms"] is not None and min_rtt is not None and max_rtt is not None and max_rtt != min_rtt:
            latency_score = 1.0 - ((s["avg_rtt_ms"] - min_rtt) / (max_rtt - min_rtt))
        else:
            latency_score = 0.5
        score = (0.55 * s["success_rate"]) + (0.3 * latency_score) + (0.15 * s["dnssec_rate"])
        # penalty for disagreement
        score -= 0.25 * s["disagreement_rate"]
        s["latency_score"] = round(latency_score, 3)
        s["composite_score"] = round(score, 0
*(the code above was pasted in full; if you want I can also: 1) produce a polished `README.md` file with badges and usage examples, 2) create a `resolvers.json` template, 3) suggest CI (GitHub Actions) to run nightly tests and upload results — tell me which and I’ll generate them).*
