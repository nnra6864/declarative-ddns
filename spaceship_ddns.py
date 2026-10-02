#!/usr/bin/env python3
"""
spaceship-ddns: declarative DNS records for Spaceship.com, with dynamic public-IP support.

* Records live in a TOML file (ddns.toml), grouped by domain.  Safe to commit.
* API credentials live elsewhere (env vars / secrets.env).  Never committed.
* Any A/AAAA record with  address = "auto"  follows your current public IP.
* Any record type the Spaceship API supports works (A, AAAA, CAA, CNAME, MX, SRV, TXT, ...).
  Fields are passed to the API as-is, so adding a new type needs no code changes.
* "{domain}" inside any string value expands to the domain the record belongs to.

Ownership model: for every (type, name) pair mentioned in the config, the config is the
source of truth.  Existing records with the same type+name but different data are deleted.
Records at (type, name) pairs the config never mentions are never touched.

Usage:
    spaceship_ddns.py sync               # dry run: show what would change
    spaceship_ddns.py sync --apply       # actually change things (what the timer runs)
    spaceship_ddns.py list example.com   # raw JSON of the live records
    spaceship_ddns.py export example.com # live records as ddns.toml snippet (bootstrap)

Requires Python 3.11+ (tomllib), no third-party packages.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

API_BASE = os.environ.get("SPACESHIP_API_BASE", "https://spaceship.dev/api/v1")
RECORD_TYPES = {"A", "AAAA", "ALIAS", "CAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "SRV", "SVCB", "TLSA", "TXT"}
DEFAULT_IP4 = ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me"]
DEFAULT_IP6 = ["https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me"]
BATCH = 500  # API max items per request
USER_AGENT = "spaceship-ddns/1.0"

XDG_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
DEFAULT_SECRETS = XDG_CONFIG / "spaceship-ddns" / "secrets.env"
DEFAULT_CONFIG = Path(os.environ.get("SPACESHIP_DDNS_CONFIG", Path(__file__).with_name("ddns.toml")))


def log(msg: str) -> None:
    print(msg, flush=True)


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


# --------------------------------------------------------------------------- secrets


def load_credentials(path: Path) -> dict[str, str]:
    """Env vars win; otherwise read KEY=VALUE lines from the secrets file."""
    if path.exists():
        if path.stat().st_mode & 0o077:
            log(f"warning: {path} is readable by other users; run: chmod 600 {path}")
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    key, secret = os.environ.get("SPACESHIP_API_KEY"), os.environ.get("SPACESHIP_API_SECRET")
    if not key or not secret:
        die(f"SPACESHIP_API_KEY / SPACESHIP_API_SECRET not set (looked in environment and {path})")
    return {"X-API-Key": key, "X-API-Secret": secret}


# --------------------------------------------------------------------------- API


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail.strip()[:500]}")
        self.status = status


def api(creds: dict, method: str, path: str, body=None, query: dict | None = None):
    url = API_BASE + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode() if body is not None else None
    headers = {**creds, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT}
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            if e.code == 429 and attempt < 2:
                try:
                    wait = int(e.headers.get("Retry-After", "5"))
                except ValueError:
                    wait = 5
                time.sleep(min(max(wait, 1), 60))
                continue
            raise ApiError(e.code, detail) from None
        except urllib.error.URLError as e:
            raise ApiError(0, f"network error: {e.reason}") from None
    raise ApiError(429, "rate limited")


def get_records(creds: dict, domain: str) -> list[dict]:
    """All records in the 'custom' group (the ones the API lets us manage)."""
    items: list[dict] = []
    skip = 0
    while True:
        page = api(creds, "GET", f"/dns/records/{domain}", query={"take": BATCH, "skip": skip})
        batch = page.get("items", [])
        items += batch
        skip += len(batch)
        if not batch or skip >= page.get("total", skip):
            break
    return [r for r in items if (r.get("group") or {}).get("type", "custom") == "custom"]


# --------------------------------------------------------------------------- public IP


class PublicIP:
    def __init__(self, settings: dict):
        self.urls = {4: settings.get("ip4_urls", DEFAULT_IP4), 6: settings.get("ip6_urls", DEFAULT_IP6)}
        self.cache: dict[int, str | None] = {}

    def get(self, version: int) -> str | None:
        if version not in self.cache:
            self.cache[version] = self._detect(version)
        return self.cache[version]

    def _detect(self, version: int) -> str | None:
        for url in self.urls[version]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    ip = ipaddress.ip_address(resp.read().decode().strip())
                if ip.version == version:
                    return str(ip)
            except Exception:
                continue
        return None


# --------------------------------------------------------------------------- record logic


def expand(value, domain: str):
    if isinstance(value, str):
        return value.replace("{domain}", domain)
    return value


def rkey(rec: dict) -> tuple[str, str]:
    return rec["type"].upper(), rec["name"].lower()


def norm(key: str, value, rtype: str) -> str:
    if key == "port":
        return str(value).lstrip("_")
    if isinstance(value, str):
        if rtype == "TXT" and key == "value":
            return value  # TXT is case-sensitive
        return value.lower().rstrip(".")
    return str(value)


def matches(want: dict, have: dict) -> bool:
    """Same record, ignoring TTL (TTL differences are an update, not a different record)."""
    for k, v in want.items():
        if k == "ttl":
            continue
        if k not in have or norm(k, v, want["type"]) != norm(k, have[k], want["type"]):
            return False
    return True


def describe(rec: dict) -> str:
    data = " ".join(f"{k}={v}" for k, v in rec.items() if k not in ("type", "name", "ttl", "group"))
    ttl = f" (ttl {rec['ttl']})" if "ttl" in rec else ""
    return f"{rec['type']:<5} {rec['name']:<20} {data}{ttl}"


def build_desired(domain: str, dcfg: dict, ttl_default: int, ips: PublicIP) -> tuple[list[dict], int]:
    """Turn one [domains."x"] table into API-shaped records. Returns (records, problem_count)."""
    out: list[dict] = []
    problems = 0
    for rtype, entries in dcfg.items():
        if rtype not in RECORD_TYPES:
            die(f"[{domain}] unknown record type '{rtype}' (valid: {', '.join(sorted(RECORD_TYPES))})")
        if not isinstance(entries, list):
            die(f"[{domain}] {rtype} must be an array of tables")
        for i, entry in enumerate(entries):
            if "name" not in entry:
                die(f"[{domain}] {rtype}[{i}] is missing 'name'")
            rec = {"type": rtype, **{k: expand(v, domain) for k, v in entry.items()}}
            rec.setdefault("ttl", ttl_default)
            if rtype in ("A", "AAAA") and rec.get("address") == "auto":
                version = 4 if rtype == "A" else 6
                ip = ips.get(version)
                if ip is None:
                    log(f"[{domain}] warning: could not detect public IPv{version}; skipping {rtype} '{rec['name']}'")
                    if version == 4:
                        problems += 1
                    continue
                rec["address"] = ip
            out.append(rec)
    return out, problems


def chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def sync_domain(creds, domain, dcfg, ttl_default, ips, *, apply: bool, force: bool, prune: bool) -> int:
    desired, problems = build_desired(domain, dcfg, ttl_default, ips)
    existing = get_records(creds, domain)

    have_by_key: dict = defaultdict(list)
    for e in existing:
        have_by_key[rkey(e)].append(e)
    want_by_key: dict = defaultdict(list)
    for w in desired:
        want_by_key[rkey(w)].append(w)

    adds: list[tuple[str, dict]] = []  # ("+" new | "~" ttl change, record)
    deletes: list[dict] = []
    for key, wants in want_by_key.items():
        haves = have_by_key.get(key, [])
        for w in wants:
            m = next((e for e in haves if matches(w, e)), None)
            if m is None:
                adds.append(("+", w))
            elif m.get("ttl") != w["ttl"]:
                adds.append(("~", w))
        if prune:
            deletes += [e for e in haves if not any(matches(w, e) for w in wants)]

    if not adds and not deletes:
        log(f"[{domain}] up to date")
        return problems

    for e in deletes:
        log(f"[{domain}] - {describe(e)}")
    for sign, w in adds:
        log(f"[{domain}] {sign} {describe(w)}")
    if not apply:
        log(f"[{domain}] dry run: nothing changed (re-run with --apply)")
        return problems

    # Delete first: single-valued types (CNAME) would conflict otherwise, and a stale
    # A record points at an IP that's no longer ours anyway.
    stale = [{k: v for k, v in e.items() if k not in ("ttl", "group")} for e in deletes]
    for batch in chunks(stale, BATCH):
        api(creds, "DELETE", f"/dns/records/{domain}", body=batch)
    new = [w for _, w in adds]
    for batch in chunks(new, BATCH):
        payload = {"items": batch}
        if force:
            payload["force"] = True
        api(creds, "PUT", f"/dns/records/{domain}", body=payload)
    log(f"[{domain}] applied: {len(deletes)} removed, {len(new)} added/updated")
    return problems


# --------------------------------------------------------------------------- commands


def load_config(path: Path) -> dict:
    if not path.exists():
        die(f"config not found: {path}")
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        die(f"{path}: {e}")
    return {}


def cmd_sync(args, creds) -> int:
    cfg = load_config(Path(args.config))
    settings = cfg.get("settings", {})
    ttl_default = int(settings.get("ttl", 300))
    domains = cfg.get("domains", {})
    if args.domain:
        if args.domain not in domains:
            die(f"domain '{args.domain}' is not in the config")
        domains = {args.domain: domains[args.domain]}
    if not domains:
        die("no [domains.\"...\"] tables in config")
    ips = PublicIP(settings)
    failures = 0
    for domain, dcfg in domains.items():
        try:
            failures += sync_domain(creds, domain, dcfg, ttl_default, ips,
                                    apply=args.apply, force=args.force, prune=not args.no_prune)
        except ApiError as e:
            print(f"[{domain}] API error: {e}", file=sys.stderr, flush=True)
            if e.status == 422 and not args.force:
                print(f"[{domain}] hint: a conflicting record exists; fix it or retry with --force", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


def cmd_list(args, creds) -> int:
    print(json.dumps(get_records(creds, args.domain), indent=2))
    return 0


def toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v))  # JSON string escapes are valid TOML basic strings


def cmd_export(args, creds) -> int:
    domain = args.domain
    by_type: dict = defaultdict(list)
    for r in get_records(creds, domain):
        by_type[r["type"]].append(r)
    print("# Generated from live records. Change dynamic addresses to \"auto\" before syncing.")
    print(f'[domains."{domain}"]')
    for rtype in sorted(by_type):
        print(f"{rtype} = [")
        for r in by_type[rtype]:
            fields = {k: v for k, v in r.items() if k not in ("type", "group")}
            ordered = ["name"] + [k for k in fields if k not in ("name", "ttl")] + (["ttl"] if "ttl" in fields else [])
            parts = []
            for k in ordered:
                v = fields[k]
                if isinstance(v, str) and k != "name" and not (rtype == "TXT" and k == "value"):
                    if v.lower() == domain:
                        v = "{domain}"
                    elif v.lower().endswith("." + domain):
                        v = v[: -len(domain)] + "{domain}"
                parts.append(f"{k} = {toml_val(v)}")
            print("  { " + ", ".join(parts) + " },")
        print("]")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Declarative DNS + dynamic IP for Spaceship.com")
    p.add_argument("-c", "--config", default=str(DEFAULT_CONFIG), help=f"config file (default: {DEFAULT_CONFIG})")
    p.add_argument("--secrets-file", default=str(DEFAULT_SECRETS), help=f"credentials file (default: {DEFAULT_SECRETS})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="make Spaceship match the config (dry run unless --apply)")
    s.add_argument("--apply", action="store_true", help="actually make changes")
    s.add_argument("--domain", help="only sync this domain")
    s.add_argument("--no-prune", action="store_true", help="never delete records, only add/update")
    s.add_argument("--force", action="store_true", help="pass force=true to the API (overrides conflict checks)")
    s.set_defaults(fn=cmd_sync)

    l = sub.add_parser("list", help="print live records as raw JSON")
    l.add_argument("domain")
    l.set_defaults(fn=cmd_list)

    e = sub.add_parser("export", help="print live records as a ddns.toml snippet")
    e.add_argument("domain")
    e.set_defaults(fn=cmd_export)

    args = p.parse_args()
    creds = load_credentials(Path(args.secrets_file))
    return args.fn(args, creds)


if __name__ == "__main__":
    sys.exit(main())
