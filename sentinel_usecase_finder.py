#!/usr/bin/env python3
"""
Sentinel Use Case Finder
------------------------
Scans the Azure/Azure-Sentinel GitHub repo and lists analytic rules that can run
on the data types you have, written out in the use case template format.

Usage examples:
  # Rules that need ONLY data types from your list (recommended)
  python sentinel_usecase_finder.py --types Syslog

  # Rules whose data types match your list EXACTLY (no more, no less)
  python sentinel_usecase_finder.py --types AZFWApplicationRule AZFWNetworkRule AZFWDnsQuery --exact

  # Also require a specific connector ID (e.g. CefAma) and include hunting queries
  python sentinel_usecase_finder.py --types CommonSecurityLog --connector CefAma --hunting

  # Filter by keyword in the rule name/description
  python sentinel_usecase_finder.py --types SecurityEvent --keyword powershell

Outputs (in ./output/):
  usecases_<label>.md   - copy/paste ready use cases in your template format
  usecases_<label>.csv  - same data as a spreadsheet

Notes:
  - First run clones the repo (shallow) into ./Azure-Sentinel. Later runs do a git pull.
    Use --no-update to skip the pull.
  - Deprecated rules are excluded by default (--include-deprecated to keep them).
  - MITRE technique names are fetched once from MITRE's CTI repo and cached.
"""
import argparse
import csv
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

REPO_URL = "https://github.com/Azure/Azure-Sentinel.git"
BLOB_BASE = "https://github.com/Azure/Azure-Sentinel/blob/master/"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
HERE = Path(__file__).resolve().parent
MITRE_CACHE = HERE / "mitre_techniques.json"

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance", "resourcedevelopment": "Resource Development",
    "initialaccess": "Initial Access", "execution": "Execution", "persistence": "Persistence",
    "privilegeescalation": "Privilege Escalation", "defenseevasion": "Defense Evasion",
    "credentialaccess": "Credential Access", "discovery": "Discovery",
    "lateralmovement": "Lateral Movement", "collection": "Collection",
    "commandandcontrol": "Command and Control", "exfiltration": "Exfiltration",
    "impact": "Impact", "preattack": "PreAttack",
    "impairprocesscontrol": "Impair Process Control", "inhibitresponsefunction": "Inhibit Response Function",
}


# ---------------------------------------------------------------- repo
def ensure_repo(repo_dir: Path, update: bool):
    if not repo_dir.exists():
        print(f"[+] Cloning {REPO_URL} (shallow) - this takes a few minutes the first time...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(repo_dir)], check=True)
    elif update:
        print("[+] Updating repo (git pull)...")
        r = subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"])
        if r.returncode != 0:
            print("[!] git pull failed - continuing with local copy")


def candidate_files(repo_dir: Path, hunting: bool):
    folders = ["Analytic Rules"] + (["Hunting Queries"] if hunting else [])
    for f in folders:
        yield from (repo_dir / "Solutions").glob(f"*/{f}/**/*.yaml")
        yield from (repo_dir / "Solutions").glob(f"*/{f}/**/*.yml")
    yield from (repo_dir / "Detections").glob("**/*.yaml")
    if hunting:
        yield from (repo_dir / "Hunting Queries").glob("**/*.yaml")


# ---------------------------------------------------------------- MITRE
def load_mitre(offline: bool):
    if MITRE_CACHE.exists():
        return json.loads(MITRE_CACHE.read_text())
    if offline:
        return {}
    try:
        print("[+] Downloading MITRE ATT&CK technique names (one-off)...")
        with urllib.request.urlopen(MITRE_URL, timeout=60) as r:
            data = json.load(r)
        names = {}
        for o in data.get("objects", []):
            if o.get("type") == "attack-pattern" and not o.get("revoked"):
                for ref in o.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        names[ref["external_id"]] = o["name"]
        MITRE_CACHE.write_text(json.dumps(names))
        return names
    except Exception as e:
        print(f"[!] Could not fetch MITRE names ({e}) - technique IDs only")
        return {}


def fmt_tactic(t):
    return TACTIC_NAMES.get(str(t).replace(" ", "").lower(), str(t))


def fmt_technique(tid, mitre):
    tid = str(tid).strip()
    name = mitre.get(tid)
    if name and "." in tid:  # sub-technique: prefix parent name
        parent = mitre.get(tid.split(".")[0])
        if parent:
            name = f"{parent}: {name}"
    return f"{tid}: {name}" if name else tid


# ---------------------------------------------------------------- parsing
def norm(s):
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def parse_rule(path: Path, repo_dir: Path):
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception:
        return None
    if not isinstance(doc, dict) or "query" not in doc or "name" not in doc:
        return None
    connectors, dtypes = [], set()
    for c in doc.get("requiredDataConnectors") or []:
        if not isinstance(c, dict):
            continue
        connectors.append(str(c.get("connectorId", "")))
        for d in c.get("dataTypes") or []:
            dtypes.add(str(d).strip())
    rel = path.relative_to(repo_dir).as_posix()
    name = str(doc.get("name", "")).strip()
    deprecated = (
        "deprecated" in rel.lower()
        or name.lower().startswith("[deprecated]")
        or str(doc.get("status", "")).lower() == "deprecated"
    )
    return {
        "name": name,
        "description": " ".join(str(doc.get("description", "")).replace("'", "").split()),
        "tactics": doc.get("tactics") or [],
        "techniques": doc.get("relevantTechniques") or [],
        "connectors": connectors,
        "dataTypes": sorted(dtypes),
        "deprecated": deprecated,
        "kind": "Hunting" if "hunting" in rel.lower() else "Analytic",
        "url": BLOB_BASE + urllib.parse.quote(rel),
        "severity": doc.get("severity", ""),
    }


def matches(rule, wanted, exact, connector, keyword):
    have = {norm(d) for d in rule["dataTypes"]}
    if not have:
        return False
    if exact and have != wanted:
        return False
    if not exact and not have.issubset(wanted):
        return False
    if connector and norm(connector) not in {norm(c) for c in rule["connectors"]}:
        return False
    if keyword and keyword.lower() not in (rule["name"] + " " + rule["description"]).lower():
        return False
    return True


# ---------------------------------------------------------------- output
def write_outputs(rules, label, log_source, mitre, outdir: Path):
    outdir.mkdir(exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", label)[:60]
    md, csvp = outdir / f"usecases_{safe}.md", outdir / f"usecases_{safe}.csv"

    with md.open("w", encoding="utf-8") as f:
        f.write(f"# Use cases for: {log_source}\n\nMatches: {len(rules)}\n\n")
        for i, r in enumerate(rules, 1):
            f.write(f"**Use case {i}: {r['name']}**  \n")
            f.write(f"**Log Source:** {log_source} ({', '.join(r['dataTypes'])})  \n")
            f.write(f"**MITRE Tactic:** {', '.join(fmt_tactic(t) for t in r['tactics']) or 'N/A'}  \n")
            f.write(f"**MITRE Technique:** {', '.join(fmt_technique(t, mitre) for t in r['techniques']) or 'N/A'}  \n")
            f.write(f"**Description:** {r['description']}  \n")
            f.write(f"**Required connectors:** {', '.join(r['connectors'])} | **Severity:** {r['severity']} | **Type:** {r['kind']}  \n")
            f.write(f"**Source:** {r['url']}\n\n---\n\n")

    with csvp.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Use case", "Log Source", "Data Types", "MITRE Tactic", "MITRE Technique",
                    "Description", "Connectors", "Severity", "Type", "Source"])
        for r in rules:
            w.writerow([r["name"], log_source, ", ".join(r["dataTypes"]),
                        ", ".join(fmt_tactic(t) for t in r["tactics"]),
                        ", ".join(fmt_technique(t, mitre) for t in r["techniques"]),
                        r["description"], ", ".join(r["connectors"]), r["severity"], r["kind"], r["url"]])
    return md, csvp


# ---------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Find Sentinel use cases for your data types")
    p.add_argument("--types", nargs="+", required=True, help="Data types available, e.g. Syslog CommonSecurityLog")
    p.add_argument("--exact", action="store_true", help="Rule data types must equal your list exactly")
    p.add_argument("--connector", help="Rule must list this connectorId (e.g. CefAma, SyslogAma, Office365)")
    p.add_argument("--keyword", help="Only rules whose name/description contains this text")
    p.add_argument("--log-source", help="Label for the Log Source line (default: the data types)")
    p.add_argument("--hunting", action="store_true", help="Include hunting queries")
    p.add_argument("--include-deprecated", action="store_true")
    p.add_argument("--repo", default=str(HERE / "Azure-Sentinel"), help="Path to local repo clone")
    p.add_argument("--no-update", action="store_true", help="Skip git pull")
    p.add_argument("--offline", action="store_true", help="No network (skip clone/pull/MITRE download)")
    a = p.parse_args()

    repo = Path(a.repo)
    if not a.offline:
        ensure_repo(repo, update=not a.no_update)
    if not repo.exists():
        sys.exit(f"[x] Repo not found at {repo}")

    wanted = {norm(t) for t in a.types}
    seen, found = set(), []
    for path in candidate_files(repo, a.hunting):
        r = parse_rule(path, repo)
        if not r or (r["deprecated"] and not a.include_deprecated):
            continue
        if not matches(r, wanted, a.exact, a.connector, a.keyword):
            continue
        key = norm(r["name"])  # same rule often exists in Detections/ and Solutions/ - prefer Solutions
        if key in seen:
            if "/Solutions/" in r["url"]:
                found = [x for x in found if norm(x["name"]) != key] + [r]
            continue
        seen.add(key)
        found.append(r)

    found.sort(key=lambda r: (r["kind"], r["name"].lower()))
    mitre = load_mitre(a.offline)
    log_source = a.log_source or ", ".join(a.types)
    md, csvp = write_outputs(found, "_".join(a.types) + ("_exact" if a.exact else ""), log_source, mitre, HERE / "output")
    print(f"[+] {len(found)} matching rule(s)\n    {md}\n    {csvp}")
    for r in found[:15]:
        print(f"    - {r['name']}  [{', '.join(r['dataTypes'])}]")
    if len(found) > 15:
        print(f"    ... and {len(found) - 15} more (see output files)")


if __name__ == "__main__":
    main()
