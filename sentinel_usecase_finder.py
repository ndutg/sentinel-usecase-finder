#!/usr/bin/env python3
"""
Sentinel Use Case Finder
------------------------
Scans the Azure/Azure-Sentinel GitHub repo and lists analytic rules by
data types (log source) and/or MITRE technique, in the use case template format.

Usage examples:
  # Data types AND MITRE technique (default --match both)
  python sentinel_usecase_finder.py --types SigninLogs AADNonInteractiveUserSignInLogs --technique T1110.003

  # Comma separated input also works
  python sentinel_usecase_finder.py --types "SigninLogs, AADNonInteractiveUserSignInLogs" --technique "T1110, T1098"

  # Data types OR technique
  python sentinel_usecase_finder.py --types Syslog --technique T1110 --match either

  # Technique only (any data source)
  python sentinel_usecase_finder.py --technique T1098

  # Data types must match EXACTLY (no more, no less)
  python sentinel_usecase_finder.py --types AZFWApplicationRule AZFWNetworkRule AZFWDnsQuery --exact

Matching rules:
  - Data types: rule must need ONLY types from your list (or exactly your list with --exact).
  - Technique:
      T1110      matches T1110 and all its sub-techniques (T1110.001, T1110.003 ...)
      T1110.003  matches T1110.003 and rules tagged only with the parent T1110
                 (many Sentinel rules list just the parent technique)
    Several techniques can be given; a rule matches if it has any of them.
  - --match both   = data types AND technique
    --match either = data types OR technique
    If only one of the two inputs is given, only that one is checked.

Outputs (in ./output/):
  usecases_<label>.md   - copy/paste ready use cases in your template format
  usecases_<label>.csv  - same data as a spreadsheet
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


def split_list(items):
    """Accept comma, semicolon and/or space separated input."""
    out = []
    for i in items:
        out += [x.strip() for x in re.split(r"[,;]", i) if x.strip()]
    return out


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


# ---------------------------------------------------------------- matching
def types_match(rule, wanted, exact):
    have = {norm(d) for d in rule["dataTypes"]}
    if not have:
        return False
    return have == wanted if exact else have.issubset(wanted)


def technique_match(rule, techs):
    rule_t = [str(t).strip().upper() for t in rule["techniques"]]
    for t in techs:
        parent = t.split(".")[0]
        for rt in rule_t:
            # exact, sub-technique of what you asked, or parent of the sub-technique you asked
            if rt == t or rt.startswith(t + ".") or ("." in t and rt == parent):
                return True
    return False


def matches(rule, wanted, exact, techs, mode, connector, keyword):
    checks = []
    if wanted:
        checks.append(types_match(rule, wanted, exact))
    if techs:
        checks.append(technique_match(rule, techs))
    if mode == "both" and not all(checks):
        return False
    if mode == "either" and not any(checks):
        return False
    if connector and norm(connector) not in {norm(c) for c in rule["connectors"]}:
        return False
    if keyword and keyword.lower() not in (rule["name"] + " " + rule["description"]).lower():
        return False
    return True


# ---------------------------------------------------------------- output
def write_outputs(rules, label, log_source, mitre, outdir: Path):
    outdir.mkdir(exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)[:80] or "results"
    md, csvp = outdir / f"usecases_{safe}.md", outdir / f"usecases_{safe}.csv"

    with md.open("w", encoding="utf-8") as f:
        f.write(f"# Use cases for: {label}\n\nMatches: {len(rules)}\n\n")
        for i, r in enumerate(rules, 1):
            src = log_source or "Log source"
            f.write(f"**Use case {i}: {r['name']}**  \n")
            f.write(f"**Log Source:** {src} ({', '.join(r['dataTypes']) or 'N/A'})  \n")
            f.write(f"**MITRE Tactic:** {', '.join(fmt_tactic(t) for t in r['tactics']) or 'N/A'}  \n")
            f.write(f"**MITRE Technique:** {', '.join(fmt_technique(t, mitre) for t in r['techniques']) or 'N/A'}  \n")
            f.write(f"**Description:** {r['description']}  \n")
            f.write(f"**Required connectors:** {', '.join(r['connectors']) or 'N/A'} | **Severity:** {r['severity']} | **Type:** {r['kind']}  \n")
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
    p = argparse.ArgumentParser(description="Find Sentinel use cases by data types and/or MITRE technique")
    p.add_argument("--types", nargs="+", default=[], help="Data types / log source tables (space or comma separated)")
    p.add_argument("--technique", nargs="+", default=[], help="MITRE technique IDs, e.g. T1059 T1110.003")
    p.add_argument("--match", choices=["both", "either"], default="both",
                   help="both = data types AND technique; either = data types OR technique")
    p.add_argument("--exact", action="store_true", help="Rule data types must equal your list exactly")
    p.add_argument("--connector", help="Rule must list this connectorId (e.g. CefAma, SyslogAma, Office365)")
    p.add_argument("--keyword", help="Only rules whose name/description contains this text")
    p.add_argument("--log-source", default="", help="Label for the Log Source line (e.g. Syslog via AMA)")
    p.add_argument("--hunting", action="store_true", help="Include hunting queries")
    p.add_argument("--include-deprecated", action="store_true")
    p.add_argument("--repo", default=str(HERE / "Azure-Sentinel"), help="Path to local repo clone")
    p.add_argument("--no-update", action="store_true", help="Skip git pull")
    p.add_argument("--offline", action="store_true", help="No network (skip clone/pull/MITRE download)")
    a = p.parse_args()

    a.types = split_list(a.types)
    techs = [t.upper() for t in split_list(a.technique)]
    if not a.types and not techs:
        sys.exit("[x] Provide --types and/or --technique")
    wanted = {norm(t) for t in a.types}

    repo = Path(a.repo)
    if not a.offline:
        ensure_repo(repo, update=not a.no_update)
    if not repo.exists():
        sys.exit(f"[x] Repo not found at {repo}")

    seen, found = set(), []
    for path in candidate_files(repo, a.hunting):
        r = parse_rule(path, repo)
        if not r or (r["deprecated"] and not a.include_deprecated):
            continue
        if not matches(r, wanted, a.exact, techs, a.match, a.connector, a.keyword):
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

    parts = []
    if a.types:
        parts.append("_".join(a.types) + ("_exact" if a.exact else ""))
    if techs:
        parts.append("_".join(techs))
    label = f"_{a.match.upper()}_".join(parts) if len(parts) == 2 else parts[0]

    md, csvp = write_outputs(found, label, a.log_source or ", ".join(a.types), mitre, HERE / "output")
    print(f"[+] {len(found)} matching rule(s)\n    {md}\n    {csvp}")
    for r in found[:15]:
        print(f"    - {r['name']}  [{', '.join(r['dataTypes'])}] {', '.join(map(str, r['techniques']))}")
    if len(found) > 15:
        print(f"    ... and {len(found) - 15} more (see output files)")


if __name__ == "__main__":
    main()
