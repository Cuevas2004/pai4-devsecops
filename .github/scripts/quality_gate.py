#!/usr/bin/env python3
"""Quality gate: falla (exit 1) si hay hallazgos >= umbral en los informes."""
import argparse, json, pathlib, sys

ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def load(p):
    try:
        return json.loads(p.read_text())
    except Exception as e:
        print(f"::warning::No se pudo leer {p}: {e}")
        return None

def semgrep(d):
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return [m.get(r.get("extra", {}).get("severity", "INFO"), "low") for r in d.get("results", [])]

def depcheck(d):
    out = []
    for dep in d.get("dependencies", []):
        for v in dep.get("vulnerabilities", []):
            out.append(v.get("severity", "medium").lower())
    return out

def zap(d):
    m = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    return [m.get(str(a.get("riskcode", "0")), "info")
            for s in d.get("site", []) for a in s.get("alerts", [])]

PARSERS = {
    "semgrep-report.json": semgrep,
    "dependency-check-report.json": depcheck,
    "zap-report.json": zap,
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--fail-on", default="high", choices=ORDER)
    a = ap.parse_args()
    th = ORDER[a.fail_on]
    blocking = 0
    for name, parser in PARSERS.items():
        for p in pathlib.Path(a.dir).rglob(name):
            d = load(p)
            if d is None:
                continue
            sev = parser(d)
            n = sum(1 for s in sev if ORDER.get(s, 0) >= th)
            print(f"{name}: {len(sev)} hallazgos, {n} >= {a.fail_on}")
            blocking += n
    if blocking:
        print(f"::error::Quality gate FALLIDO: {blocking} hallazgos >= {a.fail_on}")
        sys.exit(1)
    print("Quality gate superado")

if __name__ == "__main__":
    main()
