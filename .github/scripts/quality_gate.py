#!/usr/bin/env python3
"""Quality gate: falla (exit 1) si hay hallazgos >= umbral en los informes,
o si falta algún informe esperado o no se puede leer (fail-closed)."""
import argparse, json, pathlib, sys

ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def semgrep(d):
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return [m.get(r.get("extra", {}).get("severity", "INFO"), "low") for r in d.get("results", [])]

def depcheck(d):
    return [v.get("severity", "medium").lower()
            for dep in d.get("dependencies", []) for v in dep.get("vulnerabilities", [])]

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
    ap.add_argument("--allow-missing", action="store_true",
                    help="no fallar si falta algún informe (solo para pruebas)")
    a = ap.parse_args()
    th = ORDER[a.fail_on]
    blocking, problems = 0, []

    for name, parser in PARSERS.items():
        files = list(pathlib.Path(a.dir).rglob(name))
        if not files:
            problems.append(f"falta el informe {name}")
            continue
        for p in files:
            try:
                sev = parser(json.loads(p.read_text()))
            except Exception as e:
                problems.append(f"no se pudo leer {p}: {e}")
                continue
            n = sum(1 for s in sev if ORDER.get(s, 0) >= th)
            print(f"{name}: {len(sev)} hallazgos, {n} >= {a.fail_on}")
            blocking += n

    for pr in problems:
        print(f"::{'warning' if a.allow_missing else 'error'}::{pr}")
    if blocking:
        print(f"::error::Quality gate FALLIDO: {blocking} hallazgos >= {a.fail_on}")
        sys.exit(1)
    if problems and not a.allow_missing:
        print("::error::Quality gate FALLIDO: informes ausentes o ilegibles")
        sys.exit(1)
    print("Quality gate superado")

if __name__ == "__main__":
    main()
