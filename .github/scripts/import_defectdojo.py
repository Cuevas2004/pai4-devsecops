#!/usr/bin/env python3
"""Importa los informes del pipeline en DefectDojo mediante su API v2.

Cada informe se envia a /api/v2/import-scan/ y queda asociado al engagement
indicado. El script es tolerante a informes ausentes (avisa y continua), pero
falla si la API devuelve un error, para que el job lo refleje.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from defectdojo_client import DefectDojoClient, DefectDojoError
from dependency_check import convert_file

REPORTS = [
    (("semgrep-report.json",), "Semgrep JSON Report", "SAST"),
    (
        ("dependency-check-report.xml", "dependency-check-report.json"),
        "Dependency Check Scan",
        "SCA",
    ),
    (("zap-report.xml",), "ZAP Scan", "DAST"),
]


def _env(name, default=""):
    return os.getenv(name, default)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", nargs="?", default="reports")
    parser.add_argument("--url", default=_env("DEFECTDOJO_URL", "http://localhost:8080"))
    parser.add_argument("--api-key", default=_env("DEFECTDOJO_API_KEY"))
    parser.add_argument("--engagement", default=_env("DEFECTDOJO_ENGAGEMENT_ID"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.dry_run and not args.api_key:
        raise SystemExit("Falta DEFECTDOJO_API_KEY")
    if not args.engagement:
        raise SystemExit("Falta DEFECTDOJO_ENGAGEMENT_ID")

    reports_dir = Path(args.reports_dir)
    client = None if args.dry_run else DefectDojoClient(args.url, args.api_key)

    common = {
        "build_id": _env("GITHUB_RUN_ID", "local"),
        "branch_tag": _env("GITHUB_REF_NAME", "local"),
        "commit_hash": _env("GITHUB_SHA", "local"),
        "version": _env("GITHUB_SHA", "local")[:12],
        "source_code_management_uri": _env(
            "GITHUB_SERVER_URL", "https://github.com"
        )
        + "/"
        + _env("GITHUB_REPOSITORY", "Cuevas2004/pai4-devsecops"),
    }

    summary = []
    errors = []

    for filenames, scan_type, tool in REPORTS:
        path = next(
            (
                reports_dir / name
                for name in filenames
                if (reports_dir / name).is_file()
                and (reports_dir / name).stat().st_size > 0
            ),
            None,
        )
        row = {
            "tool": tool,
            "report": filenames[0],
            "scan_type": scan_type,
            "status": "omitido",
            "test_id": None,
            "findings": 0,
            "detail": "",
        }
        if path is None:
            row["detail"] = "informe no generado"
            print(f"::warning::{tool}: no existe {filenames[0]}; se omite")
            summary.append(row)
            continue

        row["report"] = path.name
        if scan_type == "Dependency Check Scan" and path.suffix == ".json":
            xml_path = path.with_suffix(".xml")
            try:
                convert_file(path, xml_path)
                path = xml_path
                row["detail"] = "JSON convertido a XML para DefectDojo"
                print(f"{tool}: {path.name} generado desde JSON")
            except Exception as error:
                row["status"] = "error"
                row["detail"] = f"no se pudo convertir el JSON: {error}"
                errors.append(f"{tool}: {row['detail']}")
                print(f"::error::{tool}: {row['detail']}")
                summary.append(row)
                continue

        if args.dry_run:
            row["status"] = "dry-run"
            print(f"[dry-run] {tool}: {path} -> {scan_type}")
            summary.append(row)
            continue

        try:
            response = client.import_scan(
                args.engagement,
                scan_type,
                str(path),
                test_title=f"{tool} - {_env('GITHUB_RUN_ID', 'local')}",
                tags=f"ci,devsecops,{tool.lower()}",
                **common,
            )
            stats = response.get("statistics") or {}
            test_id = response.get("test_id") or response.get("test")
            row.update(
                status="importado",
                test_id=test_id,
                findings=_count_findings(client, test_id),
                detail=json.dumps(stats, ensure_ascii=False),
            )
            print(f"OK {tool}: test={row['test_id']} hallazgos={row['findings']}")
        except DefectDojoError as error:
            row["status"] = "error"
            row["detail"] = str(error)
            errors.append(f"{tool}: {error}")
            print(f"::error::{tool}: {error}")
        summary.append(row)

    result = {"engagement": args.engagement, "reports": summary}
    output = reports_dir / "defectdojo-import.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Resumen: {output}")

    _write_step_summary(summary, args.engagement)

    if errors:
        raise SystemExit(1)


def _count_findings(client, test_id):
    if not test_id:
        return 0
    data = client.get("/api/v2/findings/", {"test": test_id, "limit": 1})
    return int(data.get("count", 0))


def _write_step_summary(rows, engagement):
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    lines = [
        "## Importacion en DefectDojo",
        "",
        f"Engagement: `{engagement}`",
        "",
        "| Herramienta | Informe | Scan type | Estado | Test | Hallazgos |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['tool']} | `{row['report']}` | {row['scan_type']} | "
            f"{row['status']} | {row['test_id'] or '-'} | {row['findings']} |"
        )
    lines.append("")
    with open(summary_file, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


if __name__ == "__main__":
    main()
