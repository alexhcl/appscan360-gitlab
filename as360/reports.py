"""Reports and exports.

  report  : POST /api/v4/Reports/Security/Scan/{scanId} (Html|Pdf|Xml|Csv|Sarif) -> poll /Reports -> /Reports/{id}/Download
  json    : GET  /api/v4/Issues/Scan/{scanId} (application/json)
  license : POST /api/v4/Reports/License/Scan/{scanId}     (SCA)
  sbom    : POST /api/v4/Reports/Sbom/{executionId}          (SCA; SPDX / CycloneDX)
  gitlab  : GitLab Security Report JSON (gl-sast-report.json / gl-dast-report.json /
            gl-dependency-scanning-report.json) built from the Issues API, so findings
            appear in the merge-request security widget and the Vulnerability Report.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .client import AS360Client
from .common import log, state_get, env

TECH_PREFIX = {"Sast": "SAST", "Dast": "DAST", "Sca": "SCA"}
GL_REPORT = {"Sast": ("sast", "gl-sast-report.json"), "Dast": ("dast", "gl-dast-report.json"),
             "Sca": ("dependency_scanning", "gl-dependency-scanning-report.json")}
GL_SEVERITY = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low",
               "Informational": "Info", "Information": "Info", "Info": "Info"}


def run_report(client: AS360Client, args) -> list[Path]:
    scan_id = state_get("scan_id", args.scan_id)
    tech = state_get("scan_tech", args.scan_tech)
    out_dir = Path(args.out_dir or ".")
    out_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []
    formats = [f.strip().lower() for f in (args.formats or "html,xml").split(",") if f.strip()]
    prefix = TECH_PREFIX.get(tech, tech.upper())
    for fmt in formats:
        if fmt in ("html", "pdf", "xml", "csv", "sarif"):
            log(f"Requesting {fmt.upper()} security report for scan {scan_id} ...")
            rid = client.request_report(scan_id, fmt, title=f"{prefix} {state_get('scan_name', None, False) or ''}",
                                        notes=f"GitLab pipeline {env('CI_PIPELINE_URL', '')}",
                                        apply_policies=args.apply_policies or "None")
            client.wait_for_report(rid, poll=args.poll_interval, timeout_min=args.timeout_minutes)
            ext = "sarif.json" if fmt == "sarif" else fmt
            dest = client.download_report(rid, out_dir / f"{prefix}_report.{ext}")
            log(f"Report saved: {dest}", "OK")
            produced.append(dest)
        elif fmt == "json":
            dest = client.export_issues(scan_id, "json", out_dir / f"{prefix}_issues.json")
            log(f"Issues exported: {dest}", "OK")
            produced.append(dest)
        elif fmt == "license":
            if tech != "Sca":
                log("license report only applies to SCA scans; skipping", "WARN"); continue
            rid = client.request_license_report(scan_id, "Html", title=f"SCA licenses {scan_id}")
            client.wait_for_report(rid, poll=args.poll_interval, timeout_min=args.timeout_minutes)
            dest = client.download_report(rid, out_dir / "SCA_license_report.html")
            log(f"License report saved: {dest}", "OK")
            produced.append(dest)
        elif fmt == "sbom":
            if tech != "Sca":
                log("sbom only applies to SCA scans; skipping", "WARN"); continue
            exec_id = state_get("execution_id", None, False) or (client.scan_details(tech, scan_id).get("LatestExecution") or {}).get("Id")
            sf = args.sbom_format or "SPDX_Json"
            rid = client.request_sbom_report(exec_id, sf, "sbom")
            client.wait_for_report(rid, poll=args.poll_interval, timeout_min=args.timeout_minutes)
            ext = {"SPDX_Json": "spdx.json", "SPDX_Text": "spdx.txt", "CycloneDX_Json": "cdx.json", "CycloneDX_XML": "cdx.xml"}[sf]
            dest = client.download_report(rid, out_dir / f"SCA_sbom.{ext}")
            log(f"SBOM saved: {dest}", "OK")
            produced.append(dest)
        elif fmt == "gitlab":
            produced.append(write_gitlab_report(client, scan_id, tech, out_dir))
        else:
            log(f"Unknown report format '{fmt}' (html,pdf,xml,csv,sarif,json,gitlab,license,sbom)", "WARN")
    return produced


def write_gitlab_report(client: AS360Client, scan_id: str, tech: str, out_dir: Path) -> Path:
    category, filename = GL_REPORT.get(tech, ("sast", "gl-sast-report.json"))
    issues = client.issues("Scan", scan_id)
    scan = client.scan_basic(scan_id)
    ex = scan.get("LatestExecution") or {}
    vulns = []
    for i in issues:
        sev = GL_SEVERITY.get(str(i.get("Severity")), "Unknown")
        loc: dict = {}
        src = i.get("SourceFile") or i.get("Location") or ""
        line = i.get("Line") or i.get("LineNumber")
        if category == "sast":
            loc = {"file": str(src), "start_line": int(line) if line else 1}
        elif category == "dast":
            loc = {"hostname": str(i.get("Host") or ""), "method": str(i.get("HttpMethod") or ""),
                   "param": str(i.get("Element") or ""), "path": str(src)}
        else:
            loc = {"file": str(src), "dependency": {"package": {"name": str(i.get("LibraryName") or i.get("IssueType") or "")},
                                                     "version": str(i.get("LibraryVersion") or "")}}
        ident = [{"type": "appscan_issue_type", "name": str(i.get("IssueType")), "value": str(i.get("IssueTypeId") or i.get("IssueType"))}]
        if i.get("Cwe"):
            ident.append({"type": "cwe", "name": f"CWE-{i['Cwe']}", "value": str(i["Cwe"]),
                          "url": f"https://cwe.mitre.org/data/definitions/{i['Cwe']}.html"})
        if i.get("Cve"):
            ident.append({"type": "cve", "name": str(i["Cve"]), "value": str(i["Cve"])})
        uid = hashlib.sha1(f"{scan_id}:{i.get('Id')}".encode()).hexdigest()
        vulns.append({
            "id": uid,
            "category": category,
            "name": str(i.get("IssueType") or "AppScan issue"),
            "description": f"{i.get('IssueType')} at {src}. Status: {i.get('Status')}. AppScan issue id {i.get('Id')}.",
            "severity": sev,
            "confidence": "Unknown",
            "scanner": {"id": "hcl_appscan_360", "name": "HCL AppScan 360°"},
            "location": loc,
            "identifiers": ident,
            "links": [{"url": f"{client.base}/main/myapps/{scan.get('AppId')}/scans/{scan_id}"}],
        })
    report = {
        "version": "15.0.7",
        "vulnerabilities": vulns,
        "scan": {
            "scanner": {"id": "hcl_appscan_360", "name": "HCL AppScan 360°", "vendor": {"name": "HCL Software"},
                        "version": "2.2"},
            "analyzer": {"id": "appscan360-gitlab", "name": "AppScan 360° GitLab integration",
                         "vendor": {"name": "community"}, "version": "1.0"},
            "type": category,
            "start_time": str(ex.get("CreatedAt") or "")[:19] or "1970-01-01T00:00:00",
            "end_time": str(ex.get("ScanEndTime") or ex.get("LastUpdatedAt") or "")[:19] or "1970-01-01T00:00:00",
            "status": "success",
        },
    }
    dest = out_dir / filename
    dest.write_text(json.dumps(report, indent=2))
    log(f"GitLab {category} report written: {dest} ({len(vulns)} findings)", "OK")
    return dest
