"""Security gates (build pass/fail decisions).

  severity   : fail if count of <sevSecGw> issues in the last execution > maxIssuesAllowed
               (criticalIssues | highIssues | mediumIssues | lowIssues | totalIssues)
  threshold  : fail if any issue with severity >= threshold (Critical/High/Medium/Low) exists
  branch     : feature -> no Critical; qa -> no Critical/High; release/main -> no Critical/High/Medium
  compliance : fail if the application is non-compliant with an enabled policy;
               prints the non-compliant issues (Issues/Application/{appId}?selectPolicyIds=..)
  license    : SCA only. Lists licenses per execution and fails on configured risk levels.
"""
from __future__ import annotations

from .client import AS360Client
from .common import log, die, state_get, env

SEV_KEYS = {"criticalIssues": "NCriticalIssues", "highIssues": "NHighIssues", "mediumIssues": "NMediumIssues",
            "lowIssues": "NLowIssues", "totalIssues": "NIssuesFound"}
SEV_ORDER = ["Low", "Medium", "High", "Critical"]


def _counts(client: AS360Client, tech: str, scan_id: str) -> dict:
    ex = client.scan_details(tech, scan_id).get("LatestExecution") or {}
    c = {k: int(ex.get(v) or 0) for k, v in SEV_KEYS.items()}
    log("There are {criticalIssues} critical, {highIssues} high, {mediumIssues} medium, {lowIssues} low issues "
        "({totalIssues} total)".format(**c), "GATE")
    return c


def gate_severity(client: AS360Client, args) -> bool:
    scan_id = state_get("scan_id", args.scan_id)
    tech = state_get("scan_tech", args.scan_tech)
    sev = args.sev_sec_gw or env("sevSecGw", "criticalIssues")
    max_allowed = int(args.max_issues_allowed if args.max_issues_allowed is not None else env("maxIssuesAllowed", "0"))
    if sev not in SEV_KEYS:
        die(f"sevSecGw must be one of {', '.join(SEV_KEYS)}")
    c = _counts(client, tech, scan_id)
    log(f"Policy: at most {max_allowed} {sev}", "GATE")
    if c[sev] > max_allowed:
        log("Security Gate build FAILED", "ERR")
        return False
    log("Security Gate passed", "OK")
    return True


def gate_threshold(client: AS360Client, args) -> bool:
    scan_id = state_get("scan_id", args.scan_id)
    tech = state_get("scan_tech", args.scan_tech)
    thr = (args.failure_threshold or "High").capitalize()
    if thr not in SEV_ORDER:
        die("--failure-threshold must be Low, Medium, High or Critical")
    c = _counts(client, tech, scan_id)
    keys = {"Critical": "criticalIssues", "High": "highIssues", "Medium": "mediumIssues", "Low": "lowIssues"}
    bad = sum(c[keys[s]] for s in SEV_ORDER[SEV_ORDER.index(thr):])
    if bad:
        log(f"{bad} issue(s) at or above {thr} severity. Security Gate build FAILED", "ERR")
        return False
    log(f"No issues at or above {thr}. Security Gate passed", "OK")
    return True


def gate_branch(client: AS360Client, args) -> bool:
    scan_id = state_get("scan_id", args.scan_id)
    tech = state_get("scan_tech", args.scan_tech)
    branch = (args.branch or env("CI_COMMIT_REF_NAME", "") or "").lower()
    c = _counts(client, tech, scan_id)
    if "feature" in branch:
        kind, limit = "feature", ("criticalIssues",)
    elif "qa" in branch or "test" in branch:
        kind, limit = "qa", ("criticalIssues", "highIssues")
    elif any(x in branch for x in ("release", "main", "master", "prod")):
        kind, limit = "release", ("criticalIssues", "highIssues", "mediumIssues")
    else:
        log(f"Branch '{branch}': unknown type, no branch gate applied", "GATE")
        return True
    log(f"Branch type: {kind} -> must have zero {', '.join(limit)}", "GATE")
    if any(c[k] > 0 for k in limit):
        log("Branch Security Gate build FAILED", "ERR")
        return False
    log("Branch Security Gate passed", "OK")
    return True


def gate_compliance(client: AS360Client, args) -> bool:
    app_id = args.app_id or state_get("app_id", None)
    app = client.get_app(app_id)
    statuses = app.get("ComplianceStatuses") or []
    log("-------------- Compliance policies ---------------", "GATE")
    ok = True
    for s in statuses:
        log(f"Enabled: {s.get('Enabled')} | Compliant: {s.get('Compliant')} | Name: {s.get('Name')}", "GATE")
    for s in statuses:
        if s.get("Enabled") and s.get("Compliant") is False:
            ok = False
            issues = client.noncompliant_issues(app_id, s.get("PolicyId"))
            log(f"Policy '{s.get('Name')}' is NOT compliant: {len(issues)} issue(s)", "ERR")
            for i in issues[: args.max_list or 50]:
                log(f"  [{i.get('Severity')}] {i.get('IssueType')} @ {i.get('Location')}  (id {i.get('Id')}, {i.get('Status')})")
    if ok:
        log("The application is compliant with all enabled policies", "OK")
    else:
        log("The application is not in compliance with enterprise policies", "ERR")
    return ok


def gate_license(client: AS360Client, args) -> bool:
    scan_id = state_get("scan_id", args.scan_id)
    tech = state_get("scan_tech", args.scan_tech)
    if tech != "Sca":
        log("License gate only applies to SCA scans; skipping", "WARN")
        return True
    exec_id = state_get("execution_id", None, False) or (client.scan_details(tech, scan_id).get("LatestExecution") or {}).get("Id")
    fail_levels = {x.strip().lower() for x in (args.fail_license_risk or "").split(",") if x.strip()}
    # LicenseModel: LicenseName, RiskLevel (Undefined|Unknown|Low|Medium|High), CopyLeft, Linking, RoyaltyFree
    licenses = client.sca_licenses(exec_id)
    # LibraryModel: LibraryName, Version, HighestIssueSeverity, NumOfIssues, Licenses[]
    libs = client.sca_libraries(exec_id)
    log(f"{len(libs)} open-source packages, {len(licenses)} distinct licenses in execution {exec_id}", "GATE")
    for lib in libs:
        lics = ", ".join(str(l.get("LicenseName") or l) for l in (lib.get("Licenses") or [])) or "-"
        log(f"  {lib.get('LibraryName')} {lib.get('Version') or ''}  licenses={lics}  issues={lib.get('NumOfIssues', 0)} "
            f"(max {lib.get('HighestIssueSeverity')})")
    bad = 0
    for lic in licenses:
        risk = str(lic.get("RiskLevel") or "")
        line = f"  license {lic.get('LicenseName')}  risk={risk}  copyleft={lic.get('CopyLeft')}  linking={lic.get('Linking')}"
        if risk.lower() in fail_levels:
            bad += 1
            log(line, "ERR")
        else:
            log(line, "GATE")
    if bad:
        log(f"{bad} license(s) with risk in [{', '.join(fail_levels)}]. License gate FAILED", "ERR")
        return False
    log("License gate passed", "OK")
    return True


GATES = {"severity": gate_severity, "threshold": gate_threshold, "branch": gate_branch,
         "compliance": gate_compliance, "license": gate_license}
