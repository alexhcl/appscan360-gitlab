"""DAST scan (web application, API, or AppScan Standard .scan/.scant file).

Request body = NewDastScan from the AppScan 360° 2.2.0 swagger (as360_swagger.json):

  {
    "ScanName", "Description", "AppId", "Execute", "Personal", "Comment", "Locale",
    "EnableMailNotification", "IncludeVerifiedDomains", "OnlyFullResults", "EnableSupportMode",
    "ScanPriority": "Regular|High",
    "PresenceId": "...",
    "ScanOrTemplateFileId": "<.scan/.scant FileId>"   -- or --   "ScanTemplateId": "<saved template id>",
    "TestOperation": "None|Retest|ContinueTest|ReportOnly",
    "LoginConfigurationType": "None|LoginSequence|LoginFile|AutomaticLogin|LoginRequests|ApiKeyLogin",
    "LoginSequenceFileId": "<.config / .login FileId>",
    "ExploreItems": [{"FileId": "<dast.config>", "TrafficType": "Manual|MultiStep|Llm"}],
    "PostmanCollectionFiles": {"CollectionJsonFileId", "EnvironmentJsonFileId", "GlobalJsonFileId", "AdditionalZipFileId"},
    "ScanConfiguration": {
      "Target": {"StartingUrl", "AdditionalDomains": [], "ShouldScanBelowThisDirectory", "UseCaseSensitivePaths",
                 "ExclusionList": [{"Type": "Exclude|Exception", "IsRegEx", "Pattern", "Description"}]},
      "Login": {"UserName", "Password", "ExtraField"},
      "HttpAuth": {"UserName", "Password", "Domain"},
      "Otp": {"SecretKey", "Length", "HashType": "None|Sha1|Sha256|Sha512", "TimeStep", "HttpParameters"},
      "Communication": {"ThreadNum", "ConnectionTimeout", "UseAutomaticTimeout", "MaxRequestsIn", "MaxRequestsTimeFrame"},
      "Tests": {"CustomTestPolicyId", "TestOptimizationLevel": "NoOptimization|Fast|Faster|Fastest",
                "TestLoginPages", "TestLoginPagesWithoutSessionIds", "TestLogoutPages", "DetectVulnerableComponents"},
      "ApplicationElements": {"EnableAutomaticFormFill"},
      "OpenAPI": {"BaseUrl", "Url", "FileId", "LoginKeys": [{"KeyName", "KeyValue"}]}
    }
  }

FileUpload fileType per file: Postman collection -> DastPostmanCollectionJson, linked files zip ->
DastPostmanCollectionZip, OpenAPI file -> DastOpenAPIFile, .config/.login/.scan/.scant -> none.
Note: `TestOnly` exists on the *read* model but not on NewDastScan; send it only with --test-only
(harmless if ignored). For a real test-only run use a .scan file with TestOperation=Retest.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

from .client import AS360Client, AS360Error
from .common import log, die, state_save, IS_WINDOWS, PRESENCE_PLATFORM
from .sast import _log_counts


# ------------------------------------------------------------------ helpers
def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def _upload_if_exists(client: AS360Client, path: str | None, what: str, file_type: str | None = None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        log(f"{what} '{path}' not found, ignoring", "WARN")
        return None
    log(f"{what}: {p}")
    return client.upload_file(p, file_type)


def _split(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


# ------------------------------------------------------------------ payload builders
def build_base(client: AS360Client, args) -> dict:
    return {
        "AppId": args.app_id,
        "ScanName": f"DAST {args.scan_name}" + (f" {args.url}" if args.url else ""),
        "Description": args.description or f"GitLab pipeline {os.environ.get('CI_PIPELINE_URL', '')}".strip(),
        "Execute": True,
        "Personal": bool(args.personal),
        "Locale": "en-US",
        "EnableMailNotification": False,
        "IncludeVerifiedDomains": True,
        "OnlyFullResults": True,
        "EnableSupportMode": False,
        "ScanPriority": args.scan_priority or "Regular",
        "Comment": args.comment or "Scan triggered by GitLab CI/CD",
    }


def build_scan_configuration(args) -> dict:
    target = {
        "StartingUrl": args.url,
        "ShouldScanBelowThisDirectory": bool(args.scan_below_directory),
        "UseCaseSensitivePaths": bool(args.case_sensitive_paths),
        "AdditionalDomains": _split(args.additional_domains),
    }
    excl = []
    for p in _split(args.exclude_paths):
        excl.append({"Type": "Exclude", "IsRegEx": p.startswith("re:"), "Pattern": p.removeprefix("re:"),
                     "Description": "GitLab CI exclusion"})
    for p in _split(args.include_paths):
        excl.append({"Type": "Exception", "IsRegEx": p.startswith("re:"), "Pattern": p.removeprefix("re:"),
                     "Description": "GitLab CI exception"})
    if excl:
        target["ExclusionList"] = excl

    tests = {
        "TestOptimizationLevel": args.optimization or "Fast",
        "TestLoginPages": bool(args.test_login_pages),
        "TestLoginPagesWithoutSessionIds": bool(args.test_login_pages_no_session),
        "TestLogoutPages": bool(args.test_logout_pages),
        "DetectVulnerableComponents": bool(args.report_vulnerable_components),
    }
    if args.test_policy_id:
        tests["CustomTestPolicyId"] = args.test_policy_id
    comm = {
        "ThreadNum": int(args.threads or 10),
        "UseAutomaticTimeout": not bool(args.connection_timeout),
        "MaxRequestsIn": int(args.max_requests or 10),
        "MaxRequestsTimeFrame": int(args.max_requests_timeframe or 1000),
    }
    if args.connection_timeout:
        comm["ConnectionTimeout"] = int(args.connection_timeout)
    cfg = {
        "Target": target,
        "Tests": tests,
        "Communication": comm,
        "ApplicationElements": {"EnableAutomaticFormFill": not bool(args.no_form_fill)},
    }
    if args.login_method == "userpass":
        if not args.login_user or not args.login_password:
            die("--login-method userpass requires --login-user and --login-password (DAST_LOGIN_USER/DAST_LOGIN_PASSWORD)")
        cfg["Login"] = {"UserName": args.login_user, "Password": args.login_password}
        if args.login_extra:
            cfg["Login"]["ExtraField"] = args.login_extra
    if args.http_auth_user:
        cfg["HttpAuth"] = {"UserName": args.http_auth_user, "Password": args.http_auth_password or "",
                           "Domain": args.http_auth_domain or ""}
    if args.otp_secret:
        cfg["Otp"] = {"SecretKey": args.otp_secret, "Length": int(args.otp_length or 6),
                      "HashType": args.otp_hash or "Sha1", "TimeStep": int(args.otp_timestep or 30),
                      "HttpParameters": args.otp_http_parameters or ""}
    return cfg


def apply_api_method(client: AS360Client, args, payload: dict, cfg: dict) -> None:
    """API explore method: postman | openapi | traffic (recorded traffic goes through ExploreItems)."""
    method = (args.api_method or "").lower()
    if method == "postman":
        cid = _upload_if_exists(client, args.postman_collection, "Postman collection", "DastPostmanCollectionJson")
        if not cid:
            die("--postman-collection <file.json> is required for --api-method postman")
        pcf = {"CollectionJsonFileId": cid}
        if args.postman_env:
            pcf["EnvironmentJsonFileId"] = _upload_if_exists(client, args.postman_env, "Postman environment", "DastPostmanCollectionJson")
        if args.postman_globals:
            pcf["GlobalJsonFileId"] = _upload_if_exists(client, args.postman_globals, "Postman globals", "DastPostmanCollectionJson")
        if args.postman_linked_files:
            pcf["AdditionalZipFileId"] = _upload_if_exists(client, args.postman_linked_files, "Postman linked files zip", "DastPostmanCollectionZip")
        payload["PostmanCollectionFiles"] = {k: v for k, v in pcf.items() if v}
    elif method == "openapi":
        oa: dict = {"BaseUrl": args.api_base_url}
        if args.openapi_url:
            oa["Url"] = args.openapi_url
        elif args.openapi_file:
            oa["FileId"] = _upload_if_exists(client, args.openapi_file, "OpenAPI specification", "DastOpenAPIFile")
            if not oa["FileId"]:
                die("OpenAPI file not found")
        else:
            die("--openapi-file or --openapi-url is required for --api-method openapi")
        if not args.api_base_url:
            die("--api-base-url is required for OpenAPI scans (Base URL of the API)")
        keys = [{"KeyName": kv.split("=", 1)[0], "KeyValue": kv.split("=", 1)[1]} for kv in _split(args.api_keys) if "=" in kv]
        if keys:
            oa["LoginKeys"] = keys
            payload["LoginConfigurationType"] = "ApiKeyLogin"
        cfg["OpenAPI"] = oa
    elif method == "traffic":
        if not args.explore_files:
            die("--explore-files <file.dast.config> is required for --api-method traffic")
    else:
        die("--api-method must be postman, openapi or traffic")
    # Domains to be tested -> AdditionalDomains
    doms = _split(args.api_domains)
    if doms:
        cfg["Target"]["AdditionalDomains"] = sorted(set(cfg["Target"].get("AdditionalDomains", []) + doms))


# ------------------------------------------------------------------ ephemeral presence
class EphemeralPresence:
    """Create an AppScan Presence on the runner so a DAST scan can reach a target that is only
    reachable from the runner network (e.g. the app started in a `services:` container).
    Presence status values (swagger): Active, NeverUsed, KeyExpired, KeyNeverUsed, Inactive, Disable.
    Deleted when the scan is finished."""

    def __init__(self, client: AS360Client, name: str, work: Path, platform: str | None = None):
        self.client, self.name, self.work = client, name, work
        self.platform = platform or PRESENCE_PLATFORM      # win_x64 | linux_x64 | osx_x64 (auto)
        self.id: str | None = None
        self.proc: subprocess.Popen | None = None

    def start(self, wait_seconds: int = 180) -> str:
        for p in self.client.presences():
            if p.get("PresenceName") == self.name:
                log(f"Deleting stale presence {p['Id']} ({self.name})")
                self.client.delete_presence(p["Id"])
        pres = self.client.create_presence(self.name)
        self.id = pres["Id"]
        log(f"Created presence {self.id} ({self.name})", "OK")
        zip_path = self.work / "presence.zip"
        pdir = self.work / "presence"
        self.client.download_presence(self.id, self.platform, zip_path)
        shutil.rmtree(pdir, ignore_errors=True)
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(pdir)
        starter_name = "startPresence.bat" if IS_WINDOWS else "startPresence.sh"
        starter = next((p for p in pdir.rglob(starter_name)), None)
        if not starter:
            die(f"{starter_name} not found in the downloaded presence package")
        if not IS_WINDOWS:
            for f in starter.parent.rglob("*"):
                if f.is_file() and f.suffix in ("", ".sh"):
                    os.chmod(f, 0o755)
        log(f"Starting presence: {starter}")
        self.proc = subprocess.Popen([str(starter)], cwd=starter.parent, shell=IS_WINDOWS,
                                     stdout=open(self.work / "presence.log", "w"), stderr=subprocess.STDOUT)
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            st = next((p for p in self.client.presences() if p.get("Id") == self.id), {})
            if st.get("Status") == "Active":
                log("Presence is Active", "OK")
                return self.id
            time.sleep(5)
        log("Presence did not become Active in time; continuing anyway (see presence.log)", "WARN")
        return self.id

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        if self.id:
            try:
                self.client.delete_presence(self.id)
                log(f"Deleted presence {self.id}", "OK")
            except AS360Error as e:
                log(f"Could not delete presence {self.id}: {e}", "WARN")


# ------------------------------------------------------------------ main
def run_dast(client: AS360Client, args) -> str:
    work = Path(args.work_dir or ".appscan360").resolve()
    work.mkdir(exist_ok=True)
    payload = build_base(client, args)
    mode = (args.dast_mode or "web").lower()

    presence: EphemeralPresence | None = None
    try:
        # ---- presence (private target)
        if args.ephemeral_presence:
            presence = EphemeralPresence(client, args.presence_name or f"gitlab-runner-{os.environ.get('CI_JOB_ID', 'local')}", work)
            payload["PresenceId"] = presence.start()
            args.wait = True  # runner must stay alive while the presence is used
        elif args.presence_id:
            payload["PresenceId"] = args.presence_id
            log(f"Using AppScan Presence {args.presence_id} (private site)")
        else:
            log("No Presence: all scanned domains must be verified/allowed in AppScan 360°")

        if mode == "file":
            # ---- AppScan Standard .scan / .scant  (ScanConfiguration must NOT be sent)
            fid = _upload_if_exists(client, args.scan_file, "Scan/template file")
            if not fid:
                die("--scan-file <file.scan|.scant> is required for --dast-mode file")
            payload["ScanOrTemplateFileId"] = fid
            payload["TestOperation"] = args.test_operation or "None"   # None | Retest | ContinueTest | ReportOnly
            if args.login_method == "recorded" and args.login_file:
                payload["LoginSequenceFileId"] = _upload_if_exists(client, args.login_file, "Login recording")
                payload["LoginConfigurationType"] = "LoginSequence"
        else:
            if mode == "api" and not args.url:
                args.url = args.api_base_url or (("https://" + _split(args.api_domains)[0]) if _split(args.api_domains) else None)
            if not args.url:
                die("--url (DAST_URL) is required")
            cfg = build_scan_configuration(args)
            if args.scan_template_id:
                payload["ScanTemplateId"] = args.scan_template_id   # saved template + optional overrides
            if mode == "api":
                apply_api_method(client, args, payload, cfg)
            payload["ScanConfiguration"] = cfg

            # ---- login recording (.config from Activity Recorder, .login from AppScan Standard)
            if args.login_method == "recorded":
                fid = _upload_if_exists(client, args.login_file, "Login recording")
                if not fid:
                    die("--login-method recorded needs --login-file (DAST_LOGIN_FILE), e.g. login.dast.config")
                payload["LoginSequenceFileId"] = fid
                payload["LoginConfigurationType"] = "LoginSequence"
            elif args.login_method == "userpass":
                payload["LoginConfigurationType"] = "AutomaticLogin"
            elif "LoginConfigurationType" not in payload:
                payload["LoginConfigurationType"] = "None"

            # ---- explore data: recorded traffic (.dast.config) and multi-step recordings
            items = []
            for f in _split(args.explore_files):
                fid = _upload_if_exists(client, f, "Explore (traffic) file")
                if fid:
                    items.append({"FileId": fid, "TrafficType": "Manual"})
            for f in _split(args.multistep_files):
                fid = _upload_if_exists(client, f, "Multi-step explore file")
                if fid:
                    items.append({"FileId": fid, "TrafficType": "MultiStep"})
            if items:
                payload["ExploreItems"] = items
            if args.test_only:
                if not items:
                    die("--test-only requires at least one --explore-files / --multistep-files recording")
                payload["TestOnly"] = True
                log("TestOnly=true sent. Note: 2.2.0 NewDastScan does not declare TestOnly; if the scan still "
                    "explores automatically, use a .scan file with --dast-mode file --test-operation Retest.", "WARN")

        # ---- raw overrides (exact keys from your instance's Swagger)
        if args.payload_json:
            extra = json.loads(Path(args.payload_json).read_text()) if Path(args.payload_json).is_file() else json.loads(args.payload_json)
            extra.pop("_comment", None)
            _deep_merge(payload, extra)
            log("Applied payload overrides from --payload-json")

        (work / "dast_payload.json").write_text(json.dumps(_redact(payload), indent=2))
        log(f"DAST payload written to {work / 'dast_payload.json'} (secrets redacted)")

        if args.rescan_id:
            r = client.rescan(args.rescan_id, comment=args.comment or "", retest_only=bool(args.test_only))
            scan_id = args.rescan_id
            log(f"Re-executed DAST scan {scan_id}, execution {r.get('Id')}", "OK")
        else:
            r = client.create_scan("Dast", payload)
            scan_id = r.get("Id") or die(f"Scan creation returned no Id: {r}")
            log(f"DAST scan created: {scan_id} ({payload['ScanName']})", "OK")
        state_save(scan_id=scan_id, scan_tech="Dast", app_id=args.app_id, scan_name=args.scan_name)

        if args.wait:
            d = client.wait_for_scan("Dast", scan_id, poll=args.poll_interval, timeout_min=args.timeout_minutes)
            state_save(execution_id=(d.get("LatestExecution") or {}).get("Id"))
            _log_counts(d)
        return scan_id
    finally:
        if presence:
            presence.stop()


def _redact(payload: dict) -> dict:
    p = json.loads(json.dumps(payload))
    sc = p.get("ScanConfiguration", {})
    for blk in ("Login", "HttpAuth"):
        if blk in sc and "Password" in sc[blk]:
            sc[blk]["Password"] = "***"
    if "Otp" in sc:
        sc["Otp"]["SecretKey"] = "***"
    for k in sc.get("OpenAPI", {}).get("LoginKeys", []):
        k["KeyValue"] = "***"
    return p
