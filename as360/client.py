"""Thin client for the HCL AppScan 360° REST API v4.

AppScan 360° exposes the same /api/v4 surface as AppScan on Cloud; only the
host, the TLS trust and the SAClientUtil download differ.

Verified against the AppScan 360° 2.2.0 swagger.json (as360_swagger.json),
the 360° documentation, the HCL appscan-sdk and HCL's appscan-dast-action.

Authentication:
  * default  -> POST /api/v4/Account/ApiKeyLogin  (bearer token)
  * direct   -> X-Api-Key: <KeyId>:<KeySecret>  (no session handling; 360° 2.2+)
"""
from __future__ import annotations

import os
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .common import log, die, normalize_host

FINAL_STATES = {"Ready", "Failed", "Cancelled", "Canceled", "PartialSuccess", "Completed", "Suspended"}
RUNNING_STATES = {"Running", "InQueue", "Starting", "Waiting to Run", "Pausing", "Paused", "Unknown", "Canceling", "Pending"}


class AS360Error(RuntimeError):
    pass


class AS360Client:
    def __init__(
        self,
        base_url: str,
        key_id: str,
        key_secret: str,
        *,
        verify: bool | str = True,
        auth_mode: str = "token",  # token | direct
        client_type: str = "gitlab-ci-python",
        timeout: int = 60,
    ):
        self.base = normalize_host(base_url)
        self.api = f"{self.base}/api/v4"
        self.key_id = key_id
        self.key_secret = key_secret
        self.auth_mode = auth_mode
        self.client_type = client_type
        self.timeout = timeout
        self.token: str | None = None

        self.s = requests.Session()
        self.s.verify = verify
        if verify is False:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        retry = Retry(total=5, backoff_factor=1.5, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE"]))
        self.s.mount("https://", HTTPAdapter(max_retries=retry))
        self.s.mount("http://", HTTPAdapter(max_retries=retry))
        self.s.headers.update({"Accept": "application/json", "ClientType": client_type})

    # ------------------------------------------------------------ auth
    def login(self) -> "AS360Client":
        if self.auth_mode == "direct":
            self.s.headers["X-Api-Key"] = f"{self.key_id}:{self.key_secret}"
            log("Using direct X-Api-Key authentication")
            return self
        log(f"Authenticating to {self.base} ...")
        r = self.s.post(f"{self.api}/Account/ApiKeyLogin",
                        json={"KeyId": self.key_id, "KeySecret": self.key_secret},
                        timeout=self.timeout)
        self._raise(r, "Authentication failed")
        self.token = r.json().get("Token")
        if not self.token:
            die("Login succeeded but no Token in response. Check APPSCAN_KEY / APPSCAN_SECRET.")
        self.s.headers["Authorization"] = f"Bearer {self.token}"
        log("Authentication successful", "OK")
        return self

    def logout(self) -> None:
        if self.token:
            try:
                self.s.get(f"{self.api}/Account/Logout", timeout=15)
            except requests.RequestException:
                pass

    def __enter__(self):
        return self.login()

    def __exit__(self, *_):
        self.logout()

    # ------------------------------------------------------------ low level
    @staticmethod
    def _raise(r: requests.Response, what: str) -> None:
        if r.ok:
            return
        body = r.text[:800]
        raise AS360Error(f"{what}: HTTP {r.status_code} {r.reason} -> {body}")

    def get(self, path: str, **params) -> Any:
        r = self.s.get(f"{self.api}/{path.lstrip('/')}", params=params or None, timeout=self.timeout)
        self._raise(r, f"GET {path} failed")
        return r.json() if r.content else None

    def post(self, path: str, payload: dict | None = None, **params) -> Any:
        r = self.s.post(f"{self.api}/{path.lstrip('/')}", json=payload, params=params or None, timeout=self.timeout)
        self._raise(r, f"POST {path} failed")
        return r.json() if r.content else None

    def put(self, path: str, payload: dict | None = None, **params) -> Any:
        r = self.s.put(f"{self.api}/{path.lstrip('/')}", json=payload, params=params or None, timeout=self.timeout)
        self._raise(r, f"PUT {path} failed")
        return r.json() if r.content else None

    def delete(self, path: str) -> None:
        r = self.s.delete(f"{self.api}/{path.lstrip('/')}", timeout=self.timeout)
        self._raise(r, f"DELETE {path} failed")

    def download(self, path: str, dest: Path, **params) -> Path:
        with self.s.get(f"{self.api}/{path.lstrip('/')}", params=params or None, stream=True,
                        timeout=max(self.timeout, 600)) as r:
            self._raise(r, f"Download {path} failed")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                for chunk in r.iter_content(1 << 16):
                    f.write(chunk)
        return dest

    @staticmethod
    def items(resp: Any) -> list:
        """v4 collection functions return {"Items": [...], "Count": n}."""
        if isinstance(resp, dict):
            return resp.get("Items") or resp.get("Applications") or []
        return resp or []

    # ------------------------------------------------------------ files
    def upload_file(self, path: str | Path, file_type: str | None = None) -> str:
        """POST /api/v4/FileUpload  (multipart field 'uploadedFile').

        file_type (required for ZIP files, from the 360° swagger enum):
          SourceCodeArchive        zipped source tree (SAST without IRX)
          ZippedXmlDast            zipped DAST xml/config
          DastPostmanCollectionJson / DastPostmanCollectionZip
          DastOpenAPIFile          OpenAPI json/yaml
          SbomSpdx                 SPDX SBOM
          AsencEncryptionArchive
        None for .irx/.config/.login/.scan/.scant.
        360° limits uploads to 2 GB, names must be ASCII, the id is valid for 30 minutes.
        """
        p = Path(path)
        if not p.is_file():
            raise AS360Error(f"File not found: {p}")
        if not p.name.isascii():
            raise AS360Error(f"Upload file name must be ASCII only: {p.name}")
        size_mb = p.stat().st_size / 1_048_576
        if size_mb > 2048:
            raise AS360Error(f"{p.name} is {size_mb:.0f} MB, above the 2 GB upload limit")
        log(f"Uploading {p.name} ({size_mb:.1f} MB) ...")
        params = {"fileType": file_type} if file_type else None
        with open(p, "rb") as fh:
            r = self.s.post(f"{self.api}/FileUpload", params=params,
                            files={"uploadedFile": (p.name, fh)}, timeout=3600)
        self._raise(r, f"Upload of {p.name} failed")
        fid = r.json().get("FileId")
        if not fid:
            raise AS360Error(f"No FileId returned for {p.name}: {r.text[:300]}")
        log(f"Uploaded {p.name} -> FileId {fid}", "OK")
        return fid

    # ------------------------------------------------------------ apps / asset groups
    def asset_groups(self) -> list:
        return self.items(self.get("AssetGroups", **{"$top": 500}))

    def asset_group_exists(self, asset_group_id: str) -> bool:
        return any(g.get("Id") == asset_group_id for g in self.asset_groups())

    def resolve_asset_group(self, id_or_name: str | None) -> str | None:
        """Accept an asset group Id or Name; '' / None -> the default asset group if the API flags one."""
        groups = self.asset_groups()
        if not id_or_name:
            default = next((g for g in groups if g.get("IsDefault")), None)
            if default:
                log(f"Using default asset group '{default.get('Name')}' ({default['Id']})")
                return default["Id"]
            if len(groups) == 1:
                log(f"Using the only asset group '{groups[0].get('Name')}' ({groups[0]['Id']})")
                return groups[0]["Id"]
            return None
        for g in groups:
            if g.get("Id") == id_or_name:
                return g["Id"]
        for g in groups:
            if str(g.get("Name", "")).lower() == id_or_name.lower():
                log(f"Asset group '{g['Name']}' -> {g['Id']}")
                return g["Id"]
        die(f"Asset group '{id_or_name}' not found. Available: " + ", ".join(f"{g.get('Name')} ({g.get('Id')})" for g in groups))

    def find_app(self, name: str) -> dict | None:
        flt = f"Name eq '{name.replace(chr(39), chr(39) * 2)}'"
        apps = self.items(self.get("Apps", **{"$filter": flt, "$top": 5}))
        return apps[0] if apps else None

    def get_app(self, app_id: str) -> dict:
        apps = self.items(self.get("Apps", **{"$filter": f"Id eq {app_id}"}))
        if not apps:
            raise AS360Error(f"Application {app_id} not found")
        return apps[0]

    def create_app(self, name: str, asset_group_id: str, **extra) -> dict:
        payload = {"Name": name, "AssetGroupId": asset_group_id, "UseOnlyAppPresences": False}
        payload.update(extra)
        return self.post("Apps", payload)

    def get_or_create_app(self, name: str, asset_group_id: str | None, **extra) -> str:
        app = self.find_app(name)
        if app:
            log(f"Application '{name}' exists, AppId {app['Id']}")
            return app["Id"]
        if not asset_group_id:
            die(f"Application '{name}' does not exist and no asset group id was given to create it.")
        if not self.asset_group_exists(asset_group_id):
            die(f"Asset group {asset_group_id} does not exist or is not visible to this API key.")
        app = self.create_app(name, asset_group_id, **extra)
        log(f"Created application '{name}', AppId {app['Id']}", "OK")
        return app["Id"]

    # ------------------------------------------------------------ scans
    def create_scan(self, tech: str, payload: dict) -> dict:
        """tech: Sast | Sca | Dast   -> POST /api/v4/Scans/{tech}"""
        return self.post(f"Scans/{tech}", payload)

    def scan_details(self, tech: str, scan_id: str) -> dict:
        return self.get(f"Scans/{tech}/{scan_id}")

    def scan_basic(self, scan_id: str) -> dict:
        items = self.items(self.get("Scans", **{"$filter": f"Id eq {scan_id}"}))
        if not items:
            raise AS360Error(f"Scan {scan_id} not found")
        return items[0]

    def rescan(self, scan_id: str, file_id: str | None = None, *, comment: str = "",
               retest_only: bool = False) -> dict:
        """POST /api/v4/Scans/{id}/Executions (ScanExecute: FileId, Comment, IsRetestOnly, ...)."""
        payload: dict = {"Comment": comment or "Re-executed from GitLab CI/CD", "IsRetestOnly": retest_only}
        if file_id:
            payload["FileId"] = file_id
        return self.post(f"Scans/{scan_id}/Executions", payload)

    def executions(self, scan_id: str) -> list:
        return self.items(self.get(f"Scans/{scan_id}/Executions"))

    def wait_for_scan(self, tech: str, scan_id: str, *, poll: int = 30, timeout_min: int = 360,
                      fail_on: Iterable[str] = ("Failed",)) -> dict:
        """Poll LatestExecution.Status until final. Returns the scan detail object."""
        log(f"Waiting for {tech} scan {scan_id} (poll {poll}s, timeout {timeout_min} min) ...")
        deadline = time.time() + timeout_min * 60
        last = None
        while time.time() < deadline:
            try:
                d = self.scan_details(tech, scan_id)
            except AS360Error as e:
                log(f"Status check failed, will retry: {e}", "WARN")
                time.sleep(poll)
                continue
            ex = d.get("LatestExecution") or {}
            status = ex.get("Status") or d.get("Status") or "Unknown"
            progress = ex.get("Progress")
            pct = f" ({progress}%)" if isinstance(progress, (int, float)) and 0 <= progress <= 100 else ""
            if status != last:
                log(f"Scan status: {status}{pct}")
                last = status
            if status in fail_on:
                msg = ex.get("UserMessage") or ex.get("ExecutionError") or ""
                raise AS360Error(f"Scan {scan_id} finished with status {status}. {msg}")
            if status in FINAL_STATES:
                return d
            time.sleep(poll)
        raise AS360Error(f"Timed out after {timeout_min} minutes waiting for scan {scan_id}")

    # ------------------------------------------------------------ issues
    def issues(self, scope: str, scope_id: str, **odata) -> list:
        """GET /api/v4/Issues/{Scan|Application|ScanExecution}/{id}  (paged)."""
        out: list = []
        top = 500
        skip = 0
        while True:
            params = {"$top": top, "$skip": skip, "applyPolicies": "None"}
            params.update(odata)
            page = self.items(self.get(f"Issues/{scope}/{scope_id}", **params))
            out.extend(page)
            if len(page) < top:
                return out
            skip += top

    def noncompliant_issues(self, app_id: str, policy_id: str) -> list:
        return self.items(self.get(f"Issues/Application/{app_id}",
                                   selectPolicyIds=policy_id, applyPolicies="Select",
                                   **{"$select": "Severity,IssueType,Location,Id,Status"}))

    # ------------------------------------------------------------ reports
    def request_report(self, scan_id: str, file_type: str = "Html", *, title: str = "", notes: str = "",
                       apply_policies: str = "None", select_policy_ids: list | None = None,
                       odata_filter: str = "", scope: str = "Scan") -> str:
        """POST /api/v4/Reports/Security/{Application|Scan|ScanExecution}/{id}
        SecurityReportOptions.ReportFileType: Pdf | Html | Xml | Csv | Sarif"""
        cfg = {
            "ReportFileType": file_type.capitalize(), "Title": title, "Notes": notes, "Locale": "en-US",
            "ApplicationDetails": True, "Summary": True, "Details": True, "Discussion": True, "Overview": True,
            "TableOfContent": True, "History": True, "Coverage": True, "MinimizeDetails": True, "Articles": True,
            "ApplicationCustomFields": False, "IssueCustomFields": True,
        }
        body = {"Configuration": cfg, "OdataFilter": odata_filter, "ApplyPolicies": apply_policies}
        if select_policy_ids:
            body["SelectPolicyIds"] = select_policy_ids
        r = self.post(f"Reports/Security/{scope}/{scan_id}", body)
        rid = r.get("Id")
        if not rid:
            raise AS360Error(f"Report request returned no Id: {r}")
        return rid

    def wait_for_report(self, report_id: str, poll: int = 15, timeout_min: int = 60) -> None:
        deadline = time.time() + timeout_min * 60
        while time.time() < deadline:
            items = self.items(self.get("Reports", **{"$filter": f"Id eq {report_id}"}))
            status = (items[0].get("Status") if items else None) or "Unknown"
            if status == "Ready":
                return
            if status == "Failed":
                raise AS360Error(f"Report {report_id} generation failed")
            log(f"Report {report_id}: {status}")
            time.sleep(poll)
        raise AS360Error(f"Timed out waiting for report {report_id}")

    def download_report(self, report_id: str, dest: Path) -> Path:
        return self.download(f"Reports/{report_id}/Download", dest)

    def request_license_report(self, scan_id: str, file_type: str = "Html", *, title: str = "", scope: str = "Scan") -> str:
        """POST /api/v4/Reports/License/{scope}/{id} (SCA license report)."""
        r = self.post(f"Reports/License/{scope}/{scan_id}",
                      {"OdataFilter": "", "Configuration": {"ReportFileType": file_type.capitalize(), "Title": title,
                                                           "Notes": "", "Locale": "en-US", "ApplicationDetails": True}})
        return r.get("Id") or self._no_id(r)

    def request_sbom_report(self, execution_id: str, sbom_format: str = "SPDX_Json", file_name: str = "sbom") -> str:
        """POST /api/v4/Reports/Sbom/{scanExecutionId}; SbomFormat: SPDX_Json | SPDX_Text | CycloneDX_Json | CycloneDX_XML"""
        r = self.post(f"Reports/Sbom/{execution_id}",
                      {"SbomFormat": sbom_format, "FileName": file_name, "DocumentName": file_name,
                       "OrganizationName": "", "CreatorName": "GitLab CI", "CreatorEmail": ""})
        return r.get("Id") or self._no_id(r)

    @staticmethod
    def _no_id(r):
        raise AS360Error(f"Report request returned no Id: {r}")

    def export_issues(self, scan_id: str, fmt: str, dest: Path) -> Path:
        """GET /api/v4/Issues/Scan/{id} as application/json or text/csv (swagger lists both).
        SARIF is produced by the report job (ReportFileType=Sarif), see request_report."""
        accept = {"csv": "text/csv", "json": "application/json"}[fmt]
        r = self.s.get(f"{self.api}/Issues/Scan/{scan_id}", headers={"Accept": accept},
                       params={"applyPolicies": "None", "$top": 100000}, timeout=600)
        self._raise(r, f"Export {fmt} failed")
        dest.write_bytes(r.content)
        return dest

    # ------------------------------------------------------------ SCA licenses
    def sca_licenses(self, scope_id: str, scope: str = "ScanExecution") -> list:
        """GET /api/v4/OsLibraries/GetLicForScope/{scope}/{id} -> LicenseModel (LicenseName, RiskLevel, ...)"""
        return self.items(self.get(f"OsLibraries/GetLicForScope/{scope}/{scope_id}", **{"$top": 5000}))

    def sca_libraries(self, scope_id: str, scope: str = "ScanExecution") -> list:
        """GET /api/v4/OsLibraries/GetLibrariesForScope/{scope}/{id} -> LibraryModel (LibraryName, Version, Licenses[], HighestIssueSeverity)"""
        return self.items(self.get(f"OsLibraries/GetLibrariesForScope/{scope}/{scope_id}", applyPolicies="None", **{"$top": 5000}))

    # ------------------------------------------------------------ presences
    def presences(self) -> list:
        return self.items(self.get("Presences"))

    def create_presence(self, name: str) -> dict:
        return self.post("Presences", {"PresenceName": name})

    def download_presence(self, presence_id: str, platform: str, dest: Path) -> Path:
        return self.download(f"Presences/{presence_id}/Download/{platform}", dest)

    def delete_presence(self, presence_id: str) -> None:
        self.delete(f"Presences/{presence_id}")

    # ------------------------------------------------------------ tools
    def download_saclient(self, dest: Path, tool_type: str | None = None) -> Path:
        """GET /api/v4/Tools/SAClientUtilByType?toolType=Win|Linux|Mac(|*Gui).
        SAClientUtil MUST come from the 360° instance (cloud build is not compatible)."""
        from .common import SACLIENT_TOOL_TYPE
        return self.download("Tools/SAClientUtilByType", dest, toolType=(tool_type or SACLIENT_TOOL_TYPE).capitalize())

    def saclient_version(self, tool_type: str = "Linux") -> str | None:
        try:
            r = self.s.get(f"{self.api}/Tools/SAClientUtilByType", params={"toolType": tool_type, "meta": "true"},
                           timeout=30)
            return r.text.strip() if r.ok else None
        except requests.RequestException:
            return None


def client_from_env(args=None) -> AS360Client:
    """Build a client from CLI args (argparse namespace) falling back to CI variables."""
    from .common import env, env_bool
    base = (getattr(args, "service_url", None) or env("APPSCAN_SERVICE_URL", None, "serviceUrl", "AS360_HOSTNAME"))
    key = getattr(args, "key_id", None) or env("APPSCAN_KEY", None, "appscanApiKeyId", "asocApiKeyId", "AS360_KEYID")
    sec = getattr(args, "key_secret", None) or env("APPSCAN_SECRET", None, "appscanApiKeySecret", "asocApiKeySecret", "AS360_SECRETID")
    if not base or not key or not sec:
        die("APPSCAN_SERVICE_URL, APPSCAN_KEY and APPSCAN_SECRET are required (or --service-url/--key-id/--key-secret).")
    ca = getattr(args, "ca_bundle", None) or env("APPSCAN_CA_BUNDLE")
    accept_untrusted = getattr(args, "accept_untrusted_ssl", None)
    if accept_untrusted is None:
        accept_untrusted = env_bool("APPSCAN_ACCEPT_UNTRUSTED_SSL", True, "acceptUntrustedSsl")
    verify: bool | str = ca if ca else (not accept_untrusted)
    auth = getattr(args, "auth_mode", None) or env("APPSCAN_AUTH_MODE", "token")
    ct = "gitlab-ci-python-" + (env("CI_PIPELINE_ID") or "local")
    return AS360Client(base, key, sec, verify=verify, auth_mode=auth, client_type=ct,
                       timeout=int(env("APPSCAN_HTTP_TIMEOUT", "60")))
