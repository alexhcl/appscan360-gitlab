#!/usr/bin/env python3
"""HCL AppScan 360° <-> GitLab CI/CD integration (Python edition).

Subcommands (each can be a separate `script:` line; state is shared via .appscan360-state.json):

  app        ensure the application exists (create in asset group if missing)  -> app_id
  sast       SAST scan: IRX generated on the runner OR zipped source uploaded to 360°
  sca        SCA scan: source tree | docker image | container | SPDX SBOM
  dast       DAST scan: web app (login none/userpass/recorded, explore files, presence),
             API (Postman / OpenAPI / recorded traffic), or .scan/.scant file
  report     HTML / PDF / XML report, CSV / JSON / SARIF export, GitLab security report
  gate       severity | threshold | branch | compliance | license
  presence   create/delete an AppScan Presence (for private targets)
  irx        only generate an IRX (no upload) - e.g. to keep it as an artifact

Every option has an environment-variable equivalent (shown in --help), so the
GitLab templates in yaml/ only need to set CI/CD variables.

Examples
  python3 appscan360.py app  --app-name "$CI_PROJECT_NAME" --asset-group-id "$APPSCAN_ASSET"
  python3 appscan360.py sast --upload-mode zip --wait
  python3 appscan360.py dast --url https://demo.testfire.net --login-method recorded --login-file login.dast.config
  python3 appscan360.py dast --dast-mode api --api-method openapi --openapi-file openapi.yaml --api-base-url https://api.example.com
  python3 appscan360.py report --formats html,xml,gitlab
  python3 appscan360.py gate severity --sev-sec-gw highIssues --max-issues-allowed 0
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from as360.common import env, env_bool, env_int, log, die, state_save, state_get, scan_name_default  # noqa: E402
from as360.client import client_from_env, AS360Error  # noqa: E402


def _bool_flag(p: argparse.ArgumentParser, name: str, envname: str, default: bool, help_: str) -> None:
    p.add_argument(f"--{name}", dest=name.replace("-", "_"), action=argparse.BooleanOptionalAction,
                   default=env_bool(envname, default), help=f"{help_} [env {envname}, default {default}]")


def add_common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("connection")
    g.add_argument("--service-url", default=None, help="AppScan 360° host, e.g. https://appscan360.example.com [env APPSCAN_SERVICE_URL]")
    g.add_argument("--key-id", default=None, help="[env APPSCAN_KEY]")
    g.add_argument("--key-secret", default=None, help="[env APPSCAN_SECRET]")
    g.add_argument("--auth-mode", choices=["token", "direct"], default=None,
                   help="token = ApiKeyLogin bearer token; direct = X-Api-Key header [env APPSCAN_AUTH_MODE]")
    g.add_argument("--ca-bundle", default=None, help="PEM bundle to trust the 360° certificate [env APPSCAN_CA_BUNDLE]")
    g.add_argument("--accept-untrusted-ssl", action=argparse.BooleanOptionalAction, default=None,
                   help="accept self-signed certs (ignored when --ca-bundle set) [env APPSCAN_ACCEPT_UNTRUSTED_SSL, default true]")
    g.add_argument("--work-dir", default=env("APPSCAN_WORK_DIR", ".appscan360"))


def add_scan_common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("scan")
    g.add_argument("--app-id", default=env("APPSCAN_APP_ID", None, "appId"), help="[env APPSCAN_APP_ID or from app step]")
    g.add_argument("--scan-name", default=env("APPSCAN_SCAN_NAME", None, "scanName") or scan_name_default())
    g.add_argument("--comment", default=env("APPSCAN_SCAN_COMMENT"))
    g.add_argument("--description", default=env("APPSCAN_SCAN_DESCRIPTION"))
    g.add_argument("--rescan-id", default=env("APPSCAN_RESCAN_ID"), help="re-execute an existing scan id instead of creating a new one")
    _bool_flag(g, "personal", "APPSCAN_PERSONAL_SCAN", False, "personal scan (does not affect app issues/compliance)")
    _bool_flag(g, "wait", "APPSCAN_WAIT", True, "wait for the scan to finish")
    g.add_argument("--poll-interval", type=int, default=env_int("APPSCAN_POLL_SECONDS", 30))
    g.add_argument("--timeout-minutes", type=int, default=env_int("APPSCAN_TIMEOUT_MINUTES", 360))
    g.add_argument("--debug", action="store_true", default=env_bool("APPSCAN_DEBUG"))
    g.add_argument("--verbose", action="store_true", default=env_bool("APPSCAN_VERBOSE"))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    # ---- app
    p = sub.add_parser("app", help="get or create the application")
    add_common(p)
    p.add_argument("--app-id", default=env("APPSCAN_APP_ID", None, "appId"),
                   help="use this existing application (verified, never created) [env APPSCAN_APP_ID]")
    p.add_argument("--app-name", default=env("APPSCAN_APP_NAME", None, "appscanAppName", "asocAppName", "CI_PROJECT_NAME"))
    p.add_argument("--asset-group-id", default=env("APPSCAN_ASSET", None, "assetGroupId"))
    p.add_argument("--business-impact", default=env("APPSCAN_BUSINESS_IMPACT"), help="Low|Medium|High|Critical (on create)")

    # ---- sast
    p = sub.add_parser("sast", help="static analysis")
    add_common(p); add_scan_common(p)
    p.add_argument("--target", default=env("APPSCAN_TARGET", "."))
    p.add_argument("--upload-mode", choices=["auto", "irx", "zip"], default=env("SAST_UPLOAD_MODE", "auto"),
                   help="irx = generate IRX on the runner; zip = upload source archive, 360° prepares it")
    p.add_argument("--config-file", default=env("SAST_CONFIG_FILE"), help="appscan-config.xml for prepare (-c)")
    _bool_flag(p, "latest-commit-only", "SAST_LATEST_COMMIT_ONLY", False, "scan only files changed in the last commit (irx mode)")
    _bool_flag(p, "source-code-only", "SAST_SOURCE_CODE_ONLY", False, "-sco: skip binaries")
    _bool_flag(p, "include-sca", "SAST_INCLUDE_SCA", False, "also run SCA in the same IRX (otherwise -sao -nc)")
    _bool_flag(p, "third-party", "SAST_THIRD_PARTY", False, "-t: include third-party Java/.NET code")
    p.add_argument("--secrets", choices=["enable", "disable", "only"], default=env("SAST_SECRETS"), help="-es/-ds/-so")
    p.add_argument("--scan-speed", choices=["simple", "balanced", "deep", "thorough"], default=env("SAST_SCAN_SPEED"))
    p.add_argument("--jdk-path", default=env("SAST_JDK_PATH"))
    p.add_argument("--zip-exclude", default=env("SAST_ZIP_EXCLUDE"), help="comma list of glob patterns to leave out of the archive")

    # ---- sca
    p = sub.add_parser("sca", help="software composition analysis")
    add_common(p); add_scan_common(p)
    p.add_argument("--target", default=env("APPSCAN_TARGET", "."))
    p.add_argument("--sca-source", choices=["source", "image", "container", "sbom"], default=env("SCA_SOURCE", "source"))
    p.add_argument("--image", default=env("SCA_IMAGE"), help="docker image (name, digest or archive)")
    p.add_argument("--container", default=env("SCA_CONTAINER"))
    p.add_argument("--sbom-file", default=env("SCA_SBOM_FILE"), help="SPDX 2.3 SBOM")
    _bool_flag(p, "consider-pkg-manager", "SCA_CONSIDER_PKG_MANAGER", True, "use package-manager config files (no = -nc)")

    # ---- dast
    p = sub.add_parser("dast", help="dynamic analysis")
    add_common(p); add_scan_common(p)
    p.add_argument("--dast-mode", choices=["web", "api", "file"], default=env("DAST_MODE", "web"))
    p.add_argument("--url", default=env("DAST_URL", None, "urlTarget"), help="starting URL")
    p.add_argument("--additional-domains", default=env("DAST_ADDITIONAL_DOMAINS"))
    p.add_argument("--exclude-paths", default=env("DAST_EXCLUDE_PATHS"), help="comma list; prefix 're:' for regex")
    p.add_argument("--include-paths", default=env("DAST_INCLUDE_PATHS"), help="exceptions to excluded paths")
    _bool_flag(p, "scan-below-directory", "DAST_SCAN_BELOW_DIRECTORY", False, "only scan below the starting directory")
    _bool_flag(p, "case-sensitive-paths", "DAST_CASE_SENSITIVE_PATHS", False, "")
    p.add_argument("--scan-template-id", default=env("DAST_SCAN_TEMPLATE_ID"), help="saved scan template id (ScanTemplateId)")
    p.add_argument("--scan-priority", choices=["Regular", "High"], default=env("DAST_SCAN_PRIORITY", "Regular"))
    # login
    p.add_argument("--login-method", choices=["none", "userpass", "recorded"], default=env("DAST_LOGIN_METHOD", "none"))
    p.add_argument("--login-user", default=env("DAST_LOGIN_USER"))
    p.add_argument("--login-password", default=env("DAST_LOGIN_PASSWORD"))
    p.add_argument("--login-extra", default=env("DAST_LOGIN_EXTRA"), help="third credential, e.g. 'PIN=1234'")
    p.add_argument("--login-file", default=env("DAST_LOGIN_FILE", None, "loginDastConfig"),
                   help="login recording (.config from Activity Recorder / .login from AppScan Standard)")
    p.add_argument("--http-auth-user", default=env("DAST_HTTP_AUTH_USER"))
    p.add_argument("--http-auth-password", default=env("DAST_HTTP_AUTH_PASSWORD"))
    p.add_argument("--http-auth-domain", default=env("DAST_HTTP_AUTH_DOMAIN"))
    p.add_argument("--otp-secret", default=env("DAST_OTP_SECRET"), help="TOTP secret for MFA logins")
    p.add_argument("--otp-length", default=env("DAST_OTP_LENGTH", "6"))
    p.add_argument("--otp-hash", choices=["None", "Sha1", "Sha256", "Sha512"], default=env("DAST_OTP_HASH", "Sha1"))
    p.add_argument("--otp-timestep", default=env("DAST_OTP_TIMESTEP", "30"))
    p.add_argument("--otp-http-parameters", default=env("DAST_OTP_HTTP_PARAMETERS"))
    # explore
    p.add_argument("--explore-files", default=env("DAST_EXPLORE_FILES", None, "manualExplorerDastConfig"),
                   help="comma list of recorded traffic files (.dast.config/.har/.exd) used as explore data")
    p.add_argument("--multistep-files", default=env("DAST_MULTISTEP_FILES"), help="multi-step operation recordings")
    _bool_flag(p, "test-only", "DAST_TEST_ONLY", False, "send TestOnly=true (test only recorded traffic; see dast.py note)")
    # tests
    p.add_argument("--test-policy-id", default=env("DAST_TEST_POLICY_ID"), help="CustomTestPolicyId (GET /api/v4/TestPolicies); empty = Default")
    p.add_argument("--optimization", default=env("DAST_OPTIMIZATION", "Fast"), help="NoOptimization|Fast|Faster|Fastest")
    _bool_flag(p, "test-login-pages", "DAST_TEST_LOGIN_PAGES", False, "")
    _bool_flag(p, "test-login-pages-no-session", "DAST_TEST_LOGIN_PAGES_NO_SESSION", False, "")
    _bool_flag(p, "test-logout-pages", "DAST_TEST_LOGOUT_PAGES", False, "")
    _bool_flag(p, "report-vulnerable-components", "DAST_REPORT_VULNERABLE_COMPONENTS", True, "")
    _bool_flag(p, "no-form-fill", "DAST_NO_FORM_FILL", False, "disable automatic form fill")
    p.add_argument("--threads", default=env("DAST_THREADS", "10"))
    p.add_argument("--connection-timeout", default=env("DAST_CONNECTION_TIMEOUT"), help="seconds; unset = automatic")
    p.add_argument("--max-requests", default=env("DAST_MAX_REQUESTS", "10"))
    p.add_argument("--max-requests-timeframe", default=env("DAST_MAX_REQUESTS_TIMEFRAME", "1000"))
    # presence
    p.add_argument("--presence-id", default=env("DAST_PRESENCE_ID", None, "appscanPresenceId"))
    _bool_flag(p, "ephemeral-presence", "DAST_EPHEMERAL_PRESENCE", False, "create a temporary Presence on this runner")
    p.add_argument("--presence-name", default=env("DAST_PRESENCE_NAME"))
    # scan file
    p.add_argument("--scan-file", default=env("DAST_SCAN_FILE", None, "scanFile"), help=".scan or .scant (dast-mode file)")
    p.add_argument("--test-operation", choices=["None", "Retest", "ContinueTest", "ReportOnly"], default=env("DAST_TEST_OPERATION", "None"),
                   help="file mode: None=full scan, Retest=test only with explore data from the file, ContinueTest, ReportOnly=import results")
    # api
    p.add_argument("--api-method", choices=["postman", "openapi", "traffic"], default=env("DAST_API_METHOD"))
    p.add_argument("--api-domains", default=env("DAST_API_DOMAINS"), help="domains to be tested (comma list)")
    p.add_argument("--api-base-url", default=env("DAST_API_BASE_URL"))
    p.add_argument("--api-keys", default=env("DAST_API_KEYS"), help="'name=value,name2=value2' API-key auth for OpenAPI")
    p.add_argument("--postman-collection", default=env("DAST_POSTMAN_COLLECTION"))
    p.add_argument("--postman-env", default=env("DAST_POSTMAN_ENV"))
    p.add_argument("--postman-globals", default=env("DAST_POSTMAN_GLOBALS"))
    p.add_argument("--postman-linked-files", default=env("DAST_POSTMAN_LINKED_FILES"), help="zip of linked files")
    p.add_argument("--openapi-file", default=env("DAST_OPENAPI_FILE"))
    p.add_argument("--openapi-url", default=env("DAST_OPENAPI_URL"))
    p.add_argument("--payload-json", default=env("DAST_PAYLOAD_JSON"), help="JSON file or string deep-merged into the request")

    # ---- report
    p = sub.add_parser("report", help="download reports / exports")
    add_common(p)
    p.add_argument("--scan-id", default=env("APPSCAN_SCAN_ID"))
    p.add_argument("--scan-tech", choices=["Sast", "Sca", "Dast"], default=env("APPSCAN_SCAN_TECH"))
    p.add_argument("--formats", default=env("APPSCAN_REPORT_FORMATS", "html,xml"), help="html,pdf,xml,csv,sarif (report job), json (issues), gitlab, license (SCA), sbom (SCA)")
    p.add_argument("--sbom-format", choices=["SPDX_Json", "SPDX_Text", "CycloneDX_Json", "CycloneDX_XML"], default=env("APPSCAN_SBOM_FORMAT", "SPDX_Json"))
    p.add_argument("--apply-policies", default=env("APPSCAN_REPORT_APPLY_POLICIES", "None"), help="None|All|Select")
    p.add_argument("--out-dir", default=env("APPSCAN_REPORT_DIR", "."))
    p.add_argument("--poll-interval", type=int, default=env_int("APPSCAN_POLL_SECONDS", 15))
    p.add_argument("--timeout-minutes", type=int, default=env_int("APPSCAN_REPORT_TIMEOUT_MINUTES", 60))

    # ---- gate
    p = sub.add_parser("gate", help="security gate")
    add_common(p)
    p.add_argument("gates", nargs="*", default=None, help="severity threshold branch compliance license [env APPSCAN_GATES]")
    p.add_argument("--scan-id", default=env("APPSCAN_SCAN_ID"))
    p.add_argument("--scan-tech", choices=["Sast", "Sca", "Dast"], default=env("APPSCAN_SCAN_TECH"))
    p.add_argument("--app-id", default=env("APPSCAN_APP_ID"))
    p.add_argument("--sev-sec-gw", default=env("APPSCAN_SEV_SEC_GW", None, "sevSecGw"))
    p.add_argument("--max-issues-allowed", type=int, default=env_int("APPSCAN_MAX_ISSUES_ALLOWED", env_int("maxIssuesAllowed", 0)))
    p.add_argument("--failure-threshold", default=env("APPSCAN_FAILURE_THRESHOLD", "High"))
    p.add_argument("--branch", default=None)
    p.add_argument("--fail-license-risk", default=env("SCA_FAIL_LICENSE_RISK", "High"), help="comma list, e.g. High,Medium")
    p.add_argument("--max-list", type=int, default=50)
    _bool_flag(p, "allow-failure", "APPSCAN_GATE_ALLOW_FAILURE", False, "report but do not fail the job")

    # ---- presence
    p = sub.add_parser("presence", help="manage AppScan Presence")
    add_common(p)
    p.add_argument("action", choices=["list", "create", "delete"])
    p.add_argument("--name", default=env("DAST_PRESENCE_NAME"))
    p.add_argument("--presence-id", default=env("DAST_PRESENCE_ID"))

    # ---- irx only
    p = sub.add_parser("irx", help="generate an IRX with SAClientUtil, no upload")
    add_common(p); add_scan_common(p)
    p.add_argument("--target", default=env("APPSCAN_TARGET", "."))
    p.add_argument("--config-file", default=env("SAST_CONFIG_FILE"))
    _bool_flag(p, "source-code-only", "SAST_SOURCE_CODE_ONLY", False, "")
    _bool_flag(p, "open-source-only", "SAST_OPEN_SOURCE_ONLY", False, "")
    p.add_argument("--scan-speed", choices=["simple", "balanced", "deep", "thorough"], default=env("SAST_SCAN_SPEED"))
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with client_from_env(args) as client:
            if args.cmd == "app":
                if args.app_id:
                    app = client.get_app(args.app_id)          # raises if the id does not exist
                    app_id = app["Id"]
                    log(f"Using existing application '{app.get('Name')}' (AppId {app_id})", "OK")
                    state_save(app_id=app_id, app_name=app.get("Name"))
                else:
                    if not args.app_name:
                        die("--app-name / APPSCAN_APP_NAME is required (or give APPSCAN_APP_ID)")
                    extra = {"BusinessImpact": args.business_impact} if args.business_impact else {}
                    app_id = client.get_or_create_app(args.app_name, args.asset_group_id, **extra)
                    state_save(app_id=app_id, app_name=args.app_name)
                Path("appId.txt").write_text(app_id)  # compatibility with the bash edition
                print(app_id)
                return 0

            if args.cmd in ("sast", "sca", "dast"):
                args.app_id = args.app_id or state_get("app_id", None, False)
                if not args.app_id:
                    die("No application id. Run `appscan360.py app` first or set APPSCAN_APP_ID.")
                if args.cmd == "sast":
                    from as360.sast import run_sast
                    scan_id = run_sast(client, args)
                elif args.cmd == "sca":
                    from as360.sca import run_sca
                    scan_id = run_sca(client, args)
                else:
                    from as360.dast import run_dast
                    scan_id = run_dast(client, args)
                Path("scanId.txt").write_text(scan_id)
                Path("scanTech.txt").write_text(args.cmd.capitalize())
                return 0

            if args.cmd == "report":
                from as360.reports import run_report
                run_report(client, args)
                return 0

            if args.cmd == "gate":
                from as360.gate import GATES
                names = args.gates or (env("APPSCAN_GATES", "severity") or "").split(",")
                results = {}
                for name in [n.strip() for n in names if n.strip()]:
                    if name not in GATES:
                        die(f"Unknown gate '{name}'. Choose from {', '.join(GATES)}")
                    results[name] = GATES[name](client, args)
                failed = [n for n, ok in results.items() if not ok]
                if failed:
                    log(f"Gate(s) failed: {', '.join(failed)}", "ERR")
                    return 0 if args.allow_failure else 2
                log("All gates passed", "OK")
                return 0

            if args.cmd == "presence":
                if args.action == "list":
                    for p in client.presences():
                        print(f"{p.get('Id')}  {p.get('PresenceName')}  {p.get('Status')}")
                elif args.action == "create":
                    p = client.create_presence(args.name or f"gitlab-{env('CI_JOB_ID', 'local')}")
                    print(p.get("Id"))
                else:
                    client.delete_presence(args.presence_id or die("--presence-id required"))
                return 0

            if args.cmd == "irx":
                from as360 import saclient
                exe = saclient.install_saclient(client)
                irx = saclient.prepare_irx(exe, Path(args.target).resolve(), name=args.scan_name,
                                           out_dir=Path(args.work_dir).resolve(), accept_ssl=client.s.verify is False,
                                           source_code_only=args.source_code_only, open_source_only=args.open_source_only,
                                           scan_speed=args.scan_speed,
                                           config_file=Path(args.config_file) if args.config_file else None)
                print(irx)
                return 0
    except AS360Error as e:
        die(str(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
