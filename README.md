# HCL AppScan 360° ↔ GitLab CI/CD (Python edition)

Runs **SAST**, **SCA** and **DAST** scans on your self-managed **HCL AppScan 360°** (REST API v4, request bodies validated against the 2.2.0 `swagger.json`) from GitLab pipelines, downloads reports, feeds findings into the GitLab security widget and applies security gates. It is a port of the official *Integration-ASoC-and-Gitlab* bash scripts and the earlier bash 360° port, rewritten in Python with the missing features added.

```
yaml/                     THE configuration: base (global settings) + sast/sca/dast/dast-api job templates.
                          Every setting with its default lives here; a project includes one remote line and
                          overrides per group/project with CI/CD variables of the same name.
appscan360.py, as360/     the Python integration (cloned by the job)
set-origin.sh             stamps your GitHub/GitLab repo URL into all templates
Dockerfile                optional runner image (SAClientUtil from your 360° host baked in)
examples/                 appscan-config.xml, API payload override, all-in-one pipeline
```

## 1. Setup (central repo on GitHub, one file per project)

1. Push this folder to GitHub or GitLab (any location) and tag it, e.g. `v1`. Nothing in the files depends on the location.
2. In AppScan 360°: **Settings → API** → generate Key ID / Secret; note an **asset group id**.
3. In GitLab, at **group** level (Settings → CI/CD → Variables, masked) so every project inherits them:
   | Variable | Value |
   |---|---|
   | `APPSCAN_TEMPLATES_URL` | raw base URL of the central repo at a ref, e.g. `https://raw.githubusercontent.com/<owner>/appscan360-gitlab/v1` or `https://gitlab.example.com/<group>/appscan360-gitlab/-/raw/v1` |
   | `APPSCAN_SCRIPTS_GIT_URL` | clone URL, e.g. `https://github.com/<owner>/appscan360-gitlab.git` (GitLab: `https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/<group>/appscan360-gitlab.git`) |
   | `APPSCAN_SCRIPTS_GIT_REF` | `v1` |
   | `APPSCAN_SERVICE_URL` | `https://appscan360.example.com` |
   | `APPSCAN_KEY` / `APPSCAN_SECRET` | API key id / secret |
   | `APPSCAN_ASSET` | asset group id |
   | `GITHUB_TOKEN` *(private repo only)* | fine-grained PAT, read access to the central repo |
   | `APPSCAN_CA_BUNDLE` *(optional)* | file variable with the CA PEM |
4. Projects need **nothing copied**. Either
   * add one line to the project's `.gitlab-ci.yml` (see `examples/project-gitlab-ci.yml`):
     `include: - remote: '$APPSCAN_TEMPLATES_URL/yaml/appscan360_scan_sast.yaml'`
   * or (Premium/Ultimate) attach `examples/compliance-framework.yml` as a compliance-framework pipeline so every project in the group runs the scans with no file change at all.
   Defaults for every setting are in `yaml/appscan360_base.yaml` (global) and `yaml/appscan360_scan_*.yaml` (per scan). To change a value for one project set a CI/CD variable of the same name in the GitLab UI (e.g. `DAST_URL`, `APPSCAN_MAX_ISSUES_ALLOWED`); to change it for everyone edit the template in GitHub.
5. Register a runner (Docker executor) that can reach both GitHub/GitLab and the 360° host.

Moving the central repo later = changing the three group variables; no file changes. **Private central repo — three template sets, same content:**
| Central repo | Folder | Auth |
|---|---|---|
| public (GitHub/GitLab) | `yaml/` | none |
| private, same GitLab instance (Option A) | `yaml-gitlab-private/` | GitLab permissions + `CI_JOB_TOKEN` |
| private, other GitLab instance (Option B) | `yaml-gitlab-remote-private/` | project access token via `?private_token=$APPSCAN_TEMPLATES_TOKEN` |

Option A details: use the templates in `yaml-gitlab-private/` (`include: project:` with `$APPSCAN_TEMPLATES_PROJECT` / `$APPSCAN_TEMPLATES_REF`, see `examples/project-gitlab-ci-private-gitlab.yml`), clone with `gitlab-ci-token:${CI_JOB_TOKEN}@…`, and allow the consuming group in the central project's Job token permissions. Private repo: the job clone works with a token in `APPSCAN_SCRIPTS_GIT_URL`, but GitLab's `include: remote:` cannot authenticate, so keep the templates readable (public repo, or a GitLab project in the same instance using `include: project:` with `$APPSCAN_TEMPLATES_PROJECT`/`ref`).

Alternatives: `APPSCAN_SCRIPTS_SOURCE=repo` (commit `appscan360/` + `yaml/` into the project) or `runner` (Dockerfile image with scripts at `/opt/appscan360`).

Each step is one `script:` line; state (app id, scan id, tech, execution id) is shared through `.appscan360-state.json`.

## 2. Feature matrix

| Area | Feature | Variable / flag |
|---|---|---|
| Auth | bearer token (`ApiKeyLogin`) or **direct `X-Api-Key`** | `APPSCAN_AUTH_MODE=token\|direct` |
| TLS | CA bundle or accept self-signed | `APPSCAN_CA_BUNDLE`, `APPSCAN_ACCEPT_UNTRUSTED_SSL` |
| App | find by name, create in asset group, business impact | `APPSCAN_APP_NAME`, `APPSCAN_ASSET`, `APPSCAN_BUSINESS_IMPACT` |
| SAST | **IRX on runner** (`appscan.sh prepare`) *or* **zip upload** (`fileType=SourceCodeArchive`, 360° prepares it) *or* auto | `SAST_UPLOAD_MODE=auto\|irx\|zip` |
| SAST | source-code-only, secrets (`-es/-ds/-so`), third-party (`-t`), scan speed (`-s`), JDK path, config file, latest-commit-only, include SCA in same IRX, zip excludes | `SAST_*` |
| SCA | source tree (`prepare_sca`), **docker image / container** (`-image/-container`), **SBOM** (`prepare_sbom`, SPDX 2.3), `-nc` | `SCA_SOURCE`, `SCA_IMAGE`, `SCA_CONTAINER`, `SCA_SBOM_FILE` |
| DAST web | starting URL, additional domains, excluded/included paths (regex with `re:`), scan-below-directory, case-sensitive paths | `DAST_URL`, `DAST_ADDITIONAL_DOMAINS`, `DAST_EXCLUDE_PATHS`, `DAST_INCLUDE_PATHS` |
| DAST login | none / **username+password** (+extra field) / **recorded** (`.config` Activity Recorder or `.login` AppScan Standard), HTTP auth (Basic/NTLM/…), **TOTP/OTP** | `DAST_LOGIN_METHOD`, `DAST_LOGIN_FILE`, `DAST_HTTP_AUTH_*`, `DAST_OTP_*` |
| DAST explore | manual-explore / recorded traffic files (`.dast.config`, `.har`), multi-step recordings, **test-only** | `DAST_EXPLORE_FILES`, `DAST_MULTISTEP_FILES`, `DAST_TEST_ONLY` |
| DAST tests | custom test policy id, optimization level, login/logout page tests, vulnerable components, form fill, threads, timeout, request rate, scan priority, saved scan template id | `DAST_TEST_POLICY_ID`, `DAST_OPTIMIZATION`, `DAST_THREADS`, `DAST_SCAN_PRIORITY`, `DAST_SCAN_TEMPLATE_ID` |
| DAST file | AppScan Standard **`.scan` / `.scant`**, `TestOperation=None\|Retest\|ContinueTest\|ReportOnly` | `DAST_MODE=file`, `DAST_SCAN_FILE`, `DAST_TEST_OPERATION` |
| DAST API | **Postman** (collection + env + globals + linked zip), **OpenAPI** (file or URL, base URL, API keys), **recorded API traffic**, domains to test | `DAST_MODE=api`, `DAST_API_METHOD`, `DAST_*` |
| Presence | existing Presence id, or **ephemeral Presence started on the runner** and deleted afterwards | `DAST_PRESENCE_ID`, `DAST_EPHEMERAL_PRESENCE` |
| All scans | personal scan, comment, **rescan** existing scan id, wait/poll/timeout, URL validation | `APPSCAN_PERSONAL_SCAN`, `APPSCAN_RESCAN_ID`, `APPSCAN_TIMEOUT_MINUTES` |
| Reports | HTML / **PDF** / XML / **CSV** / **SARIF** security report, JSON issue export, **GitLab security report** (`gl-sast-report.json`, `gl-dast-report.json`, `gl-dependency-scanning-report.json`), SCA **license report** and **SBOM** (SPDX / CycloneDX) | `APPSCAN_REPORT_FORMATS`, `APPSCAN_SBOM_FORMAT` |
| Gates | `severity` (count of sevSecGw ≤ max), `threshold` (no issue ≥ severity), `branch` (feature/qa/release rules), `compliance` (app policies, lists non-compliant issues), `license` (SCA license risk) | `APPSCAN_GATES`, `APPSCAN_SEV_SEC_GW`, `APPSCAN_MAX_ISSUES_ALLOWED`, `APPSCAN_FAILURE_THRESHOLD`, `SCA_FAIL_LICENSE_RISK` |

Run `python3 appscan360.py <cmd> --help` for the full list; every flag shows its environment variable.

## 3. SAST: IRX vs zip

AppScan 360° accepts either. Rule of thumb:

* **zip** (no SAClientUtil needed, `python:3.12-slim` image is enough): archive of the whole tree, ≤ 2 GB, ASCII names. C/C++, .NET and "other" languages are scanned as source; **Java archives are scanned as bytecode** by default – put `appscan-config.xml` with `sourceCodeOnly="true"` at the archive root to scan Java source instead. Not supported in archives: .NET assemblies, `.sln`, Ruby `.gem`, Windows reserved file names.
* **irx** (SAClientUtil downloaded from *your* 360° host, needs JDK/Maven for Java): required for .NET Core, JDK selection, `-s` scan speed, secrets flags, third-party inclusion and latest-commit-only scans. `appscan.sh update` is never run – the client version is tied to the 360° install.

## 4. DAST request body

All DAST bodies follow the `NewDastScan` schema of the 360° 2.2.0 `swagger.json` (see the docstring of `as360/dast.py` for the full tree):

* Web scan → `ScanConfiguration.{Target,Login,HttpAuth,Otp,Communication,Tests,ApplicationElements}`, `LoginSequenceFileId`, `LoginConfigurationType`, `ExploreItems[{FileId,TrafficType}]`.
* Postman → top-level `PostmanCollectionFiles.{CollectionJsonFileId,EnvironmentJsonFileId,GlobalJsonFileId,AdditionalZipFileId}` (files uploaded with `fileType=DastPostmanCollectionJson|DastPostmanCollectionZip`).
* OpenAPI → `ScanConfiguration.OpenAPI.{BaseUrl,Url|FileId,LoginKeys[{KeyName,KeyValue}]}` (`fileType=DastOpenAPIFile`), `LoginConfigurationType=ApiKeyLogin` when keys are given.
* `.scan/.scant` → `ScanOrTemplateFileId` + `TestOperation` (`None` full scan, `Retest` = test only with the explore data in the file, `ContinueTest`, `ReportOnly` = import results). `ScanConfiguration` is not sent in this mode.
* Domains: without a Presence every domain (starting URL + `AdditionalDomains`) must be verified/allowed in 360°.

**Test-only on a new web scan:** `NewDastScan` does not declare `TestOnly` (it is only on the read model), so `DAST_TEST_ONLY=yes` sends it best-effort. The supported way to run tests only against recorded traffic is a `.scan` file with `DAST_TEST_OPERATION=Retest`, or `APPSCAN_RESCAN_ID` (uses `IsRetestOnly` on `POST /Scans/{id}/Executions`).

Anything not exposed by the CLI (Recurrence, `ScanConfiguration.Llm`, …) can be added with `DAST_PAYLOAD_JSON` (deep-merged; see `examples/dast_api_payload_override.json`). The generated request (secrets redacted) is saved as `.appscan360/dast_payload.json` and kept as a job artifact.

## 5. Ephemeral Presence

`DAST_EPHEMERAL_PRESENCE=yes` creates a Presence named after the job, downloads the `linux_x64` package from 360°, runs `startPresence.sh` on the runner, waits for it to become active, runs the scan with `PresenceId`, and deletes the Presence at the end (also on failure). Use it to scan an app started as a GitLab `services:` container. The runner needs outbound access to the 360° host.

## 6. Windows runners

The Python code detects the OS automatically (SAClientUtil `Win`/`Linux`/`Mac` download, `appscan.bat` vs `appscan.sh`, Presence `win_x64`/`linux_x64`). Only the job's `before_script` is shell-specific, so each template folder has a `*_windows.yaml` twin with a PowerShell `before_script`: on a Windows runner (shell executor, PowerShell, Python 3 and Git on PATH) include `appscan360_scan_sast_windows.yaml` instead of `appscan360_scan_sast.yaml`. Same variables, same behaviour. A project can carry both jobs with `rules:` on a variable if it has mixed runners. Note: .NET (non-Core) SAST needs the Windows SAClientUtil, which this makes possible.

## 7. Not covered / notes

* IAST (agent-based) is not part of this integration.
* .NET (non-Core) IRX generation needs a Windows runner (use the `*_windows.yaml` templates).
* `SCA_SOURCE=image|container` needs a docker CLI and socket in the job (use the Dockerfile image with `/var/run/docker.sock` mounted or a DinD service).
* The example script you had (`as360_scan.py`) embeds a live key id/secret – rotate that key and use masked CI/CD variables.
