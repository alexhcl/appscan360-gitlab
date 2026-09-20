"""SCA (Software Composition Analysis) scan.

Sources for the IRX (all via SAClientUtil from the 360° host):
  source     - appscan.sh prepare_sca             (== prepare -oso; package-manager files + source)
  image      - appscan.sh prepare_sca -image X    (Docker image name/digest/archive; docker CLI needed)
  container  - appscan.sh prepare_sca -container  (running container / archive)
  sbom       - appscan.sh prepare_sbom file.spdx.json  (SPDX 2.3 SBOM, no source needed)

Then: POST /api/v4/Scans/Sca {AppId, ApplicationFileId, ScanName, Execute, ...}
Licenses per execution: GET /api/v4/OSLibraries/GetLicensesForScope/ScanExecution/{execId}
"""
from __future__ import annotations

from pathlib import Path

from .client import AS360Client
from .common import log, die, state_save
from . import saclient
from .sast import _safe, _log_counts


def run_sca(client: AS360Client, args) -> str:
    source = Path(args.target or ".").resolve()
    work = Path(args.work_dir or ".appscan360").resolve()
    work.mkdir(exist_ok=True)
    scan_name = args.scan_name
    accept_ssl = client.s.verify is False
    appscan_sh = saclient.install_saclient(client)

    kind = (args.sca_source or "source").lower()
    if kind == "image":
        irx = saclient.prepare_sca_irx(appscan_sh, source, name=_safe(scan_name), out_dir=work,
                                       accept_ssl=accept_ssl, image=args.image, debug=args.debug)
    elif kind == "container":
        irx = saclient.prepare_sca_irx(appscan_sh, source, name=_safe(scan_name), out_dir=work,
                                       accept_ssl=accept_ssl, container=args.container, debug=args.debug)
    elif kind == "sbom":
        irx = saclient.prepare_sbom_irx(appscan_sh, Path(args.sbom_file), name=_safe(scan_name), out_dir=work,
                                        accept_ssl=accept_ssl)
    else:
        irx = saclient.prepare_sca_irx(appscan_sh, source, name=_safe(scan_name), out_dir=work,
                                       accept_ssl=accept_ssl, no_config_files=not args.consider_pkg_manager,
                                       debug=args.debug)

    file_id = client.upload_file(irx)
    payload = {
        "AppId": args.app_id,
        "ApplicationFileId": file_id,
        "ScanName": f"SCA {scan_name}",
        "Description": args.description or "",
        "Execute": True,
        "Personal": bool(args.personal),
        "Locale": "en-US",
        "EnableMailNotification": False,
        "Comment": args.comment or "Scan triggered by GitLab CI/CD",
    }
    if args.rescan_id:
        r = client.rescan(args.rescan_id, file_id, comment=args.comment or "")
        scan_id = args.rescan_id
        log(f"Re-executed SCA scan {scan_id}, execution {r.get('Id')}", "OK")
    else:
        r = client.create_scan("Sca", payload)
        scan_id = r.get("Id") or die(f"Scan creation returned no Id: {r}")
        log(f"SCA scan created: {scan_id}", "OK")
    state_save(scan_id=scan_id, scan_tech="Sca", app_id=args.app_id, scan_name=scan_name)

    if args.wait:
        d = client.wait_for_scan("Sca", scan_id, poll=args.poll_interval, timeout_min=args.timeout_minutes)
        state_save(execution_id=(d.get("LatestExecution") or {}).get("Id"))
        _log_counts(d)
    return scan_id
