"""SAST scan.

Two upload modes (both supported by AppScan 360°):

  irx   - generate the IRX on the GitLab runner with SAClientUtil (`appscan.sh prepare`)
          and upload it. Needed for Java/.NET bytecode data-flow analysis when the
          build artifacts are on the runner, for .NET Core, for scan-speed/secrets/
          third-party options, and when the source must not leave the runner un-prepared.
  zip   - zip the source tree (optionally + build artifacts) and upload it as
          fileType=SourceCodeArchive. AppScan 360° prepares it server-side.
          Limits: 2 GB, ASCII file names, no .NET assemblies / .sln / .gem,
          Java archives are scanned as bytecode unless appscan-config.xml sets
          sourceCodeOnly=true. (See "About scanning using an archive file".)
  auto  - irx if SAClientUtil is available or can be downloaded, otherwise zip.

POST /api/v4/Scans/Sast  (NewSastScan)
  {AppId, ApplicationFileId, ScanName, Description, Execute, Personal, Locale, Comment, EnableMailNotification}
"""
from __future__ import annotations

import fnmatch
import os
import zipfile
from pathlib import Path

from .client import AS360Client, AS360Error
from .common import log, die, state_save
from . import saclient

DEFAULT_ZIP_EXCLUDES = [".git", ".git/*", "*/.git/*", "node_modules", "*/node_modules/*", ".appscan360",
                        "*/.appscan360/*", "*.irx", ".appscan360-state.json", "*_report.*", "gl-*-report.json"]


def zip_source(source_dir: Path, out_zip: Path, excludes: list[str] | None = None) -> Path:
    """Zip the whole directory tree (relative paths, ASCII names enforced)."""
    excludes = list(DEFAULT_ZIP_EXCLUDES) + (excludes or [])
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    log(f"Zipping {source_dir} -> {out_zip}")
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            rel_root = os.path.relpath(root, source_dir)
            dirs[:] = [d for d in dirs if not _excluded(os.path.normpath(os.path.join(rel_root, d)), excludes)]
            for f in files:
                rel = os.path.normpath(os.path.join(rel_root, f))
                if _excluded(rel, excludes):
                    continue
                if not rel.isascii():
                    log(f"Skipping non-ASCII path (not supported by 360° archive scan): {rel}", "WARN")
                    continue
                zf.write(os.path.join(root, f), rel)
                n += 1
    size = out_zip.stat().st_size / 1_048_576
    log(f"Archive contains {n} files ({size:.1f} MB)", "OK")
    if size > 2048:
        die("Archive exceeds the 2 GB AppScan 360° upload limit. Use IRX mode or exclude directories.")
    return out_zip


def _excluded(rel: str, patterns: list[str]) -> bool:
    rel = rel.replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, p) or rel == p or rel.startswith(p.rstrip("/*") + "/") for p in patterns)


def run_sast(client: AS360Client, args) -> str:
    source = Path(args.target or ".").resolve()
    work = Path(args.work_dir or ".appscan360").resolve()
    work.mkdir(exist_ok=True)
    scan_name = args.scan_name
    mode = (args.upload_mode or "auto").lower()
    accept_ssl = client.s.verify is False

    # ---- decide mode
    appscan_sh = None
    if mode in ("irx", "auto"):
        try:
            appscan_sh = saclient.install_saclient(client)
        except (AS360Error, SystemExit) as e:
            if mode == "irx":
                raise
            log(f"SAClientUtil unavailable ({e}); falling back to zip upload", "WARN")
    mode = "irx" if appscan_sh else "zip"
    log(f"SAST upload mode: {mode}")

    # ---- build artifact
    if mode == "irx":
        cfg = Path(args.config_file) if args.config_file else None
        if args.latest_commit_only:
            files = saclient.latest_commit_files(source)
            if files:
                cfg = saclient.write_config_for_files(source, files, work / "appscan-config.xml",
                                                      source_code_only=True,
                                                      enable_secrets=args.secrets != "disable")
            else:
                log("No changed files detected; scanning everything", "WARN")
        irx = saclient.prepare_irx(
            appscan_sh, source, name=_safe(scan_name), out_dir=work, accept_ssl=accept_ssl,
            source_code_only=args.source_code_only, open_source_only=False,
            static_only=not args.include_sca, secrets=args.secrets, third_party=args.third_party,
            scan_speed=args.scan_speed, no_config_files=not args.include_sca, config_file=cfg,
            jdk_path=args.jdk_path, verbose=args.verbose, debug=args.debug)
        file_id = client.upload_file(irx)
    else:
        if args.latest_commit_only:
            log("latest-commit-only requires IRX mode (appscan-config.xml is applied by the CLI); ignoring", "WARN")
        if args.config_file:
            log("Note: an appscan-config.xml inside the archive root is honoured by the server-side prepare "
                "(e.g. sourceCodeOnly=true for Java).", "INFO")
        excludes = [e for e in (args.zip_exclude or "").split(",") if e]
        archive = zip_source(source, work / f"{_safe(scan_name)}.zip", excludes)
        file_id = client.upload_file(archive, file_type="SourceCodeArchive")

    # ---- create scan
    payload = {
        "AppId": args.app_id,
        "ApplicationFileId": file_id,
        "ScanName": f"SAST {scan_name}",
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
        log(f"Re-executed SAST scan {scan_id}, execution {r.get('Id')}", "OK")
    else:
        r = client.create_scan("Sast", payload)
        scan_id = r.get("Id")
        if not scan_id:
            die(f"Scan creation returned no Id: {r}")
        log(f"SAST scan created: {scan_id} ({payload['ScanName']})", "OK")
    state_save(scan_id=scan_id, scan_tech="Sast", app_id=args.app_id, scan_name=scan_name, upload_mode=mode)

    if args.wait:
        d = client.wait_for_scan("Sast", scan_id, poll=args.poll_interval, timeout_min=args.timeout_minutes)
        state_save(execution_id=(d.get("LatestExecution") or {}).get("Id"))
        _log_counts(d)
    return scan_id


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def _log_counts(detail: dict) -> None:
    ex = detail.get("LatestExecution") or {}
    log("Issues: critical={} high={} medium={} low={} info={} total={}".format(
        ex.get("NCriticalIssues", 0), ex.get("NHighIssues", 0), ex.get("NMediumIssues", 0),
        ex.get("NLowIssues", 0), ex.get("NInfoIssues", 0), ex.get("NIssuesFound", 0)), "OK")
