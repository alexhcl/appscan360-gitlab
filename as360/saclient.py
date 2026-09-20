"""SAClientUtil (Static Analyzer Command Line Utility) handling.

The utility is downloaded from the AppScan 360° instance itself:
  GET /api/v4/Tools/SAClientUtilByType?toolType=linux
Do NOT run `appscan.sh update` against 360°: the client version is tied to the
installation (cloud builds are not interchangeable).

Commands wrapped (CLI reference, Linux/macOS):
  appscan.sh prepare      [-c cfg] [-d dir] [-n name] [-sco] [-oso] [-sao] [-es|-ds|-so] [-t] [-s speed] [-nc] [-jdk path]
  appscan.sh prepare_sca  [-d dir] [-n name] [-image img | -container ctr]
  appscan.sh prepare_sbom <sbom.spdx.json> [-d dir] [-n name]
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

from .common import log, die, env
from .client import AS360Client


def find_appscan_sh() -> str | None:
    exe = shutil.which("appscan.sh")
    if exe:
        return exe
    for base in (env("APPSCAN_INSTALL_DIR"), str(Path.home() / "SAClientUtil"), "/opt/SAClientUtil"):
        if base and Path(base, "bin", "appscan.sh").is_file():
            return str(Path(base, "bin", "appscan.sh"))
    return None


def install_saclient(client: AS360Client, install_dir: Path | None = None, tool_type: str = "Linux") -> str:
    """Return path to appscan.sh, downloading SAClientUtil from the 360° host if needed."""
    exe = find_appscan_sh()
    if exe:
        log(f"Using existing SAClientUtil: {exe}")
        return exe
    install_dir = install_dir or Path(env("APPSCAN_INSTALL_DIR", str(Path.home() / "SAClientUtil")))
    zip_path = install_dir.parent / "SAClientUtil.zip"
    log(f"Downloading SAClientUtil ({tool_type}) from {client.base} ...")
    client.download_saclient(zip_path, tool_type)
    tmp = install_dir.parent / "SAClientUtil_extract"
    shutil.rmtree(tmp, ignore_errors=True)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(tmp)
    zip_path.unlink(missing_ok=True)
    roots = [p for p in tmp.iterdir() if p.is_dir() and p.name.startswith("SAClientUtil")]
    if not roots:
        die("SAClientUtil zip did not contain a SAClientUtil_* folder")
    shutil.rmtree(install_dir, ignore_errors=True)
    shutil.move(str(roots[0]), str(install_dir))
    shutil.rmtree(tmp, ignore_errors=True)
    exe = str(install_dir / "bin" / "appscan.sh")
    os.chmod(exe, 0o755)
    os.environ["PATH"] = f"{install_dir / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
    log(f"SAClientUtil installed at {install_dir}", "OK")
    subprocess.run([exe, "version"], check=False)
    return exe


def _run(cmd: list[str], cwd: str | None = None) -> None:
    log("Running: " + " ".join(cmd))
    r = subprocess.run(cmd, cwd=cwd)
    if r.returncode != 0:
        die(f"Command failed with exit code {r.returncode}: {cmd[0]} {cmd[1]}")


def newest_irx(directory: str | Path) -> Path | None:
    files = sorted(glob.glob(str(Path(directory) / "*.irx")), key=os.path.getmtime, reverse=True)
    return Path(files[0]) if files else None


def write_config_for_files(target_dir: Path, files: list[str], out: Path,
                           source_code_only: bool = True, enable_secrets: bool = True) -> Path:
    """appscan-config.xml restricting the IRX to specific files (e.g. latest commit diff)."""
    inc = "".join(f"<Include>{f}</Include>" for f in files)
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        f'<Configuration enableSecrets="{str(enable_secrets).lower()}" '
        f'sourceCodeOnly="{str(source_code_only).lower()}" staticAnalysisOnly="true">'
        f'<Targets><Target path="{target_dir.resolve()}">{inc}</Target></Targets></Configuration>'
    )
    out.write_text(xml)
    log(f"Wrote {out} restricting the scan to {len(files)} file(s)")
    return out


def latest_commit_files(repo_dir: Path) -> list[str]:
    r = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"], cwd=repo_dir,
                       capture_output=True, text=True)
    if r.returncode != 0:
        log("git diff failed (shallow clone? set GIT_DEPTH: 2). Falling back to full scan.", "WARN")
        return []
    return [f for f in r.stdout.splitlines() if f.strip() and Path(repo_dir, f).is_file()]


def prepare_irx(
    appscan_sh: str,
    target_dir: Path,
    *,
    name: str,
    out_dir: Path,
    accept_ssl: bool = True,
    source_code_only: bool = False,
    open_source_only: bool = False,
    static_only: bool = False,
    secrets: str | None = None,       # enable | disable | only | None(org default)
    third_party: bool = False,
    scan_speed: str | None = None,    # simple | balanced | deep | thorough
    no_config_files: bool = False,    # -nc : ignore SCA package-manager config files
    config_file: Path | None = None,
    jdk_path: str | None = None,
    verbose: bool = False,
    debug: bool = False,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [appscan_sh, "prepare", "-d", str(out_dir), "-n", name]
    if config_file:
        cmd += ["-c", str(config_file)]
    if source_code_only:
        cmd.append("-sco")
    if open_source_only:
        cmd.append("-oso")
    if static_only:
        cmd.append("-sao")
    if secrets == "enable":
        cmd.append("-es")
    elif secrets == "disable":
        cmd.append("-ds")
    elif secrets == "only":
        cmd.append("-so")
    if third_party:
        cmd.append("-t")
    if scan_speed:
        cmd += ["-s", scan_speed]
    if no_config_files:
        cmd.append("-nc")
    if jdk_path:
        cmd += ["-jdk", jdk_path]
    if verbose:
        cmd.append("-v")
    if debug:
        cmd.append("-X")
    if accept_ssl:
        cmd.append("-acceptssl")
    _run(cmd, cwd=str(target_dir))
    irx = out_dir / (name if name.endswith(".irx") else name + ".irx")
    if not irx.is_file():
        irx = newest_irx(out_dir) or die("No .irx file was generated. Check the SAClientUtil logs.")
    log(f"IRX generated: {irx} ({irx.stat().st_size / 1_048_576:.1f} MB)", "OK")
    return irx


def prepare_sca_irx(appscan_sh: str, target_dir: Path, *, name: str, out_dir: Path, accept_ssl: bool = True,
                    image: str | None = None, container: str | None = None, no_config_files: bool = False,
                    debug: bool = False) -> Path:
    """prepare_sca: source tree (== prepare -oso), or a Docker image / container (docker CLI required)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [appscan_sh, "prepare_sca", "-d", str(out_dir), "-n", name]
    if image:
        cmd += ["-image", image]
    if container:
        cmd += ["-container", container]
    if no_config_files:
        cmd.append("-nc")
    if debug:
        cmd.append("-X")
    if accept_ssl:
        cmd.append("-acceptssl")
    _run(cmd, cwd=str(target_dir))
    irx = out_dir / (name if name.endswith(".irx") else name + ".irx")
    if not irx.is_file():
        irx = newest_irx(out_dir) or die("prepare_sca produced no .irx file")
    log(f"SCA IRX generated: {irx}", "OK")
    return irx


def prepare_sbom_irx(appscan_sh: str, sbom_file: Path, *, name: str, out_dir: Path, accept_ssl: bool = True) -> Path:
    """prepare_sbom <sbom.spdx.json>: IRX from an SPDX 2.3 SBOM (no source needed)."""
    if not sbom_file.is_file():
        die(f"SBOM file not found: {sbom_file}")
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [appscan_sh, "prepare_sbom", str(sbom_file), "-d", str(out_dir), "-n", name]
    if accept_ssl:
        cmd.append("-acceptssl")
    _run(cmd)
    irx = out_dir / (name if name.endswith(".irx") else name + ".irx")
    if not irx.is_file():
        irx = newest_irx(out_dir) or die("prepare_sbom produced no .irx file")
    return irx
