"""Extract the three pinned Ubuntu 24.04 packages into a local directory.

This is a preparation recipe, never an OS compatibility override. It does
not install packages, run maintainer scripts, invoke sudo or change APT/WSL.
"""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import re
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=ROOT / "target/polyml-userspace")
    ap.add_argument("--package-dir", type=Path, help="Use already downloaded, byte-pinned packages")
    args = ap.parse_args()
    lock = json.loads((ROOT / "tools/polyml-noble-amd64.lock.json").read_text(encoding="utf-8"))
    if (lock["format"], lock["binding_status"], lock["distribution"], lock["version_id"], lock["architecture"], lock["version"]) != (1, "bound", "ubuntu", "24.04", "amd64", "5.7.1-5build1"):
        raise ValueError("The exact Ubuntu 24.04 amd64 package lock is required")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ValueError("This userspace recipe requires a genuine Ubuntu 24.04 amd64 environment")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise ValueError("Ubuntu 24.04 is required; a 26.04 host is not relabeled")
    packages = lock["packages"]
    if len(packages) != 3 or {member["name"] for member in packages} != {"polyml", "polyml-modules", "libpolyml9"}:
        raise ValueError("All three exact packages are required")
    for member in packages:
        if member["file"] != member["name"] + "_5.7.1-5build1_amd64.deb" or re.fullmatch(r"[0-9a-f]{64}", member["sha256"]) is None:
            raise ValueError("Unsupported package name or unbound digest")
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb is None:
        raise ValueError("The actual dpkg-deb extraction tool is required")
    out = args.output.absolute()
    if not out.is_relative_to((ROOT / "target").absolute()):
        raise ValueError("Userspace output must stay inside this repository's target directory")
    out.mkdir(parents=True, exist_ok=False)
    downloads = out / "packages"
    downloads.mkdir()
    if args.package_dir is None:
        apt_get = shutil.which("apt-get")
        if apt_get is None:
            raise ValueError("apt-get download is unavailable; provide byte-pinned packages")
        subprocess.run([apt_get, "download", *[member["name"] + "=5.7.1-5build1" for member in packages]], cwd=downloads, check=True, timeout=180)
    else:
        for member in packages:
            shutil.copyfile(args.package_dir / member["file"], downloads / member["file"])
    for member in packages:
        path = downloads / member["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != member["sha256"]:
            raise ValueError("Package bytes differ from the preserved lock: " + member["name"])
    extracted = out / "root"
    for member in packages:
        subprocess.run([dpkg_deb, "--extract", str(downloads / member["file"]), str(extracted)], check=True, timeout=60)
    binary = extracted / "usr/bin/poly"
    library = extracted / "usr/lib/x86_64-linux-gnu"
    if not binary.is_file() or not library.is_dir():
        raise ValueError("Pinned packages did not produce the required executable/library layout")
    wrapper = out / "bin/poly"
    wrapper.parent.mkdir()
    wrapper.write_text("#!/bin/sh\nset -eu\nLD_LIBRARY_PATH=" + shlex.quote(str(library)) + '${LD_LIBRARY_PATH:+:"$LD_LIBRARY_PATH"}\nexport LD_LIBRARY_PATH\nexec ' + shlex.quote(str(binary)) + ' "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    receipt = {"status": "packages-extracted-not-runtime-executed", "os_release": release,
        "lock_sha256": hashlib.sha256((ROOT / "tools/polyml-noble-amd64.lock.json").read_bytes()).hexdigest(),
        "polyml_wrapper": str(wrapper), "package_pins": packages, "system_package_install": False,
        "sudo": False, "runtime_executions": 0}
    (out / "preparation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "polyml": str(wrapper)}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
