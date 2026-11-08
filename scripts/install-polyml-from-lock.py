"""Install only the explicitly pinned Ubuntu runtime in an ephemeral CI job.

No Poly/ML program runs here. Package SHA-256 values must first be obtained
from the official Ubuntu metadata and bound by the maintainer. This tool does
not install a latest/unpinned fallback or alter repository security settings.
"""
from pathlib import Path
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent.parent


def main():
    lock=json.loads((ROOT/"tools/polyml-noble-amd64.lock.json").read_text(encoding="utf-8"))
    if lock.get("format")!=1 or lock.get("binding_status")!="bound":
        raise ValueError("Poly/ML package pins are unbound; official package SHA-256 values are required")
    if lock.get("version")!="5.7.1-5build1" or lock.get("architecture")!="amd64":
        raise ValueError("Unsupported Poly/ML package pin")
    packages=lock.get("packages")
    if not isinstance(packages,list) or len(packages)!=3:raise ValueError("Three pinned Poly/ML packages are required")
    names=set()
    for member in packages:
        name=member.get("name")
        if name not in {"polyml","polyml-modules","libpolyml9"} or name in names:raise ValueError("Unexpected package")
        names.add(name)
        if member.get("file")!=name+"_5.7.1-5build1_amd64.deb":raise ValueError("Unexpected package filename")
        if not isinstance(member.get("sha256"),str) or not re.fullmatch("[0-9a-f]{64}",member["sha256"]):
            raise ValueError("A verified package SHA-256 is required")
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        raise ValueError("This package recipe is for Ubuntu 24.04 amd64 CI")
    release={}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key,value=line.split("=",1);release[key]=value.strip('"')
    if release.get("ID")!="ubuntu" or release.get("VERSION_ID")!="24.04":
        raise ValueError("Ubuntu 24.04 is required by the package pin")
    subprocess.run(["sudo","apt-get","update","-qq"],check=True,timeout=180)
    with tempfile.TemporaryDirectory(prefix="oip-polyml-") as temp:
        argv=["apt-get","download",*[name+"=5.7.1-5build1" for name in sorted(names)]]
        subprocess.run(argv,cwd=temp,check=True,timeout=180)
        files=[]
        for member in packages:
            path=Path(temp)/member["file"]
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=member["sha256"]:
                raise ValueError("Official package bytes differ from the lock: "+member["name"])
            files.append(str(path))
        subprocess.run(["sudo","apt-get","install","--no-install-recommends","-y",*files],check=True,timeout=180)
    for name in sorted(names):
        version=subprocess.run(["dpkg-query","-W","-f=${Version}",name],check=True,capture_output=True,text=True).stdout
        if version!="5.7.1-5build1":raise ValueError("Installed package version differs")
    print("Pinned Ubuntu Poly/ML packages installed and byte checked.")


if __name__=="__main__":
    try:main()
    except (ValueError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(2)
