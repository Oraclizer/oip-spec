"""Exchange real signed packets from the pinned Rust and Go implementations.

Go and Cargo are taken from --go and --cargo, then from the GO and CARGO
environment variables, and otherwise from PATH. The Go module cache and proxy
settings come from the caller's environment.
"""
import argparse
from pathlib import Path
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "wire-interop"
ENV = os.environ.copy()
ENV.setdefault("GOTOOLCHAIN", "local")
ENV.setdefault("GOCACHE", str(ROOT / "target" / "wire-go-build"))

def run(args, directory, capture=False):
    return subprocess.run(args, cwd=directory, env=ENV, check=True,
                          stdout=subprocess.PIPE if capture else None, timeout=600).stdout

def normalized(data):
    return data.replace(b"\r\n", b"\n")

def tool(explicit, variable, program):
    located = explicit or os.environ.get(variable) or shutil.which(program)
    if not located:
        raise SystemExit(f"{program} not found: pass its path or set {variable}")
    return str(located)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go")
    parser.add_argument("--cargo")
    args = parser.parse_args()
    go_tool = tool(args.go, "GO", "go")
    cargo = tool(args.cargo, "CARGO", "cargo")
    OUT.mkdir(parents=True, exist_ok=True)
    rust = normalized(run([cargo, "run", "--offline", "--locked", "--quiet", "--example", "wire_corpus"], ROOT, True))
    go = normalized(run([go_tool, "run", "-mod=readonly", "./cmd/wire-corpus"], ROOT / "go", True))
    if rust != go:
        raise SystemExit("Rust/Go generated signed corpus differs")
    rust_path, go_path = OUT / "rust.txt", OUT / "go.txt"
    rust_path.write_bytes(rust)
    go_path.write_bytes(go)
    ENV["OIP_RUST_WIRE_CORPUS"] = str(rust_path)
    ENV["OIP_GO_WIRE_CORPUS"] = str(go_path)
    run([go_tool, "test", "-mod=readonly", "./..."], ROOT / "go")
    run([cargo, "test", "--offline", "--locked", "--lib",
         "authority::recovery::wire::vector_tests::go_generated_frames_execute_on_the_same_persistent_authority",
         "--", "--exact"], ROOT)
    print("Rust and Go exchanged the signed corpus.")

if __name__ == "__main__":
    main()
