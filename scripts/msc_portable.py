#!/usr/bin/env python3
"""Build a portable MSC bundle or deploy it on a fresh Linux x86-64 worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
SOCKET = "unix:///var/run/docker.sock"
BUNDLE_FILES = (
    "bin/twinet",
    "examples/msc/msc.json",
    "scripts/msc_portable.py",
    "docs/13_msc.md",
)


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def output(args, **kwargs):
    return run(args, stdout=subprocess.PIPE, text=True, **kwargs).stdout.strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def docker(*args, **kwargs):
    return run(["docker", "--host", SOCKET, *args], **kwargs)


def image_refs(spec):
    refs = sorted({spec[key] for key in ("image", "router_image", "switch_image")})
    for ref in refs:
        if not isinstance(ref, str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", ref):
            raise ValueError("Portable deployment requires all three images pinned with @sha256:digest")
    return refs


def container_names(spec):
    names = {device["id"] for device in spec["devices"]}
    for device in spec["devices"]:
        if device["role"] in {"black", "firewall", "gray-firewall"}:
            names.add(device["id"] + "-frr")
    return names


def validate_destination(prefix, state, launcher, names, existing):
    collisions = sorted(names & existing)
    if collisions:
        raise ValueError("Containers already exist: " + ", ".join(collisions) +
                         ". Use the existing deployment's console/check/up commands.")
    for path in (prefix, state):
        if path.exists() and (not path.is_dir() or any(path.iterdir())):
            raise ValueError(f"Refusing existing nonempty destination {path}; use a fresh destination")
    if launcher.exists() or launcher.is_symlink():
        raise ValueError(f"Refusing to overwrite {launcher}")


def verify_bundle(root):
    manifest = json.loads((root / "msc_bundle.json").read_text())
    if manifest.get("schema_version") != 1 or manifest.get("platform") != "linux/amd64":
        raise ValueError("Unsupported MSC bundle version or platform")
    if set(manifest.get("sha256", {})) != set(BUNDLE_FILES):
        raise ValueError("Bundle file inventory is incomplete or unexpected")
    for name, digest in manifest["sha256"].items():
        path = root / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError(f"Bundle checksum mismatch: {name}")
    return manifest


def build_binary(root, destination):
    if (root / "msc_bundle.json").is_file():
        manifest = verify_bundle(root)
        shutil.copy2(root / "bin/twinet", destination)
        return manifest["source"]
    from source_digest import source_digest

    go_version = re.search(r"^go (\S+)$", (root / "go.mod").read_text(), re.MULTILINE).group(1)
    digest = source_digest(root)
    commit = "source-archive"
    dirty = None
    if (root / ".git").exists():
        git = ["git", "-c", f"safe.directory={root}", "-C", root]
        commit = output([*git, "rev-parse", "HEAD"])
        dirty = bool(output([*git, "status", "--porcelain"]))
    prefix = "github.com/HongyuHe/twinet"
    flags = " ".join([
        "-s -w",
        f"-X {prefix}/internal/cli.Version=msc-portable",
        f"-X {prefix}/internal/cli.Commit={commit}",
        f"-X {prefix}/internal/cli.SourceDigest={digest}",
        f"-X {prefix}/internal/grade.GraderSource={digest}",
    ])
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOTOOLCHAIN="auto")
    args = ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags,
            "-o", str(destination), "./cmd/twinet"]
    if shutil.which("go"):
        stage("Building a static Linux CLI with the local Go toolchain")
        run(args, cwd=root, env=env)
        builder = output(["go", "version"], cwd=root, env=env)
    else:
        stage("Building the CLI in Docker; no host Go installation is needed")
        builder = f"golang:{go_version}-bookworm"
        docker("pull", builder)
        docker("run", "--rm", "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}",
               "-e", "CGO_ENABLED=0", "-e", "GOOS=linux", "-e", "GOARCH=amd64",
               "-e", "GOTOOLCHAIN=auto", "-e", "GOCACHE=/tmp/go-cache",
               "-e", "GOMODCACHE=/tmp/go-mod", "-e", "HOME=/tmp",
               "-v", f"{root}:/src:ro", "-v", f"{destination.parent}:/out",
               "-w", "/src", builder, *args[:-2], f"/out/{destination.name}", args[-1])
        builder = output(["docker", "--host", SOCKET, "image", "inspect", builder,
                          "--format", "{{.Id}}"])
    destination.chmod(0o755)
    return {"commit": commit, "dirty": dirty, "source_sha256": digest, "builder": builder}


def bundle(args):
    destination = args.output.resolve()
    checksum = destination.with_name(destination.name + ".sha256")
    if destination.exists() or checksum.exists():
        raise ValueError(f"Refusing to overwrite {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="msc-bundle-") as temporary:
        root = Path(temporary) / "twinet-msc"
        (root / "bin").mkdir(parents=True)
        source = build_binary(ROOT, root / "bin/twinet")
        for name in BUNDLE_FILES[1:]:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        spec = json.loads((root / "examples/msc/msc.json").read_text())
        manifest = {"schema_version": 1, "platform": "linux/amd64", "source": source,
                    "images": image_refs(spec), "sha256": {name: sha256(root / name) for name in BUNDLE_FILES}}
        (root / "msc_bundle.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with destination.open("xb") as stream:
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                archive.add(root, arcname="twinet-msc")
    checksum.write_text(f"{sha256(destination)}  {destination.name}\n")
    stage(f"Created {destination} ({destination.stat().st_size / 1024**2:.1f} MiB)")
    print("Copy the archive and checksum to the destination, verify, extract, and run:")
    print("sudo python3 twinet-msc/scripts/msc_portable.py deploy --install-deps")


def prerequisites(install):
    if sys.platform != "linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ValueError("The published MSC images require an x86-64 Linux worker or VM")
    if os.geteuid() != 0:
        raise ValueError("Deployment requires root: run with sudo")
    if install:
        if not shutil.which("apt-get"):
            raise ValueError("--install-deps supports Debian/Ubuntu; install dependencies manually on other distributions")
        packages = ["ca-certificates", "iproute2", "iptables", "kmod"]
        if not shutil.which("docker"):
            packages.append("docker.io")
        stage("Installing worker dependencies")
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", *packages], env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
        run(["systemctl", "enable", "--now", "docker"])
    for command in ("docker", "ip", "modprobe", "timedatectl"):
        if not shutil.which(command):
            raise ValueError(f"Missing {command}; retry with --install-deps or install it manually")
    docker("info", stdout=subprocess.DEVNULL)
    for module in ("openvswitch", "xfrm_user", "af_key", "esp4", "xt_policy", "xt_u32"):
        run(["modprobe", module])
    output(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])


def deploy(args):
    started = time.monotonic()
    spec_path = (args.spec or ROOT / "examples/msc/msc.json").resolve()
    spec = json.loads(spec_path.read_text())
    if spec.get("version") != 2:
        raise ValueError("Portable deployment expects the FRR/OVS version-2 MSC manifest")
    refs = image_refs(spec)
    if (ROOT / "msc_bundle.json").exists():
        verify_bundle(ROOT)
    prerequisites(args.install_deps)
    prefix, state, launcher = args.prefix.resolve(), args.state_dir.resolve(), args.launcher.absolute()
    existing = set(output(["docker", "--host", SOCKET, "ps", "-a", "--format", "{{.Names}}"]).splitlines())
    validate_destination(prefix, state, launcher, container_names(spec), existing)
    for reserved in (Path("/"), Path("/usr"), Path("/usr/local"), Path("/var"), Path("/etc")):
        if prefix == reserved or state == reserved:
            raise ValueError(f"Choose a dedicated deployment directory, not {reserved}")
    report_dir = args.report_dir.resolve() if args.report_dir else Path("/var/lib/twinet/msc-deploy") / time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    report_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="msc-build-") as temporary:
        binary = Path(temporary) / "twinet"
        source = build_binary(ROOT, binary)
        command = [binary, "--runtime", "docker", "--runtime-socket", SOCKET, "msc", "--spec", spec_path, "--state-dir", state]
        plan = json.loads(output([*command, "plan"]))
        stage("Pulling the three pinned device images")
        for ref in refs:
            docker("pull", ref)
            architecture = output(["docker", "--host", SOCKET, "image", "inspect", ref, "--format", "{{.Os}}/{{.Architecture}}"])
            if architecture != "linux/amd64":
                raise ValueError(f"Unsupported image platform {architecture}: {ref}")
        (prefix / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, prefix / "bin/twinet")
        installed_spec = prefix / "msc.json"
        installed_spec.write_text(json.dumps(plan, indent=2) + "\n")
        installed_spec.chmod(0o644)
        command = [prefix / "bin/twinet", "--runtime", "docker", "--runtime-socket", SOCKET,
                   "msc", "--spec", installed_spec, "--state-dir", state]
        launcher.parent.mkdir(parents=True, exist_ok=True)
        with launcher.open("x") as stream:
            stream.write("#!/bin/sh\nexec " + shlex.join([str(x) for x in command]) + ' "$@"\n')
        launcher.chmod(0o755)
        record = {"source": source, "binary_sha256": sha256(prefix / "bin/twinet"),
                  "images": refs, "devices": len(plan["devices"]), "links": len(plan["links"]),
                  "prefix": str(prefix), "state_dir": str(state), "launcher": str(launcher), "passed": False}
        record_path = report_dir / "deployment.json"
        record_path.write_text(json.dumps(record, indent=2) + "\n")
        stage("Creating devices, fresh credentials, OSPF, and both IPsec layers")
        with (report_dir / "up.log").open("w") as log:
            run([*command, "up"], stdout=log, stderr=subprocess.STDOUT)
        ready = time.monotonic() - started
        stage(f"Network ready after {ready:.1f}s; checking isolation, native state, and encrypted carriage")
        with (report_dir / "check.json").open("w") as result, (report_dir / "check.stderr").open("w") as log:
            run([*command, "check"], stdout=result, stderr=log)
        check = json.loads((report_dir / "check.json").read_text())
        if check.get("passed") is not True or not check.get("checks") or any(item.get("passed") is not True for item in check["checks"]):
            raise ValueError(f"Deployment checks failed; inspect {report_dir}")
        stage("Installing hourly certificate and CRL renewal")
        run([*command, "credentials", "install-timer"])
        if args.export:
            stage("Exporting a fresh public evidence snapshot")
            run([*command, "export", "--output", report_dir / "snapshot"])
        record.update(passed=True, checks=len(check["checks"]), spec_sha256=check["spec_sha256"],
                      ready_seconds=round(ready, 2), total_seconds=round(time.monotonic() - started, 2))
        record_path.write_text(json.dumps(record, indent=2) + "\n")
        stage(f"PASS: {record['checks']} checks; results in {report_dir}")
        print(f"Open a router: sudo {launcher} console BLACK")
        print(f"Open a switch: sudo {launcher} console G_A1")
        print(f"Open a host:   sudo {launcher} console R_A1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("bundle", help="Package a static CLI, the pinned manifest, installer, and documentation")
    pack.add_argument("--output", type=Path, required=True)
    pack.set_defaults(function=bundle)
    install = commands.add_parser("deploy", help="Create and verify MSC on a fresh worker; existing deployments are refused")
    install.add_argument("--install-deps", action="store_true", help="Install Docker and host tools using apt")
    install.add_argument("--spec", type=Path, help="Optional expanded version-2 manifest with pinned image digests")
    install.add_argument("--prefix", type=Path, default=Path("/opt/twinet-msc"))
    install.add_argument("--state-dir", type=Path, default=Path("/var/lib/twinet/msc"))
    install.add_argument("--launcher", type=Path, default=Path("/usr/local/bin/twinet-msc"))
    install.add_argument("--report-dir", type=Path)
    install.add_argument("--export", action="store_true", help="Also save a public evidence snapshot after validation")
    install.set_defaults(function=deploy)
    args = parser.parse_args()
    try:
        args.function(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"msc_portable: {error}", file=sys.stderr)
        print("Existing devices and private state are preserved. Inspect the deployment logs before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
