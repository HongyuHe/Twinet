#!/usr/bin/env python3
"""Compute the canonical content identity for compiled Twinet grader inputs."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys


DOMAIN = b"twinet-grader-source/v1\x00"
BUILD_ROOTS = ("cmd", "internal")
ROOT_FILES = ("go.mod", "go.sum")


def build_inputs(root: Path) -> list[Path]:
    paths: list[Path] = []
    for directory in BUILD_ROOTS:
        base = root / directory
        if not base.is_dir():
            raise ValueError(f"missing build input directory: {directory}")
        paths.extend(path.relative_to(root) for path in base.rglob("*.go") if path.is_file())
    for name in ROOT_FILES:
        path = root / name
        if not path.is_file():
            raise ValueError(f"missing build input file: {name}")
        paths.append(path.relative_to(root))
    return sorted(paths, key=lambda path: path.as_posix().encode("utf-8"))


def update_framed(digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    for relative in build_inputs(root):
        update_framed(digest, relative.as_posix().encode("utf-8"))
        update_framed(digest, (root / relative).read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", type=Path, help="repository root")
    args = parser.parse_args()
    try:
        print(source_digest(args.root.resolve()))
    except (OSError, ValueError) as err:
        print(f"source_digest: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
