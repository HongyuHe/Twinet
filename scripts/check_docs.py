#!/usr/bin/env python3
"""Check local Markdown references and evidence labels.

The implementation-status document is the only canonical home for numeric
performance results. Other current documentation may state a labelled target,
but links to the canonical ledger instead of copying a result that could drift.
Historical assessment and concurrently maintained fault/objective documents are
intentionally excluded from the benchmark policy; their links are still
checked.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CANONICAL_STATUS = DOCS / "09_status.md"
BENCHMARK_EXEMPT = {
    DOCS / "01_assessment.md",
    DOCS / "09_status.md",
    DOCS / "10_fault_injection.md",
    DOCS / "11_scalability_and_reliability_objectives.md",
}

INLINE_LINK = re.compile(r"!?\[[^\]]*]\(([^)\n]+)\)")
REFERENCE_LINK = re.compile(r"(?m)^\s*\[[^\]]+]:\s*(\S+)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")
INLINE_CODE = re.compile(r"`([^`]+)`")
PATH_TOKEN = re.compile(
    r"(?<![\w.-])(?:(?:\./|\.\./|docs/|internal/|examples/|scripts/|cmd/|images/|test/)"
    r"[A-Za-z0-9_./@+=:-]+)"
)
TIMING = re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|m|h|seconds?|minutes?|hours?)\b", re.IGNORECASE)
PERFORMANCE_WORD = re.compile(
    r"\b(?:deploy(?:ment|ed|s)?|grad(?:e|ing|ed)|benchmark|throughput|latency|"
    r"convergence|scale|wall.?clock)\b",
    re.IGNORECASE,
)


def markdown_files() -> list[Path]:
    return [ROOT / "README.md", *sorted(DOCS.glob("*.md"))]


def github_slug(value: str, seen: dict[str, int]) -> str:
    value = re.sub(r"\[([^\]]+)]\([^)]*\)", r"\1", value)
    value = re.sub(r"`([^`]*)`", r"\1", value)
    value = re.sub(r"<[^>]*>", "", value)
    value = value.lower()
    value = re.sub(r"[^a-z0-9 _-]", "", value)
    value = re.sub(r"[\s_]+", "-", value).strip("-")
    count = seen.get(value, 0)
    seen[value] = count + 1
    return value if count == 0 else f"{value}-{count}"


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    found: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADING.match(line)
        if match:
            found.add(github_slug(match.group(1), seen))
    return found


def local_target(raw: str) -> tuple[str, str] | None:
    raw = raw.strip()
    if raw.startswith("<") and ">" in raw:
        raw = raw[1 : raw.index(">")]
    else:
        raw = raw.split(maxsplit=1)[0]
    raw = raw.replace(r"\ ", " ")
    parsed = urlparse(raw)
    if parsed.scheme or raw.startswith("//") or raw.startswith("mailto:") or raw.startswith("data:"):
        return None
    path, _, fragment = raw.partition("#")
    return unquote(path), unquote(fragment)


def check_link(source: Path, target: str, fragment: str, problems: list[str]) -> None:
    destination = source.resolve() if not target else (source.parent / target).resolve()
    if not destination.exists():
        problems.append(f"{source.relative_to(ROOT)}: missing local link/path {target!r}")
        return
    if fragment:
        if not destination.is_file():
            problems.append(f"{source.relative_to(ROOT)}: anchor #{fragment} names non-file {target!r}")
            return
        if fragment not in anchors(destination):
            problems.append(
                f"{source.relative_to(ROOT)}: missing anchor #{fragment} in "
                f"{destination.relative_to(ROOT)}"
            )


def check_links(paths: list[Path], problems: list[str]) -> None:
    for source in paths:
        body = source.read_text(encoding="utf-8")
        raw_targets = INLINE_LINK.findall(body) + REFERENCE_LINK.findall(body)
        for raw in raw_targets:
            parsed = local_target(raw)
            if parsed is None:
                continue
            target, fragment = parsed
            if not target and not fragment:
                continue
            check_link(source, target, fragment, problems)


def check_inline_paths(paths: list[Path], problems: list[str]) -> None:
    for source in paths:
        body = source.read_text(encoding="utf-8")
        for code in INLINE_CODE.findall(body):
            for token in PATH_TOKEN.findall(code):
                token = token.rstrip(".,:;)")
                if "*" in token or "$" in token:
                    continue
                if token.startswith("../"):
                    target = (source.parent / token).resolve()
                else:
                    target = (ROOT / token.removeprefix("./")).resolve()
                if not target.exists():
                    problems.append(f"{source.relative_to(ROOT)}: missing referenced path {token!r}")


def check_benchmark_labels(paths: list[Path], problems: list[str]) -> None:
    canonical = CANONICAL_STATUS.read_text(encoding="utf-8")
    if "## Measurements" not in canonical or "| **Measured** |" not in canonical:
        problems.append("docs/09_status.md: missing canonical measurement/status labels")

    for path in paths:
        if path in BENCHMARK_EXEMPT:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not TIMING.search(line) or not PERFORMANCE_WORD.search(line):
                continue
            context = "\n".join(lines[max(0, index - 2) : min(len(lines), index + 3)]).lower()
            if not any(label in context for label in ("measured", "target", "historical", "legacy")):
                problems.append(
                    f"{path.relative_to(ROOT)}:{index + 1}: benchmark-like result lacks "
                    "a measured/target/historical label"
                )
                continue
            if "target" in context or "historical" in context or "legacy" in context:
                continue
            if "measured" in context:
                problems.append(
                    f"{path.relative_to(ROOT)}:{index + 1}: numeric measured results belong "
                    "only in docs/09_status.md; link to that ledger instead"
                )


def main() -> int:
    paths = markdown_files()
    problems: list[str] = []
    check_links(paths, problems)
    check_inline_paths(paths, problems)
    check_benchmark_labels(paths, problems)
    if problems:
        print("documentation check failed:", file=sys.stderr)
        for problem in sorted(set(problems)):
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"documentation check passed ({len(paths)} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
