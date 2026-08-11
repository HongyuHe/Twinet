#!/usr/bin/env python3
"""Check a manifest against the generated JSON Schema.

The schema is reflected from the Go types, so it cannot describe a field the
loader does not accept. What it can do is fall behind: a field renamed in Go
changes the schema, and a manifest in the repository that still uses the old
name would then be quietly wrong. This is what notices.
"""

import sys

import yaml

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - reported by the caller
    print("jsonschema is not installed; skipping", file=sys.stderr)
    raise SystemExit(0)

import json


def main() -> int:
    schema_path, manifest_path = sys.argv[1], sys.argv[2]
    with open(schema_path) as f:
        schema = json.load(f)
    with open(manifest_path) as f:
        doc = yaml.safe_load(f)

    errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    if not errors:
        print(f"  {manifest_path}: matches the schema")
        return 0
    print(f"  {manifest_path}: {len(errors)} schema error(s)", file=sys.stderr)
    for e in errors[:10]:
        where = "/".join(str(p) for p in e.path) or "(root)"
        print(f"    {where}: {e.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
