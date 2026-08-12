#!/usr/bin/env python3
"""Check a manifest against the generated JSON Schema.

The schema is reflected from the Go types, so it cannot describe a field the
loader does not accept. What it can do is fall behind: a field renamed in Go
changes the schema, and a manifest in the repository that still uses the old
name would then be quietly wrong. This is what notices.

A root manifest is a Lab, so it is checked against the whole schema. An AS
template is a different document -- an ASTemplate -- and is checked against that
definition with ``--def ASTemplate``. Templates were shipped unchecked until a
compact ``[A, B]`` link in one of them turned out to validate nowhere, so they
are checked here now too.
"""

import argparse
import json
import sys

import yaml

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - reported by the caller
    print("jsonschema is not installed; skipping", file=sys.stderr)
    raise SystemExit(0)


def subschema(schema: dict, name: str) -> dict:
    """Return a schema that validates a document against one $def.

    The definition's own ``#/$defs/...`` references resolve because the whole
    ``$defs`` block is carried along as the wrapper's root.
    """
    defs = schema.get("$defs", {})
    if name not in defs:
        print(f"no definition {name!r} in schema", file=sys.stderr)
        raise SystemExit(2)
    return {
        "$schema": schema.get("$schema", "https://json-schema.org/draft/2020-12/schema"),
        "$defs": defs,
        "$ref": f"#/$defs/{name}",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("schema", help="path to the generated JSON Schema")
    ap.add_argument("manifest", help="path to the YAML document to check")
    ap.add_argument(
        "--def",
        dest="definition",
        default=None,
        help="validate against #/$defs/NAME instead of the whole schema "
        "(e.g. --def ASTemplate for an AS template)",
    )
    args = ap.parse_args()

    with open(args.schema) as f:
        schema = json.load(f)
    with open(args.manifest) as f:
        doc = yaml.safe_load(f)

    target = subschema(schema, args.definition) if args.definition else schema
    errors = sorted(Draft202012Validator(target).iter_errors(doc), key=lambda e: list(e.path))
    if not errors:
        print(f"  {args.manifest}: matches the schema")
        return 0
    print(f"  {args.manifest}: {len(errors)} schema error(s)", file=sys.stderr)
    for e in errors[:10]:
        where = "/".join(str(p) for p in e.path) or "(root)"
        print(f"    {where}: {e.message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
