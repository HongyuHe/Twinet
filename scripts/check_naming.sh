#!/usr/bin/env bash
# Enforce the repository's naming conventions.
#
#   files   snake_case          twinet_motd, bgp_json.go, 04_networking.md
#   folders this-kind-of-format internal/grade, .github/workflows
#
# A convention that is only written down decays; this makes it a build failure.
# Names that are fixed by a tool or by long-standing convention (README, Makefile,
# Dockerfile, go.mod, Go's testdata directory) are exempt, because renaming them
# would break the tools that look for them.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

is_exempt_file() {
    case "$1" in
        README.md|LICENSE|Makefile|Dockerfile|Dockerfile.*|AGENTS.md|CLAUDE.md|\
        CONTRIBUTING.md|CHANGELOG.md|CODEOWNERS|.gitignore|.dockerignore|\
        .golangci.yml|.editorconfig|go.mod|go.sum) return 0 ;;
    esac
    # Any dotfile at the root of a tool's own directory, e.g. .github/*.
    case "$1" in .*) return 0 ;; esac
    return 1
}

is_exempt_dir() {
    case "$1" in
        # Go requires this exact spelling for test fixtures.
        testdata) return 0 ;;
        # Tool-owned directories.
        .git|.github|.claude) return 0 ;;
    esac
    return 1
}

while IFS= read -r path; do
    name=$(basename "$path")
    is_exempt_file "$name" && continue
    # snake_case, with an optional extension: my_file.go, twinet_motd, a.b.c
    if ! printf '%s' "$name" | grep -qE '^[a-z0-9]+(_[a-z0-9]+)*(\.[a-z0-9]+)*$'; then
        echo "file is not snake_case: $path"
        fail=1
    fi
done < <(git ls-files)

while IFS= read -r dir; do
    [ "$dir" = "." ] && continue
    name=$(basename "$dir")
    is_exempt_dir "$name" && continue
    # this-kind-of-format
    if ! printf '%s' "$name" | grep -qE '^[a-z0-9]+(-[a-z0-9]+)*$'; then
        echo "folder is not this-kind-of-format: $dir"
        fail=1
    fi
done < <(git ls-files | xargs -r -n1 dirname | sort -u)

if [ "$fail" -ne 0 ]; then
    echo
    echo "Naming conventions: files are snake_case, folders are this-kind-of-format."
    echo "Exemptions for tool-mandated names live in $0."
    exit 1
fi

echo "naming conventions: ok"
