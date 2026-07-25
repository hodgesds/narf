#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 VERSION [--create] [--commit SHA]" >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
version=${1#v}
shift
create=0
commit=HEAD
while [[ $# -gt 0 ]]; do
    case "$1" in
        --create) create=1; shift ;;
        --commit) [[ $# -ge 2 ]] || usage; commit=$2; shift 2 ;;
        *) usage ;;
    esac
done

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] ||
    { echo "invalid semantic version: $version" >&2; exit 1; }
git diff --quiet
git diff --cached --quiet
[[ -z $(git status --porcelain --untracked-files=normal) ]] ||
    { echo "working tree must be clean" >&2; exit 1; }
git rev-parse --verify "${commit}^{commit}" >/dev/null
if git rev-parse --verify --quiet "refs/tags/v${version}" >/dev/null; then
    echo "tag already exists: v${version}" >&2
    exit 1
fi

subject="NARF ${version}"
if [[ $create -eq 0 ]]; then
    printf 'Validated release tag v%s at %s.\n' "$version" "$(git rev-parse --short "$commit")"
    printf 'Human maintainer command:\n  git tag -s v%s %s -m %q\n' \
        "$version" "$commit" "$subject"
    exit 0
fi

git tag -s "v${version}" "$commit" -m "$subject"
echo "Created signed local tag v${version}; review it before pushing."

