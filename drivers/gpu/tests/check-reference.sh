#!/usr/bin/env bash
# Opt-in Linux source gate. Ordinary kernel vector replays need no Linux tree.
set -euo pipefail
usage() {
    echo 'Usage: check-reference.sh --linux-tree PATH --linux-revision FULL_COMMIT_ID' >&2
}
die() {
    echo "gpu-reference: $*" >&2
    exit 1
}
linux_tree=
revision=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --linux-tree)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            linux_tree=$2
            shift 2 ;;
        --linux-revision)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            revision=${2,,}
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done
[ -n "$linux_tree" ] && [ -n "$revision" ] || { usage; exit 2; }
[[ "$revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] ||
    die '--linux-revision must be a full commit object ID'
linux_tree=$(CDPATH= cd -- "$linux_tree" && pwd -P) || die 'Linux source directory is unavailable'
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
# Avoid updating the reference index during read-only Git checks.
export GIT_OPTIONAL_LOCKS=0
verify_reference() {
    local top actual dirty
    top=$(git -C "$linux_tree" rev-parse --show-toplevel 2>/dev/null) ||
        die 'Linux source must be a Git checkout; archive provenance is not a verified commit'
    [ "$top" = "$linux_tree" ] || die '--linux-tree must name the Linux Git checkout root'
    actual=$(git -C "$linux_tree" rev-parse --verify 'HEAD^{commit}') || die 'cannot resolve Linux HEAD'
    [ "$actual" = "$revision" ] || die "Linux HEAD is $actual, expected $revision"
    dirty=$(git -C "$linux_tree" -c core.fsmonitor=false status \
        --porcelain=v1 --untracked-files=all --ignored=matching) || die 'cannot verify Linux source cleanliness'
    [ -z "$dirty" ] || die 'Linux checkout has modified, untracked or ignored files; use a clean checkout'
    [ -d "$linux_tree/drivers/gpu/drm" ] || die 'Linux checkout lacks drivers/gpu/drm'
}
verify_reference
mapfile -d '' checks < <(find "$here" -mindepth 2 -type f -name check.sh -print0 | sort -z)
[ "${#checks[@]}" -gt 0 ] || die 'no GPU check.sh reference harnesses found'
echo "gpu-reference: Linux $revision ($linux_tree), ${#checks[@]} primary harnesses"
failed=()
for check in "${checks[@]}"; do
    verify_reference
    name=${check#"$here/"}
    echo "gpu-reference: running $name"
    # gfx12_shader uses LINUX_SRC; other primary checks take a positional
    # path. Set both so none can silently fall back to /usr/src/linux.
    if (cd -- "$(dirname "$check")" && LINUX_SRC="$linux_tree" bash "$check" "$linux_tree"); then
        echo "gpu-reference: PASS $name"
    else
        failed+=("$name")
        echo "gpu-reference: FAIL $name (see the harness diagnostic above)" >&2
    fi
    verify_reference
done
if [ "${#failed[@]}" -gt 0 ]; then
    printf 'gpu-reference: failed: %s\n' "${failed[@]}" >&2
    exit 1
fi
echo "gpu-reference: all ${#checks[@]} primary harnesses passed at Linux $revision"
