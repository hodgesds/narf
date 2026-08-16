#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: packaging/publish-crates.sh --version VERSION [--plan|--check|--execute]

  --plan     print the dependency-ordered public crate list
  --check    package-check every public crate without uploading (default)
  --execute  publish from the matching signed release tag
EOF
    exit 2
}

version=
mode=check
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) [[ $# -ge 2 ]] || usage; version=${2#v}; shift 2 ;;
        --plan) mode=plan; shift ;;
        --check) mode=check; shift ;;
        --execute) mode=execute; shift ;;
        *) usage ;;
    esac
done

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || {
    echo "invalid or missing semantic version: ${version:-<empty>}" >&2
    exit 1
}

for tool in cargo git jq awk; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required release tool is unavailable: $tool" >&2
        exit 1
    }
done
if [[ $mode == execute ]] && ! command -v curl >/dev/null 2>&1; then
    echo "required release tool is unavailable: curl" >&2
    exit 1
fi

root=$(git rev-parse --show-toplevel)
cd "$root"
metadata=$(mktemp)
rows=$(mktemp)
plan=$(mktemp)
trap 'rm -f "$metadata" "$rows" "$plan"' EXIT

cargo metadata --no-deps --format-version 1 >"$metadata"

bad_versions=$(jq -r --arg version "$version" '
    .workspace_members as $members
    | .packages[]
    | select(.id as $id | $members | index($id))
    | select(.publish != [])
    | select(.version != $version)
    | "\(.name)=\(.version)"
' "$metadata")
[[ -z $bad_versions ]] || {
    echo "public workspace crates do not match release version $version:" >&2
    echo "$bad_versions" >&2
    exit 1
}

private_crates=$(jq -r '
    .workspace_members as $members
    | [.packages[]
       | select(.id as $id | $members | index($id))
       | select(.publish == [])
       | .name]
    | sort
    | join(" ")
' "$metadata")
[[ $private_crates == xtask ]] || {
    echo "unexpected private workspace crate set: $private_crates" >&2
    exit 1
}

libc_version=$(cargo metadata --manifest-path narf-libc/Cargo.toml \
    --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "narf-libc") | .version')
[[ $libc_version == "$version" ]] || {
    echo "narf-libc is $libc_version, expected $version" >&2
    exit 1
}

bad_requirements=$(jq -r --arg version "^$version" '
    .workspace_members as $members
    | .packages[]
    | select(.id as $id | $members | index($id))
    | select(.publish != [])
    | .name as $package
    | .dependencies[]
    | select(.path != null and .req != $version)
    | "\($package) -> \(.name) requires \(.req)"
' "$metadata")
[[ -z $bad_requirements ]] || {
    echo "internal path dependencies must carry registry version ^$version:" >&2
    echo "$bad_requirements" >&2
    exit 1
}

jq -r '
    .workspace_members as $members
    | .packages[]
    | select(.id as $id | $members | index($id))
    | select(.publish != [])
    | [.name, ([.dependencies[] | select(.path != null) | .name] | unique | join(","))]
    | @tsv
' "$metadata" >"$rows"
# narf-libc deliberately owns a separate workspace so user-space builds do not
# inherit kernel codegen settings. It is still part of the public SDK graph.
printf 'narf-libc\tnarf-user-runtime\n' >>"$rows"

awk -F '\t' '
    {
        if ($1 in node) {
            print "duplicate crate in publication graph: " $1 > "/dev/stderr"
            exit 2
        }
        node[$1] = 1
        dependencies[$1] = $2
        count++
    }
    END {
        for (package in node) {
            dep_count = split(dependencies[package], deps, ",")
            for (i = 1; i <= dep_count; i++) {
                dependency = deps[i]
                if (dependency != "" && dependency in node && dependency != package) {
                    edge[dependency, package] = 1
                    indegree[package]++
                }
            }
        }
        for (emitted = 0; emitted < count; emitted++) {
            next_package = ""
            for (package in node) {
                if (!done[package] && indegree[package] == 0 &&
                    (next_package == "" || package < next_package)) {
                    next_package = package
                }
            }
            if (next_package == "") {
                print "cycle in crates.io publication graph" > "/dev/stderr"
                exit 3
            }
            print next_package
            done[next_package] = 1
            for (package in node) {
                if (edge[next_package, package]) {
                    indegree[package]--
                }
            }
        }
    }
' "$rows" >"$plan"

expected=$(wc -l <"$rows")
actual=$(wc -l <"$plan")
[[ $actual -eq $expected ]] || {
    echo "publication plan contains $actual crates, expected $expected" >&2
    exit 1
}

if [[ $mode == plan ]]; then
    cat "$plan"
    exit 0
fi

echo "package-checking $actual crates at version $version"
# Cargo understands path dependencies between members and packages this set in
# dependency order. narf-compat-relibc is checked separately because its
# narf-libc dependency intentionally lives in a nested workspace.
cargo publish --workspace --exclude narf-compat-relibc \
    --dry-run --allow-dirty --no-verify --quiet
# Local patches let Cargo normalize and archive the two cross-workspace crates
# before their registry dependencies exist. Published manifests still contain
# registry requirements; the patches affect this preflight only.
cargo package --manifest-path narf-libc/Cargo.toml --no-verify --allow-dirty --quiet \
    --config "patch.crates-io.narf-user-runtime.path=\"$root/user-runtime\""
cargo package --package narf-compat-relibc --no-verify --allow-dirty --quiet \
    --config "patch.crates-io.narf-libc.path=\"$root/narf-libc\"" \
    --config "patch.crates-io.narf-user-runtime.path=\"$root/user-runtime\"" \
    --config "patch.crates-io.narf-kernel-test.path=\"$root/verification/kernel-test\""

oversized=$(find target/package -maxdepth 1 -type f \
    -name "*-$version.crate" -size +10000000c -print)
[[ -z $oversized ]] || {
    echo "crate archives exceed crates.io's 10 MB limit:" >&2
    echo "$oversized" >&2
    exit 1
}

if [[ $mode == check ]]; then
    echo "crate publication preflight passed"
    exit 0
fi

[[ -z $(git status --porcelain) ]] || {
    echo "refusing to publish from a dirty worktree" >&2
    exit 1
}
tag="v$version"
tag_commit=$(git rev-list -n 1 "$tag" 2>/dev/null || true)
[[ -n $tag_commit && $tag_commit == "$(git rev-parse HEAD)" ]] || {
    echo "release tag $tag does not point at HEAD" >&2
    exit 1
}
[[ $(git cat-file -t "refs/tags/$tag" 2>/dev/null || true) == tag ]] || {
    echo "release tag $tag is not an annotated tag" >&2
    exit 1
}
if [[ ${NARF_RELEASE_TAG_VERIFIED:-0} != 1 ]]; then
    git verify-tag "$tag"
fi
[[ -n ${CARGO_REGISTRY_TOKEN:-} ]] || {
    echo "CARGO_REGISTRY_TOKEN is required for --execute" >&2
    exit 1
}

published=0
while IFS= read -r crate; do
    endpoint="https://crates.io/api/v1/crates/$crate/$version"
    status=$(curl -sS -o /dev/null -w '%{http_code}' \
        -A 'narf-crate-publisher/0.1 (https://github.com/hodgesds/narf)' "$endpoint")
    case "$status" in
        200)
            echo "already published: $crate $version"
            continue
            ;;
        404) ;;
        *)
            echo "crates.io returned HTTP $status for $crate $version" >&2
            exit 1
            ;;
    esac

    echo "publishing $crate $version"
    if [[ $crate == narf-libc ]]; then
        command=(cargo publish --manifest-path narf-libc/Cargo.toml --locked --no-verify)
    else
        command=(cargo publish --package "$crate" --locked --no-verify)
    fi
    if ! "${command[@]}"; then
        # Cargo can time out after a successful upload while waiting for the
        # sparse index. Treat the version appearing in the API as success so a
        # signed-tag release can be resumed safely.
        status=$(curl -sS -o /dev/null -w '%{http_code}' \
            -A 'narf-crate-publisher/0.1 (https://github.com/hodgesds/narf)' "$endpoint")
        [[ $status == 200 ]] || exit 1
    fi
    published=$((published + 1))
done <"$plan"

echo "crate release complete: $published uploaded, $((actual - published)) already present"
