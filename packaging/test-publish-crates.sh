#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
plan=$(mktemp)
trap 'rm -f "$plan"' EXIT
version=$(cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "cargo-narf") | .version')

packaging/publish-crates.sh --version "$version" --plan >"$plan"

[[ $(wc -l <"$plan") -eq 117 ]]
[[ $(sort -u "$plan" | wc -l) -eq 117 ]]
! grep -qx xtask "$plan"

line_of() {
    grep -nx "$1" "$plan" | cut -d: -f1
}

kernel_test=$(line_of narf-kernel-test)
lib=$(line_of narf-lib)
user_runtime=$(line_of narf-user-runtime)
libc=$(line_of narf-libc)
relibc=$(line_of narf-compat-relibc)
frame=$(line_of narf-frame)

((kernel_test < lib))
((user_runtime < libc))
((libc < relibc))
((relibc < frame))
[[ $frame -eq 117 ]]

echo "crate publication plan tests passed"
