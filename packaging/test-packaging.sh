#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p target/x86_64-unknown-none/release
for path in target/x86_64-unknown-none/release/narf-frame
do
    if [[ ! -e $path ]]; then
        printf 'packaging-test-fixture\n' >"$path"
        printf '%s\n' "$path" >>"$tmp/created"
    fi
done

NARF_SKIP_GRUB_CHECK=1 packaging/build-release.sh --version 0.0.0-test.1 --skip-build \
    --formats tar,gentoo --output "$tmp/out" --source-date-epoch 1700000000
test -f "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz"
test -f "$tmp/out/gentoo/sys-kernel/narf-kernel/narf-kernel-0.0.0-test.1.ebuild"
test -f "$tmp/out/release-manifest.json"
(cd "$tmp/out" && sha256sum -c SHA256SUMS)
tar -tzf "$tmp/out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null

# Exercise the source-installable Cargo frontend as well as the underlying
# release builder. It must produce the same package layout without installing
# anything on the host.
cargo run -q -p cargo-narf -- narf package --version 0.0.0-test.1 \
    --formats tar --skip-build --output "$tmp/cargo-out" \
    --source-date-epoch 1700000000
test -f "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz"
tar -tzf "$tmp/cargo-out/narf-0.0.0-test.1-x86_64.tar.gz" |
    grep -F './boot/narf-kernel-0.0.0-test.1' >/dev/null

if [[ -f $tmp/created ]]; then
    while IFS= read -r path; do rm -f "$path"; done <"$tmp/created"
fi
echo "packaging tests passed"
