#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d /tmp/narf-squashfs-fixture.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mkdir -p "$tmp/root/nested"
printf 'narf-squashfs\n' >"$tmp/root/hello.txt"
printf 'nested-payload\n' >"$tmp/root/nested/data.txt"
ln -s nested/data.txt "$tmp/root/data-link"
mkfifo "$tmp/root/pipe"
truncate -s 16384 "$tmp/root/sparse.bin"
printf 'tail-data' | dd of="$tmp/root/sparse.bin" bs=1 seek=12000 conv=notrunc status=none

mksq=mksquashfs
if ! "$mksq" -version >/dev/null 2>&1; then
    mksq='/lib64/ld-linux-x86-64.so.2 /usr/local/bin/mksquashfs'
fi

# shellcheck disable=SC2086 # mksq intentionally contains loader + program.
$mksq "$tmp/root" "$here/linux-gzip.sqfs" -noappend -no-progress \
    -all-root -no-xattrs -comp gzip -b 4096 -mkfs-time 1700000000 -all-time 1700000000
