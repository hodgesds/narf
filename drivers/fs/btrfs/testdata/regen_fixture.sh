#!/usr/bin/env bash
# Regenerate the committed btrfs test fixtures.
#
# The driver's unit tests mount these under a `RamBlockDevice`. They are built
# from a staging directory with `mkfs.btrfs --rootdir` (no loop mount / no root
# required) and pinned options so the on-disk layout is deterministic. Because a
# btrfs image has a hard 16 MiB minimum but only ~90 KiB of it is non-zero, we
# store a compact *sparse* encoding (see the `NARFBTR1` format below) and rebuild
# the full zero-filled image at test time — keeping the committed blob and the
# kernel `.rodata` embed tiny.
#
# Three fixtures are produced from the same staging tree:
#   fixture.img.sparse       uncompressed (data reads exercise inline/regular)
#   fixture-zlib.img.sparse  --compress zlib (exercises the zlib read path)
#   fixture-zstd.img.sparse  --compress zstd (exercises the zstd read path)
#
# Staging tree: hello.txt (tiny -> inline; carries a user.narf xattr),
# big.dat (12000 B -> regular extents), subdir/note.txt, and link.txt (a
# symlink to hello.txt).
#
# Pinned so a future btrfs-progs can't silently drift the layout:
#   --csum crc32c            driver only supports CRC32C
#   --sectorsize 4096        page-sized sectors
#   --nodesize 4096          required by mixed mode; keeps the image at 16 MiB
#   -M                       mixed block groups (small-image layout)
#   -O ^free-space-tree,^no-holes   explicit hole extents
#
# btrfs-progs pinned at: v6.17.1 (update this line if you regen with a newer one).
set -euo pipefail
cd "$(dirname "$0")"

stage="$(mktemp -d)"
img="$(mktemp)"
imgz="$(mktemp)"
imgzst="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst"' EXIT

mkdir -p "$stage/subdir"
printf 'narf\n' > "$stage/hello.txt"                               # tiny -> inline extent
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$stage/big.dat"                                             # 12000 B -> regular extents
printf 'nested file\n' > "$stage/subdir/note.txt"
ln -s hello.txt "$stage/link.txt"                                  # symlink
setfattr -n user.narf -v hi "$stage/hello.txt"                     # xattr

sparse_encode() { # <image> <dst.sparse>
    python3 - "$1" "$2" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, 'rb').read()
bs = 4096
runs = []
i = 0
while i < len(data):
    if any(data[i:i+bs]):
        j = i
        while j < len(data) and any(data[j:j+bs]):
            j += bs
        runs.append((i, data[i:j]))
        i = j
    else:
        i += bs
with open(dst, 'wb') as f:
    f.write(b'NARFBTR1')
    f.write(len(data).to_bytes(8, 'little'))
    f.write(len(runs).to_bytes(4, 'little'))
    for off, blob in runs:
        f.write(off.to_bytes(8, 'little'))
        f.write(len(blob).to_bytes(8, 'little'))
        f.write(blob)
print("wrote %s: total=%d runs=%d payload=%d"
      % (dst, len(data), len(runs), sum(len(b) for _, b in runs)))
PY
}

truncate -s 16M "$img"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --rootdir "$stage" "$img" >/dev/null
btrfs check "$img" >/dev/null
sparse_encode "$img" fixture.img.sparse

truncate -s 16M "$imgz"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --compress zlib --rootdir "$stage" "$imgz" >/dev/null
btrfs check "$imgz" >/dev/null
sparse_encode "$imgz" fixture-zlib.img.sparse

truncate -s 16M "$imgzst"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --compress zstd --rootdir "$stage" "$imgzst" >/dev/null
btrfs check "$imgzst" >/dev/null
sparse_encode "$imgzst" fixture-zstd.img.sparse

echo "regenerated fixture.img.sparse + fixture-zlib.img.sparse + fixture-zstd.img.sparse"
