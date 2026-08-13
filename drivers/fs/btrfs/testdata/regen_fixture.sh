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
# Pinned so a future btrfs-progs can't silently drift the layout:
#   --csum crc32c            driver only supports CRC32C
#   --sectorsize 4096        page-sized sectors
#   --nodesize 4096          required by mixed mode; keeps the image at 16 MiB
#   -M                       mixed block groups (small-image layout)
#   -O ^free-space-tree,^no-holes   primary fixture: explicit hole extents
#
# btrfs-progs pinned at: v6.17.1 (update this line if you regen with a newer one).
set -euo pipefail
cd "$(dirname "$0")"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/subdir"
printf 'narf\n' > "$stage/hello.txt"                               # tiny -> inline extent
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$stage/big.dat"                                             # 12000 B -> regular extents
printf 'nested file\n' > "$stage/subdir/note.txt"

img="$(mktemp)"; trap 'rm -rf "$stage" "$img"' EXIT
truncate -s 16M "$img"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --rootdir "$stage" "$img" >/dev/null
btrfs check "$img" >/dev/null

python3 - "$img" fixture.img.sparse <<'PY'
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
echo "regenerated fixture.img.sparse"
