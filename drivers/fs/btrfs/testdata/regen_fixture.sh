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
#   fixture-lzo.img.sparse   --compress lzo (exercises the LZO read path)
#   fixture-manyfiles.img.sparse  400 files -> a multi-level FS b-tree
#   fixture-defaultsubvol.img.sparse  default subvolume set to `def`
#
# Staging tree: hello.txt (tiny -> inline; carries a user.narf xattr),
# big.dat (12000 B -> regular extents), subdir/note.txt, link.txt (a symlink to
# hello.txt), hardlink.txt (a hard link to hello.txt), nulldev/blkdev/fifo
# (device + FIFO special files), and snap/inside.txt where snap is created as a
# nested subvolume (its dir entry resolves to a ROOT_ITEM).
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
imglzo="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo"' EXIT

mkdir -p "$stage/subdir" "$stage/snap"
printf 'narf\n' > "$stage/hello.txt"                               # tiny -> inline extent
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$stage/big.dat"                                             # 12000 B -> regular extents
printf 'nested file\n' > "$stage/subdir/note.txt"
printf 'inside subvol\n' > "$stage/snap/inside.txt"               # file in the snap subvolume
ln -s hello.txt "$stage/link.txt"                                  # symlink
ln "$stage/hello.txt" "$stage/hardlink.txt"                        # hardlink (shares hello.txt's inode)
mknod "$stage/nulldev" c 1 3                                       # char device 1:3
mknod "$stage/blkdev" b 8 0                                        # block device 8:0
mkfifo "$stage/fifo"                                               # FIFO
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
    -O ^free-space-tree,^no-holes --subvol rw:snap --rootdir "$stage" "$img" >/dev/null
btrfs check "$img" >/dev/null
sparse_encode "$img" fixture.img.sparse

truncate -s 16M "$imgz"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --subvol rw:snap --compress zlib --rootdir "$stage" "$imgz" >/dev/null
btrfs check "$imgz" >/dev/null
sparse_encode "$imgz" fixture-zlib.img.sparse

truncate -s 16M "$imgzst"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --subvol rw:snap --compress zstd --rootdir "$stage" "$imgzst" >/dev/null
btrfs check "$imgzst" >/dev/null
sparse_encode "$imgzst" fixture-zstd.img.sparse

truncate -s 16M "$imglzo"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --subvol rw:snap --compress lzo --rootdir "$stage" "$imglzo" >/dev/null
btrfs check "$imglzo" >/dev/null
sparse_encode "$imglzo" fixture-lzo.img.sparse

# A tiny image whose default subvolume is set to `def` (not FS_TREE), so a plain
# mount must land inside `def` rather than at the top-level FS_TREE.
defstage="$(mktemp -d)"
imgdef="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$defstage" "$imgdef"' EXIT
mkdir -p "$defstage/def"
printf 'root file\n' > "$defstage/rootfile.txt"
printf 'default subvol file\n' > "$defstage/def/dfile.txt"
truncate -s 16M "$imgdef"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --subvol default:def --rootdir "$defstage" "$imgdef" >/dev/null
btrfs check "$imgdef" >/dev/null
sparse_encode "$imgdef" fixture-defaultsubvol.img.sparse

# A realistic *laptop distro* image: non-mixed block groups, nodesize 16384,
# zstd, and — unlike the other fixtures — btrfs-progs DEFAULT features
# (free-space-tree / space_cache=v2, no-holes, extref, skinny-metadata,
# big-metadata), with a Fedora/openSUSE-style subvolume layout (`root` as the
# default subvolume, `home` as a second subvolume). Proves the driver reads what
# a real laptop's btrfs root looks like. Non-mixed btrfs has a ~128 MiB floor.
labstage="$(mktemp -d)"
imglab="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab"' EXIT
mkdir -p "$labstage/root/etc" "$labstage/home/user"
printf 'NAME="NARF Laptop"\nID=narf\n' > "$labstage/root/etc/os-release"
printf 'root subvol file\n' > "$labstage/root/rootfile.txt"
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$labstage/root/big.dat"
printf 'home user file\n' > "$labstage/home/user/notes.txt"
truncate -s 128M "$imglab"
mkfs.btrfs --csum crc32c --nodesize 16384 --sectorsize 4096 --compress zstd \
    --subvol default:root --subvol rw:home --rootdir "$labstage" "$imglab" >/dev/null
btrfs check "$imglab" >/dev/null
sparse_encode "$imglab" fixture-laptop.img.sparse

# A separate tree of 400 small (inline) files, forcing the FS b-tree to grow to
# more than one level so tests exercise internal-node descent and leaf-to-leaf
# cursor advance. Needs a 32 MiB image for the extra metadata.
many="$(mktemp -d)"
imgmany="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab"' EXIT
python3 -c "
for i in range(400):
    open('$many/file%03d.txt'%i,'w').write('content-of-file-%03d\n'%i)
"
truncate -s 32M "$imgmany"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --rootdir "$many" "$imgmany" >/dev/null
btrfs check "$imgmany" >/dev/null
sparse_encode "$imgmany" fixture-manyfiles.img.sparse

echo "regenerated fixture{,-zlib,-zstd,-lzo,-defaultsubvol,-manyfiles,-laptop}.img.sparse"
