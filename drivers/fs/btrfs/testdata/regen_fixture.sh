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
#   fixture-{xxhash,sha256,blake2}.img.sparse  alternate checksum algorithms
#   fixture-nestedsubvol.img.sparse  normal-dir/subvolume/subvolume path
#   fixture-manyfiles.img.sparse  400 files -> a multi-level FS b-tree
#   fixture-defaultsubvol.img.sparse  default subvolume set to `def`
#   fixture-fst.img.sparse   like fixture.img but WITH a free-space tree
#                            (space_cache=v2); exercises the write path's
#                            free-space-tree maintenance
#
# Staging tree: hello.txt (tiny -> inline; carries a user.narf xattr),
# big.dat (12000 B -> regular extents), subdir/note.txt, link.txt (a symlink to
# hello.txt), hardlink.txt (a hard link to hello.txt), nulldev/blkdev/fifo
# (device + FIFO special files), and snap/inside.txt where snap is created as a
# nested subvolume (its dir entry resolves to a ROOT_ITEM).
#
# Pinned so a future btrfs-progs can't silently drift the layout:
#   --csum crc32c            writable fixture checksum (alternate read-only
#                            checksum fixtures are generated separately)
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
imgxx="$(mktemp)"
imgsha="$(mktemp)"
imgblake="$(mktemp)"
nestedstage="$(mktemp -d)"
imgnested="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgxx" "$imgsha" "$imgblake" "$nestedstage" "$imgnested"' EXIT

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

# A normal directory followed by two nested subvolume roots. This distinguishes
# path walking from the old one-component lookup and exercises tree changes at
# both `container/outer` and `container/outer/inner`.
mkdir -p "$nestedstage/container/outer/inner" "$nestedstage/container/outer/rochild"
printf 'container file\n' > "$nestedstage/container/top.txt"
printf 'outer subvolume file\n' > "$nestedstage/container/outer/outer.txt"
printf 'deep subvolume file\n' > "$nestedstage/container/outer/inner/deep.txt"
printf 'read-only subvolume file\n' > "$nestedstage/container/outer/rochild/readonly.txt"
truncate -s 16M "$imgnested"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes \
    --subvol rw:container/outer --subvol rw:container/outer/inner \
    --subvol ro:container/outer/rochild \
    --rootdir "$nestedstage" "$imgnested" >/dev/null
btrfs check "$imgnested" >/dev/null
sparse_encode "$imgnested" fixture-nestedsubvol.img.sparse
rm -rf "$nestedstage"
rm -f "$imgnested"

if [[ "${NARF_BTRFS_NESTED_ONLY:-0}" == 1 ]]; then
    exit 0
fi

# Real mkfs images for every non-default checksum algorithm. These are mounted
# read-only by NARF; keeping them genuine also covers their CSUM_ITEM widths.
# Set NARF_BTRFS_CSUM_ONLY=1 to regenerate just these three fixtures.
for spec in \
    "xxhash:$imgxx:fixture-xxhash.img.sparse" \
    "sha256:$imgsha:fixture-sha256.img.sparse" \
    "blake2:$imgblake:fixture-blake2.img.sparse"
do
    IFS=: read -r algorithm checksum_img output <<<"$spec"
    truncate -s 16M "$checksum_img"
    mkfs.btrfs --csum "$algorithm" --sectorsize 4096 --nodesize 4096 -M \
        -O ^free-space-tree,^no-holes --subvol rw:snap --rootdir "$stage" "$checksum_img" >/dev/null
    btrfs check "$checksum_img" >/dev/null
    sparse_encode "$checksum_img" "$output"
done
rm -f "$imgxx" "$imgsha" "$imgblake"

if [[ "${NARF_BTRFS_CSUM_ONLY:-0}" == 1 ]]; then
    exit 0
fi

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

# Same small mixed layout as the base fixture but WITH the free-space tree
# (space_cache=v2) enabled (btrfs-progs default; only `^no-holes` is overridden).
# A minimal staging tree (hello.txt + big.dat, no subvolumes/specials) keeps the
# fs/csum/extent/root/free-space trees each a single leaf so the COW write path —
# including its free-space-tree maintenance — is exercised, and the NARF-written
# image stays `btrfs check`-clean for a real Linux kernel.
imgfst="$(mktemp)"
fststage="$(mktemp -d)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage"' EXIT
printf 'narf\n' > "$fststage/hello.txt"
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$fststage/big.dat"
truncate -s 16M "$imgfst"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^no-holes --rootdir "$fststage" "$imgfst" >/dev/null
btrfs check "$imgfst" >/dev/null
sparse_encode "$imgfst" fixture-fst.img.sparse

# A tiny image whose default subvolume is set to `def` (not FS_TREE), so a plain
# mount must land inside `def` rather than at the top-level FS_TREE.
defstage="$(mktemp -d)"
imgdef="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage" "$defstage" "$imgdef"' EXIT
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
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab"' EXIT
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
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab"' EXIT
python3 -c "
for i in range(400):
    open('$many/file%03d.txt'%i,'w').write('content-of-file-%03d\n'%i)
"
truncate -s 32M "$imgmany"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^free-space-tree,^no-holes --rootdir "$many" "$imgmany" >/dev/null
btrfs check "$imgmany" >/dev/null
sparse_encode "$imgmany" fixture-manyfiles.img.sparse

# A 96 MiB image large enough that mkfs writes a SECOND superblock copy (the
# 64 MiB mirror; the 256 GiB one still doesn't fit). Small feature set (mixed
# block groups, nodesize 4096, free-space tree, no compression) so the COW write
# path applies — this exercises writing all superblock mirrors in lockstep and
# leaves room past 64 MiB to grow a chunk without overlapping the mirror.
mirrstage="$(mktemp -d)"
imgmirr="$(mktemp)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab" "$mirrstage" "$imgmirr"' EXIT
printf 'narf\n' > "$mirrstage/hello.txt"
python3 -c "import sys;sys.stdout.write(''.join('L%04d\n'%i for i in range(2000)))" \
    > "$mirrstage/big.dat"
truncate -s 96M "$imgmirr"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M \
    -O ^no-holes --rootdir "$mirrstage" "$imgmirr" >/dev/null
btrfs check "$imgmirr" >/dev/null
sparse_encode "$imgmirr" fixture-mirror.img.sparse

# Like fixture-mirror (96 MiB mixed + free-space tree, hello.txt + big.dat), but
# with one data block group deliberately **fragmented** so its free space is
# tracked with a `FREE_SPACE_BITMAP` (`btrfs` converts to bitmaps once a group has
# many free extents) instead of `FREE_SPACE_EXTENT`s. Exercises the write path's
# bitmap read/set/recount. Needs a loop mount to fragment (root); `fstrim`
# discards the freed blocks so the sparse blob stays small.
imgbm="$(mktemp)"
bmmnt="$(mktemp -d)"
trap 'rm -rf "$stage" "$img" "$imgz" "$imgzst" "$imglzo" "$imgfst" "$fststage" "$defstage" "$imgdef" "$many" "$imgmany" "$labstage" "$imglab" "$mirrstage" "$imgmirr" "$imgbm"; umount "$bmmnt" 2>/dev/null; rmdir "$bmmnt" 2>/dev/null' EXIT
truncate -s 96M "$imgbm"
mkfs.btrfs --csum crc32c --sectorsize 4096 --nodesize 4096 -M -O ^no-holes "$imgbm" >/dev/null
mount -o loop "$imgbm" "$bmmnt"
printf 'narf\n' > "$bmmnt/hello.txt"
python3 -c "open('$bmmnt/big.dat','w').write(''.join('L%04d\n'%i for i in range(2000)))"
python3 -c "
import os
for i in range(160): open('$bmmnt/f%04d'%i,'wb').write(bytes([(i*7)&0xff])*4096)
os.sync()
for i in range(0,160,2): os.remove('$bmmnt/f%04d'%i)  # alternating -> fragmented free space
os.sync()
"
sync; fstrim "$bmmnt"; sync; umount "$bmmnt"
btrfs check "$imgbm" >/dev/null
btrfs inspect-internal dump-tree -t FREE_SPACE "$imgbm" | grep -q FREE_SPACE_BITMAP \
    || { echo "fixture-bitmap has no FREE_SPACE_BITMAP" >&2; exit 1; }
sparse_encode "$imgbm" fixture-bitmap.img.sparse

echo "regenerated fixture{,-zlib,-zstd,-lzo,-fst,-defaultsubvol,-manyfiles,-laptop,-mirror,-bitmap}.img.sparse"
