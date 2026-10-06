#!/usr/bin/env python3
"""Derive linux-times.sqfs from linux-gzip.sqfs with distinct inode mtimes.

mksquashfs's `-all-time` stamps one mtime on every inode, which cannot tell a
file's time from its directory's. This rewrites the image's single inode-table
metadata block uncompressed (header bit 0x8000) with a fixed, distinct
`squashfs_base_inode.mtime` per inode, then shifts every table that follows it.
Inode references stay valid: the table is still one block at offset 0.

mtimes (seconds; SquashFS has no sub-second field):
  /                 1600000000
  /nested           1650000123
  /hello.txt        1700000123
  /nested/data.txt  0xF0000000  (>= 2^31: Linux's le32_to_cpu decode is
                                 unsigned, year 2097, not before 1970)
"""
import struct
import sys
import zlib

SRC, DST = sys.argv[1], sys.argv[2]
img = bytearray(open(SRC, 'rb').read())
FMT = '<IIIIIHHHHHHQQQQQQQQ'
sb = list(struct.unpack_from(FMT, img, 0))
(BYTES_USED, ID_TABLE, XATTR_TABLE, INODE_TABLE, DIR_TABLE, FRAG_TABLE,
 LOOKUP_TABLE) = range(12, 19)
assert sb[0] == 0x73717368 and sb[5] == 1, 'expected a gzip SquashFS 4.0 image'
block_size = sb[3]

hdr = struct.unpack_from('<H', img, sb[INODE_TABLE])[0]
raw_len = hdr & 0x7fff
assert sb[INODE_TABLE] + 2 + raw_len == sb[DIR_TABLE], 'inode table is not one block'
raw = bytes(img[sb[INODE_TABLE] + 2:sb[DIR_TABLE]])
table = bytearray(raw if hdr & 0x8000 else zlib.decompress(raw))

# Walk the inodes (squashfs_fs.h layouts) to find each one's mtime field.
mtime_at = {}
p = 0
while p < len(table):
    itype, _mode, _uid, _gid, _mtime, ino = struct.unpack_from('<HHHHII', table, p)
    mtime_at[ino] = p + 8
    if itype == 1:    # basic dir
        p += 32
    elif itype == 2:  # basic file
        frag, _off, size = struct.unpack_from('<III', table, p + 20)
        nblocks = size // block_size if frag != 0xffffffff else -(-size // block_size)
        p += 32 + 4 * nblocks
    elif itype == 3:  # basic symlink
        p += 24 + struct.unpack_from('<I', table, p + 20)[0]
    elif itype in (6, 7):  # basic fifo / socket
        p += 20
    elif itype == 8:  # extended dir
        i_count = struct.unpack_from('<H', table, p + 32)[0]
        q = p + 40
        for _ in range(i_count):
            q += 12 + struct.unpack_from('<I', table, q + 8)[0] + 1
        p = q
    elif itype == 9:  # extended file
        size, = struct.unpack_from('<Q', table, p + 24)
        frag, = struct.unpack_from('<I', table, p + 44)
        nblocks = size // block_size if frag != 0xffffffff else -(-size // block_size)
        p += 56 + 4 * nblocks
    else:
        raise SystemExit('unhandled inode type %d' % itype)
assert p == len(table), 'inode walk did not end on the table boundary'


def ino_of(path):
    """Inode number of `path` via the directory table (names are unique)."""
    # The directory table ends where the fragment table's first metadata
    # block (pointed to by its index) begins.
    dir_end, = struct.unpack_from('<Q', img, sb[FRAG_TABLE])
    dirs = bytes(img[sb[DIR_TABLE]:dir_end])
    found = {}
    q = 0
    while q < len(dirs):
        h = struct.unpack_from('<H', dirs, q)[0]
        blk = dirs[q + 2:q + 2 + (h & 0x7fff)]
        data = blk if h & 0x8000 else zlib.decompress(blk)
        r = 0
        while r < len(data):
            count, _start, base = struct.unpack_from('<IIi', data, r)
            r += 12
            for _ in range(count + 1):
                _off, delta, _t, nsize = struct.unpack_from('<HhHH', data, r)
                name = data[r + 8:r + 9 + nsize].decode()
                found[name] = base + delta
                r += 9 + nsize
        q += 2 + (h & 0x7fff)
    return found[path]


root_ino = struct.unpack_from('<I', table, (sb[11] & 0xffff) + 12)[0]
times = {
    root_ino: 1600000000,
    ino_of('nested'): 1650000123,
    ino_of('hello.txt'): 1700000123,
    ino_of('data.txt'): 0xF0000000,
}
for ino, t in times.items():
    struct.pack_into('<I', table, mtime_at[ino], t)

new_block = struct.pack('<H', 0x8000 | len(table)) + bytes(table)
delta = len(new_block) - (2 + raw_len)
out = bytearray(img[:sb[INODE_TABLE]]) + new_block + img[sb[DIR_TABLE]:sb[BYTES_USED]]
# Every table after the inode table moves by `delta`, and so does each u64
# metadata-block pointer in the fragment, export and id indexes.
for field in (DIR_TABLE, FRAG_TABLE, LOOKUP_TABLE, ID_TABLE, BYTES_USED):
    if sb[field] != 0xffffffffffffffff:
        sb[field] += delta
assert sb[XATTR_TABLE] == 0xffffffffffffffff, 'xattr table relocation not handled'
for index, count in ((FRAG_TABLE, -(-sb[4] * 16 // 8192)),
                     (LOOKUP_TABLE, -(-sb[1] * 8 // 8192)),
                     (ID_TABLE, -(-sb[8] * 4 // 8192))):
    if sb[index] == 0xffffffffffffffff or count == 0:
        continue
    for i in range(count):
        at = sb[index] + 8 * i
        ptr, = struct.unpack_from('<Q', out, at)
        struct.pack_into('<Q', out, at, ptr + delta)
struct.pack_into(FMT, out, 0, *sb)
out += bytes(-len(out) % 4096)
open(DST, 'wb').write(out)
print('wrote %s: inodes %s' % (DST, sorted(times.items())))
