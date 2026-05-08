# Analysis: ext2 Block Pointer Walk

**Sources:**
- Card, Ts'o, Tweedie. _Design and Implementation of the Second
  Extended Filesystem_. <https://web.mit.edu/tytso/www/linux/ext2intro.html>
- OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

## The 15-pointer scheme

Every ext2 inode carries 15 32-bit block pointers in `i_block[0..15]`:

- `i_block[0]` … `i_block[11]` — **direct** pointers. Together these
  reach the first `12 * BS` bytes of the file (where `BS` is the
  block size).
- `i_block[12]` — **single-indirect**. Points at a block whose
  contents are an array of `BS / 4` block pointers, each of which
  references one data block. Reach: `(BS / 4) * BS` bytes beyond the
  direct region.
- `i_block[13]` — **double-indirect**. Points at a block whose
  contents are `BS / 4` single-indirect block pointers. Reach:
  `(BS / 4)² * BS` bytes beyond the single-indirect region.
- `i_block[14]` — **triple-indirect**. Points at a block whose
  contents are `BS / 4` double-indirect block pointers. Reach:
  `(BS / 4)³ * BS` bytes beyond the double-indirect region.

## Address arithmetic

Given a logical-byte offset `O` into a file, the corresponding
logical block index is `B = O / BS`. Then:

```
let p = BS / 4;          // pointers per indirect block
let direct_max = 12;
let single_max = direct_max + p;
let double_max = single_max + p * p;
let triple_max = double_max + p * p * p;

if B < direct_max:
    physical = i_block[B]
elif B < single_max:
    L = B - direct_max
    L1_block = i_block[12]
    physical = read_pointer(L1_block, L)
elif B < double_max:
    L  = B - single_max
    L1 = L / p          // index into the L1 block
    L0 = L % p          // index into the leaf L0 block
    L1_block = i_block[13]
    leaf_block_no = read_pointer(L1_block, L1)
    physical = read_pointer(leaf_block_no, L0)
elif B < triple_max:
    L  = B - double_max
    L2 = L / (p * p)
    L1 = (L / p) % p
    L0 = L % p
    L2_block = i_block[14]
    middle = read_pointer(L2_block, L2)
    leaf   = read_pointer(middle, L1)
    physical = read_pointer(leaf, L0)
else:
    out-of-range
```

The driver caches each indirect block by its block number; pointer-
zero indicates a hole (zero-filled), which on a read returns zero bytes
for the corresponding range.

## Bounds and safety

Each pointer-array index must be in `[0, p)`; an out-of-range
arithmetic result indicates corruption and is mapped to
`FsError::Io(IOError)`. A cycle in the indirect chain (a pointer
pointing back at its own block, or a chain longer than the
total-block count) is similarly rejected.
