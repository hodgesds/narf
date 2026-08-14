//! CRC32C (Castagnoli) — btrfs's default checksum and directory name hash.
//!
//! btrfs uses CRC32C in two distinct ways, both built on the same reflected
//! Castagnoli polynomial (`0x82F63B78`):
//!
//! * **Block checksums** (superblock + every tree node) — the on-disk value is
//!   the standard CRC32C with initial value `0xFFFF_FFFF` and a final XOR of
//!   `0xFFFF_FFFF`, computed over the block bytes *after* the 32-byte csum
//!   field. See [`block_csum`]. This mirrors Linux's crc32c crypto shash
//!   (`crypto/crc32c_generic.c`), whose `.init` seeds `~0` and `.final` emits
//!   `~crc`.
//!
//! * **Directory name hash** — `btrfs_name_hash()` in the kernel is the *raw*
//!   running CRC32C (`lib/crc32c.c`, no inversions) seeded with `~1`
//!   (`0xFFFF_FFFE`). Its result forms the `offset` of `DIR_ITEM` keys, so the
//!   same polynomial that validates a node also locates a file by name. See
//!   [`name_hash`].
//!
//! Getting the polynomial wrong breaks *both* — a lookup would miss every file
//! even while enumeration works — so the check-value test in `tests.rs` guards
//! this module before anything depends on it.

/// Reflected Castagnoli polynomial.
const POLY: u32 = 0x82F6_3B78;

/// Compile-time CRC32C lookup table (one entry per input byte).
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                POLY ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = build_table();

/// Raw running CRC32C update, matching Linux `crc32c(seed, data, len)`
/// (`lib/crc32c.c`): no pre/post inversion, the caller supplies the seed and
/// interprets the residue. This is the primitive both public helpers build on.
pub fn crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        let idx = ((crc ^ u32::from(byte)) & 0xff) as usize;
        crc = TABLE[idx] ^ (crc >> 8);
    }
    crc
}

/// On-disk block checksum (superblock and every tree node): standard CRC32C
/// with `~0` seed and final inversion. `data` is the block content starting
/// *after* the 32-byte csum field. The low 4 bytes of the result are what
/// btrfs stores; the remaining csum bytes are zero for CRC32C.
pub fn block_csum(data: &[u8]) -> u32 {
    !crc32c(!0u32, data)
}

/// `btrfs_name_hash()`: raw CRC32C seeded with `~1`, used as the `offset`
/// component of a `DIR_ITEM` key so a name resolves to its directory entry.
pub fn name_hash(name: &[u8]) -> u32 {
    crc32c(!1u32, name)
}
