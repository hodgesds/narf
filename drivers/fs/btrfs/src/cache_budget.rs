//! Byte budgets of the driver's own caches, derived from the machine's RAM.
//!
//! The node cache and the verified extent-data cache used to be fixed counts
//! (4,096 nodes per filesystem, 8,192 entries and 32 MiB shared). A count says
//! nothing about the bytes behind it, and a fixed size is too much for a small
//! guest and needlessly little for a large host. Linux sizes its caches from
//! the pages it manages (`totalram_pages()`: the dentry and inode hash tables,
//! `min_free_kbytes`, the dirty limits) and leaves the rest to reclaim; here
//! each cache gets a fixed fraction of RAM, clamped to a floor (so a tiny
//! machine still caches a working set) and a ceiling (so a large one does not
//! keep hundreds of megabytes of metadata copies the page cache could use),
//! and gives memory back to the shrinker under pressure
//! ([`crate::volume`]'s node cache, [`crate::decompress_cache`]).

/// One MiB.
pub(crate) const MIB: usize = 1 << 20;

/// RAM assumed when the frame allocator has not reported any (the std host
/// harness, which runs the driver without a NARF kernel underneath).
pub(crate) const ASSUMED_RAM_BYTES: u64 = 4 << 30;

/// A cache budget as a fraction of RAM.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Fraction {
    /// The cache may hold `ram / divisor` bytes ...
    pub divisor: u64,
    /// ... but never less than this ...
    pub floor: usize,
    /// ... nor more than this.
    pub ceiling: usize,
}

impl Fraction {
    /// The budget on a machine with `ram` bytes (`None`: unknown).
    pub(crate) const fn of(self, ram: Option<u64>) -> usize {
        let ram = match ram {
            Some(ram) => ram,
            None => ASSUMED_RAM_BYTES,
        };
        let share = ram / self.divisor;
        if share < self.floor as u64 {
            self.floor
        } else if share > self.ceiling as u64 {
            self.ceiling
        } else {
            share as usize
        }
    }
}

/// Metadata node cache, per mounted filesystem: 1/128 of RAM (0.78%),
/// 4 MiB .. 256 MiB. 4 GiB of RAM: 32 MiB (2,048 16 KiB nodes);
/// 64 GiB: 256 MiB (16,384 nodes).
pub(crate) const NODE_CACHE: Fraction = Fraction {
    divisor: 128,
    floor: 4 * MIB,
    ceiling: 256 * MIB,
};

/// Verified extent-data cache, shared by every filesystem: 1/128 of RAM,
/// 4 MiB .. 128 MiB. 4 GiB: 32 MiB; 64 GiB: 128 MiB.
pub(crate) const DATA_CACHE: Fraction = Fraction {
    divisor: 128,
    floor: 4 * MIB,
    ceiling: 128 * MIB,
};

/// Bytes of RAM the frame allocator manages, or `None` before it reports
/// any.
pub(crate) fn total_ram_bytes() -> Option<u64> {
    let pages = narf_memory::frame::stats().total as u64;
    (pages != 0).then(|| pages.saturating_mul(narf_memory::frame::PAGE_SIZE))
}

/// Base page size the reclaim shrinkers count in.
pub(crate) const PAGE: usize = narf_memory::frame::PAGE_SIZE as usize;
