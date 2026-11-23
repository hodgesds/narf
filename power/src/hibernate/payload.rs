//! The hibernation payload (S4 lane 6): the plaintext the sealed image
//! carries, Linux's `swsusp_info` header plus its page data.
//!
//! ```text
//! [ header page ]  PayloadHeader, zero-padded to 4 KiB
//! [ frame table ]  page_count frame numbers, u64 LE, zero-padded to 4 KiB
//! [ pages ]        page_count × 4 KiB, in frame-table order
//! ```
//!
//! Like `swsusp_info`, the header records what the resume must match
//! before it restores anything:
//! - the kernel's virtual base and physical bounds, standing in for
//!   Linux's `utsname` and `check_image_kernel`;
//! - a hash of the RAM layout, standing in for
//!   `arch_hibernation_header_save`'s e820 checksum;
//! - the arch restore record, which lane 8 fills.
//!
//! [`PayloadSource`] streams it from a snapshot as an
//! [`ImageSource`](crate::suspend_service::ImageSource), so the sealed
//! writer never holds more than one chunk.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_crypto::sha256::Sha256;

use super::snapshot::Snapshot;
use crate::suspend_service::ImageSource;

pub const PAYLOAD_MAGIC: &[u8; 8] = b"NARFSNAP";
pub const PAYLOAD_VERSION: u32 = 1;
const PAGE: u64 = 4096;
/// Bytes of the arch restore record (lane 8).
pub const ARCH_RECORD_LEN: usize = 512;
/// Encoded header bytes before the arch record.
const FIXED_LEN: usize = 8 + 4 + 4 + 8 + 8 + 8 + 8 + 32;

/// The payload header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadHeader {
    pub page_count: u64,
    /// `kaslr::kernel_virt_base`: the image kernel's link base plus slide.
    pub kernel_virt_base: u64,
    /// `kaslr::image_phys_bounds`.
    pub kernel_phys: (u64, u64),
    /// [`ram_layout_hash`] of the hibernating kernel.
    pub ram_hash: [u8; 32],
    /// The per-arch restore record (lane 8), zero until it exists.
    pub arch: [u8; ARCH_RECORD_LEN],
}

/// Why a payload header was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    Short,
    Magic,
    Version(u32),
}

impl PayloadHeader {
    /// The header for `page_count` pages of the running kernel.
    pub fn for_running_kernel(page_count: u64) -> Self {
        Self {
            page_count,
            kernel_virt_base: narf_memory::kaslr::kernel_virt_base(),
            kernel_phys: narf_memory::kaslr::image_phys_bounds(),
            ram_hash: ram_layout_hash(&narf_memory::frame::saveable_ram_ranges()),
            arch: [0; ARCH_RECORD_LEN],
        }
    }

    /// The header page, written into `page`.
    pub fn encode_into(&self, page: &mut [u8; PAGE as usize]) {
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            page[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(PAYLOAD_MAGIC);
        put(&PAYLOAD_VERSION.to_le_bytes());
        put(&(ARCH_RECORD_LEN as u32).to_le_bytes());
        put(&self.page_count.to_le_bytes());
        put(&self.kernel_virt_base.to_le_bytes());
        put(&self.kernel_phys.0.to_le_bytes());
        put(&self.kernel_phys.1.to_le_bytes());
        put(&self.ram_hash);
        put(&self.arch);
    }

    /// The header page.
    pub fn encode(&self) -> [u8; PAGE as usize] {
        let mut page = [0u8; PAGE as usize];
        self.encode_into(&mut page);
        page
    }

    pub fn decode(page: &[u8]) -> Result<Self, PayloadError> {
        if page.len() < FIXED_LEN + ARCH_RECORD_LEN {
            return Err(PayloadError::Short);
        }
        if &page[..8] != PAYLOAD_MAGIC {
            return Err(PayloadError::Magic);
        }
        let u32_at = |at: usize| u32::from_le_bytes(page[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(page[at..at + 8].try_into().unwrap());
        let version = u32_at(8);
        if version != PAYLOAD_VERSION || u32_at(12) as usize != ARCH_RECORD_LEN {
            return Err(PayloadError::Version(version));
        }
        let mut ram_hash = [0; 32];
        ram_hash.copy_from_slice(&page[48..80]);
        let mut arch = [0; ARCH_RECORD_LEN];
        arch.copy_from_slice(&page[FIXED_LEN..FIXED_LEN + ARCH_RECORD_LEN]);
        Ok(Self {
            page_count: u64_at(16),
            kernel_virt_base: u64_at(24),
            kernel_phys: (u64_at(32), u64_at(40)),
            ram_hash,
            arch,
        })
    }
}

/// SHA-256 over the RAM ranges (`[start_pfn, end_pfn)` pairs, u64 LE): what
/// must match between the hibernating and the resuming kernel.
pub fn ram_layout_hash(ranges: &[(u64, u64)]) -> [u8; 32] {
    let mut h = Sha256::new();
    for &(start, end) in ranges {
        h.update(&start.to_le_bytes());
        h.update(&end.to_le_bytes());
    }
    h.finalize()
}

/// Byte offset of the frame table.
pub const fn frame_table_offset() -> u64 {
    PAGE
}

/// Byte offset of the first page for `page_count` pages.
pub const fn pages_offset(page_count: u64) -> u64 {
    PAGE + (page_count * 8).div_ceil(PAGE) * PAGE
}

/// Payload length for `page_count` pages.
pub const fn payload_len(page_count: u64) -> u64 {
    pages_offset(page_count) + page_count * PAGE
}

/// The pages a payload streams: a snapshot, or a test's fake.
pub trait Pages {
    fn count(&self) -> usize;
    fn pfn(&self, i: usize) -> u64;
    fn page(&self, i: usize) -> &[u8; PAGE as usize];
}

impl Pages for Snapshot {
    fn count(&self) -> usize {
        self.len()
    }

    fn pfn(&self, i: usize) -> u64 {
        self.pfns()[i]
    }

    fn page(&self, i: usize) -> &[u8; PAGE as usize] {
        Snapshot::page(self, i).1
    }
}

/// A payload streamed from its pages.
pub struct PayloadSource<'a, P: Pages + ?Sized> {
    /// The encoded header page, heap-allocated: a 4 KiB array by value in
    /// the caller's frame is what put `hibernate`'s callers over budget.
    header: Box<[u8; PAGE as usize]>,
    pages: &'a P,
}

impl<P: Pages + ?Sized> core::fmt::Debug for PayloadSource<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PayloadSource")
            .field("pages", &self.pages.count())
            .finish_non_exhaustive()
    }
}

impl<'a, P: Pages + ?Sized> PayloadSource<'a, P> {
    pub fn new(header: &PayloadHeader, pages: &'a P) -> Self {
        debug_assert_eq!(header.page_count, pages.count() as u64);
        // The encoded header page (4 KiB) lives on the heap, not in the
        // caller's frame: building it by value in `hibernate`'s poll kept
        // both the page and `encode`'s own copy there (8552 bytes, main
        // run 45082275318).
        let mut encoded = Box::new([0u8; PAGE as usize]);
        header.encode_into(&mut encoded);
        Self {
            header: encoded,
            pages,
        }
    }

    fn count(&self) -> u64 {
        self.pages.count() as u64
    }
}

impl<P: Pages + ?Sized> ImageSource for PayloadSource<'_, P> {
    fn len(&self) -> u64 {
        payload_len(self.count())
    }

    fn read_at(&self, mut offset: u64, mut out: &mut [u8]) {
        let table = frame_table_offset();
        let pages = pages_offset(self.count());
        while !out.is_empty() {
            let taken = if offset < table {
                let n = out.len().min((table - offset) as usize);
                let at = offset as usize;
                out[..n].copy_from_slice(&self.header[at..at + n]);
                n
            } else if offset < pages {
                // The frame table, eight bytes per frame, then zero padding.
                let n = out.len().min((pages - offset) as usize);
                for (k, byte) in out[..n].iter_mut().enumerate() {
                    let at = offset - table + k as u64;
                    let i = (at / 8) as usize;
                    *byte = if (i as u64) < self.count() {
                        self.pages.pfn(i).to_le_bytes()[(at % 8) as usize]
                    } else {
                        0
                    };
                }
                n
            } else {
                let i = ((offset - pages) / PAGE) as usize;
                let within = ((offset - pages) % PAGE) as usize;
                let n = out.len().min(PAGE as usize - within);
                out[..n].copy_from_slice(&self.pages.page(i)[within..within + n]);
                n
            };
            offset += taken as u64;
            out = &mut out[taken..];
        }
    }
}

/// Frame numbers decoded from a frame-table region.
pub fn decode_frame_table(bytes: &[u8], page_count: u64) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .take(page_count as usize)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect()
}

#[cfg(feature = "kernel-test")]
#[path = "payload_tests.rs"]
mod tests;
