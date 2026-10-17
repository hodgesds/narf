//! NVMe data-pointer construction: PRP entries and PRP lists, plus the
//! controller limits that bound a single data transfer (MDTS, CAP.MPSMIN,
//! the namespace LBA format).
//!
//! Everything here is pure arithmetic over addresses and Identify bytes, so
//! the kernel tests can drive it against a software model of the
//! controller's PRP walk without any DMA.
//!
//! References (NVMe Base Specification 2.0c):
//! - §4.1.1 PRP entry: bits 1:0 of every entry are zero; only the first
//!   entry (PRP1) may carry a non-zero offset into a memory page, every
//!   later entry is page aligned.
//! - §4.1.1.1 PRP list: when PRP2 is a list pointer, the last entry of a
//!   full list page points to the next list page.
//! - §5.17.2.1 Identify Controller byte 77, MDTS: maximum data transfer in
//!   units of the minimum memory page size (CAP.MPSMIN), as a power of two;
//!   zero means no limit.
//!
//! Linux reference: drivers/nvme/host/pci.c `nvme_pci_setup_data_prp` (the
//! PRP1 / PRP2 / chained-list layout, including the "move the last entry to
//! the new list page" chaining step) and drivers/nvme/host/core.c
//! `nvme_mps_to_sectors` / `nvme_init_identify` (MDTS) and
//! `nvme_enable_ctrl` (the CAP.MPSMIN check).

/// Host memory page size the driver programs into `CC.MPS` (MPS = 0).
/// Linux: `NVME_CTRL_PAGE_SHIFT` in drivers/nvme/host/nvme.h.
pub const NVME_CTRL_PAGE_SHIFT: u32 = 12;
/// `1 << NVME_CTRL_PAGE_SHIFT`.
pub const NVME_CTRL_PAGE_SIZE: usize = 1 << NVME_CTRL_PAGE_SHIFT;
/// 8-byte PRP entries per list page.
pub const PRPS_PER_PAGE: usize = NVME_CTRL_PAGE_SIZE / 8;

/// Largest single data transfer the host side issues, whatever MDTS says.
///
/// Linux caps a request at `NVME_MAX_BYTES` (8 MiB, drivers/nvme/host/pci.c)
/// and then at the DMA mapping limit; on the target host the drives report
/// 1 MiB (`max_hw_sectors_kb` = 1024). NARF uses one persistent PRP-list page
/// per controller, and 2 MiB is the most that one page always describes
/// (511 or 512 entries after PRP1, whatever the PRP1 offset), so the cap is
/// 2 MiB.
pub const NVME_HOST_MAX_TRANSFER: u32 = 2 * 1024 * 1024;

/// Result of [`setup_prps`]: the two SQE data-pointer dwords and how many
/// list pages were written.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrpPair {
    /// SQE PRP1 (DPTR bytes 0..8).
    pub prp1: u64,
    /// SQE PRP2: zero, the second data page, or the first list page.
    pub prp2: u64,
    /// Number of list pages used (0 when PRP2 is zero or a data page).
    pub list_pages: usize,
}

/// Why a buffer cannot be described by PRPs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrpError {
    /// Zero-length transfer.
    Empty,
    /// The buffer start is not dword aligned (§4.1.1: bits 1:0 are zero).
    Misaligned,
    /// `addr + len` wraps the 64-bit address space.
    Overflow,
    /// The transfer needs more PRP-list pages than the caller supplied.
    ListTooSmall,
}

/// Number of PRP-list pages a physically contiguous transfer of `len` bytes
/// starting at `addr` needs. Zero when PRP1 (and possibly PRP2 as a data
/// pointer) suffices.
pub fn prp_list_pages_needed(addr: u64, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let off = (addr as usize) & (NVME_CTRL_PAGE_SIZE - 1);
    let first = core::cmp::min(len, NVME_CTRL_PAGE_SIZE - off);
    let rem = len - first;
    if rem <= NVME_CTRL_PAGE_SIZE {
        return 0;
    }
    let entries = rem.div_ceil(NVME_CTRL_PAGE_SIZE);
    if entries <= PRPS_PER_PAGE {
        1
    } else {
        // Every page but the last gives up its final slot to the chain
        // pointer: 511 data entries per chained page.
        1 + (entries - PRPS_PER_PAGE).div_ceil(PRPS_PER_PAGE - 1)
    }
}

/// Build the PRP data pointer for a physically contiguous buffer of `len`
/// bytes at device address `addr`.
///
/// `lists` is the CPU view of the list pages, concatenated
/// (`PRPS_PER_PAGE` entries per page); `list_dma[k]` is the device address
/// of list page `k`. Entries are written as native `u64`, which is the
/// little-endian layout NVMe expects on every NARF target.
///
/// Layout (Linux `nvme_pci_setup_data_prp`):
/// - PRP1 = `addr`, covering up to the end of its page.
/// - Remainder ≤ one page: PRP2 = the next page.
/// - Otherwise PRP2 = `list_dma[0]`; entries are the following page
///   addresses in order. When a list page is full and data remains, its last
///   entry is moved to slot 0 of the next list page and replaced by that
///   page's address.
pub fn setup_prps(
    addr: u64,
    len: usize,
    lists: &mut [u64],
    list_dma: &[u64],
) -> Result<PrpPair, PrpError> {
    if len == 0 {
        return Err(PrpError::Empty);
    }
    if addr & 0x3 != 0 {
        return Err(PrpError::Misaligned);
    }
    if addr.checked_add(len as u64).is_none() {
        return Err(PrpError::Overflow);
    }
    let page = NVME_CTRL_PAGE_SIZE;
    let off = (addr as usize) & (page - 1);
    let first = core::cmp::min(len, page - off);
    let mut cur = addr + first as u64;
    let mut rem = len - first;
    if rem == 0 {
        return Ok(PrpPair {
            prp1: addr,
            prp2: 0,
            list_pages: 0,
        });
    }
    if rem <= page {
        return Ok(PrpPair {
            prp1: addr,
            prp2: cur,
            list_pages: 0,
        });
    }
    let needed = prp_list_pages_needed(addr, len);
    if needed > list_dma.len() || lists.len() < needed * PRPS_PER_PAGE {
        return Err(PrpError::ListTooSmall);
    }
    let mut list = 0usize;
    let mut i = 0usize;
    loop {
        lists[list * PRPS_PER_PAGE + i] = cur;
        i += 1;
        let step = core::cmp::min(rem, page);
        cur += step as u64;
        rem -= step;
        if rem == 0 {
            break;
        }
        if i == PRPS_PER_PAGE {
            // Chain: the full page's last slot becomes the pointer to the
            // next list page, and the entry it held moves to that page.
            let last = lists[list * PRPS_PER_PAGE + PRPS_PER_PAGE - 1];
            lists[list * PRPS_PER_PAGE + PRPS_PER_PAGE - 1] = list_dma[list + 1];
            list += 1;
            lists[list * PRPS_PER_PAGE] = last;
            i = 1;
        }
    }
    Ok(PrpPair {
        prp1: addr,
        prp2: list_dma[0],
        list_pages: list + 1,
    })
}

/// Maximum data transfer in bytes for a controller, mirroring Linux:
/// `MDTS == 0` means unlimited, otherwise `1 << (MDTS + 12 + CAP.MPSMIN)`
/// (`nvme_mps_to_sectors`), then clamped to [`NVME_HOST_MAX_TRANSFER`].
pub fn max_transfer_bytes(mdts: u8, mpsmin: u8) -> u32 {
    if mdts == 0 {
        return NVME_HOST_MAX_TRANSFER;
    }
    let shift = mdts as u32 + 12 + mpsmin as u32;
    if shift >= 32 {
        return NVME_HOST_MAX_TRANSFER;
    }
    core::cmp::min(1u32 << shift, NVME_HOST_MAX_TRANSFER)
}

/// Whether the controller accepts the 4 KiB host page size NARF programs
/// into `CC.MPS`. Linux `nvme_enable_ctrl` refuses a controller whose
/// `CAP.MPSMIN` page is larger than the host page (`-ENODEV`); MPSMAX is at
/// least MPSMIN, so a 4 KiB minimum always admits MPS = 0.
pub fn host_page_supported(mpsmin: u8) -> bool {
    NVME_CTRL_PAGE_SHIFT >= 12 + mpsmin as u32
}

/// Decoded namespace LBA format (Identify Namespace, NVM command set).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NamespaceFormat {
    /// NSZE: namespace size in logical blocks.
    pub nsze: u64,
    /// Logical block size in bytes (`1 << LBADS`, or 512 if unusable).
    pub lba_bytes: u32,
    /// Metadata bytes per block (LBAF.MS).
    pub metadata_bytes: u16,
    /// False when NARF must not issue block I/O to this namespace: an LBA
    /// size outside 512..=4096, or per-block metadata (NARF never supplies a
    /// metadata pointer). Linux treats both as a zero-capacity disk
    /// (`nvme_update_disk_info` / `nvme_init_integrity`).
    pub usable: bool,
}

/// Decode NSZE / FLBAS / LBAF from an Identify Namespace page. `id_ns` must
/// hold at least the first 384 bytes (header + 64 LBA formats).
///
/// Field offsets (NVM Command Set Specification 1.0c §4.1.5.1): NSZE bytes
/// 0..8, NLBAF byte 25 (zero-based), FLBAS byte 26, LBAF[n] at 128 + 4n with
/// MS in bytes 0..2 and LBADS in byte 2. The format index is Linux
/// `nvme_lbaf_index`: FLBAS bits 3:0, plus bits 6:5 as index bits 5:4.
pub fn decode_namespace_format(id_ns: &[u8]) -> NamespaceFormat {
    let unusable = NamespaceFormat {
        nsze: 0,
        lba_bytes: 512,
        metadata_bytes: 0,
        usable: false,
    };
    if id_ns.len() < 384 {
        return unusable;
    }
    let nsze = u64::from_le_bytes([
        id_ns[0], id_ns[1], id_ns[2], id_ns[3], id_ns[4], id_ns[5], id_ns[6], id_ns[7],
    ]);
    let flbas = id_ns[26];
    let idx = ((flbas & 0x0F) | ((flbas & 0x60) >> 1)) as usize;
    let lbaf = 128 + idx * 4;
    let ms = u16::from_le_bytes([id_ns[lbaf], id_ns[lbaf + 1]]);
    let lbads = id_ns[lbaf + 2] as u32;
    if !(9..=NVME_CTRL_PAGE_SHIFT).contains(&lbads) {
        return NamespaceFormat { nsze, ..unusable };
    }
    NamespaceFormat {
        nsze,
        lba_bytes: 1 << lbads,
        metadata_bytes: ms,
        usable: ms == 0,
    }
}
