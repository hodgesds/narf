//! AMD-Vi IOMMU register layout + caps decode + DTE / command-ring
//! encoders.
//!
//! Spec: `arch/specification/iommu-interconnect.md` §2; AMD IOMMU
//! Specification rev 3.10 (Pub 48882). Bit positions cross-checked
//! against Linux `drivers/iommu/amd/amd_iommu_types.h` and
//! `drivers/iommu/amd/iommu.c` (GPL-2.0-or-later — see project
//! relicense note 2026-05-20).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const AMD_VI_DEV_TAB_BASE: usize = 0x00;
pub const AMD_VI_CMD_BUF_BASE: usize = 0x08;
pub const AMD_VI_EVT_LOG_BASE: usize = 0x10;
pub const AMD_VI_CTRL: usize = 0x18;
pub const AMD_VI_EXT_FEATURES: usize = 0x30;
pub const AMD_VI_PPR_LOG_BASE: usize = 0x40;
pub const AMD_VI_CMD_HEAD: usize = 0x2000;
pub const AMD_VI_CMD_TAIL: usize = 0x2008;
pub const AMD_VI_EVT_HEAD: usize = 0x2010;
pub const AMD_VI_EVT_TAIL: usize = 0x2018;

pub const CTRL_IOMMUEN: u64 = 1 << 0;
pub const CTRL_HTTUNEN: u64 = 1 << 1;
pub const CTRL_EVTLOGEN: u64 = 1 << 2;
pub const CTRL_EVTINTEN: u64 = 1 << 3;
pub const CTRL_COMWAITINTEN: u64 = 1 << 4;
pub const CTRL_CMDBUFEN: u64 = 1 << 8;
pub const CTRL_PPRLOGEN: u64 = 1 << 12;

pub const EFR_PREFSUP: u64 = 1 << 0;
pub const EFR_PPRSUP: u64 = 1 << 1;
pub const EFR_XTSUP: u64 = 1 << 2;
pub const EFR_NXSUP: u64 = 1 << 4;
pub const EFR_GTSUP: u64 = 1 << 5;
pub const EFR_IASUP: u64 = 1 << 7;
pub const EFR_GASUP: u64 = 1 << 8;

// ── Device Table Entry layout (AMD IOMMU spec §2.2.2.1) ──────────
//
// A DTE is a 256-bit (32-byte) packed structure; the device table
// is a contiguous array indexed by `BDF` (bus<<8 | dev<<3 | fn).
// We split it into four 64-bit lanes here to match Linux's
// `struct dev_table_entry { u64 data[4]; }`.
//
// data[0] layout (low → high):
//   [0]      V        Valid — entry is in use.
//   [1]      TV       Translation Valid — page-table root is live.
//   [2..7]   reserved
//   [7..8]   HAD      Host Access Dirty.
//   [9..12]  MODE     Page-table walk depth (0 = passthrough, 4 = 4-level).
//   [12..52] HOST_PT  Page-table root, page-aligned.
//   [52]     PPR      PPR enabled.
//   [54]     GIOV     Guest I/O virtualisation.
//   [55]     GV       Guest valid (SVM).
//   [56..58] GLX      Guest CR3 levels.
//   [61]     IR       Read access permitted.
//   [62]     IW       Write access permitted.
//
// data[1] layout:
//   [0..16]  DomainID
//   [32..42] reserved flag bits (IOTLB enable, etc.)
//
// data[2]: IRTE pointer + IV (IRTE-Valid) at bit 0; bits 6..52 are
// the IRTE root, bit-aligned per DTE_IRQ_PHYS_ADDR_MASK.
//
// data[3]: reserved for nested-paging / extended use cases.

pub const DTE_V: u64 = 1 << 0;
pub const DTE_TV: u64 = 1 << 1;
pub const DTE_HAD: u64 = 0b11 << 7;
pub const DTE_MODE_SHIFT: u32 = 9;
pub const DTE_MODE_MASK: u64 = 0b111 << DTE_MODE_SHIFT;
pub const DTE_HOST_PT_MASK: u64 = 0x000F_FFFF_FFFF_F000;
pub const DTE_PPR: u64 = 1 << 52;
pub const DTE_GIOV: u64 = 1 << 54;
pub const DTE_GV: u64 = 1 << 55;
pub const DTE_GLX_SHIFT: u32 = 56;
pub const DTE_GLX_MASK: u64 = 0b11 << DTE_GLX_SHIFT;
pub const DTE_IR: u64 = 1 << 61;
pub const DTE_IW: u64 = 1 << 62;
pub const DTE_DOMID_MASK: u64 = 0xFFFF;

// data[2] flags
pub const DTE_IV: u64 = 1 << 0; // IRTE valid
pub const DTE_IRTE_PTR_MASK: u64 = 0x000F_FFFF_FFFF_FFC0; // [6..52]

// Page-table walk-mode encodings (§2.2.3 Table 6).
pub const DTE_MODE_PASSTHROUGH: u64 = 0;
pub const DTE_MODE_1_LEVEL: u64 = 1;
pub const DTE_MODE_2_LEVEL: u64 = 2;
pub const DTE_MODE_3_LEVEL: u64 = 3;
pub const DTE_MODE_4_LEVEL: u64 = 4;
pub const DTE_MODE_5_LEVEL: u64 = 5;
pub const DTE_MODE_6_LEVEL: u64 = 6;

/// Permission bits used by [`iommu_map_perms`].
pub const PERM_READ: u8 = 0b01;
pub const PERM_WRITE: u8 = 0b10;

/// AMD-Vi Device-Table Entry. 32 bytes laid out as four little-
/// endian u64 lanes; Linux uses the same shape (`struct
/// dev_table_entry`). The IOMMU walks this every DMA so the layout
/// is rigidly architectural — every field is bit-precise per
/// §2.2.2.1.
#[repr(C, align(32))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceTableEntry {
    pub data: [u64; 4],
}

impl DeviceTableEntry {
    /// Build a fully-valid DTE pointing at a 4-level host page-table
    /// root with `domain_id`, the given perms (`PERM_READ`,
    /// `PERM_WRITE`), and a 4-level walk.
    ///
    /// Mirrors the `set_dte_entry` path Linux runs after attaching a
    /// dmar_domain to a device. The page-table root must be
    /// page-aligned (4 KiB) and < 2^52.
    pub const fn identity(domain_id: u16, pt_root: u64, perms: u8) -> Self {
        let mut data = [0u64; 4];
        let mut d0: u64 = DTE_V | DTE_TV;
        d0 |= DTE_MODE_4_LEVEL << DTE_MODE_SHIFT;
        d0 |= pt_root & DTE_HOST_PT_MASK;
        if perms & PERM_READ != 0 {
            d0 |= DTE_IR;
        }
        if perms & PERM_WRITE != 0 {
            d0 |= DTE_IW;
        }
        data[0] = d0;
        data[1] = (domain_id as u64) & DTE_DOMID_MASK;
        DeviceTableEntry { data }
    }

    /// Passthrough DTE — no translation, no page-table walk. Used
    /// when the device hangs off the identity domain (current
    /// `IommuMode::Identity`).
    pub const fn passthrough(domain_id: u16) -> Self {
        let mut data = [0u64; 4];
        data[0] = DTE_V | (DTE_MODE_PASSTHROUGH << DTE_MODE_SHIFT) | DTE_IR | DTE_IW;
        data[1] = (domain_id as u64) & DTE_DOMID_MASK;
        DeviceTableEntry { data }
    }

    /// Attach an interrupt-remapping table to this DTE. `irte_root`
    /// must be 128-byte aligned per §2.2.5.1.
    pub const fn with_irte(mut self, irte_root: u64) -> Self {
        self.data[2] = (irte_root & DTE_IRTE_PTR_MASK) | DTE_IV;
        self
    }

    pub const fn is_valid(&self) -> bool {
        (self.data[0] & DTE_V) != 0
    }

    pub const fn page_table_root(&self) -> u64 {
        self.data[0] & DTE_HOST_PT_MASK
    }

    pub const fn domain_id(&self) -> u16 {
        (self.data[1] & DTE_DOMID_MASK) as u16
    }

    pub const fn walk_mode(&self) -> u64 {
        (self.data[0] & DTE_MODE_MASK) >> DTE_MODE_SHIFT
    }
}

// ── Command-ring encoders (AMD IOMMU spec §2.4) ──────────────────
//
// Each command is 128 bits — Linux models it as `u32 data[4]`. The
// opcode lives in `data[1] >> 28` (`CMD_SET_TYPE`). We use `u32`
// lanes here for the same reason: the spec talks bit-positions in
// dword-relative terms.

pub const CMD_COMPL_WAIT: u32 = 0x01;
pub const CMD_INV_DEV_ENTRY: u32 = 0x02;
pub const CMD_INV_IOMMU_PAGES: u32 = 0x03;
pub const CMD_INV_IOTLB_PAGES: u32 = 0x04;
pub const CMD_INV_IRT: u32 = 0x05;
pub const CMD_COMPLETE_PPR: u32 = 0x07;
pub const CMD_INV_ALL: u32 = 0x08;

pub const CMD_COMPL_WAIT_STORE_MASK: u32 = 0x01;
pub const CMD_COMPL_WAIT_INT_MASK: u32 = 0x02;
pub const CMD_INV_IOMMU_PAGES_SIZE_MASK: u32 = 0x01;
pub const CMD_INV_IOMMU_PAGES_PDE_MASK: u32 = 0x02;
pub const CMD_INV_ALL_PAGES_ADDRESS: u64 = 0x7FFF_FFFF_FFFF_FFFF;

/// IOMMU command — 16 bytes, four u32 lanes per the AMD spec.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IommuCmd {
    pub data: [u32; 4],
}

impl IommuCmd {
    const fn empty() -> Self {
        IommuCmd { data: [0; 4] }
    }

    #[inline]
    const fn set_type(mut self, op: u32) -> Self {
        self.data[1] |= op << 28;
        self
    }

    /// Build a `COMPLETION_WAIT` command. Linux's
    /// `build_completion_wait` — writes a 64-bit token to `sem_paddr`
    /// when the IOMMU drains the queue.
    pub const fn completion_wait(sem_paddr: u64, token: u64) -> Self {
        let mut cmd = IommuCmd::empty();
        cmd.data[0] = (sem_paddr as u32) | CMD_COMPL_WAIT_STORE_MASK;
        cmd.data[1] = (sem_paddr >> 32) as u32;
        cmd.data[2] = token as u32;
        cmd.data[3] = (token >> 32) as u32;
        cmd.set_type(CMD_COMPL_WAIT)
    }

    /// Build a `INVALIDATE_DEVTAB_ENTRY` for the given BDF. Mirrors
    /// Linux's `build_inv_dte`.
    pub const fn invalidate_devtab(bdf: u16) -> Self {
        let mut cmd = IommuCmd::empty();
        cmd.data[0] = bdf as u32;
        cmd.set_type(CMD_INV_DEV_ENTRY)
    }

    /// Build a `INVALIDATE_IOMMU_PAGES` command. `address` is the
    /// IOVA range start; when `all` is set, the entire address
    /// space for `domain_id` is flushed.
    pub const fn invalidate_pages(domain_id: u16, address: u64, all: bool) -> Self {
        let mut cmd = IommuCmd::empty();
        let inv_addr = if all {
            CMD_INV_ALL_PAGES_ADDRESS
        } else {
            address & 0xFFFF_FFFF_FFFF_F000
        };
        cmd.data[1] = domain_id as u32;
        cmd.data[2] = (inv_addr as u32) | CMD_INV_IOMMU_PAGES_PDE_MASK;
        if all {
            cmd.data[2] |= CMD_INV_IOMMU_PAGES_SIZE_MASK;
        }
        cmd.data[3] = (inv_addr >> 32) as u32;
        cmd.set_type(CMD_INV_IOMMU_PAGES)
    }

    /// `INVALIDATE_ALL` — single-command IOTLB + DTE flush.
    pub const fn invalidate_all() -> Self {
        IommuCmd::empty().set_type(CMD_INV_ALL)
    }

    #[inline]
    pub const fn opcode(&self) -> u32 {
        self.data[1] >> 28
    }
}

// ── Interrupt Remapping Table Entry (§2.2.5) ─────────────────────
//
// A 64-bit IRTE remaps a single MSI vector. Linux's `struct irte`
// for AMD; we encode the basic Remap variant (1024-entry table)
// here — the 4 KiB variant adds an extra dword that we don't need
// for boot bring-up.
//
// Layout (low → high):
//   [0]      Valid
//   [1]      NoMapEn
//   [2..5]   IntCtl  (00=APIC, 01=fixed, 10=remap)
//   [5]      SuppressIOPF
//   [6..11]  Destination Mode + APIC
//   [16..24] Vector
//   [24..32] Destination ID (xAPIC)
pub const IRTE_VALID: u64 = 1 << 0;
pub const IRTE_NO_MAP: u64 = 1 << 1;
pub const IRTE_REMAP_INTCTL: u64 = 2 << 60;
pub const IRTE_REMAP_INTCTL_MASK: u64 = 0x3 << 60;

#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Irte {
    pub raw: u64,
}

impl Irte {
    /// Build a remap IRTE that retargets an interrupt at `vector` to
    /// CPU `dest_id` with the IntCtl=remap encoding.
    pub const fn remap(vector: u8, dest_id: u8) -> Self {
        let raw =
            IRTE_VALID | IRTE_REMAP_INTCTL | ((vector as u64) << 16) | ((dest_id as u64) << 24);
        Irte { raw }
    }

    pub const fn is_valid(&self) -> bool {
        (self.raw & IRTE_VALID) != 0
    }

    pub const fn vector(&self) -> u8 {
        ((self.raw >> 16) & 0xFF) as u8
    }

    pub const fn dest_id(&self) -> u8 {
        ((self.raw >> 24) & 0xFF) as u8
    }
}

// ── Device-table size encoding ───────────────────────────────────
//
// MMIO DEV_TABLE_BASE register at offset 0x00 packs:
//   [0..12]   Size = (entries / 256) - 1, i.e. dev_table_size / 4K - 1
//   [12..52]  Physical address (page-aligned)
//
// The standard table size is 64 KiB × 4 = 256 KiB → 8192 DTEs ×
// 32 B; that covers the entire 16-bit BDF space.

/// Encode the value to write into the AMD-Vi `DEV_TAB_BASE` MMIO
/// register: `(phys | size_field)` where `size_field` is
/// `(table_size_bytes >> 12) - 1`.
pub const fn encode_dev_table_base(phys: u64, table_size_bytes: u64) -> u64 {
    let size_field = (table_size_bytes >> 12).saturating_sub(1);
    (phys & 0x000F_FFFF_FFFF_F000) | (size_field & 0x1FF)
}

/// Inverse — extract page-aligned base and table-size-in-bytes.
pub const fn decode_dev_table_base(reg: u64) -> (u64, u64) {
    let phys = reg & 0x000F_FFFF_FFFF_F000;
    let size_field = reg & 0x1FF;
    let bytes = (size_field + 1) << 12;
    (phys, bytes)
}

// ── Command buffer ring (AMD IOMMU spec §2.4.1) ──────────────────
//
// MMIO `CMD_BUF_BASE_OFFSET` (0x08) layout:
//   [0..12]   reserved
//   [12..52]  Command buffer base (page-aligned)
//   [56..60]  Size field — Linux uses 0x9 (512 entries, 8 KiB ring)
//
// `CMD_HEAD` (0x2000) is the hardware-owned head; software writes
// `CMD_TAIL` (0x2008) to push a new command. The ring is empty
// when head == tail.

pub const CMD_BUF_SIZE_SHIFT: u32 = 56;
pub const CMD_BUF_SIZE_512: u64 = 0x9 << CMD_BUF_SIZE_SHIFT;
pub const CMD_BUF_ENTRIES_512: usize = 512;
pub const CMD_BUF_BYTES_512: usize = 8192; // 512 * 16 B

/// Encode the value for `MMIO[CMD_BUF_BASE]`. Standard 512-entry
/// ring (`size=0x9`) — Linux's default.
pub const fn encode_cmd_buf_base(phys: u64) -> u64 {
    (phys & 0x000F_FFFF_FFFF_F000) | CMD_BUF_SIZE_512
}

/// Inverse of [`encode_cmd_buf_base`].
pub const fn decode_cmd_buf_base(reg: u64) -> (u64, u64) {
    let phys = reg & 0x000F_FFFF_FFFF_F000;
    let size_field = (reg >> CMD_BUF_SIZE_SHIFT) & 0xF;
    (phys, size_field)
}

/// Encode the next tail offset for a `wrap`-sized ring. The
/// hardware ignores bits below 4 (each command is 16 bytes),
/// `Linux MMIO_CMD_HEAD_MASK` is `GENMASK_ULL(18, 4)`.
pub const fn advance_ring_tail(tail: u32, count: u32, ring_bytes: u32) -> u32 {
    // ring_bytes must be a power of two; entries are 16 B each.
    (tail + count * 16) & (ring_bytes - 1)
}

// ── Event log ring (AMD IOMMU spec §2.4.2) ───────────────────────
//
// Same shape as the command ring — 16-byte entries written by
// hardware when a fault, DTE-mismatch, IOTLB issue, etc. fires.
//
// MMIO `EVT_LOG_BASE_OFFSET` (0x10) packs the same way as
// `CMD_BUF_BASE_OFFSET` (size at [56..60], base at [12..52]).

pub const EVT_LOG_SIZE_SHIFT: u32 = 56;
pub const EVT_LOG_SIZE_512: u64 = 0x9 << EVT_LOG_SIZE_SHIFT;
pub const EVT_LOG_BYTES_512: usize = 8192;

pub const fn encode_evt_log_base(phys: u64) -> u64 {
    (phys & 0x000F_FFFF_FFFF_F000) | EVT_LOG_SIZE_512
}

pub const fn decode_evt_log_base(reg: u64) -> (u64, u64) {
    let phys = reg & 0x000F_FFFF_FFFF_F000;
    let size_field = (reg >> EVT_LOG_SIZE_SHIFT) & 0xF;
    (phys, size_field)
}

// ── AMD-Vi I/O Page Table Entry (spec §2.2.3) ────────────────────
//
// AMD-Vi page tables are a 4-level (or 5-level with 5-level paging
// enabled) walk that very closely mirrors x86_64 host paging. PTEs
// are 64 bits and laid out as:
//
//   [0]      IR  Read permission
//   [1]      IW  Write permission
//   [9..12]  Next-level / page-size pointer
//   [12..52] Page frame (when leaf) or next-level table base
//   [60]     FC  Forced coherent
//   [61]     IR-on-IO
//   [62]     IW-on-IO
//
// We model just the boot bring-up subset: Present (IR|IW), R/W,
// addr mask. Identical mask to host PTEs.

pub const PTE_IR: u64 = 1 << 0;
pub const PTE_IW: u64 = 1 << 1;
pub const PTE_PRESENT_MASK: u64 = PTE_IR | PTE_IW;
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // PM_ADDR_MASK
pub const PTE_NEXT_LEVEL_SHIFT: u32 = 9;
pub const PTE_NEXT_LEVEL_MASK: u64 = 0b111 << PTE_NEXT_LEVEL_SHIFT;

/// Build a leaf PTE (next-level=0 ⇒ this is a 4 KiB frame).
pub const fn pte_leaf(phys: u64, read: bool, write: bool) -> u64 {
    let mut v = phys & PTE_ADDR_MASK;
    if read {
        v |= PTE_IR;
    }
    if write {
        v |= PTE_IW;
    }
    v
}

/// Build a non-leaf PTE pointing at a next-level table base. The
/// AMD walker decodes the next-level field at bits 9..12 — set it
/// to the next level (1..6) to continue the walk.
pub const fn pte_next(next_table: u64, next_level: u8) -> u64 {
    (next_table & PTE_ADDR_MASK)
        | PTE_IR
        | PTE_IW
        | (((next_level & 0x7) as u64) << PTE_NEXT_LEVEL_SHIFT)
}

pub const fn pte_present(pte: u64) -> bool {
    (pte & PTE_PRESENT_MASK) != 0
}

pub const fn pte_addr(pte: u64) -> u64 {
    pte & PTE_ADDR_MASK
}

pub const fn pte_next_level(pte: u64) -> u8 {
    ((pte & PTE_NEXT_LEVEL_MASK) >> PTE_NEXT_LEVEL_SHIFT) as u8
}

/// Compute the 9-bit per-level index of `iova` for a 4-level walk.
/// Level 4 is the top (PML4-equivalent), 1 is the leaf.
pub const fn pte_level_index(iova: u64, level: u32) -> usize {
    let shift = 12 + 9 * (level - 1);
    ((iova >> shift) & 0x1FF) as usize
}

// ── AMD-Vi I/O page-table walker ─────────────────────────────────
//
// Same shape as the VT-d walker. Returns the resolved phys or the
// level at which a not-present PTE terminated the walk. Used at
// test time to confirm the per-level shift math against a
// synthetic table.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdViWalkResult {
    Mapped { phys: u64, offset: u64 },
    NotPresent { level: u32 },
}

pub fn walk_iopt<F>(root_table: &[u64; 512], iova: u64, mut fetch: F) -> AmdViWalkResult
where
    F: FnMut(u64) -> Option<[u64; 512]>,
{
    let mut current = root_table[pte_level_index(iova, 4)];
    let mut level = 4u32;
    while level > 1 {
        if !pte_present(current) {
            return AmdViWalkResult::NotPresent { level };
        }
        let next_phys = pte_addr(current);
        let next_table = match fetch(next_phys) {
            Some(t) => t,
            None => return AmdViWalkResult::NotPresent { level: level - 1 },
        };
        let next_idx = pte_level_index(iova, level - 1);
        current = next_table[next_idx];
        level -= 1;
    }
    if !pte_present(current) {
        return AmdViWalkResult::NotPresent { level: 1 };
    }
    AmdViWalkResult::Mapped {
        phys: pte_addr(current),
        offset: iova & 0xFFF,
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct AmdViCaps {
    pub iommu_enabled: bool,
    pub event_log_enabled: bool,
    pub command_buf_enabled: bool,
    pub ppr_supported: bool,
    pub gt_supported: bool,
    pub xts_supported: bool,
}

unsafe fn r64(base: usize, off: usize) -> u64 {
    // SAFETY: caller-asserted MMIO mapping covers the offset.
    unsafe { read_volatile((base + off) as *const u64) }
}

unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((base + off) as *mut u64, v);
    }
}

/// Decode the caps that matter for boot-time bring-up.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of an AMD-Vi
/// engine register block.
pub unsafe fn read_caps(reg_base: usize) -> AmdViCaps {
    // SAFETY: caller-asserted.
    let ctrl = unsafe { r64(reg_base, AMD_VI_CTRL) };
    let efr = unsafe { r64(reg_base, AMD_VI_EXT_FEATURES) };
    decode_caps(ctrl, efr)
}

pub fn decode_caps(ctrl: u64, efr: u64) -> AmdViCaps {
    AmdViCaps {
        iommu_enabled: ctrl & CTRL_IOMMUEN != 0,
        event_log_enabled: ctrl & CTRL_EVTLOGEN != 0,
        command_buf_enabled: ctrl & CTRL_CMDBUFEN != 0,
        ppr_supported: efr & EFR_PPRSUP != 0,
        gt_supported: efr & EFR_GTSUP != 0,
        xts_supported: efr & EFR_XTSUP != 0,
    }
}

/// # Safety
/// `reg_base` is the engine's MMIO mapping.
pub unsafe fn read_ctrl(reg_base: usize) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { r64(reg_base, AMD_VI_CTRL) }
}

pub unsafe fn write_ctrl(reg_base: usize, value: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, AMD_VI_CTRL, value);
    }
}

/// Program `MMIO[DEV_TAB_BASE]`. `phys` is the physical address of
/// the device table (page-aligned, 32 B/entry, 256 KiB total for
/// the standard 8K-BDF table), `bytes` is the total table size.
///
/// # Safety
/// `reg_base` is the AMD-Vi engine's MMIO mapping; the table at
/// `phys` must be allocated, page-aligned, and have lifetime that
/// outlives the IOMMU's use of it.
pub unsafe fn program_dev_table_base(reg_base: usize, phys: u64, bytes: u64) {
    let value = encode_dev_table_base(phys, bytes);
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, AMD_VI_DEV_TAB_BASE, value);
    }
}

/// Program `MMIO[CMD_BUF_BASE]` with a 512-entry (8 KiB) ring at
/// `phys`. The size field is fixed at `0x9` matching Linux.
///
/// # Safety
/// See [`program_dev_table_base`].
pub unsafe fn program_cmd_buf_base(reg_base: usize, phys: u64) {
    let value = encode_cmd_buf_base(phys);
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, AMD_VI_CMD_BUF_BASE, value);
    }
}

/// Program `MMIO[EVT_LOG_BASE]` with a 512-entry (8 KiB) event
/// log at `phys`.
///
/// # Safety
/// See [`program_dev_table_base`].
pub unsafe fn program_evt_log_base(reg_base: usize, phys: u64) {
    let value = encode_evt_log_base(phys);
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, AMD_VI_EVT_LOG_BASE, value);
    }
}

/// Push a single command onto the in-RAM command ring at offset
/// `tail`. Returns the new tail offset. The caller is responsible
/// for writing `tail` back into `MMIO[CMD_TAIL]` to hand the
/// command to hardware. `ring_bytes` should be 8192 for the
/// standard 512-entry ring.
///
/// # Safety
/// `ring_virt` must point at the kernel-mapped virtual address of
/// the command buffer (the same buffer whose phys was given to
/// `program_cmd_buf_base`). `tail` must be in-range.
pub unsafe fn push_command(
    ring_virt: *mut IommuCmd,
    tail: u32,
    cmd: IommuCmd,
    ring_bytes: u32,
) -> u32 {
    let slot_idx = (tail / 16) as usize;
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile(ring_virt.add(slot_idx), cmd);
    }
    advance_ring_tail(tail, 1, ring_bytes)
}
