//! BAR decode + size detection + MMIO mapping.
//!
//! Spec: `bus/specification/spec.md` §5 — Stage-3 lands the read-side of
//! BAR sizing so a driver can ask "where in physical memory does BAR N
//! live and how big is it" without owning a config-space accessor of
//! its own. The MSI-X table programmer (msix.rs) uses this to find the
//! BAR named by `MsixTable::bir()`.
//!
//! `map_bar` is NARF's `pci_iomap`: it `ioremap`s the BAR window into a
//! kernel VA (`MmioRegion.virt`) and the accessors deref that — so BARs
//! above the boot identity map (64-bit BARs a large-`phys-bits` host
//! parks far above 4 GiB) are reachable, matching Linux, which never
//! dereferences `pci_resource_start` directly.
//!
//! BAR sizing is the standard PCI ritual:
//!   1. Read original BAR value (preserve type/prefetch bits).
//!   2. Write 0xFFFF_FFFF.
//!   3. Read back. Mask off the type/prefetch bits.
//!   4. Invert + add 1 → size.
//!   5. Restore original value.
//!
//! Naked u32 BARs span 4 GiB. 64-bit MMIO BARs use two adjacent BAR
//! slots (low + high u32); we sniff bit 2 of the type field to detect
//! that case and read the upper word too.

use core::sync::atomic::Ordering;

use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};

/// Type-decode of a single BAR slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BarKind {
    /// 32-bit MMIO BAR. `phys` < 4 GiB by construction.
    Mmio32 { prefetchable: bool },
    /// 64-bit MMIO BAR. `phys` may be above 4 GiB. Consumes two
    /// adjacent BAR slots in the type-0 header.
    Mmio64 { prefetchable: bool },
    /// I/O-port BAR. x86_64 only; aarch64 has no I/O-port space, so
    /// drivers must ignore these (or platform code must trap them).
    Io,
}

/// One decoded BAR.
#[derive(Copy, Clone, Debug)]
pub struct Bar {
    /// Slot index in the type-0 header (0..6). For a 64-bit BAR this
    /// names the *low* slot — the high slot is `idx + 1`.
    pub idx: u8,
    pub kind: BarKind,
    /// Physical base. Zero means the BAR is unprogrammed (e.g. firmware
    /// hasn't assigned a window) — drivers should treat that as "absent."
    pub phys: PhysAddr,
    /// Size in bytes, derived from the size-detection write-read-restore
    /// cycle. Zero means the BAR is unimplemented (write of 0xFFFF_FFFF
    /// reads back as zero).
    pub size: u64,
}

/// BAR-decode error surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BarError {
    /// Caller asked for a BAR index >= 6, or for the high half of a
    /// 64-bit BAR (slot 1 / 3 / 5 of a pair).
    OutOfRange,
    /// Caller asked for a BAR on a non-PCIe device (virtio-mmio
    /// transports use their own fixed register layout, not BARs).
    NotPcie,
    /// BAR is unimplemented or unprogrammed (size == 0).
    Unimplemented,
}

/// Type-0 PCIe configuration-space layout, BAR window.
const BAR0_OFFSET: u64 = 0x10;
/// Six BAR slots (0x10..0x28).
pub const NUM_BARS: u8 = 6;

/// Bit 0 of a BAR: 0 = MMIO, 1 = I/O.
const BAR_TYPE_IO: u32 = 1 << 0;
/// Bits 1..2 of an MMIO BAR: 00 = 32-bit, 10 = 64-bit.
const BAR_MMIO_64BIT: u32 = 0b10 << 1;
/// Bit 3: prefetchable.
const BAR_MMIO_PREFETCH: u32 = 1 << 3;

/// MMIO BAR address mask (clears the low 4 type/prefetch bits).
const BAR_MMIO_ADDR_MASK_32: u32 = 0xFFFF_FFF0;
/// I/O BAR address mask (clears the low 2 reserved bits).
const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC;

/// Read BAR `idx` of `device` and return the decoded slot.
///
/// # Safety
/// `device.kind` must be PCIe and the function must own its cfg window
/// exclusively for the duration of this call (size detection writes to
/// the BAR briefly and restores it). Concurrent BAR access is UB.
pub unsafe fn read_bar(device: &BusDevice, idx: u8) -> Result<Bar, BarError> {
    if idx >= NUM_BARS {
        return Err(BarError::OutOfRange);
    }
    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(BarError::NotPcie),
    };

    let off = BAR0_OFFSET + (idx as u64) * 4;
    // SAFETY: cfg_phys + off lives inside the function's 4-KiB cfg
    // window (off < 0x28 < 0x100); identity-mapped.
    // SAFETY: Valid memory or trusted environment
    let original = unsafe { cfg_read32(cfg_phys, off) };

    // I/O-port BAR? Bit 0 set.
    if original & BAR_TYPE_IO != 0 {
        // Size: write all-1s, read back, mask, invert, +1.
        // SAFETY: same window; we restore below.
        let size_low = unsafe {
            cfg_write32(cfg_phys, off, 0xFFFF_FFFF);
            let v = cfg_read32(cfg_phys, off);
            cfg_write32(cfg_phys, off, original);
            v
        };
        let masked = size_low & BAR_IO_ADDR_MASK;
        let size = if masked == 0 {
            0
        } else {
            ((!masked) as u64).wrapping_add(1) & 0xFFFF
        };
        if size == 0 {
            return Err(BarError::Unimplemented);
        }
        return Ok(Bar {
            idx,
            kind: BarKind::Io,
            phys: PhysAddr::new((original & BAR_IO_ADDR_MASK) as u64),
            size,
        });
    }

    // MMIO BAR. Bits 1..2 = 10 ⇒ 64-bit (consumes the next slot too).
    let is_64 = (original & 0b110) == BAR_MMIO_64BIT;
    let prefetchable = (original & BAR_MMIO_PREFETCH) != 0;

    // Size detection on the low slot.
    // SAFETY: cfg-space writes restored below; same window.
    let size_low = unsafe {
        cfg_write32(cfg_phys, off, 0xFFFF_FFFF);
        let v = cfg_read32(cfg_phys, off);
        cfg_write32(cfg_phys, off, original);
        v
    };

    if is_64 {
        if idx + 1 >= NUM_BARS {
            return Err(BarError::OutOfRange);
        }
        let off_hi = off + 4;
        // SAFETY: high slot is in the same 4-KiB cfg window.
        let original_hi = unsafe { cfg_read32(cfg_phys, off_hi) };
        // SAFETY: cfg-space writes restored below; same window.
        let size_hi = unsafe {
            cfg_write32(cfg_phys, off_hi, 0xFFFF_FFFF);
            let v = cfg_read32(cfg_phys, off_hi);
            cfg_write32(cfg_phys, off_hi, original_hi);
            v
        };
        let phys = ((original_hi as u64) << 32) | ((original & BAR_MMIO_ADDR_MASK_32) as u64);
        let size_combined = ((size_hi as u64) << 32) | ((size_low & BAR_MMIO_ADDR_MASK_32) as u64);
        if size_combined == 0 {
            return Err(BarError::Unimplemented);
        }
        let size = (!size_combined).wrapping_add(1);
        return Ok(Bar {
            idx,
            kind: BarKind::Mmio64 { prefetchable },
            phys: PhysAddr::new(phys),
            size,
        });
    }

    // 32-bit MMIO.
    let masked = size_low & BAR_MMIO_ADDR_MASK_32;
    if masked == 0 {
        return Err(BarError::Unimplemented);
    }
    let size = ((!masked) as u64).wrapping_add(1) & 0xFFFF_FFFF;
    Ok(Bar {
        idx,
        kind: BarKind::Mmio32 { prefetchable },
        phys: PhysAddr::new((original & BAR_MMIO_ADDR_MASK_32) as u64),
        size,
    })
}

/// Map a device's BAR for MMIO access.
///
/// This is NARF's `pci_iomap` (`drivers/pci/iomap.c`): the BAR's
/// physical window is `ioremap`'d into a fresh kernel VA and the
/// returned `MmioRegion.virt` is what the accessors dereference. That
/// makes BARs the boot identity map doesn't cover — 64-bit BARs a
/// large-`phys-bits` host (e.g. KVM `-cpu host`) places far above
/// 4 GiB — reachable, exactly as Linux never derefs `pci_resource_start`
/// directly but always maps it first. Uncached (`Device`) for control
/// BARs; write-combining for prefetchable windows (framebuffers/ROMs).
///
/// If `ioremap` fails (or the BAR is unprogrammed), `virt` falls back
/// to the raw phys — correct for the low BARs the boot map already
/// covers, and no worse than the pre-ioremap behaviour otherwise.
///
/// # Safety
/// See `read_bar`: `device` must be PCIe and the caller must hold
/// exclusive access to the function's cfg window.
pub unsafe fn map_bar(device: &BusDevice, idx: u8) -> Result<MmioRegion, BarError> {
    // SAFETY: forwarded.
    let bar = unsafe { read_bar(device, idx)? };
    if matches!(bar.kind, BarKind::Io) {
        // I/O-port BARs aren't MMIO; callers wanting them go through
        // `read_bar` and use `outb/inb` directly.
        return Err(BarError::NotPcie);
    }

    let phys = bar.phys.raw();
    // Unprogrammed BAR (phys == 0) or zero-size: nothing to ioremap;
    // keep the raw phys so behaviour matches the old identity-map path.
    let virt = if phys == 0 || bar.size == 0 {
        phys
    } else {
        use narf_memory::ioremap::{ioremap, MmioAttrs};
        // ioremap requires page-aligned phys + page-multiple len; a BAR
        // base is naturally aligned to its size (>= 16 bytes) but not
        // necessarily to a page, so map from the containing page.
        let page_off = phys & 0xFFF;
        let aligned_phys = phys - page_off;
        let map_len = (bar.size + page_off + 0xFFF) & !0xFFF;
        let attrs = match bar.kind {
            BarKind::Mmio32 { prefetchable: true } | BarKind::Mmio64 { prefetchable: true } => {
                // Prefetchable window (framebuffer/ROM): write-combining on
                // x86 (PAT) coalesces writes; aarch64's MmioAttrs has no WC
                // variant, so fall back to write-back (cacheable) there.
                #[cfg(target_arch = "x86_64")]
                {
                    MmioAttrs::WriteCombining
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    MmioAttrs::WriteBack
                }
            }
            _ => MmioAttrs::Device,
        };
        // SAFETY: `device` ownership is the caller's contract (see fn
        // safety); `map_len` covers the full BAR window from its page
        // base. ioremap installs the VA→phys PTEs with the right memtype.
        match unsafe { ioremap(aligned_phys, map_len, attrs) } {
            Ok(m) => m.virt + page_off,
            Err(_) => phys,
        }
    };

    Ok(MmioRegion {
        phys: bar.phys,
        virt,
        len: bar.size,
        kind: bar.kind,
    })
}

/// A mapped MMIO region. `virt` is the kernel virtual address the
/// device window is reachable at — from `ioremap` when `map_bar`
/// mapped it (the Linux `pci_iomap` model: BARs above the boot
/// identity map get their own VA), or equal to `phys` for regions a
/// caller built directly over an identity-mapped window. All MMIO
/// reads/writes go through this handle's `read32` / `write32` helpers
/// (which deref `virt`) and do the volatile + barrier dance. `phys`
/// is retained for callers that record or re-derive the BAR base.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub phys: PhysAddr,
    /// Dereferenceable kernel VA for MMIO access. `== phys.raw()` for
    /// identity-mapped regions; an ioremap VA for above-map BARs.
    pub virt: u64,
    pub len: u64,
    pub kind: BarKind,
}

impl MmioRegion {
    /// Read an 8-bit MMIO byte at `offset`.
    ///
    /// # Safety
    /// `offset + 1 <= self.len` and the device behind the BAR must
    /// tolerate the read at this offset.
    #[inline]
    pub unsafe fn read8(&self, offset: u64) -> u8 {
        // SAFETY: caller-asserted in-range; arch::mmio supplies the
        // volatile + arch-correct barrier.
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::mmio::read8(self.virt + offset) }
    }

    /// Write an 8-bit MMIO byte at `offset`.
    ///
    /// # Safety
    /// `offset + 1 <= self.len`; caller owns the device exclusively.
    #[inline]
    pub unsafe fn write8(&self, offset: u64, value: u8) {
        // SAFETY: caller-asserted in-range.
        unsafe {
            narf_arch::mmio::write8(self.virt + offset, value);
        }
    }

    /// Read a naturally-aligned 16-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 2 <= self.len`, `offset` 2-byte aligned, and the
    /// device behind the BAR must tolerate the read at this offset.
    #[inline]
    pub unsafe fn read16(&self, offset: u64) -> u16 {
        // SAFETY: caller-asserted in-range, naturally-aligned;
        // arch::mmio supplies the volatile + arch-correct barrier.
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_arch::mmio::read16(self.virt + offset) }
    }

    /// Write a naturally-aligned 16-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 2 <= self.len`, `offset` 2-byte aligned; caller owns
    /// the device exclusively.
    #[inline]
    pub unsafe fn write16(&self, offset: u64, value: u16) {
        // SAFETY: caller-asserted in-range, naturally-aligned.
        unsafe {
            narf_arch::mmio::write16(self.virt + offset, value);
        }
    }

    /// Read a naturally-aligned 32-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 4 <= self.len` and the device behind the BAR must
    /// tolerate a register read at this offset (no read-side effect
    /// the caller doesn't want).
    #[inline]
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        // SAFETY: caller-asserted in-range, naturally-aligned.
        unsafe { narf_arch::mmio::read32(self.virt + offset) }
    }

    /// Write a naturally-aligned 32-bit MMIO word at `offset`.
    ///
    /// # Safety
    /// `offset + 4 <= self.len`; caller owns the device exclusively.
    #[inline]
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        // SAFETY: caller-asserted in-range, naturally-aligned.
        unsafe {
            narf_arch::mmio::write32(self.virt + offset, value);
        }
    }
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    // SAFETY: caller asserts the slot is readable.
    unsafe { narf_arch::mmio::read32(cfg.raw() + off) }
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    // SAFETY: caller asserts the slot is writable.
    unsafe {
        narf_arch::mmio::write32(cfg.raw() + off, value);
    }
}

// ── BAR self-assignment ─────────────────────────────────────────────
//
// Substitute for the firmware-side BAR allocation that UEFI / EDK2
// would normally have done before kernel boot. NARF is launched
// directly via `-kernel` on QEMU virt (aarch64) so no firmware
// stage runs; PCIe BARs come up unassigned (read as 0) and the
// kernel must do the assignment itself.
//
// Pool is a single bump-pointer over a configurable phys range.
// Per-arch boot calls `init_mmio_pool(base, len)` once before
// `assign_pci_bars`. On x86_64 the seabios firmware has already
// done the assignment, so we skip the pass entirely; on aarch64
// virt the pool covers `0x1000_0000 .. 0x3eff_0000` (~750 MiB).

use core::sync::atomic::AtomicU64;

static MMIO_POOL_BASE: AtomicU64 = AtomicU64::new(0);
static MMIO_POOL_END: AtomicU64 = AtomicU64::new(0);
static MMIO_POOL_NEXT: AtomicU64 = AtomicU64::new(0);

/// Initialise the PCIe-MMIO pool. Idempotent — re-init clobbers
/// the previous range + cursor.
pub fn init_mmio_pool(base: u64, len: u64) {
    MMIO_POOL_BASE.store(base, Ordering::Release);
    MMIO_POOL_END.store(base + len, Ordering::Release);
    MMIO_POOL_NEXT.store(base, Ordering::Release);
}

/// Reserve a `size`-byte window aligned to `align`. Returns the
/// phys base or `None` if the pool is exhausted. `align` is
/// forced to a power of two (usually `size`).
pub fn allocate_pci_mmio(size: u64, align: u64) -> Option<u64> {
    let align = align.max(0x1000).next_power_of_two();
    loop {
        let cur = MMIO_POOL_NEXT.load(Ordering::Relaxed);
        let aligned = (cur + align - 1) & !(align - 1);
        let end = aligned.checked_add(size)?;
        if end > MMIO_POOL_END.load(Ordering::Relaxed) {
            return None;
        }
        if MMIO_POOL_NEXT
            .compare_exchange_weak(cur, end, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return Some(aligned);
        }
    }
}

/// Errors from `assign_pci_bars`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AssignError {
    PoolExhausted,
}

/// Walk every device's BAR window. For each unprogrammed BAR
/// (phys == 0 but size > 0), allocate from the MMIO pool and
/// write the assignment back to cfg space. Sets the device's
/// PCI_COMMAND.MEM_SPACE bit so the BAR decode is enabled.
///
/// Skipped silently when the pool wasn't initialised (typical on
/// x86_64 where seabios already programmed BARs).
///
/// # Safety
/// `device` must be PCIe with cfg space writable; caller owns
/// the device exclusively for the duration of the call.
pub unsafe fn assign_unprogrammed_bars(device: &BusDevice) -> Result<u32, AssignError> {
    if MMIO_POOL_BASE.load(Ordering::Acquire) == 0 {
        return Ok(0); // Pool not initialised — assume firmware did it.
    }
    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        _ => return Ok(0),
    };
    let mut assigned = 0u32;
    let mut idx = 0u8;
    while idx < NUM_BARS {
        // SAFETY: caller-asserted cfg-space ownership.
        let bar = match unsafe { read_bar(device, idx) } {
            Ok(b) => b,
            Err(_) => {
                idx += 1;
                continue;
            } // unimplemented slot
        };
        // Already programmed? Skip. (firmware path or earlier pass.)
        if bar.phys.raw() != 0 {
            idx += if matches!(bar.kind, BarKind::Mmio64 { .. }) {
                2
            } else {
                1
            };
            continue;
        }
        match bar.kind {
            BarKind::Mmio32 { prefetchable: _ } => {
                // Allocate + write low half.
                let base = match allocate_pci_mmio(bar.size, bar.size) {
                    Some(p) => p,
                    None => return Err(AssignError::PoolExhausted),
                };
                let off = BAR0_OFFSET + (idx as u64) * 4;
                // SAFETY: cfg-space write at validated offset.
                let original = unsafe { cfg_read32(cfg_phys, off) };
                let type_bits = original & 0x0F;
                // SAFETY: same.
                unsafe {
                    cfg_write32(
                        cfg_phys,
                        off,
                        (base as u32 & BAR_MMIO_ADDR_MASK_32) | type_bits,
                    );
                }
                assigned += 1;
                idx += 1;
            }
            BarKind::Mmio64 { prefetchable: _ } => {
                let base = match allocate_pci_mmio(bar.size, bar.size) {
                    Some(p) => p,
                    None => return Err(AssignError::PoolExhausted),
                };
                let off_lo = BAR0_OFFSET + (idx as u64) * 4;
                let off_hi = off_lo + 4;
                // SAFETY: cfg-space writes at validated offsets.
                let orig_lo = unsafe { cfg_read32(cfg_phys, off_lo) };
                let type_bits = orig_lo & 0x0F;
                // SAFETY: off_lo/off_hi are BAR0_OFFSET + idx*4 with idx <
                // NUM_BARS, so both lie inside this device's 256-byte config
                // space at cfg_phys, whose ownership the caller asserted.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    cfg_write32(
                        cfg_phys,
                        off_lo,
                        (base as u32 & BAR_MMIO_ADDR_MASK_32) | type_bits,
                    );
                    cfg_write32(cfg_phys, off_hi, (base >> 32) as u32);
                }
                assigned += 1;
                idx += 2;
            }
            BarKind::Io => {
                // I/O BARs not allocated by this pool. Skip.
                idx += 1;
            }
        }
    }
    if assigned > 0 {
        // Enable MEM_SPACE in the command register so the new BAR
        // window decodes.
        const COMMAND_OFFSET: u64 = 0x04;
        const CMD_MEM_SPACE: u32 = 1 << 1;
        // SAFETY: cfg-space access at validated offset.
        let cmd = unsafe { cfg_read32(cfg_phys, COMMAND_OFFSET) };
        // SAFETY: same.
        unsafe {
            cfg_write32(cfg_phys, COMMAND_OFFSET, cmd | CMD_MEM_SPACE);
        }
    }
    Ok(assigned)
}

/// Test-only: read back current pool state.
#[doc(hidden)]
pub fn pool_snapshot() -> (u64, u64, u64) {
    (
        MMIO_POOL_BASE.load(Ordering::Relaxed),
        MMIO_POOL_NEXT.load(Ordering::Relaxed),
        MMIO_POOL_END.load(Ordering::Relaxed),
    )
}
