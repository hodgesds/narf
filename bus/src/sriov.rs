//! PCI Express SR-IOV extended-capability programming (the bus half
//! of PF SR-IOV enablement).
//!
//! Grounding (STRICT): every offset and bit comes from Linux @
//! cbbddb6 — `include/uapi/linux/pci_regs.h` (`PCI_SRIOV_*`) for the
//! capability layout and `drivers/pci/iov.c` (`sriov_init`,
//! `sriov_enable`, `sriov_disable`, `pci_iov_set_numvfs`,
//! `pci_iov_virtfn_bus` / `pci_iov_virtfn_devfn`) for the enable
//! sequence. No PCIe-spec copy was consulted; the two Linux files
//! are the authority here.
//!
//! What this module does (Linux `pci_iov_init` + `pci_enable_sriov`,
//! collapsed into one pass because NARF keeps no persistent
//! `pci_sriov` struct per device):
//! * decode the SR-IOV capability (`read_sriov_caps`, pure
//!   `SriovCaps::decode` over the 64-byte cap image),
//! * pick the System Page Size (`choose_system_page_size`: the
//!   lowest set bit of Supported Page Sizes, Linux `sriov_init`'s
//!   `pgsz &= ~(pgsz - 1)`; NARF pages are 4 KiB, so Linux's
//!   below-system-page-size mask step is a no-op here),
//! * size each VF BAR with the standard write-all-ones probe and
//!   program it from the MMIO pool (`allocate_pci_mmio`), window
//!   sized per-VF-size x TotalVFs exactly as Linux sizes the
//!   resource (`resource_set_size(res, per_vf * total)`),
//! * write NumVFs, re-read VF Offset / VF Stride (they may change
//!   when NumVFs changes, `pci_iov_set_numvfs`), validate them,
//!   and set Control VF Enable + VF Memory Space Enable
//!   (`sriov_enable`'s `ctrl |= VFE | MSE`).
//!
//! What it does NOT do (sequenced follow-ups, not silently
//! dropped): VF enumeration — creating `BusDevice`s at the
//! `virtfn_bus` / `virtfn_devfn` addresses and scanning them is a
//! bus-enumeration lane (the pure geometry helpers are here for
//! it); the 100 ms settle Linux does after setting VF Enable
//! (`msleep(100)` before `sriov_add_vfs`) belongs with that lane,
//! since nothing enumerates VFs yet; the 1 s settle after clearing
//! VF Enable is likewise omitted (enable is called before any VF
//! traffic exists); I/O-space VF BARs are refused
//! (`IoBarUnsupported`) because NARF has no I/O-space allocator.
//! The caller must remove enumerated VFs before `disable_sriov`,
//! mirroring Linux's `sriov_disable` (which removes VFs first).

use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, CapError, Read, Write};
use narf_memory::PhysAddr;

use crate::device::{BusDevice, BusKind};
use crate::pci_cap_ext::{find_cap, id, ExtCapError};
use crate::registry::BusDeviceCap;

/// SR-IOV Capabilities register offset (pci_regs.h).
pub const SRIOV_CAP_OFF: u64 = 0x04;
/// SR-IOV Capabilities: VF Migration Capable (pci_regs.h).
pub const SRIOV_CAP_VFM: u32 = 0x0000_0001;
/// SR-IOV Control register offset (pci_regs.h).
pub const SRIOV_CTRL_OFF: u64 = 0x08;
/// SR-IOV Control: VF Enable (pci_regs.h).
pub const SRIOV_CTRL_VFE: u16 = 0x0001;
/// SR-IOV Control: VF Migration Enable (pci_regs.h).
pub const SRIOV_CTRL_VFM: u16 = 0x0002;
/// SR-IOV Control: VF Migration Interrupt Enable (pci_regs.h).
pub const SRIOV_CTRL_INTR: u16 = 0x0004;
/// SR-IOV Control: VF Memory Space Enable (pci_regs.h).
pub const SRIOV_CTRL_MSE: u16 = 0x0008;
/// SR-IOV Control: ARI Capable Hierarchy (pci_regs.h).
pub const SRIOV_CTRL_ARI: u16 = 0x0010;
/// SR-IOV Status register offset (pci_regs.h).
pub const SRIOV_STATUS_OFF: u64 = 0x0A;
/// SR-IOV InitialVFs register offset (pci_regs.h).
pub const SRIOV_INITIAL_VF_OFF: u64 = 0x0C;
/// SR-IOV TotalVFs register offset (pci_regs.h).
pub const SRIOV_TOTAL_VF_OFF: u64 = 0x0E;
/// SR-IOV NumVFs register offset (pci_regs.h).
pub const SRIOV_NUM_VF_OFF: u64 = 0x10;
/// SR-IOV Function Dependency Link offset (pci_regs.h).
pub const SRIOV_FUNC_LINK_OFF: u64 = 0x12;
/// SR-IOV VF Offset register offset (pci_regs.h).
pub const SRIOV_VF_OFFSET_OFF: u64 = 0x14;
/// SR-IOV VF Stride register offset (pci_regs.h).
pub const SRIOV_VF_STRIDE_OFF: u64 = 0x16;
/// SR-IOV VF Device ID register offset (pci_regs.h).
pub const SRIOV_VF_DID_OFF: u64 = 0x1A;
/// SR-IOV Supported Page Sizes register offset (pci_regs.h).
pub const SRIOV_SUP_PGSIZE_OFF: u64 = 0x1C;
/// SR-IOV System Page Size register offset (pci_regs.h).
pub const SRIOV_SYS_PGSIZE_OFF: u64 = 0x20;
/// SR-IOV VF BAR0 register offset (pci_regs.h).
pub const SRIOV_BAR_OFF: u64 = 0x24;
/// Number of VF BARs (pci_regs.h: `PCI_SRIOV_NUM_BARS`).
pub const SRIOV_NUM_BARS: usize = 6;
/// SR-IOV capability size in bytes (pci_regs.h).
pub const SRIOV_CAP_SIZE: u64 = 0x40;

/// Errors from SR-IOV decode / enable / disable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SriovError {
    /// Caller's cap epoch was revoked.
    AuthorityRevoked,
    /// Device isn't a PCIe transport (e.g. virtio-mmio).
    NotPcie,
    /// Device has no SR-IOV extended capability.
    CapNotPresent,
    /// NumVFs is already non-zero (Linux `sriov_enable`: `-EINVAL`
    /// when `iov->num_VFs` is set).
    AlreadyEnabled,
    /// Requested VF count is 0 or above TotalVFs (or above
    /// InitialVFs on a non-migration-capable device).
    BadVfCount,
    /// InitialVFs > TotalVFs, or InitialVFs != TotalVFs on a
    /// non-migration-capable device (Linux `sriov_enable`: `-EIO`).
    InitialVfMismatch,
    /// Supported Page Sizes is 0 (Linux `sriov_init`: `-EIO`).
    NoSupportedPageSize,
    /// A VF BAR's per-VF size is not a multiple of the System Page
    /// Size (Linux `sriov_init`: `-EIO`).
    BarUnaligned,
    /// A VF BAR is I/O-space; NARF has no I/O-space allocator.
    IoBarUnsupported,
    /// The MMIO pool has no window for a VF BAR.
    PoolExhausted,
    /// VF Offset re-read as 0 after NumVFs was written (Linux
    /// `compute_max_vf_buses`: `-EIO`).
    VfOffsetInvalid,
    /// VF Stride re-read as 0 with more than one VF (Linux
    /// `compute_max_vf_buses`: `-EIO`).
    VfStrideInvalid,
    /// A config-space transaction did not read back (e.g. a BAR
    /// probe restore failed).
    ConfigFailed,
}

impl From<CapError> for SriovError {
    fn from(_: CapError) -> Self {
        SriovError::AuthorityRevoked
    }
}

impl From<ExtCapError> for SriovError {
    fn from(e: ExtCapError) -> Self {
        match e {
            ExtCapError::AuthorityRevoked => SriovError::AuthorityRevoked,
            ExtCapError::NotPcie => SriovError::NotPcie,
        }
    }
}

/// Decoded SR-IOV capability snapshot. Offsets are relative to the
/// capability start (`pos`); `decode` fills them from the 64-byte
/// cap image (16 dwords, `PCI_EXT_CAP_SRIOV_SIZEOF`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SriovCaps {
    /// Capability offset in config space.
    pub pos: u64,
    /// VF Migration Capable (Capabilities bit 0).
    pub cap_vfm: bool,
    /// Raw Control word.
    pub ctrl: u16,
    /// VF Enable currently set.
    pub vf_enable: bool,
    /// InitialVFs.
    pub initial_vfs: u16,
    /// TotalVFs.
    pub total_vfs: u16,
    /// NumVFs currently programmed.
    pub num_vfs: u16,
    /// Function Dependency Link.
    pub func_link: u8,
    /// First VF Offset.
    pub vf_offset: u16,
    /// VF Stride.
    pub vf_stride: u16,
    /// VF Device ID.
    pub vf_device_id: u16,
    /// Supported Page Sizes bitmask (bit n = 4 KiB << n).
    pub supported_page_sizes: u32,
    /// System Page Size currently programmed.
    pub system_page_size: u32,
    /// Raw VF BAR registers (0 = unprogrammed).
    pub vf_bars: [u32; SRIOV_NUM_BARS],
}

impl SriovCaps {
    /// Decode the 64-byte SR-IOV capability image (dwords at
    /// `pos..pos+0x40`). Pure; the words are the caller's copy of
    /// config space, so a fixture can build one literally.
    pub fn decode(pos: u64, words: &[u32; 16]) -> Self {
        Self {
            pos,
            cap_vfm: words[1] & SRIOV_CAP_VFM != 0,
            ctrl: (words[2] & 0xFFFF) as u16,
            vf_enable: words[2] & (SRIOV_CTRL_VFE as u32) != 0,
            initial_vfs: (words[3] & 0xFFFF) as u16,
            total_vfs: ((words[3] >> 16) & 0xFFFF) as u16,
            num_vfs: (words[4] & 0xFFFF) as u16,
            func_link: ((words[4] >> 16) & 0xFF) as u8,
            vf_offset: (words[5] & 0xFFFF) as u16,
            vf_stride: ((words[5] >> 16) & 0xFFFF) as u16,
            vf_device_id: ((words[6] >> 16) & 0xFFFF) as u16,
            supported_page_sizes: words[7],
            system_page_size: words[8],
            vf_bars: [
                words[9], words[10], words[11], words[12], words[13], words[14],
            ],
        }
    }
}

/// One programmed VF BAR window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VfBar {
    /// VF BAR index (0..6).
    pub index: u8,
    /// Window base (start of the TotalVFs-sized window).
    pub base: u64,
    /// Size per VF.
    pub per_vf_size: u64,
    /// 64-bit BAR (consumes the next slot).
    pub is_64bit: bool,
    /// Prefetchable.
    pub prefetchable: bool,
}

/// Result of a successful `enable_sriov`: the VF geometry the
/// enumeration lane needs plus the programmed VF BAR windows.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SriovEnabled {
    /// VFs enabled.
    pub num_vfs: u16,
    /// First VF Offset (re-read after NumVFs was written).
    pub vf_offset: u16,
    /// VF Stride (re-read after NumVFs was written).
    pub vf_stride: u16,
    /// VF Device ID.
    pub vf_device_id: u16,
    /// System Page Size programmed.
    pub page_size: u32,
    /// Programmed VF BAR windows (`None` = unimplemented slot, or
    /// the high half of a 64-bit BAR).
    pub vf_bars: [Option<VfBar>; SRIOV_NUM_BARS],
}

/// Choose the System Page Size from Supported Page Sizes (Linux
/// `sriov_init`): the lowest set bit (`pgsz &= ~(pgsz - 1)`), i.e.
/// the smallest supported page size. `None` when nothing is
/// supported. Bit n means a 4 KiB << n page.
pub const fn choose_system_page_size(supported: u32) -> Option<u32> {
    if supported == 0 {
        return None;
    }
    Some(supported & supported.wrapping_neg())
}

/// 32-bit VF BAR size from the probe mask (Linux `__pci_read_base`
/// via `size_bar`: mask off the type bits, invert, add 1). Returns
/// 0 when the BAR is unimplemented (mask 0).
pub const fn vf_bar_size_32(mask: u32) -> u64 {
    let masked = mask & 0xFFFF_FFF0;
    if masked == 0 {
        return 0;
    }
    ((!masked) as u64).wrapping_add(1) & 0xFFFF_FFFF
}

/// 64-bit VF BAR size from the low/high probe masks. Returns 0
/// when the BAR is unimplemented.
pub const fn vf_bar_size_64(mask_lo: u32, mask_hi: u32) -> u64 {
    let combined = ((mask_hi as u64) << 32) | ((mask_lo & 0xFFFF_FFF0) as u64);
    if combined == 0 {
        return 0;
    }
    (!combined).wrapping_add(1)
}

/// VF device/function number (Linux `pci_iov_virtfn_devfn`):
/// `(pf_devfn + offset + stride * vf_id) & 0xff`.
pub const fn virtfn_devfn(pf_devfn: u8, offset: u16, stride: u16, vf_id: u16) -> u8 {
    ((pf_devfn as u16 + offset + stride * vf_id) & 0xFF) as u8
}

/// VF bus number (Linux `pci_iov_virtfn_bus`): the PF bus plus the
/// carry out of the devfn addition.
pub const fn virtfn_bus(pf_bus: u8, pf_devfn: u8, offset: u16, stride: u16, vf_id: u16) -> u16 {
    pf_bus as u16 + ((pf_devfn as u16 + offset + stride * vf_id) >> 8)
}

/// Minimal config-space accessor the SR-IOV programming core runs
/// over — the same shape as `bar.rs`'s private `Config` trait, so
/// the enable sequence is fixture-testable against a fake image
/// without a live device.
trait SriovCfg {
    fn read16(&mut self, off: u64) -> u16;
    fn write16(&mut self, off: u64, value: u16);
    fn read32(&mut self, off: u64) -> u32;
    fn write32(&mut self, off: u64, value: u32);
}

/// ECAM-backed `SriovCfg` over a device's identity-mapped cfg window.
struct EcamSriovCfg(PhysAddr);

impl SriovCfg for EcamSriovCfg {
    fn read16(&mut self, off: u64) -> u16 {
        // SAFETY: constructed only by the public fns over a live
        // device's 4 KiB cfg window; all offsets are bounded,
        // naturally-aligned PCI fields.
        unsafe { cfg_read16(self.0, off) }
    }
    fn write16(&mut self, off: u64, value: u16) {
        // SAFETY: same window; a word write never writes RW1C PCI
        // Status (Control and Status are separate words here).
        unsafe { cfg_write16(self.0, off, value) }
    }
    fn read32(&mut self, off: u64) -> u32 {
        // SAFETY: same window; dword-aligned offsets only.
        unsafe { cfg_read32(self.0, off) }
    }
    fn write32(&mut self, off: u64, value: u32) {
        // SAFETY: same window; dword-aligned offsets only.
        unsafe { cfg_write32(self.0, off, value) }
    }
}

#[inline]
unsafe fn cfg_read16(cfg: PhysAddr, off: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 2-byte aligned.
    let v = unsafe {
        if let Some(p) = crate::ecam::ptr_for(cfg, off) {
            narf_arch::mmio::read16(p as u64)
        } else {
            u16::MAX
        }
    };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write16(cfg: PhysAddr, off: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 2-byte aligned.
    unsafe {
        if let Some(p) = crate::ecam::ptr_for(cfg, off) {
            narf_arch::mmio::write16(p as u64, value);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is readable + 4-byte aligned.
    let v = unsafe {
        if let Some(p) = crate::ecam::ptr_for(cfg, off) {
            narf_arch::mmio::read32(p as u64)
        } else {
            u32::MAX
        }
    };
    compiler_fence(Ordering::SeqCst);
    v
}

#[inline]
unsafe fn cfg_write32(cfg: PhysAddr, off: u64, value: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller asserts the slot is writable + 4-byte aligned.
    unsafe {
        if let Some(p) = crate::ecam::ptr_for(cfg, off) {
            core::ptr::write_volatile(p as *mut u32, value);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn pcie_cfg_phys(device: &BusDevice) -> Result<PhysAddr, SriovError> {
    match device.kind {
        BusKind::Pcie { cfg_phys, .. } => Ok(cfg_phys),
        BusKind::VirtioMmio { .. } => Err(SriovError::NotPcie),
    }
}

/// Read the SR-IOV capability, if the device has one. Cap-gated
/// (read); returns `None` when the device has no SR-IOV cap.
pub fn read_sriov_caps(
    cap: &Cap<BusDeviceCap, Read>,
    device: &BusDevice,
) -> Result<Option<SriovCaps>, SriovError> {
    let Some(hdr) = find_cap(cap, device, id::SR_IOV)? else {
        return Ok(None);
    };
    let cfg = pcie_cfg_phys(device)?;
    let mut words = [0u32; 16];
    for (i, w) in words.iter_mut().enumerate() {
        // SAFETY: `hdr.offset` is inside the 4 KiB cfg window (the
        // walker bounds it) and the cap image is 64 bytes.
        *w = unsafe { cfg_read32(cfg, hdr.offset + (i as u64) * 4) };
    }
    Ok(Some(SriovCaps::decode(hdr.offset, &words)))
}

/// BAR probe: write all-ones, read the mask, restore the original,
/// verify the restore (Linux `__pci_read_base` ritual, same as
/// `bar.rs::probe_mask`). Returns the mask.
fn probe_vf_bar_mask(cfg: &mut impl SriovCfg, off: u64) -> Result<u32, SriovError> {
    let original = cfg.read32(off);
    cfg.write32(off, u32::MAX);
    let mask = cfg.read32(off);
    cfg.write32(off, original);
    if cfg.read32(off) != original {
        return Err(SriovError::ConfigFailed);
    }
    Ok(mask)
}

/// Enable `num_vfs` VFs: the `sriov_init` + `sriov_enable` sequence
/// over `cfg` at capability offset `pos`. `alloc_mmio(size, align)`
/// reserves a VF BAR window (the production caller passes
/// `crate::bar::allocate_pci_mmio`).
///
/// Order (Linux): clear a stale VF Enable; refuse when NumVFs is
/// already set; validate Total/InitialVFs and the migration-capable
/// rule; program the System Page Size; size + program each VF BAR
/// (window = per-VF size x TotalVFs); write NumVFs and re-read VF
/// Offset / VF Stride; set Control VF Enable + VF Memory Space
/// Enable.
fn enable_sriov_cfg(
    cfg: &mut impl SriovCfg,
    pos: u64,
    num_vfs: u16,
    alloc_mmio: &mut dyn FnMut(u64, u64) -> Option<u64>,
) -> Result<SriovEnabled, SriovError> {
    // Stale VF Enable (e.g. left by firmware): Linux `sriov_init`
    // clears Control and waits 1 s. The wait is omitted here —
    // enable runs before any VF traffic exists.
    let mut ctrl = cfg.read16(pos + SRIOV_CTRL_OFF);
    if ctrl & SRIOV_CTRL_VFE != 0 {
        cfg.write16(pos + SRIOV_CTRL_OFF, 0);
        ctrl = 0;
    }
    if cfg.read16(pos + SRIOV_NUM_VF_OFF) != 0 {
        return Err(SriovError::AlreadyEnabled);
    }
    let total = cfg.read16(pos + SRIOV_TOTAL_VF_OFF);
    let initial = cfg.read16(pos + SRIOV_INITIAL_VF_OFF);
    let cap = cfg.read32(pos + SRIOV_CAP_OFF);
    let vfm = cap & SRIOV_CAP_VFM != 0;
    if initial > total || (!vfm && initial != total) {
        return Err(SriovError::InitialVfMismatch);
    }
    if num_vfs == 0 || num_vfs > total || (!vfm && num_vfs > initial) {
        return Err(SriovError::BadVfCount);
    }
    let supported = cfg.read32(pos + SRIOV_SUP_PGSIZE_OFF);
    let Some(page_size) = choose_system_page_size(supported) else {
        return Err(SriovError::NoSupportedPageSize);
    };
    cfg.write32(pos + SRIOV_SYS_PGSIZE_OFF, page_size);

    // Size + program the VF BARs with VF Enable clear (no decode
    // while sizing, Linux `sriov_init`). The window covers all
    // TotalVFs so a later NumVFs increase still fits.
    let mut vf_bars: [Option<VfBar>; SRIOV_NUM_BARS] = [None; SRIOV_NUM_BARS];
    let mut i = 0usize;
    while i < SRIOV_NUM_BARS {
        let off = pos + SRIOV_BAR_OFF + (i as u64) * 4;
        let orig = cfg.read32(off);
        if orig & 0x1 != 0 {
            return Err(SriovError::IoBarUnsupported);
        }
        let is_64 = (orig & 0b110) == 0b100;
        let mask_lo = probe_vf_bar_mask(cfg, off)?;
        let size = if is_64 {
            let mask_hi = probe_vf_bar_mask(cfg, off + 4)?;
            vf_bar_size_64(mask_lo, mask_hi)
        } else {
            vf_bar_size_32(mask_lo)
        };
        if size == 0 {
            // Unimplemented BAR: nothing to expose.
            if is_64 {
                i += 1;
            }
            i += 1;
            continue;
        }
        if size % (page_size as u64) != 0 {
            return Err(SriovError::BarUnaligned);
        }
        let window = size
            .checked_mul(total as u64)
            .and_then(|total_size| alloc_mmio(total_size, size))
            .ok_or(SriovError::PoolExhausted)?;
        let prefetchable = orig & (1 << 3) != 0;
        cfg.write32(off, ((window & 0xFFFF_FFF0) as u32) | (orig & 0xF));
        if is_64 {
            cfg.write32(off + 4, (window >> 32) as u32);
        }
        vf_bars[i] = Some(VfBar {
            index: i as u8,
            base: window,
            per_vf_size: size,
            is_64bit: is_64,
            prefetchable,
        });
        if is_64 {
            i += 1;
        }
        i += 1;
    }

    // NumVFs first (Offset/Stride may change when it changes),
    // then re-read + validate the geometry.
    cfg.write16(pos + SRIOV_NUM_VF_OFF, num_vfs);
    let vf_offset = cfg.read16(pos + SRIOV_VF_OFFSET_OFF);
    let vf_stride = cfg.read16(pos + SRIOV_VF_STRIDE_OFF);
    if vf_offset == 0 {
        return Err(SriovError::VfOffsetInvalid);
    }
    if num_vfs > 1 && vf_stride == 0 {
        return Err(SriovError::VfStrideInvalid);
    }
    ctrl |= SRIOV_CTRL_VFE | SRIOV_CTRL_MSE;
    cfg.write16(pos + SRIOV_CTRL_OFF, ctrl);
    // No 100 ms settle here: Linux msleeps before `sriov_add_vfs`;
    // NARF has no VF enumeration yet, so the settle belongs with
    // that lane.
    let vf_device_id = cfg.read16(pos + SRIOV_VF_DID_OFF);
    Ok(SriovEnabled {
        num_vfs,
        vf_offset,
        vf_stride,
        vf_device_id,
        page_size,
        vf_bars,
    })
}

/// Enable `num_vfs` VFs on a PF (the bus half of SR-IOV enablement;
/// the device-side half is the driver's VT allocation, e.g. igb's
/// `vt_allocate`). Cap-gated (write). The caller must have claimed
/// the device's `BusDeviceCap`.
pub fn enable_sriov(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    num_vfs: u16,
) -> Result<SriovEnabled, SriovError> {
    cap.check_live()?;
    // `find_cap` takes a Read cap; derive it from the caller's
    // Write cap (same epoch), the pattern `clear_aer_status` uses.
    let read_cap: Cap<BusDeviceCap, Read> = cap
        .derive::<Read>()
        .map_err(|_| SriovError::AuthorityRevoked)?;
    let Some(hdr) = find_cap(&read_cap, device, id::SR_IOV)? else {
        return Err(SriovError::CapNotPresent);
    };
    let cfg = pcie_cfg_phys(device)?;
    let mut ecfg = EcamSriovCfg(cfg);
    enable_sriov_cfg(
        &mut ecfg,
        hdr.offset,
        num_vfs,
        &mut crate::bar::allocate_pci_mmio,
    )
}

/// Core of `disable_sriov` over a config accessor: clear VF Enable
/// + VF Memory Space Enable, then NumVFs.
fn disable_sriov_cfg(cfg: &mut impl SriovCfg, pos: u64) {
    let ctrl = cfg.read16(pos + SRIOV_CTRL_OFF);
    cfg.write16(
        pos + SRIOV_CTRL_OFF,
        ctrl & !(SRIOV_CTRL_VFE | SRIOV_CTRL_MSE),
    );
    cfg.write16(pos + SRIOV_NUM_VF_OFF, 0);
}

/// Disable SR-IOV on a PF (Linux `sriov_disable`, config-space
/// half): clear VF Enable + VF Memory Space Enable, then NumVFs.
/// The caller must already have removed enumerated VFs.
pub fn disable_sriov(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice) -> Result<(), SriovError> {
    cap.check_live()?;
    let read_cap: Cap<BusDeviceCap, Read> = cap
        .derive::<Read>()
        .map_err(|_| SriovError::AuthorityRevoked)?;
    let Some(hdr) = find_cap(&read_cap, device, id::SR_IOV)? else {
        return Err(SriovError::CapNotPresent);
    };
    let cfg = pcie_cfg_phys(device)?;
    let mut ecfg = EcamSriovCfg(cfg);
    disable_sriov_cfg(&mut ecfg, hdr.offset);
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::*;

    /// Capability offset used by the fake images.
    const POS: u64 = 0x100;

    fn cap_words() -> [u32; 16] {
        // Header: id 0x10, version 1, next 0.
        let mut w = [0u32; 16];
        w[0] = 0x0010 | (1 << 16);
        // Cap: migration-capable.
        w[1] = SRIOV_CAP_VFM;
        // Ctrl/Status: disabled.
        w[2] = 0;
        // Initial 4 | Total 7.
        w[3] = 4 | (7 << 16);
        // NumVFs 0 | FuncLink 0.
        w[4] = 0;
        // VF Offset 0x08 | VF Stride 0x01.
        w[5] = 0x08 | (0x01 << 16);
        // VF Device ID 0xABCD.
        w[6] = 0xABCD << 16;
        // Supported Page Sizes: 4K + 64K.
        w[7] = 0x1 | 0x10;
        // System Page Size: unset.
        w[8] = 0;
        // VF BARs raw: BAR0 64-bit MMIO, BAR2 32-bit MMIO.
        w[9] = 0x4;
        w[11] = 0x0;
        w
    }

    fn smoke_sriov_decode() -> TestResult {
        let caps = SriovCaps::decode(POS, &cap_words());
        if caps.pos != POS
            || !caps.cap_vfm
            || caps.ctrl != 0
            || caps.vf_enable
            || caps.initial_vfs != 4
            || caps.total_vfs != 7
            || caps.num_vfs != 0
            || caps.func_link != 0
            || caps.vf_offset != 0x08
            || caps.vf_stride != 0x01
            || caps.vf_device_id != 0xABCD
            || caps.supported_page_sizes != 0x11
            || caps.system_page_size != 0
            || caps.vf_bars[0] != 0x4
            || caps.vf_bars[2] != 0
        {
            return TestResult::Fail("SR-IOV capability decode drift");
        }
        if SRIOV_CTRL_OFF != 0x08
            || SRIOV_STATUS_OFF != 0x0A
            || SRIOV_INITIAL_VF_OFF != 0x0C
            || SRIOV_TOTAL_VF_OFF != 0x0E
            || SRIOV_NUM_VF_OFF != 0x10
            || SRIOV_FUNC_LINK_OFF != 0x12
            || SRIOV_VF_OFFSET_OFF != 0x14
            || SRIOV_VF_STRIDE_OFF != 0x16
            || SRIOV_VF_DID_OFF != 0x1A
            || SRIOV_SUP_PGSIZE_OFF != 0x1C
            || SRIOV_SYS_PGSIZE_OFF != 0x20
            || SRIOV_BAR_OFF != 0x24
            || SRIOV_CAP_SIZE != 0x40
        {
            return TestResult::Fail("SR-IOV register offset drift");
        }
        if SRIOV_CTRL_VFE != 0x1 || SRIOV_CTRL_MSE != 0x8 || SRIOV_CTRL_ARI != 0x10 {
            return TestResult::Fail("SR-IOV control bit drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_decode);

    fn smoke_sriov_page_size_choice() -> TestResult {
        if choose_system_page_size(0).is_some() {
            return TestResult::Fail("empty Supported Page Sizes chose a size");
        }
        if choose_system_page_size(0x1) != Some(0x1)
            || choose_system_page_size(0x5) != Some(0x1)
            || choose_system_page_size(0x2) != Some(0x2)
            || choose_system_page_size(0x8000_0000) != Some(0x8000_0000)
        {
            return TestResult::Fail("System Page Size is not the lowest set bit");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_page_size_choice);

    fn smoke_sriov_bar_sizes() -> TestResult {
        // 32-bit: mask 0xFFF0_0000 -> 1 MiB; 0 -> unimplemented.
        if vf_bar_size_32(0xFFF0_0000) != 0x10_0000
            || vf_bar_size_32(0) != 0
            || vf_bar_size_32(0xFFFF_FFF0) != 0x10
        {
            return TestResult::Fail("32-bit VF BAR size math drift");
        }
        // 64-bit: low 0, high 0xFFFF_F000 -> 2^48.
        if vf_bar_size_64(0, 0xFFFF_F000) != 0x1_0000_0000_0000 || vf_bar_size_64(0, 0) != 0 {
            return TestResult::Fail("64-bit VF BAR size math drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_bar_sizes);

    fn smoke_sriov_virtfn_geometry() -> TestResult {
        if virtfn_devfn(0x00, 0x08, 0x01, 3) != 0x0B {
            return TestResult::Fail("VF devfn math drift");
        }
        if virtfn_bus(0, 0xF8, 0x08, 0x01, 1) != 1 || virtfn_devfn(0xF8, 0x08, 0x01, 1) != 0x01 {
            return TestResult::Fail("VF bus carry math drift");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_virtfn_geometry);

    /// Fake config space: a 4 KiB word image plus BAR-sizing
    /// behaviour (a write of all-ones to a VF BAR slot arms the
    /// preloaded sizing mask for the next read, exactly the
    /// hardware ritual the probe relies on).
    struct FakeCfg {
        words: [u32; 1024],
        bar_masks: [u32; SRIOV_NUM_BARS],
        sizing_armed: [bool; SRIOV_NUM_BARS],
    }

    impl FakeCfg {
        fn new() -> Self {
            let mut f = Self {
                words: [0u32; 1024],
                bar_masks: [0u32; SRIOV_NUM_BARS],
                sizing_armed: [false; SRIOV_NUM_BARS],
            };
            let w = cap_words();
            for (i, word) in w.iter().enumerate() {
                f.words[(POS as usize) / 4 + i] = *word;
            }
            f
        }

        fn bar_slot(off: u64) -> Option<usize> {
            if !(POS + SRIOV_BAR_OFF..POS + SRIOV_BAR_OFF + 24).contains(&off) {
                return None;
            }
            Some(((off - POS - SRIOV_BAR_OFF) / 4) as usize)
        }

        fn set_bar_mask(&mut self, slot: usize, mask: u32) {
            self.bar_masks[slot] = mask;
        }
    }

    impl SriovCfg for FakeCfg {
        fn read16(&mut self, off: u64) -> u16 {
            let w = self.words[(off / 4) as usize];
            ((w >> ((off % 4) * 8)) & 0xFFFF) as u16
        }
        fn write16(&mut self, off: u64, value: u16) {
            let idx = (off / 4) as usize;
            let shift = (off % 4) * 8;
            let mask = !(0xFFFFu32 << shift);
            self.words[idx] = (self.words[idx] & mask) | ((value as u32) << shift);
        }
        fn read32(&mut self, off: u64) -> u32 {
            if let Some(i) = Self::bar_slot(off) {
                if self.sizing_armed[i] {
                    return self.bar_masks[i];
                }
            }
            self.words[(off / 4) as usize]
        }
        fn write32(&mut self, off: u64, value: u32) {
            if let Some(i) = Self::bar_slot(off) {
                if value == u32::MAX {
                    self.sizing_armed[i] = true;
                    return;
                }
                self.sizing_armed[i] = false;
            }
            self.words[(off / 4) as usize] = value;
        }
    }

    fn smoke_sriov_enable_sequence() -> TestResult {
        let mut cfg = FakeCfg::new();
        // BAR0: 64-bit, 64 KiB per VF. BAR2: 32-bit, 4 KiB per VF.
        cfg.set_bar_mask(0, 0xFFFF_0000);
        cfg.set_bar_mask(1, 0xFFFF_FFFF);
        cfg.set_bar_mask(2, 0xFFFF_F000);
        let mut reqs: [(u64, u64); 2] = [(0, 0); 2];
        let mut nreq = 0usize;
        let mut alloc = |size: u64, align: u64| -> Option<u64> {
            if nreq < 2 {
                reqs[nreq] = (size, align);
            }
            nreq += 1;
            Some(0x8000_0000 + ((nreq as u64) - 1) * 0x10_0000)
        };
        let enabled = match enable_sriov_cfg(&mut cfg, POS, 2, &mut alloc) {
            Ok(e) => e,
            Err(_) => return TestResult::Fail("SR-IOV enable sequence failed"),
        };
        // System Page Size = lowest supported bit (4K).
        if cfg.read32(POS + SRIOV_SYS_PGSIZE_OFF) != 0x1 {
            return TestResult::Fail("System Page Size was not the smallest supported");
        }
        // NumVFs + Control VFE|MSE.
        if cfg.read16(POS + SRIOV_NUM_VF_OFF) != 2 {
            return TestResult::Fail("NumVFs was not programmed");
        }
        let ctrl = cfg.read16(POS + SRIOV_CTRL_OFF);
        if ctrl & (SRIOV_CTRL_VFE | SRIOV_CTRL_MSE) != (SRIOV_CTRL_VFE | SRIOV_CTRL_MSE) {
            return TestResult::Fail("Control VF Enable + MSE were not set");
        }
        // VF BAR0 (64-bit): window base in low + high words. The
        // low word keeps the BAR type bits (0x4 = 64-bit).
        if cfg.read32(POS + SRIOV_BAR_OFF) != 0x8000_0004 {
            return TestResult::Fail("VF BAR0 base was not programmed");
        }
        if cfg.read32(POS + SRIOV_BAR_OFF + 4) != 0 {
            return TestResult::Fail("VF BAR0 high half drift");
        }
        // VF BAR2 (32-bit): second allocation.
        if cfg.read32(POS + SRIOV_BAR_OFF + 8) != 0x8010_0000 {
            return TestResult::Fail("VF BAR2 base was not programmed");
        }
        // Geometry re-read.
        if enabled.num_vfs != 2
            || enabled.vf_offset != 0x08
            || enabled.vf_stride != 0x01
            || enabled.vf_device_id != 0xABCD
            || enabled.page_size != 0x1
        {
            return TestResult::Fail("enabled VF geometry drift");
        }
        if enabled.vf_bars[0]
            != Some(VfBar {
                index: 0,
                base: 0x8000_0000,
                per_vf_size: 0x1_0000,
                is_64bit: true,
                prefetchable: false,
            })
            || enabled.vf_bars[1].is_some()
            || enabled.vf_bars[2]
                != Some(VfBar {
                    index: 2,
                    base: 0x8010_0000,
                    per_vf_size: 0x1000,
                    is_64bit: false,
                    prefetchable: false,
                })
        {
            return TestResult::Fail("enabled VF BAR windows drift");
        }
        // Second enable refuses (NumVFs already set).
        if enable_sriov_cfg(&mut cfg, POS, 2, &mut alloc).is_ok() {
            return TestResult::Fail("double SR-IOV enable was accepted");
        }
        // Windows are per-VF size x TotalVFs (7), aligned to the
        // per-VF size.
        if reqs[0] != (0x1_0000 * 7, 0x1_0000) || reqs[1] != (0x1000 * 7, 0x1000) {
            return TestResult::Fail("VF BAR window sizing drift");
        }
        // Disable round-trip: Control cleared, NumVFs back to 0.
        disable_sriov_cfg(&mut cfg, POS);
        if cfg.read16(POS + SRIOV_CTRL_OFF) & (SRIOV_CTRL_VFE | SRIOV_CTRL_MSE) != 0
            || cfg.read16(POS + SRIOV_NUM_VF_OFF) != 0
        {
            return TestResult::Fail("SR-IOV disable did not clear Control/NumVFs");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_enable_sequence);

    fn smoke_sriov_enable_rejections() -> TestResult {
        // Count above TotalVFs.
        let mut cfg = FakeCfg::new();
        let mut alloc = |_: u64, _: u64| -> Option<u64> { Some(0x8000_0000) };
        if enable_sriov_cfg(&mut cfg, POS, 8, &mut alloc) != Err(SriovError::BadVfCount) {
            return TestResult::Fail("VF count above TotalVFs was accepted");
        }
        // No supported page size.
        let mut cfg = FakeCfg::new();
        cfg.write32(POS + SRIOV_SUP_PGSIZE_OFF, 0);
        if enable_sriov_cfg(&mut cfg, POS, 2, &mut alloc) != Err(SriovError::NoSupportedPageSize) {
            return TestResult::Fail("empty Supported Page Sizes was accepted");
        }
        // Unaligned VF BAR size (per-VF 0x1810, page 4K).
        let mut cfg = FakeCfg::new();
        cfg.set_bar_mask(0, 0xFFFF_E7F0);
        cfg.set_bar_mask(1, 0xFFFF_FFFF);
        if enable_sriov_cfg(&mut cfg, POS, 2, &mut alloc) != Err(SriovError::BarUnaligned) {
            return TestResult::Fail("page-unaligned VF BAR was accepted");
        }
        // Pool exhaustion.
        let mut cfg = FakeCfg::new();
        cfg.set_bar_mask(0, 0xFFFF_0000);
        cfg.set_bar_mask(1, 0xFFFF_FFFF);
        let mut no_alloc = |_: u64, _: u64| -> Option<u64> { None };
        if enable_sriov_cfg(&mut cfg, POS, 2, &mut no_alloc) != Err(SriovError::PoolExhausted) {
            return TestResult::Fail("MMIO pool exhaustion was accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("bus/sriov", smoke_sriov_enable_rejections);
}
