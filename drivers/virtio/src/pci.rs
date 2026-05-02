//! virtio-PCI modern transport (VirtIO 1.2 §4.1).
//!
//! The modern transport places its register surface in BAR-mapped
//! MMIO instead of the cfg-space-resident layout the legacy
//! transport used. Five vendor-specific capabilities (cap ID 0x09)
//! discriminated by their `cfg_type` byte point at the BAR + offset
//! of each register region:
//!
//!   1 = Common configuration (the one drivers use for status,
//!       feature negotiation, queue setup).
//!   2 = Notify (BAR + offset where the driver writes
//!       `queue_notify_off * notify_off_multiplier`).
//!   3 = ISR status.
//!   4 = Device-specific configuration (e.g. block-device capacity).
//!   5 = PCI configuration access (alternate path; not used here).
//!
//! Register layout for `Common Cfg` (VirtIO 1.2 §4.1.4.3):
//!
//! | offset | name                     | width |
//! |--------|--------------------------|-------|
//! | 0x00   | device_feature_select    | u32   |
//! | 0x04   | device_feature           | u32   |
//! | 0x08   | driver_feature_select    | u32   |
//! | 0x0C   | driver_feature           | u32   |
//! | 0x10   | msix_config              | u16   |
//! | 0x12   | num_queues               | u16   |
//! | 0x14   | device_status            | u8    |
//! | 0x15   | config_generation        | u8    |
//! | 0x16   | queue_select             | u16   |
//! | 0x18   | queue_size               | u16   |
//! | 0x1A   | queue_msix_vector        | u16   |
//! | 0x1C   | queue_enable             | u16   |
//! | 0x1E   | queue_notify_off         | u16   |
//! | 0x20   | queue_desc               | u64   |
//! | 0x28   | queue_driver             | u64   |
//! | 0x30   | queue_device             | u64   |
//!
//! The driver maps the BARs the caps point at (via `bus::map_bar`)
//! and reads/writes through the resulting `MmioRegion`s.

use narf_bus::{map_bar, BusDevice, MmioRegion};
use narf_memory::PhysAddr;

/// Vendor-specific cap id (PCIe spec § 7.7.4) that virtio uses for
/// its capability headers.
pub const VIRTIO_PCI_CAP_VENDOR: u8 = 0x09;

/// `cfg_type` discriminator values (VirtIO 1.2 §4.1.4).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CfgType {
    Common = 1,
    Notify = 2,
    Isr    = 3,
    Device = 4,
    PciCfg = 5,
}

impl CfgType {
    pub fn from_raw(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Common,
            2 => Self::Notify,
            3 => Self::Isr,
            4 => Self::Device,
            5 => Self::PciCfg,
            _ => return None,
        })
    }
}

/// One discovered virtio-PCI cap header.
#[derive(Copy, Clone, Debug)]
pub struct VirtioCap {
    pub cfg_type: CfgType,
    pub bar:      u8,
    /// Offset in the BAR.
    pub offset:   u32,
    /// Length of the region in the BAR.
    pub length:   u32,
    /// Only valid for `CfgType::Notify`. The notify register address
    /// is `bar.start + offset + queue_notify_off * notify_off_multiplier`.
    pub notify_off_multiplier: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VirtioPciError {
    NotPcie,
    NoVendorCap,
    BarMapFailed,
    /// `Common Cfg` cap missing — this is required for any working
    /// modern transport.
    NoCommonCfg,
    NoNotifyCfg,
    DeviceRejectedFeatures,
    NoQueues,
    /// `queue_size` / `queue_num_max` returned 0.
    QueueTooSmall,
    /// `add_buffer` couldn't fit the descriptor chain.
    AddBufferFailed,
    /// Polled completion never observed (timeout).
    CompletionTimeout,
}

/// Walk the standard cap list looking for the four virtio caps and
/// return them as a tuple `(common, notify, isr, device)`. Notify
/// includes the `notify_off_multiplier` extracted from offset 16 of
/// the header. The function reads only — caller's BusDevice cap is
/// the implicit authority since cfg-space reads are non-mutating.
///
/// # Safety
/// `device` must be PCIe + live; caller ensures cfg-space exclusivity
/// for the duration of the walk.
pub unsafe fn discover(device: &BusDevice) -> Result<VirtioCaps, VirtioPciError> {
    use narf_bus::pci_cap;

    let cfg = match device.kind {
        narf_bus::BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        _ => return Err(VirtioPciError::NotPcie),
    };
    let mut common = None;
    let mut notify = None;
    let mut isr    = None;
    let mut dev_c  = None;
    // SAFETY: bounded cap-list walk.
    for hdr in unsafe { pci_cap::iter(device) }
        .map_err(|_| VirtioPciError::NotPcie)?
    {
        if hdr.id != VIRTIO_PCI_CAP_VENDOR { continue; }
        // Vendor-specific cap layout (VirtIO 1.2 §4.1.4):
        //   +0  cap_vndr (u8) = 0x09
        //   +1  cap_next (u8)
        //   +2  cap_len  (u8) — typically 16 (or 20 for Notify)
        //   +3  cfg_type (u8)
        //   +4  bar      (u8)
        //   +5  id       (u8) reserved
        //   +6  pad[2]
        //   +8  offset   (u32)
        //   +12 length   (u32)
        //   +16 notify_off_multiplier (u32) — Notify cap only
        // SAFETY: cfg-space identity-mapped; offsets stay below 0x100.
        let cfg_type = unsafe { cfg_read8(cfg, hdr.offset + 3) };
        let bar      = unsafe { cfg_read8(cfg, hdr.offset + 4) };
        let offset   = unsafe { cfg_read32(cfg, hdr.offset + 8) };
        let length   = unsafe { cfg_read32(cfg, hdr.offset + 12) };
        let multi    = if cfg_type == CfgType::Notify as u8 {
            // SAFETY: Notify cap is at least 20 bytes by spec.
            unsafe { cfg_read32(cfg, hdr.offset + 16) }
        } else { 0 };
        let Some(cfg_kind) = CfgType::from_raw(cfg_type) else { continue; };
        let cap = VirtioCap { cfg_type: cfg_kind, bar, offset, length,
            notify_off_multiplier: multi };
        match cfg_kind {
            CfgType::Common => common = Some(cap),
            CfgType::Notify => notify = Some(cap),
            CfgType::Isr    => isr    = Some(cap),
            CfgType::Device => dev_c  = Some(cap),
            CfgType::PciCfg => {}
        }
    }

    let common = common.ok_or(VirtioPciError::NoCommonCfg)?;
    let notify = notify.ok_or(VirtioPciError::NoNotifyCfg)?;
    Ok(VirtioCaps { common, notify, isr, device_cfg: dev_c })
}

/// Snapshot of the four caps a modern virtio-PCI driver needs.
#[derive(Debug)]
pub struct VirtioCaps {
    pub common:     VirtioCap,
    pub notify:     VirtioCap,
    pub isr:        Option<VirtioCap>,
    pub device_cfg: Option<VirtioCap>,
}

/// Mapped region for a virtio-PCI cap. Wraps `MmioRegion` + the
/// in-BAR offset so reads / writes target the right window.
///
/// Carries a `virt` field — the kernel virtual address that
/// resolves to the BAR. On x86_64 BARs in low RAM this is just
/// the phys (identity-mapped); on aarch64 (and any BAR above the
/// boot identity map) it's an ioremap'd kernel VA. All reads /
/// writes use `virt`, so the same code path works on both arches.
#[derive(Debug)]
pub struct VirtioRegion {
    pub region: MmioRegion,
    /// Kernel virtual base of the mapped BAR.
    pub virt:   u64,
    pub offset: u64,
    pub length: u64,
}

impl VirtioRegion {
    /// Address of register at `off` bytes into the region. Always
    /// goes through `self.virt` so cross-arch / above-identity-map
    /// BARs work uniformly.
    #[inline]
    fn addr(&self, off: u64) -> u64 { self.virt + self.offset + off }

    /// Read a 32-bit register at `off` bytes into the region.
    ///
    /// # Safety
    /// `off + 4 <= self.length`.
    #[inline]
    pub unsafe fn read32(&self, off: u64) -> u32 {
        // SAFETY: caller-bounded; addr() honours the kernel-VA mapping.
        unsafe { narf_arch::mmio::read32(self.addr(off)) }
    }

    /// Write a 32-bit register at `off` bytes into the region.
    ///
    /// # Safety
    /// Same as `read32`.
    #[inline]
    pub unsafe fn write32(&self, off: u64, v: u32) {
        // SAFETY: caller-bounded.
        unsafe { narf_arch::mmio::write32(self.addr(off), v); }
    }

    /// 64-bit register split into two 32-bit writes (LE).
    /// VirtIO mandates that 64-bit common-cfg fields are written
    /// low-half first, high-half second — but on QEMU x86_64 we have
    /// the freedom to use 64-bit MMIO. The split form is universally
    /// safe.
    #[inline]
    pub unsafe fn write64_split(&self, off: u64, v: u64) {
        // SAFETY: caller-bounded.
        unsafe {
            self.write32(off, v as u32);
            self.write32(off + 4, (v >> 32) as u32);
        }
    }

    #[inline]
    pub unsafe fn read16(&self, off: u64) -> u16 {
        // SAFETY: caller-bounded.
        unsafe { narf_arch::mmio::read16(self.addr(off)) }
    }

    #[inline]
    pub unsafe fn write16(&self, off: u64, v: u16) {
        // SAFETY: caller-bounded.
        unsafe { narf_arch::mmio::write16(self.addr(off), v); }
    }

    #[inline]
    pub unsafe fn read8(&self, off: u64) -> u8 {
        // SAFETY: caller-bounded.
        unsafe { narf_arch::mmio::read8(self.addr(off)) }
    }

    #[inline]
    pub unsafe fn write8(&self, off: u64, v: u8) {
        // SAFETY: caller-bounded.
        unsafe { narf_arch::mmio::write8(self.addr(off), v); }
    }
}

/// Map a virtio-PCI cap's BAR + carve out the cap's window.
///
/// On x86_64 with BARs in low RAM the BAR phys is identity-mapped,
/// so `virt = phys` for free. On aarch64 (and any BAR above the
/// boot identity map), we ioremap the BAR onto a fresh kernel VA
/// so subsequent reads / writes don't fault. The choice happens
/// per-arch via the ioremap module — both arches have it.
///
/// # Safety
/// Forwarded to `bus::map_bar` + `memory::ioremap`. Caller owns
/// the device exclusively.
pub unsafe fn map_cap(
    device: &BusDevice,
    cap:    &VirtioCap,
) -> Result<VirtioRegion, VirtioPciError> {
    // SAFETY: caller-asserted.
    let region = unsafe { map_bar(device, cap.bar) }
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    // ioremap covers the whole BAR (page-aligned both ends). The
    // cap's `offset` is added inside `VirtioRegion::addr` on every
    // access.
    let bar_phys_pg = region.phys.raw() & !0xFFFu64;
    let bar_end     = (region.phys.raw() + region.len + 0xFFF) & !0xFFFu64;
    let bar_len_pg  = bar_end - bar_phys_pg;
    // Reject zero-phys BARs — happens on aarch64 today because
    // QEMU virt + `-kernel` means no firmware assigned the BARs.
    // Until a kernel-side BAR allocator runs during PCIe
    // enumeration, virtio devices on aarch64 will return BAR=0
    // and we can't map a real window. Without this check ioremap
    // would happily map phys 0 (low RAM!) and reads would
    // succeed but return wrong data.
    if bar_phys_pg == 0 {
        return Err(VirtioPciError::BarMapFailed);
    }
    // SAFETY: caller owns the BAR window; we map in kernel VA
    // space using strongly-uncached attributes for MMIO.
    let mapping = unsafe {
        narf_memory::ioremap::ioremap(
            bar_phys_pg, bar_len_pg, narf_memory::ioremap::MmioAttrs::Device,
        )
    }.map_err(|_| VirtioPciError::BarMapFailed)?;
    // virt aligns to the page boundary of the BAR; add back the
    // offset within the page.
    let intra_page = region.phys.raw() - bar_phys_pg;
    Ok(VirtioRegion {
        region,
        virt:   mapping.virt + intra_page,
        offset: cap.offset as u64,
        length: cap.length as u64,
    })
}

// ── Common Cfg register offsets ─────────────────────────────────────

pub const CC_DEVICE_FEATURE_SELECT: u64 = 0x00;
pub const CC_DEVICE_FEATURE:        u64 = 0x04;
pub const CC_DRIVER_FEATURE_SELECT: u64 = 0x08;
pub const CC_DRIVER_FEATURE:        u64 = 0x0C;
pub const CC_MSIX_CONFIG:           u64 = 0x10;
pub const CC_NUM_QUEUES:            u64 = 0x12;
pub const CC_DEVICE_STATUS:         u64 = 0x14;
pub const CC_CONFIG_GENERATION:     u64 = 0x15;
pub const CC_QUEUE_SELECT:          u64 = 0x16;
pub const CC_QUEUE_SIZE:            u64 = 0x18;
pub const CC_QUEUE_MSIX_VECTOR:     u64 = 0x1A;
pub const CC_QUEUE_ENABLE:          u64 = 0x1C;
pub const CC_QUEUE_NOTIFY_OFF:      u64 = 0x1E;
pub const CC_QUEUE_DESC:            u64 = 0x20;
pub const CC_QUEUE_DRIVER:          u64 = 0x28;
pub const CC_QUEUE_DEVICE:          u64 = 0x30;

// ── MSI-X enablement (shared across virtio-PCI drivers) ────────────

/// Enable MSI-X on a virtio-PCI device and bind one queue to one
/// MSI-X vector. Factored out of virtio-blk-pci so every live
/// driver can share it. Returned `(irq_vector, MsixTable)` is
/// stashed by the driver so completion paths can wait on it via
/// `narf_interrupts::wait_for_irq(irq_vector)`.
///
/// # Safety
/// Caller owns the device's BAR + cfg-space exclusively.
pub unsafe fn enable_msix_queue(
    common: &VirtioRegion,
    cap:    &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    device: &narf_bus::BusDevice,
    q_idx:  u16,
) -> Result<(u8, narf_bus::MsixTable), VirtioPciError> {
    let mut table = narf_bus::msix::enable_msix(cap, device)
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    let v = narf_interrupts::vector::alloc()
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    let _ = table.alloc_vector().ok_or(VirtioPciError::BarMapFailed)?;
    // SAFETY: x2APIC online for any post-init driver.
    let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
    // SAFETY: caller-asserted exclusive ownership.
    unsafe { table.program_vector(0, target_apic, v) }
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    // SAFETY: same.
    unsafe { table.enable() }
        .map_err(|_| VirtioPciError::BarMapFailed)?;
    // SAFETY: identity-mapped MMIO common-cfg region.
    unsafe {
        common.write16(CC_QUEUE_SELECT, q_idx);
        common.write16(CC_QUEUE_MSIX_VECTOR, 0);
    }
    // SAFETY: same.
    let actual = unsafe { common.read16(CC_QUEUE_MSIX_VECTOR) };
    if actual != 0 {
        return Err(VirtioPciError::BarMapFailed);
    }
    Ok((v, table))
}

// ── helpers ─────────────────────────────────────────────────────────

#[inline]
unsafe fn cfg_read8(cfg: PhysAddr, off: u64) -> u8 {
    // SAFETY: caller asserts the slot is readable.
    unsafe { narf_arch::mmio::read8(cfg.raw() + off) }
}

#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    // SAFETY: caller asserts the slot is readable + 4-byte aligned.
    unsafe { narf_arch::mmio::read32(cfg.raw() + off) }
}
