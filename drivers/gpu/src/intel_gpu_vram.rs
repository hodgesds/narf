//! Qualified DG2/Xe2 local memory: layout probe and owned CPU-visible pool.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_vram.c
//! {tile_vram_size,get_flat_ccs_offset,determine_lmem_bar_size}, xe_regs.h
//! (GSMBASE, SG_TILE_ADDR_RANGE) and xe_gt_regs.h (XE2_FLAT_CCS_BASE_RANGE_*,
//! MIRROR_FUSE3). Usable VRAM ends at the flat-CCS base (or GSMBASE without
//! flat CCS); the stolen/GSM/CCS tail is never allocated. Only the LMEM BAR's
//! CPU-visible prefix is pooled. Reservations never access the BAR. Before
//! publication, the GT runtime initializes Xe2 data through its owned WC
//! mapping, or executes DG2's trusted data and flat-CCS clear. Xe2 compression is enabled
//! only by compressed PAT indices, which this driver never admits, so stale
//! CCS metadata cannot affect any admitted access. DG2 requires 64 KiB
//! allocations/PTE groups and fresh flat-CCS initialization on every reuse.

use crate::amdgpu_vram::{Pool, Reservation, UnmappedPool, UnmappedReservation};
use alloc::sync::Arc;
use core::ops::Range;
use narf_bus::MmioRegion;
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

const GIB: u64 = 1 << 30;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VramError {
    Unavailable,
    Unstable,
    Layout,
    Mapping,
}

/// Probed tile-0 local-memory layout, in device physical addresses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VramLayout {
    pub tile_size: u64,
    pub tile_offset: u64,
    /// Bytes from `tile_offset` that the driver may allocate.
    pub usable: u64,
}

/// Raw Xe2 register words captured with the GT awake and MCR steered to an
/// unterminated instance (0x8800/0x8804).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Xe2VramRegisters {
    pub tile_range: u32,
    pub ccs_lower: u32,
    pub ccs_upper: u32,
    pub fuse3: u32,
    pub gsm_base: u64,
}

/// Xe-HPG's flat-CCS base is an MCR-steered 64 KiB pointer, not the Xe2
/// per-node split register. Linux xe_vram.c::get_flat_ccs_offset.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dg2VramRegisters {
    pub tile_range: u32,
    pub ccs_base: u32,
    pub gsm_base: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VramRegisters {
    Xe2(Xe2VramRegisters),
    Dg2(Dg2VramRegisters),
}

impl VramLayout {
    pub fn from_registers(regs: VramRegisters) -> Result<Self, VramError> {
        match regs {
            VramRegisters::Xe2(regs) => Self::xe2(regs),
            VramRegisters::Dg2(regs) => Self::dg2(regs),
        }
    }

    pub fn dg2(regs: Dg2VramRegisters) -> Result<Self, VramError> {
        if regs.tile_range == u32::MAX || regs.ccs_base == u32::MAX || regs.gsm_base == u64::MAX {
            return Err(VramError::Unavailable);
        }
        let tile_size = u64::from((regs.tile_range >> 8) & 0x3ff) * GIB;
        let tile_offset = u64::from((regs.tile_range >> 1) & 0x7f) * GIB;
        let ccs = u64::from(regs.ccs_base >> 8) * 65536;
        let end = tile_offset
            .checked_add(tile_size)
            .ok_or(VramError::Layout)?;
        // This driver owns tile zero only. Never pool CCS, stolen/GSM, a
        // foreign tile, or an unqualified tail. Xe-HPG has one CCS byte per
        // 256 data bytes; unlike Xe2, no adjacency equality is assumed.
        if tile_size == 0
            || tile_offset != 0
            || ccs == 0
            || ccs >= regs.gsm_base
            || regs.gsm_base > end
            || regs.gsm_base - ccs < tile_size / 256
        {
            return Err(VramError::Layout);
        }
        Ok(Self {
            tile_size,
            tile_offset,
            usable: ccs,
        })
    }

    pub fn xe2(regs: Xe2VramRegisters) -> Result<Self, VramError> {
        if [regs.tile_range, regs.ccs_lower, regs.ccs_upper, regs.fuse3].contains(&u32::MAX)
            || regs.gsm_base == u64::MAX
        {
            return Err(VramError::Unavailable);
        }
        let tile_size = u64::from((regs.tile_range >> 8) & 0x3ff) * GIB;
        let tile_offset = u64::from((regs.tile_range >> 1) & 0x7f) * GIB;
        let base = if regs.ccs_lower & 1 != 0 {
            // get_flat_ccs_offset: per-node HW view times enabled L3 nodes,
            // rounded up to 128K, with no hole before GSMBASE.
            let nodes = (regs.fuse3 >> 16).count_ones() as u64;
            let mut offset =
                u64::from(regs.ccs_upper & 0xff) << 32 | u64::from(regs.ccs_lower & !0x3f);
            offset = offset.checked_mul(nodes).ok_or(VramError::Layout)?;
            offset = offset.checked_add(0x1ffff).ok_or(VramError::Layout)? & !0x1ffff;
            if nodes == 0 || regs.gsm_base.checked_sub(tile_size / 512) != Some(offset) {
                return Err(VramError::Layout);
            }
            offset
        } else {
            regs.gsm_base
        };
        let usable = base
            .checked_sub(tile_offset)
            .filter(|usable| *usable != 0 && *usable <= tile_size && usable % 4096 == 0)
            .ok_or(VramError::Layout)?;
        Ok(Self {
            tile_size,
            tile_offset,
            usable,
        })
    }
}

static BOOT_FRAMEBUFFER: IrqSafeSpinLock<Option<Range<u64>>> = IrqSafeSpinLock::new(None);

/// The firmware console framebuffer's physical bytes. A scanout inside the
/// LMEM BAR stays excluded from allocation for the pool's lifetime.
pub fn record_boot_framebuffer(fb: narf_graphics_driver::generic::GenericFb) {
    let bytes = u64::from(fb.pitch) * u64::from(fb.height);
    if let Some(end) = fb.addr.checked_add(bytes).filter(|_| bytes != 0) {
        BOOT_FRAMEBUFFER.lock().get_or_insert(fb.addr..end);
    }
}

/// One card's local memory. The ordinary pool owns only the CPU-visible
/// prefix; an explicit fresh BMG receipt may add a disjoint unmapped pool.
/// Reservations require owned initialization before use.
#[derive(Debug)]
pub struct Vram {
    pool: Pool,
    unmapped: Option<UnmappedPool>,
    grant: Option<Arc<crate::intel_gpu_gt::smallbar::DpaGrant>>,
    allocation_gate: IrqSafeSpinLock<()>,
    /// Kernel CPU access to the LMEM BAR. The GT owner closes it before the
    /// function may leave D0 (the BAR does not decode in D3) and reopens it
    /// once a resumed GT is running again.
    cpu_gate: IrqSafeSpinLock<CpuGate>,
    pub layout: VramLayout,
    /// LMEM BAR physical base: device address `d` is CPU address `bar + d`
    /// (xe_vram.c dpa_base 0, io_start + tile offset).
    bar: u64,
    page_size: u64,
}

#[derive(Debug, Default)]
struct CpuGate {
    closed: bool,
    users: usize,
}

/// One kernel CPU access to a pool's LMEM BAR; the pool cannot be closed for
/// runtime suspend while it lives.
#[derive(Debug)]
pub(crate) struct CpuAccess<'a>(&'a Vram);

impl Drop for CpuAccess<'_> {
    fn drop(&mut self) {
        self.0.cpu_gate.lock().users -= 1;
    }
}

impl Vram {
    /// # Safety
    /// `bar` is this function's LMEM BAR (BAR2) mapped write-combining, and
    /// `layout` was probed from the same device. No other kernel owner
    /// allocates from this VRAM except the recorded boot framebuffer.
    pub unsafe fn new(bar: MmioRegion, layout: VramLayout) -> Result<Arc<Self>, VramError> {
        // SAFETY: forwarded exclusive, mapped-aperture contract.
        unsafe { Self::new_inner(bar, layout, 4096) }
    }

    /// # Safety
    /// As `new`, with a layout qualified by `VramLayout::dg2`. Every returned
    /// allocation additionally requires a completed trusted flat-CCS clear
    /// before it can be published to a handle, CPU mapping or user VM.
    pub unsafe fn new_dg2(bar: MmioRegion, layout: VramLayout) -> Result<Arc<Self>, VramError> {
        // SAFETY: the caller supplies the same exclusive aperture ownership.
        unsafe { Self::new_inner(bar, layout, 65536) }
    }

    unsafe fn new_inner(
        bar: MmioRegion,
        layout: VramLayout,
        page_size: u64,
    ) -> Result<Arc<Self>, VramError> {
        let len = bar
            .len
            .checked_sub(layout.tile_offset)
            .ok_or(VramError::Mapping)?
            .min(layout.usable)
            & !(page_size - 1);
        if len == 0 {
            return Err(VramError::Mapping);
        }
        let mapping = MmioRegion {
            phys: narf_memory::PhysAddr::new(bar.phys.raw() + layout.tile_offset),
            virt: bar.virt + layout.tile_offset,
            len,
            kind: bar.kind,
        };
        let mut protected = alloc::vec::Vec::new();
        if let Some(fb) = BOOT_FRAMEBUFFER.lock().clone() {
            let base = mapping.phys.raw();
            let start = fb.start.max(base);
            let end = fb.end.min(base + len);
            if start < end {
                protected.push(start - base..end - base);
            }
        }
        // SAFETY: the caller grants exclusive ownership of the visible usable
        // prefix; the firmware console range is permanently protected.
        let pool = unsafe { Pool::from_owned_aperture(mapping, layout.tile_offset, &protected) }
            .map_err(|_| VramError::Mapping)?;
        Ok(Arc::new(Self {
            pool,
            unmapped: None,
            grant: None,
            allocation_gate: IrqSafeSpinLock::new(()),
            cpu_gate: IrqSafeSpinLock::new(CpuGate::default()),
            layout,
            bar: bar.phys.raw(),
            page_size,
        }))
    }

    /// # Safety
    /// The derived receipt owns this exact PF's whole ordinary usable DPA
    /// incarnation, permanently excluding inherited and future boot/CSC actors.
    pub(crate) unsafe fn new_smallbar(
        bar: MmioRegion,
        layout: VramLayout,
        grant: Arc<crate::intel_gpu_gt::smallbar::DpaGrant>,
    ) -> Result<Arc<Self>, VramError> {
        if !grant.matches(bar, layout) || layout.tile_offset != 0 || bar.len >= layout.usable {
            return Err(VramError::Layout);
        }
        // SAFETY: the same receipt includes the existing CPU-visible prefix.
        let mut vram = unsafe { Self::new_inner(bar, layout, 4096)? };
        let inner = Arc::get_mut(&mut vram).ok_or(VramError::Mapping)?;
        let base = inner.pool.size();
        // SAFETY: this disjoint tail lies strictly before the source CCS/DSM
        // boundary. No CPU address or MmioRegion is created for it.
        inner.unmapped = Some(
            unsafe { UnmappedPool::from_owned(base, layout.usable - base, &[]) }
                .map_err(|_| VramError::Mapping)?,
        );
        inner.grant = Some(grant);
        Ok(vram)
    }
    pub(crate) fn smallbar_enabled(&self) -> bool {
        self.grant.is_some()
    }
    pub(crate) fn matches_smallbar(&self, grant: &crate::intel_gpu_gt::smallbar::DpaGrant) -> bool {
        self.grant.as_ref().is_some_and(|old| old.same_owner(grant))
    }
    pub(crate) fn smallbar_access(
        &self,
        m: &impl crate::intel_gpu_aux::MmioWindow,
    ) -> Result<(), crate::intel_gpu_gt::lnl::Error> {
        self.grant
            .as_ref()
            .ok_or(crate::intel_gpu_gt::lnl::Error::Unsupported)?
            .current(m)
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn smallbar_current(&self, m: &impl crate::intel_gpu_aux::MmioWindow) -> bool {
        self.smallbar_access(m).is_ok()
    }
    pub fn usage(&self) -> (u64, u64) {
        let _gate = self.allocation_gate.lock();
        let visible = self.pool.size() - self.pool.available();
        let hidden = self
            .unmapped
            .as_ref()
            .map_or(0, |pool| pool.size() - pool.available());
        (visible + hidden, visible)
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn fixture_reserve_unmapped(
        &self,
        size: u64,
    ) -> Result<UnmappedReservation, FsError> {
        let _gate = self.allocation_gate.lock();
        self.unmapped
            .as_ref()
            .ok_or(FsError::Unsupported)?
            .reserve_aligned(size, self.page_size)
            .map_err(|_| FsError::OutOfMemory)
    }

    pub fn page_size(&self) -> u64 {
        self.page_size
    }
    pub(crate) fn requires_ccs_clear(&self) -> bool {
        self.page_size == 65536
    }

    pub fn total(&self) -> u64 {
        self.layout.usable
    }
    pub fn visible(&self) -> u64 {
        self.pool.size()
    }
    pub fn used(&self) -> u64 {
        self.usage().0
    }

    /// The CPU physical window every visible allocation's frames lie in:
    /// `[bar, bar + tile_offset + visible)`.
    pub(crate) fn cpu_window(&self) -> (u64, u64) {
        (self.bar, self.layout.tile_offset + self.visible())
    }

    /// Admit one kernel CPU access to the BAR, or `None` while the GT owner
    /// has closed it for runtime suspend.
    pub(crate) fn cpu_access(&self) -> Option<CpuAccess<'_>> {
        let mut gate = self.cpu_gate.lock();
        if gate.closed {
            return None;
        }
        gate.users += 1;
        Some(CpuAccess(self))
    }

    /// Close kernel CPU access before the function may leave D0. Refused
    /// (`false`, nothing changed) while an access is in flight.
    pub(crate) fn close_cpu_access(&self) -> bool {
        let mut gate = self.cpu_gate.lock();
        if gate.users != 0 {
            return false;
        }
        gate.closed = true;
        true
    }

    /// Reopen kernel CPU access once the function is in D0 with a running GT.
    pub(crate) fn open_cpu_access(&self) {
        self.cpu_gate.lock().closed = false;
    }

    /// Reserve `size` bytes without accessing the BAR. The returned device
    /// range is exclusive, but its prior contents are not yet initialized.
    pub fn allocate(self: &Arc<Self>, size: u64) -> Result<VramAllocation, FsError> {
        if size == 0 || size % self.page_size != 0 {
            return Err(FsError::InvalidData);
        }
        self.allocate_class(size, true)
    }
    pub(crate) fn allocate_class(
        self: &Arc<Self>,
        size: u64,
        visible: bool,
    ) -> Result<VramAllocation, FsError> {
        if size == 0 || size % self.page_size != 0 {
            return Err(FsError::InvalidData);
        }
        let _gate = self.allocation_gate.lock();
        let reservation = if !visible && size <= 128 * 1024 * 1024 {
            self.unmapped
                .as_ref()
                .and_then(|pool| pool.reserve_aligned(size, self.page_size).ok())
                .map(LocalRange::Unmapped)
        } else {
            None
        };
        let reservation = match reservation {
            Some(range) => range,
            None => LocalRange::Visible(
                self.pool
                    .reserve_aligned(size, self.page_size)
                    .map_err(|_| FsError::OutOfMemory)?,
            ),
        };
        Ok(VramAllocation {
            reservation: Some(reservation),
            vram: self.clone(),
        })
    }
}

/// An exclusively reserved VRAM range. Dropping it proves no GPU job, VM snapshot or
/// CPU mapping still references it (they all retain the owning GEM object).
#[derive(Debug)]
pub struct VramAllocation {
    reservation: Option<LocalRange>,
    vram: Arc<Vram>,
}

#[derive(Debug)]
enum LocalRange {
    Visible(Reservation),
    Unmapped(UnmappedReservation),
}

impl VramAllocation {
    pub(crate) fn smallbar_access(
        &self,
        m: &impl crate::intel_gpu_aux::MmioWindow,
    ) -> Result<(), crate::intel_gpu_gt::lnl::Error> {
        self.vram.smallbar_access(m)
    }
    pub(crate) fn pool_is(&self, pool: &Arc<Vram>) -> bool {
        Arc::ptr_eq(&self.vram, pool)
    }
    pub(crate) fn page_size(&self) -> u64 {
        self.vram.page_size()
    }
    pub(crate) fn requires_ccs_clear(&self) -> bool {
        self.vram.requires_ccs_clear()
    }
    /// See [`Vram::cpu_access`].
    pub(crate) fn cpu_access(&self) -> Option<CpuAccess<'_>> {
        self.vram.cpu_access()
    }
    fn reservation(&self) -> &LocalRange {
        self.reservation.as_ref().expect("live VRAM reservation")
    }
    /// Device physical address for PPGTT device-memory PTEs.
    pub fn device_address(&self) -> u64 {
        match self.reservation() {
            LocalRange::Visible(r) => r.address(),
            LocalRange::Unmapped(r) => r.address(),
        }
    }
    pub fn size(&self) -> u64 {
        match self.reservation() {
            LocalRange::Visible(r) => r.size(),
            LocalRange::Unmapped(r) => r.size(),
        }
    }
    /// CPU physical address through the LMEM BAR.
    pub fn cpu_address(&self) -> Option<u64> {
        match self.reservation() {
            LocalRange::Visible(_) => Some(self.vram.bar + self.device_address()),
            LocalRange::Unmapped(_) => None,
        }
    }
    /// Kernel WC alias of the allocation.
    pub(crate) fn kernel_virt(&self) -> Option<u64> {
        match self.reservation() {
            LocalRange::Visible(r) => Some(r.mapping().virt),
            LocalRange::Unmapped(_) => None,
        }
    }
}

impl Drop for VramAllocation {
    fn drop(&mut self) {
        let _gate = self.vram.allocation_gate.lock();
        let mut reservation = self.reservation.take().expect("live VRAM reservation");
        if let LocalRange::Visible(range) = &mut reservation {
            // SAFETY: the last GEM owner is gone; every native retirement or
            // verified full reset has already released its retaining graph.
            unsafe { range.stopped() };
        }
        // UnmappedReservation likewise stays owned until all GPU reaches retire.
        drop(reservation);
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn regs(tile_range: u32, lower: u32, upper: u32, fuse3: u32, gsm: u64) -> Xe2VramRegisters {
        Xe2VramRegisters {
            tile_range,
            ccs_lower: lower,
            ccs_upper: upper,
            fuse3,
            gsm_base: gsm,
        }
    }

    // A 12 GiB tile at offset 0: TILEx size field 12, offset field 0.
    fn smoke_xe2_vram_layout_vectors() -> TestResult {
        let tile = 12u32 << 8;
        let size = 12 * GIB;
        let gsm = size - 0x400_0000; // 64 MiB stolen
        let ccs = gsm - size / 512;
        // Per-node HW view with 4 enabled L3 nodes; bit 0 enables flat CCS.
        let per_node = ccs / 4;
        let lower = (per_node as u32 & !0x3f) | 1;
        let upper = (per_node >> 32) as u32;
        let layout = VramLayout::xe2(regs(tile, lower, upper, 0xf << 16, gsm)).unwrap();
        assert_eq!(
            (layout.tile_size, layout.tile_offset, layout.usable),
            (size, 0, ccs)
        );
        // Without flat CCS, usable memory ends at GSMBASE.
        let layout = VramLayout::xe2(regs(tile, 0, 0, 0, gsm)).unwrap();
        assert_eq!(layout.usable, gsm);
        // A tile offset is removed from the usable size.
        let layout = VramLayout::xe2(regs(tile | 1 << 1, 0, 0, 0, gsm + GIB)).unwrap();
        assert_eq!((layout.tile_offset, layout.usable), (GIB, gsm));
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_vram", smoke_xe2_vram_layout_vectors);

    fn smoke_xe2_vram_layout_refusals() -> TestResult {
        let tile = 12u32 << 8;
        let size = 12 * GIB;
        let gsm = size - 0x400_0000;
        // A hole between the CCS base and GSMBASE.
        assert_eq!(
            VramLayout::xe2(regs(tile, 0x1001, 0, 0xf << 16, gsm)),
            Err(VramError::Layout)
        );
        // Flat CCS with no enabled L3 node.
        assert_eq!(
            VramLayout::xe2(regs(tile, 1, 0, 0, gsm)),
            Err(VramError::Layout)
        );
        // GSMBASE below the tile offset, or beyond the tile.
        assert_eq!(
            VramLayout::xe2(regs(tile | 2 << 1, 0, 0, 0, GIB)),
            Err(VramError::Layout)
        );
        assert_eq!(
            VramLayout::xe2(regs(tile, 0, 0, 0, size + 4096)),
            Err(VramError::Layout)
        );
        assert_eq!(
            VramLayout::xe2(regs(u32::MAX, 0, 0, 0, gsm)),
            Err(VramError::Unavailable)
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_vram", smoke_xe2_vram_layout_refusals);
}
