//! Navi22 (GC 10.3.2) kernel queues: shared register layout, BAR2 doorbells,
//! VRAM-backed ring storage, and the GFX ring owner. GC 10.3.2 runs without
//! MES: the gfx ring is programmed directly (`gfx_v10_0_cp_gfx_resume`,
//! the `amdgpu_async_gfx_ring=0` path) and compute queues are mapped by the
//! KIQ (`amdgpu_kiq_navi22`). Production SDMA lives in
//! `amdgpu_sdma_navi22_queues`. Sources: Linux gfx_v10_0.c, nv.c,
//! nbio_v2_3.c, clearstate_gfx10.h, nvd.h. Only privileged VMID0 rings are
//! created; no user queues, MES, preemption, GFXOFF or clock gating.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_fence_navi22 as fence,
    amdgpu_pm4_defs::{
        packet3, PACKET3_INDIRECT_BUFFER, PACKET3_MAP_QUEUES, PACKET3_NOP, PACKET3_RELEASE_MEM,
        PACKET3_SET_BASE, PACKET3_SET_RESOURCES, PACKET3_SET_UCONFIG_REG, PACKET3_WRITE_DATA,
    },
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence as barrier, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_cp_navi22_regs.rs"]
pub(crate) mod regs;
use regs::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    DataMismatch,
}

// linux-ctx: hdr=gc101,pm4,sdma,amdgpu,nbio,hdp
/// Linux AMDGPU_NAVI10_DOORBELL_* assignments as `ring->doorbell_index`
/// (64-bit doorbell index << 1, i.e. a dword index into BAR2).
pub mod doorbell {
    pub const KIQ: u32 = 0x000 << 1; // linux: AMDGPU_NAVI10_DOORBELL_KIQ << 1
    pub const MEC_RING0: u32 = 0x003 << 1; // linux: AMDGPU_NAVI10_DOORBELL_MEC_RING0 << 1
    pub const USERQUEUE_END: u32 = 0x08a; // linux: AMDGPU_NAVI10_DOORBELL_USERQUEUE_END
    pub const GFX_RING0: u32 = 0x08b << 1; // linux: AMDGPU_NAVI10_DOORBELL_GFX_RING0 << 1
    pub const SDMA0: u32 = 0x100 << 1; // linux: AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE0 << 1
    pub const SDMA1: u32 = 0x10a << 1; // linux: AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE1 << 1
    pub const SDMA2: u32 = 0x114 << 1; // linux: AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE2 << 1
    pub const SDMA3: u32 = 0x11e << 1; // linux: AMDGPU_NAVI10_DOORBELL_sDMA_ENGINE3 << 1
    /// `adev->doorbell_index.sdma_doorbell_range` (nv.c).
    pub const SDMA_RANGE: u32 = 20; // linux: n/a (literal in nv.c:nv_init_doorbell_index)
}
/// First BAR2 page: every kernel doorbell above lies inside it.
pub const DOORBELL_BYTES: u64 = 4096; // linux: n/a (NARF mapping size, one page)

/// UC mapping of the first BAR2 page plus its bus address for the NBIF
/// self-ring aperture. The kernel doorbell block sits at BAR2 offset 0, as
/// Linux's first doorbell-domain allocation does.
#[derive(Clone, Copy, Debug)]
pub struct Doorbells {
    map: MmioRegion,
    bus: u64,
}
impl Doorbells {
    /// Map the doorbell page of BAR2. Performs only PCI BAR sizing/mapping.
    ///
    /// # Safety
    /// `device` is the Navi22 PF exclusively owned by the caller, its BAR2 is
    /// programmed and not otherwise mapped or in use, and the mapping stays
    /// permanent. Call during single-CPU boot before any doorbell is enabled.
    pub unsafe fn map_navi22(device: &narf_bus::BusDevice) -> Result<Self, Error> {
        // SAFETY: caller owns the device configuration space during boot.
        let bar = unsafe { narf_bus::read_bar(device, 2) }.map_err(|_| Error::Unsupported)?;
        let phys = bar.phys.raw();
        if matches!(bar.kind, narf_bus::BarKind::Io)
            || phys == 0
            || phys % DOORBELL_BYTES != 0
            || bar.size < DOORBELL_BYTES
        {
            return Err(Error::Unsupported);
        }
        use narf_memory::ioremap::{ioremap, MmioAttrs};
        // SAFETY: the BAR window belongs to this device; doorbells require
        // uncached device memory so each 64-bit store reaches the NBIF.
        let mapping = unsafe { ioremap(phys, DOORBELL_BYTES, MmioAttrs::Device) }
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            map: MmioRegion {
                phys: bar.phys,
                virt: mapping.va(),
                len: DOORBELL_BYTES,
                kind: bar.kind,
            },
            bus: phys,
        })
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn from_region(map: MmioRegion) -> Self {
        Self {
            bus: map.phys.raw(),
            map,
        }
    }
    /// Map a known discrete RDNA2 physical function's BAR2 doorbell page.
    ///
    /// # Safety
    /// Caller owns this PF's configuration/BAR2 exclusively during single-CPU
    /// boot and retains the mapping for the lifetime of every queue owner.
    pub unsafe fn map_rdna2(device: &narf_bus::BusDevice) -> Result<Self, Error> {
        crate::amdgpu_rdna2::for_pci_id(device.id.vendor, device.id.device)
            .ok_or(Error::Unsupported)?;
        // SAFETY: all validated discrete RDNA2 profiles use the NBIF BAR2
        // doorbell page; caller supplies its exclusive permanent mapping contract.
        unsafe { Self::map_navi22(device) }
    }
    pub fn bus_address(&self) -> u64 {
        self.bus
    }
    /// The permanent UC mapping, for owners that need 32-bit doorbells (VCN).
    pub(crate) fn region(&self) -> MmioRegion {
        self.map
    }
}

/// GC BASE_IDX 0/1, NBIO BASE_IDX 2, HDP and OSSSYS BASE_IDX 0 bank byte
/// offsets in BAR5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub profile: &'static crate::amdgpu_rdna2::Profile,
    pub gc: [u64; 2],
    /// GC segment 2 for SDMA2/3, resolved only by the family queue owner.
    pub sdma_high: Option<u64>,
    pub nbio: u64,
    pub hdp: u64,
    /// OSSSYS 5.0.3 segment 0: the IH VMID LUT a client job's flush writes.
    pub oss: u64,
}
impl Layout {
    pub(crate) fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI22 {
            return Err(Error::Unsupported);
        }
        Self::resolve_for(gpu, &crate::amdgpu_rdna2::NAVI22, &[(5, 0, 3)])
    }
    pub(crate) fn resolve_rdna2(gpu: &AmdGpu) -> Result<Self, Error> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        Self::resolve_for(gpu, profile, &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3)])
    }
    fn resolve_for(
        gpu: &AmdGpu,
        profile: &'static crate::amdgpu_rdna2::Profile,
        oss_versions: &[(u8, u8, u8)],
    ) -> Result<Self, Error> {
        if gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        let reg = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        crate::amdgpu_psp_ring::bank(gpu, ip::HW_ID_SDMA0, &[profile.sdma_version], 0, 0)
            .map_err(|_| Error::Unsupported)?;
        let layout = Self {
            profile,
            sdma_high: None,
            gc: [
                reg(ip::HW_ID_GC, &[profile.gc_version], 0, LAST_GC0)?,
                reg(ip::HW_ID_GC, &[profile.gc_version], 1, LAST_GC1)?,
            ],
            nbio: reg(
                ip::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                2,
                LAST_NBIO,
            )?,
            hdp: reg(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                0xd1, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
            )?,
            oss: reg(
                ip::HW_ID_OSSSYS,
                oss_versions,
                0,
                crate::amdgpu_navi22_submit::IH_VMID_LUT_LAST,
            )?,
        };
        let golden =
            crate::amdgpu_rdna2::golden::for_gc(profile.gc_version).ok_or(Error::Unsupported)?;
        for row in golden {
            // Bound every row as well as the common queue register windows.
            reg(
                ip::HW_ID_GC,
                &[profile.gc_version],
                usize::from(row.base_index),
                row.offset,
            )?;
        }
        // SET_UCONFIG_REG and the CSB context index are encoded relative to
        // fixed apertures; reject bases that would alias other registers.
        if layout.dword(SCRATCH_REG0) < 0xc000 // linux-lit: 0xc000=PACKET3_SET_UCONFIG_REG_START
            || crate::amdgpu_clearstate_gfx10::csb(layout.segment(1), 0).is_none()
            // linux-lit: 0xffff=GRBM_CAM_DATA__CAM_ADDR_MASK
            || layout.dword(CAM_REMAP[0].0) > 0xffff
            // linux-lit: 0xffff=GRBM_CAM_DATA__CAM_ADDR_MASK
            || layout.dword(CAM_REMAP[6].1) > 0xffff
        {
            return Err(Error::Unsupported);
        }
        Ok(layout)
    }
    /// BAR5 byte address of a GC register.
    pub(crate) fn reg(&self, r: Reg) -> u64 {
        self.gc[r.0 as usize] + u64::from(r.1) * 4
    }
    /// SOC15 absolute dword offset (`SOC15_REG_OFFSET`).
    pub(crate) fn dword(&self, r: Reg) -> u32 {
        (self.reg(r) / 4) as u32
    }
    pub(crate) fn segment(&self, index: usize) -> u32 {
        (self.gc[index] / 4) as u32
    }
    /// SOC15 absolute dword offset of an OSSSYS BASE_IDX 0 register.
    pub(crate) fn oss(&self, offset: u32) -> u32 {
        (self.oss / 4) as u32 + offset
    }
    /// `sdma_v5_2_get_reg_offset` for instances 0/1 (non-HYP registers).
    pub(crate) fn sdma(&self, instance: u32, r: Reg) -> u64 {
        match instance {
            0 | 1 => self.reg(r) + u64::from(instance * SDMA1_REG_OFFSET) * 4,
            2 | 3 => {
                self.sdma_high
                    .expect("SDMA2/3 bank validated before allocation")
                    + u64::from(r.1 + (instance - 2) * SDMA3_REG_OFFSET) * 4
            }
            _ => unreachable!("validated SDMA instance"),
        }
    }
    pub(crate) fn nbio(&self, reg: u32) -> u64 {
        self.nbio + u64::from(reg) * 4
    }
}

pub(crate) trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// 64-bit store to BAR2 dword `index` (`WDOORBELL64`).
    fn doorbell(&mut self, index: u32, value: u64);
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
pub(crate) struct Mmio {
    regs: MmioRegion,
    doorbells: MmioRegion,
}
impl Mmio {
    pub(crate) fn new(gpu: &AmdGpu, doorbells: Doorbells) -> Self {
        Self {
            regs: gpu.regs,
            doorbells: doorbells.map,
        }
    }
}
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds every GC/NBIO/HDP bank inside BAR5 and the
        // exclusive owner only calls this inside live PCI authority.
        unsafe { self.regs.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded exclusive register mapping and authority.
        unsafe { self.regs.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: offsets are bounded by the owner's permanent reservation.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained reservation and dword-aligned bounded offset.
        unsafe { map.write32(offset, value) };
    }
    fn doorbell(&mut self, index: u32, value: u64) {
        let offset = u64::from(index) * 4;
        if offset + 8 <= self.doorbells.len {
            barrier(Ordering::SeqCst);
            // SAFETY: bounded inside the permanent UC doorbell page.
            unsafe { narf_arch::mmio::write64(self.doorbells.virt + offset, value) };
            barrier(Ordering::SeqCst);
        }
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
pub(crate) fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
pub(crate) async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
/// Ring test / register poll bound (`adev->usec_timeout`, 100 ms).
pub(crate) const REG_TIMEOUT_MS: u64 = 100; // linux: AMDGPU_MAX_USEC_TIMEOUT / 1000
/// IB test fence bound (`AMDGPU_IB_TEST_TIMEOUT`, 1 s).
// linux: n/a (AMDGPU_IB_TEST_TIMEOUT msecs_to_jiffies(1000), amdgpu_ib.c)
pub(crate) const FENCE_TIMEOUT_MS: u64 = 1000;

/// Live PCI authority plus register access shared by every queue owner.
#[derive(Debug)]
pub(crate) struct Hw<I: Io> {
    pub io: I,
    pub authority: Cap<BusDeviceCap, Write>,
    pub layout: Layout,
}
impl<I: Io> Hw<I> {
    pub(crate) fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (io, layout) = (&mut self.io, self.layout);
        self.authority
            .invoke(Op(|| f(io, layout)))
            .map_err(|_| Error::Revoked)?
    }
    /// Bounded sample loop; `engine` selects the fence hook slot.
    pub(crate) async fn poll<T>(
        &mut self,
        engine: fence::Engine,
        timeout_ms: u64,
        mut f: impl FnMut(&mut I, Layout) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let deadline = narf_time::Deadline::after_ms(timeout_ms);
        #[cfg(feature = "kernel-test")]
        let poll_limit = self.io.wait_poll_limit();
        #[cfg(not(feature = "kernel-test"))]
        let poll_limit = None;
        fence::wait(engine, deadline, Error::Timeout, poll_limit, || {
            self.access(|io, l| f(io, l))
        })
        .await
    }
}
pub(crate) fn update<I: Io>(io: &mut I, address: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | (value & mask));
    Ok(())
}
/// CPU writes to VRAM through BAR0 must leave the HDP write cache before an
/// engine fetches them (`amdgpu_device_flush_hdp`).
pub(crate) fn flush<I: Io>(io: &mut I, l: Layout) {
    barrier(Ordering::SeqCst);
    // linux: n/a (nbio_v2_3.c MMIO_REG_HOLE_OFFSET 0x80000 - PAGE_SIZE + KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL 0)
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4); // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
    barrier(Ordering::SeqCst);
}
/// HDP read-cache invalidate before the CPU samples engine writes.
pub(crate) fn invalidate<I: Io>(io: &mut I, l: Layout) {
    io.write(l.hdp + 0xd1 * 4, 1); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    io.read(l.hdp + 0xd1 * 4); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    barrier(Ordering::SeqCst);
}
/// `nv_grbm_select(me, pipe, queue, vmid)`.
pub(crate) fn grbm_select<I: Io>(io: &mut I, l: Layout, me: u32, pipe: u32, queue: u32, vmid: u32) {
    io.write(
        l.reg(GRBM_GFX_CNTL),
        // linux-lit: 3=GRBM_GFX_CNTL__PIPEID_MASK; 2=GRBM_GFX_CNTL__MEID__SHIFT; 4=GRBM_GFX_CNTL__VMID__SHIFT
        // linux-lit: 0xf=GRBM_GFX_CNTL__VMID_MASK >> 4; 7=GRBM_GFX_CNTL__QUEUEID_MASK >> 8; 8=GRBM_GFX_CNTL__QUEUEID__SHIFT
        (pipe & 3) | ((me & 3) << 2) | ((vmid & 0xf) << 4) | ((queue & 7) << 8),
    );
}

/// PM4 / SDMA packet encoders shared by the owners and their models.
pub(crate) mod pm4 {
    use super::*;
    pub(crate) const UCONFIG_START: u32 = 0xc000; // linux: PACKET3_SET_UCONFIG_REG_START
    /// `PACKET3(PACKET3_NOP, 0x3FFF)`: the CP's one-dword NOP.
    // linux-lit: 0xc0000000=PACKET3(0, 0)
    pub(crate) const NOP: u32 = 0xc000_0000 | (0x3fff << 16) | (PACKET3_NOP << 8);
    pub(crate) fn set_uconfig(dword: u32, value: u32) -> [u32; 3] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx_v10_0_ring_test_ring)
            packet3(PACKET3_SET_UCONFIG_REG, 1),
            dword - UCONFIG_START,
            value,
        ]
    }
    /// WRITE_DATA, DST_SEL(5) memory, WR_CONFIRM, ENGINE_SEL(0).
    pub(crate) fn write_data(address: u64, value: u32) -> [u32; 5] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx_v10_0_ring_test_ib)
            packet3(PACKET3_WRITE_DATA, 3),
            (5 << 8) | (1 << 20), // linux: WRITE_DATA_DST_SEL(5) | WR_CONFIRM
            address as u32,
            (address >> 32) as u32,
            value,
        ]
    }
    /// `gfx_v10_0_ring_emit_ib_gfx` (VMID0, no CE/preemption) and
    /// `_compute` (adds INDIRECT_BUFFER_VALID).
    pub(crate) fn indirect_buffer(address: u64, dwords: u32, compute: bool) -> [u32; 4] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx_v10_0_ring_emit_ib_*)
            packet3(PACKET3_INDIRECT_BUFFER, 2),
            address as u32 & !3, // linux: n/a (dword alignment, BUG_ON in gfx_v10_0_ring_emit_ib_*)
            (address >> 32) as u32,
            // linux-lit: 23=23 * (INDIRECT_BUFFER_VALID >> 23)
            dwords | if compute { 1 << 23 } else { 0 },
        ]
    }
    /// `gfx_v10_0_ring_emit_fence`, 32-bit data with an EOP interrupt request
    /// (delivered only once IH enables the CP timestamp interrupt).
    pub(crate) fn release_mem(address: u64, seq: u32) -> [u32; 8] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx_v10_0_ring_emit_fence)
            packet3(PACKET3_RELEASE_MEM, 6),
            // 0x14 = CACHE_FLUSH_AND_INV_TS_EVENT (navi10_enum.h, not a checker header set)
            // linux: PACKET3_RELEASE_MEM_GCR_SEQ | PACKET3_RELEASE_MEM_GCR_GL2_WB | PACKET3_RELEASE_MEM_GCR_GLM_INV | PACKET3_RELEASE_MEM_GCR_GLM_WB | PACKET3_RELEASE_MEM_CACHE_POLICY(3) | PACKET3_RELEASE_MEM_EVENT_TYPE(0x14) | PACKET3_RELEASE_MEM_EVENT_INDEX(5)
            (1 << 22) | (1 << 21) | (1 << 13) | (1 << 12) | (3 << 25) | 0x14 | (5 << 8),
            // linux: PACKET3_RELEASE_MEM_DATA_SEL(1) | PACKET3_RELEASE_MEM_INT_SEL(2)
            (1 << 29) | (2 << 24),
            address as u32,
            (address >> 32) as u32,
            seq,
            0,
            0,
        ]
    }
    /// `PACKET3(SET_BASE, 2)` CE partition base from `gfx_v10_0_cp_gfx_start`.
    pub(crate) fn ce_partition_base() -> [u32; 4] {
        // linux-lit: 3=PACKET3_BASE_INDEX(CE_PARTITION_BASE)
        // linux: n/a (count 2 and 0x8000 literals in gfx_v10_0_cp_gfx_start)
        [packet3(PACKET3_SET_BASE, 2), 3, 0x8000, 0x8000]
    }
    /// `gfx10_kiq_set_resources`; no cleaner shader is installed (address 0).
    pub(crate) fn set_resources(queue_mask: u64) -> [u32; 8] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx10_kiq_set_resources)
            packet3(PACKET3_SET_RESOURCES, 6),
            0, // linux: PACKET3_SET_RESOURCES_VMID_MASK(0) | PACKET3_SET_RESOURCES_QUEUE_TYPE(0)
            queue_mask as u32,
            (queue_mask >> 32) as u32,
            0, // linux: n/a (cleaner shader address lo; none installed)
            0, // linux: n/a (cleaner shader address hi; none installed)
            0, // linux: n/a (oac mask literal 0 in gfx10_kiq_set_resources)
            0, // linux: n/a (gds heap literal 0 in gfx10_kiq_set_resources)
        ]
    }
    /// `gfx10_kiq_map_queues` for a compute queue (ENGINE_SEL 0).
    pub(crate) fn map_queues(
        me: u32,
        pipe: u32,
        queue: u32,
        doorbell: u32,
        mqd: u64,
        wptr: u64,
    ) -> [u32; 7] {
        [
            // linux: n/a (count literal in gfx_v10_0.c:gfx10_kiq_map_queues)
            packet3(PACKET3_MAP_QUEUES, 5),
            // linux-lit: 13=13 * (PACKET3_MAP_QUEUES_QUEUE(1) >> 13); 16=16 * (PACKET3_MAP_QUEUES_PIPE(1) >> 16)
            // linux-lit: 18=18 * (PACKET3_MAP_QUEUES_ME(1) >> 18); 29=29 * (PACKET3_MAP_QUEUES_NUM_QUEUES(1) >> 29)
            (queue << 13) | (pipe << 16) | (u32::from(me != 1) << 18) | (1 << 29),
            doorbell << 2, // linux-lit: 2=2 * (PACKET3_MAP_QUEUES_DOORBELL_OFFSET(1) >> 2)
            mqd as u32,
            (mqd >> 32) as u32,
            wptr as u32,
            (wptr >> 32) as u32,
        ]
    }
    pub(crate) const SDMA_NOP: u32 = 0; // linux: SDMA_PKT_NOP_HEADER_OP(SDMA_OP_NOP)
    /// SDMA_OP_WRITE / SUBOP_WRITE_LINEAR of one dword.
    pub(crate) fn sdma_write(address: u64, value: u32) -> [u32; 5] {
        // linux-lit: 2=SDMA_PKT_HEADER_OP(SDMA_OP_WRITE) | SDMA_PKT_HEADER_SUB_OP(SDMA_SUBOP_WRITE_LINEAR)
        // linux-lit: 0=SDMA_PKT_WRITE_UNTILED_DW_3_COUNT(0)
        [2, address as u32, (address >> 32) as u32, 0, value]
    }
    /// SDMA_OP_FENCE, MTYPE UC, then SDMA_OP_TRAP (`sdma_v5_2_ring_emit_fence`).
    pub(crate) fn sdma_fence(address: u64, seq: u32) -> [u32; 6] {
        [
            // linux: SDMA_PKT_HEADER_OP(SDMA_OP_FENCE) | SDMA_PKT_FENCE_HEADER_MTYPE(0x3)
            5 | (3 << 16),
            address as u32,
            (address >> 32) as u32,
            seq,
            6, // linux: SDMA_PKT_HEADER_OP(SDMA_OP_TRAP)
            0, // linux: SDMA_PKT_TRAP_INT_CONTEXT_INT_CONTEXT(0)
        ]
    }
    /// SDMA_OP_INDIRECT, VMID0, no CSA (`sdma_v5_2_ring_emit_ib`).
    pub(crate) fn sdma_indirect(address: u64, dwords: u32) -> [u32; 6] {
        [
            4, // linux: SDMA_PKT_HEADER_OP(SDMA_OP_INDIRECT) | SDMA_PKT_INDIRECT_HEADER_VMID(0)
            address as u32 & !0x1f, // linux: n/a (literal 0xffffffe0 in sdma_v5_2_ring_emit_ib)
            (address >> 32) as u32,
            dwords,
            0, // linux: n/a (CSA address lo; no CSA, VMID0)
            0, // linux: n/a (CSA address hi; no CSA, VMID0)
        ]
    }
}

/// One kernel queue's VRAM: ring, writeback, IB, MQD/CSB and EOP pages.
pub(crate) const RING_BYTES: u64 = 8192; // linux: n/a (NARF queue layout)
pub(crate) const RING_DW: u64 = RING_BYTES / 4;
pub(crate) const WB: u64 = 8192; // linux: n/a (NARF queue layout)
pub(crate) const RPTR: u64 = WB;
pub(crate) const WPTR: u64 = WB + 8;
pub(crate) const FENCE: u64 = WB + 16;
pub(crate) const SCRATCH: u64 = WB + 24;
pub(crate) const VM_FENCE: u64 = WB + 32;
pub(crate) const IB: u64 = 12288; // linux: n/a (NARF queue layout)
pub(crate) const MQD: u64 = 16384; // linux: n/a (NARF queue layout)
pub(crate) const EOP: u64 = 20480; // linux: n/a (NARF queue layout)
pub(crate) const QUEUE_BYTES: u64 = 24576; // linux: n/a (NARF queue layout)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// PM4: dword pointers, 256-dword fetch alignment.
    Cp,
    /// SDMA: byte pointers, 16-dword alignment.
    Sdma,
}
#[derive(Debug)]
pub(crate) struct Queue {
    pub memory: Reservation,
    pub kind: Kind,
    pub doorbell: u32,
    pub engine: fence::Engine,
    /// Monotonic dword write pointer (`ring->wptr`).
    pub wptr: u64,
    pub seq: u32,
}
impl Queue {
    pub(crate) fn new(
        pool: &Pool,
        kind: Kind,
        doorbell: u32,
        engine: fence::Engine,
    ) -> Result<Self, Error> {
        Ok(Self {
            memory: pool.reserve(QUEUE_BYTES).map_err(|_| Error::Allocation)?,
            kind,
            doorbell,
            engine,
            wptr: 0,
            seq: 0,
        })
    }
    pub(crate) fn address(&self, offset: u64) -> u64 {
        self.memory.address() + offset
    }
    pub(crate) fn map(&self) -> MmioRegion {
        self.memory.mapping()
    }
    /// Zero all storage; scratch starts at Linux's 0xCAFEDEAD sentinel.
    pub(crate) fn clear<I: Io>(&mut self, io: &mut I) {
        let map = self.map();
        for offset in (0..QUEUE_BYTES).step_by(4) {
            io.write_memory(map, offset, 0);
        }
        // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ib)
        io.write_memory(map, SCRATCH, 0xcafe_dead);
        self.wptr = 0;
    }
    pub(crate) fn write<I: Io>(&self, io: &mut I, offset: u64, words: &[u32]) {
        let map = self.map();
        for (i, &word) in words.iter().enumerate() {
            io.write_memory(map, offset + i as u64 * 4, word);
        }
    }
    fn align(&self) -> u64 {
        match self.kind {
            Kind::Cp => 256,  // linux: n/a (.align_mask 0xff in gfx_v10_0.c ring funcs)
            Kind::Sdma => 16, // linux: n/a (.align_mask 0xf in sdma_v5_2.c ring funcs)
        }
    }
    /// Append dwords. Callers submit only to an idle ring, so one submission
    /// (including commit padding) must fit without overtaking the CP.
    pub(crate) fn emit<I: Io>(&mut self, io: &mut I, words: &[u32]) -> Result<(), Error> {
        if words.len() as u64 + self.align() > RING_DW {
            return Err(Error::Invalid);
        }
        let map = self.map();
        for &word in words {
            io.write_memory(map, (self.wptr % RING_DW) * 4, word);
            self.wptr += 1;
        }
        Ok(())
    }
    /// `amdgpu_ring_commit` padding: `gfx_v10_ring_insert_nop` or SDMA NOPs.
    fn pad<I: Io>(&mut self, io: &mut I) {
        let mask = self.align() - 1;
        let count = (self.align() - (self.wptr & mask)) & mask;
        let map = self.map();
        let mut put = |q: &mut Self, word| {
            io.write_memory(map, (q.wptr % RING_DW) * 4, word);
            q.wptr += 1;
        };
        match (self.kind, count) {
            (_, 0) => {}
            (Kind::Cp, 1) => put(self, pm4::NOP),
            (Kind::Cp, n) => {
                // linux: n/a (literal in gfx_v10_0.c:gfx_v10_ring_insert_nop)
                put(self, packet3(PACKET3_NOP, (n as u32 - 2).min(0x3ffe)));
                for _ in 1..n {
                    put(self, pm4::NOP);
                }
            }
            (Kind::Sdma, n) => {
                for _ in 0..n {
                    put(self, pm4::SDMA_NOP);
                }
            }
        }
    }
    /// Value the engine expects in its wptr writeback and doorbell.
    pub(crate) fn hw_wptr(&self) -> u64 {
        match self.kind {
            Kind::Cp => self.wptr,
            // linux: n/a (literal in sdma_v5_2.c:sdma_v5_2_ring_set_wptr)
            Kind::Sdma => self.wptr << 2,
        }
    }
    /// Pad, publish the shadow wptr, flush HDP and ring the doorbell
    /// (`gfx_v10_0_ring_set_wptr_*`, `sdma_v5_2_ring_set_wptr`).
    pub(crate) fn commit<I: Io>(&mut self, io: &mut I, l: Layout) {
        self.pad(io);
        let wptr = self.hw_wptr();
        self.write(io, WPTR, &[wptr as u32, (wptr >> 32) as u32]);
        flush(io, l);
        io.doorbell(self.doorbell, wptr);
    }
    /// Read engine-written writeback after an HDP read invalidate.
    pub(crate) fn read<I: Io>(&self, io: &mut I, l: Layout, offset: u64) -> u32 {
        invalidate(io, l);
        io.read_memory(self.map(), offset)
    }
    pub(crate) fn next_seq(&mut self) -> u32 {
        // Zero is the initial writeback and the VMID manager's "no job".
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }
}

/// TDR sample: the last emitted sequence and the fence writeback, read after
/// an HDP invalidate. An all-ones invalidate read-back means device loss.
pub(crate) fn progress<I: Io>(
    hw: &mut Hw<I>,
    queue: &Queue,
) -> Result<crate::amdgpu_navi22_tdr::Progress, Error> {
    hw.access(|io, l| {
        let signaled = queue.read(io, l, FENCE);
        checked(io.read(l.hdp + 0xd1 * 4))?; // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
        Ok(crate::amdgpu_navi22_tdr::Progress {
            engine: queue.engine,
            emitted: queue.seq,
            signaled,
        })
    })
}
/// Wait for the engine to write `seq` into the queue's fence slot.
pub(crate) async fn wait_fence<I: Io>(
    hw: &mut Hw<I>,
    queue: &Queue,
    seq: u32,
) -> Result<(), Error> {
    hw.poll(queue.engine, FENCE_TIMEOUT_MS, |io, l| {
        let value = queue.read(io, l, FENCE);
        Ok(fence::signaled(value, seq).then_some(()))
    })
    .await
}
/// `gfx_v10_0_ring_test_ring`: SCRATCH_REG0 0xCAFEDEAD -> SET_UCONFIG_REG
/// 0xDEADBEEF, polled through MMIO for at most `adev->usec_timeout`.
pub(crate) async fn ring_test<I: Io>(hw: &mut Hw<I>, queue: &mut Queue) -> Result<(), Error> {
    hw.access(|io, l| {
        // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ring)
        io.write(l.reg(SCRATCH_REG0), 0xcafe_dead);
        // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ring)
        queue.emit(io, &pm4::set_uconfig(l.dword(SCRATCH_REG0), 0xdead_beef))?;
        queue.commit(io, l);
        Ok(())
    })?;
    hw.poll(queue.engine, REG_TIMEOUT_MS, |io, l| {
        // linux: n/a (literal in gfx_v10_0_ring_test_ring)
        Ok((checked(io.read(l.reg(SCRATCH_REG0)))? == 0xdead_beef).then_some(()))
    })
    .await
}
/// `gfx_v10_0_ring_test_ib`: an IB writes 0xDEADBEEF to writeback memory,
/// then the ring fence must signal before the value is checked.
pub(crate) async fn ib_test<I: Io>(hw: &mut Hw<I>, queue: &mut Queue) -> Result<u32, Error> {
    let compute = queue.engine != fence::Engine::Gfx;
    let seq = queue.next_seq();
    hw.access(|io, l| {
        // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ib)
        queue.write(io, SCRATCH, &[0xcafe_dead]);
        queue.write(
            io,
            IB,
            // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ib)
            &pm4::write_data(queue.address(SCRATCH), 0xdead_beef),
        );
        // linux: n/a (ib.length_dw literal in gfx_v10_0_ring_test_ib)
        queue.emit(io, &pm4::indirect_buffer(queue.address(IB), 5, compute))?;
        queue.emit(io, &pm4::release_mem(queue.address(FENCE), seq))?;
        queue.commit(io, l);
        Ok(())
    })?;
    wait_fence(hw, queue, seq).await?;
    hw.access(|io, l| match queue.read(io, l, SCRATCH) {
        0xdead_beef => Ok(seq), // linux: n/a (literal in gfx_v10_0.c:gfx_v10_0_ring_test_ib)
        _ => Err(Error::DataMismatch),
    })
}

/// Lock-free reader of the kernel queues' fence writeback (gfx, compute,
/// SDMA0, SDMA1), for client job completion without the boot owner. Each
/// sample invalidates the HDP read cache first, as `Queue::read` does; both
/// operations are idempotent and safe concurrently with the owner's MMIO.
#[derive(Clone, Copy, Debug)]
pub struct FenceReader {
    regs: MmioRegion,
    hdp_invalidate: u64,
    slots: [Option<MmioRegion>; 6],
    authority: Cap<BusDeviceCap, Write>,
}
impl FenceReader {
    pub(crate) fn present(&self, ring: usize) -> bool {
        self.slots.get(ring).is_some_and(Option::is_some)
    }
    /// The last sequence ring `ring` (0 gfx, 1 compute, 2/3 SDMA) wrote.
    pub fn completed(&self, ring: usize) -> Result<u32, Error> {
        self.completed_at(ring, FENCE)
    }
    pub(crate) fn vm_completed(&self, ring: usize) -> Result<u32, Error> {
        self.completed_at(ring, VM_FENCE)
    }
    fn completed_at(&self, ring: usize, offset: u64) -> Result<u32, Error> {
        let slot = self
            .slots
            .get(ring)
            .copied()
            .flatten()
            .ok_or(Error::Invalid)?;
        let (regs, hdp) = (self.regs, self.hdp_invalidate);
        self.authority
            .invoke(Op(|| {
                // SAFETY: the HDP invalidate register lies in the BAR5 bank
                // Layout bounded; the slot is the queue's permanent, published
                // writeback reservation, whose FENCE dword is in bounds.
                unsafe {
                    regs.write32(hdp, 1);
                    checked(regs.read32(hdp))?;
                    barrier(Ordering::SeqCst);
                    // All 32 bits of a fence value, including all-ones,
                    // are valid. Detect loss from the HDP register instead.
                    Ok(slot.read32(offset))
                }
            }))
            .map_err(|_| Error::Revoked)?
    }
}
impl Gfx {
    pub(crate) fn fence_map(&self) -> MmioRegion {
        self.engine.queue.map()
    }
    /// A [`FenceReader`] over this owner's registers and `slots`.
    pub(crate) fn fence_reader(&self, slots: [Option<MmioRegion>; 6]) -> FenceReader {
        FenceReader {
            regs: self.engine.hw.io.regs,
            hdp_invalidate: self.engine.hw.layout.hdp + 0xd1 * 4,
            slots,
            authority: self.engine.hw.authority,
        }
    }
}

/// Evidence from every Navi22 kernel queue after the cold-boot IB tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueProof {
    pub gfx: GfxProof,
    pub compute: crate::amdgpu_kiq_navi22::Proof,
    pub sdma: crate::amdgpu_sdma_navi22_queues::Proof,
}

/// NBIF doorbell aperture (`nv_common_hw_init`) and self-ring aperture
/// (`nv_common_late_init`), nbio_v2_3.c. Idempotent.
pub(crate) fn enable_doorbells<I: Io>(io: &mut I, l: Layout, bus: u64) -> Result<(), Error> {
    // linux-lit: 1=RCC_DEV0_EPF0_RCC_DOORBELL_APER_EN__BIF_DOORBELL_APER_EN_MASK
    update(io, l.nbio(NBIO_DOORBELL_APER_EN), 1, 1)?;
    io.write(l.nbio(NBIO_SELFRING_BASE_LOW), bus as u32);
    io.write(l.nbio(NBIO_SELFRING_BASE_HIGH), (bus >> 32) as u32);
    // linux-lit: 0b11=BIF_BX_PF_DOORBELL_SELFRING_GPA_APER_CNTL__DOORBELL_SELFRING_GPA_APER_EN_MASK | BIF_BX_PF_DOORBELL_SELFRING_GPA_APER_CNTL__DOORBELL_SELFRING_GPA_APER_MODE_MASK
    io.write(l.nbio(NBIO_SELFRING_CNTL), 0b11);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GfxState {
    Prepared,
    Configuring,
    Configured,
    Starting,
    Running,
    Testing,
    Verified,
    Failed,
}
/// Evidence from the GFX ring owner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GfxProof {
    /// GRBM CAM remapping was already present (`check_grbm_cam_remapping`).
    pub cam_remapped: bool,
    /// The RLC CSIB and gfx ring both received this many CSB dwords.
    pub csb_dwords: u32,
    /// Ring test passed via SCRATCH_REG0.
    pub ring: bool,
    /// Last IB-test fence sequence.
    pub ib_fence: u32,
}
/// gfx ring 0 (ME0 pipe 0), 8 KiB: RB_BUFSZ = order_base_2(8192 / 8).
const RB_BUFSZ: u32 = 10; // linux: n/a (order_base_2(NARF 8 KiB ring / 8))
                          // linux: (0 << SH_MEM_CONFIG__ADDRESS_MODE__SHIFT) | (3 << SH_MEM_CONFIG__ALIGNMENT_MODE__SHIFT) | (0 << SH_MEM_CONFIG__RETRY_MODE__SHIFT) | (3 << SH_MEM_CONFIG__INITIAL_INST_PREFETCH__SHIFT)
const SH_MEM_CONFIG_DEFAULT: u32 = (3 << 2) | (3 << 14); // 64-bit, unaligned, retry all
const FIRST_KFD_VMID: u32 = 8; // linux: n/a (literal in gmc_v10_0.c:gmc_v10_0_sw_init)

#[derive(Debug)]
pub(crate) struct GfxEngine<I: Io> {
    pub hw: Hw<I>,
    pub queue: Queue,
    pub state: GfxState,
    pub proof: GfxProof,
    /// The ASIC's golden sequence already applied (`golden`), so `configure`
    /// does not rewrite them after other engines started.
    pub golden: bool,
}
fn program_golden<I: Io>(io: &mut I, l: Layout) -> Result<(), Error> {
    let rows =
        crate::amdgpu_rdna2::golden::for_gc(l.profile.gc_version).ok_or(Error::Unsupported)?;
    for row in rows {
        let (reg, and, or) = (Reg(row.base_index, row.offset), row.and_mask, row.or_mask);
        // soc15_program_register_sequence
        if and == u32::MAX {
            // linux: n/a (soc15_program_register_sequence full-mask test)
            io.write(l.reg(reg), or);
        } else {
            update(io, l.reg(reg), and, or)?;
        }
    }
    Ok(())
}
impl<I: Io> GfxEngine<I> {
    /// The state is stored outside the future: cancellation leaves `busy`
    /// and blocks every later step, so no sequence is ever replayed.
    fn begin(&mut self, from: GfxState, busy: GfxState) -> Result<(), Error> {
        if self.state != from {
            return Err(Error::Busy);
        }
        self.state = busy;
        Ok(())
    }
    fn finish(&mut self, result: Result<(), Error>, done: GfxState) -> Result<(), Error> {
        self.state = if result.is_ok() {
            done
        } else {
            GfxState::Failed
        };
        result
    }
    /// gfx_v10_0_init_golden_registers, the first step of gfx_v10_0_hw_init,
    /// which Linux runs before SDMA's hw_init. Once, before `configure`.
    pub(crate) fn golden(&mut self) -> Result<(), Error> {
        if self.state != GfxState::Prepared || self.golden {
            return Err(Error::Busy);
        }
        let result = self.hw.access(|io, l| {
            checked(io.read(l.reg(GRBM_CNTL)))?;
            program_golden(io, l)
        });
        // Even a partial sequence must not be replayed by `configure`.
        self.golden = true;
        if result.is_err() {
            self.state = GfxState::Failed;
        }
        result
    }
    /// golden registers (unless `golden` ran), GRBM CAM, constants_init,
    /// rlc_resume (PSP autoload) and the gui-idle interrupt mask from
    /// `gfx_v10_0_cp_resume`.
    pub(crate) async fn configure(&mut self) -> Result<(), Error> {
        self.begin(GfxState::Prepared, GfxState::Configuring)?;
        let result = self.configure_inner().await;
        self.finish(result, GfxState::Configured)
    }
    async fn configure_inner(&mut self) -> Result<(), Error> {
        let csb = crate::amdgpu_clearstate_gfx10::csb(self.hw.layout.segment(1), 0)
            .ok_or(Error::Unsupported)?;
        let queue = &mut self.queue;
        self.hw.access(|io, l| {
            checked(io.read(l.reg(GRBM_CNTL)))?;
            queue.clear(io);
            queue.write(io, MQD, &csb);
            flush(io, l);
            Ok(())
        })?;
        // Published before the RLC can learn the CSIB address.
        self.queue.memory.publish();
        let golden = !self.golden;
        self.golden = true;
        let cam = self.hw.access(|io, l| {
            if golden {
                program_golden(io, l)?;
            }
            // gfx_v10_0_check_grbm_cam_remapping
            let data = checked(io.read(l.reg(VGT_ESGS_RING_SIZE)))?;
            io.write(l.reg(VGT_ESGS_RING_SIZE), 0);
            // linux: n/a (pattern literal in gfx_v10_0_check_grbm_cam_remapping)
            io.write(l.reg(VGT_ESGS_RING_SIZE_UMD), 0xdead_beef);
            // linux: n/a (pattern literal in gfx_v10_0_check_grbm_cam_remapping)
            let remapped = io.read(l.reg(VGT_ESGS_RING_SIZE)) == 0xdead_beef;
            if remapped {
                io.write(l.reg(VGT_ESGS_RING_SIZE_UMD), data);
            } else {
                io.write(l.reg(VGT_ESGS_RING_SIZE), data);
                // gfx_v10_0_setup_grbm_cam_remapping, auto-incrementing index
                io.write(l.reg(GRBM_CAM_INDEX), 0);
                for (umd, target) in CAM_REMAP {
                    io.write(l.reg(GRBM_CAM_DATA_UPPER), 0);
                    // linux-lit: 16=GRBM_CAM_DATA__CAM_REMAPADDR__SHIFT
                    io.write(l.reg(GRBM_CAM_DATA), l.dword(umd) | (l.dword(target) << 16));
                }
            }
            // gfx_v10_0_constants_init. setup_rb/get_cu_info only read and
            // end in SE/SA/instance broadcast; tile steering is 0 on GC 10.3.
            // linux-lit: 0xff=GRBM_CNTL__READ_TIMEOUT_MASK
            update(io, l.reg(GRBM_CNTL), 0xff, 0xff)?;
            // linux-lit: 0xe0000000=GRBM_GFX_INDEX__SA_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__INSTANCE_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__SE_BROADCAST_WRITES_MASK
            io.write(l.reg(GRBM_GFX_INDEX), 0xe000_0000);
            for vmid in 0..16 {
                // linux: n/a (AMDGPU_NUM_VMID 16, amdgpu_ids.h not in checker sets)
                grbm_select(io, l, 0, 0, 0, vmid);
                io.write(l.reg(SH_MEM_CONFIG), SH_MEM_CONFIG_DEFAULT);
                if vmid != 0 {
                    // private 0x1000.., shared 0x2000.. (gmc_v10_0 apertures)
                    // linux-lit: 0x20001000=(0x2000000000000000 >> 48 << SH_MEM_BASES__SHARED_BASE__SHIFT) | (0x1000000000000000 >> 48 << SH_MEM_BASES__PRIVATE_BASE__SHIFT)
                    io.write(l.reg(SH_MEM_BASES), 0x2000_1000);
                }
            }
            grbm_select(io, l, 0, 0, 0, 0);
            // gfx_v10_0_init_compute_vmid
            for vmid in FIRST_KFD_VMID..16 {
                grbm_select(io, l, 0, 0, 0, vmid);
                io.write(l.reg(SH_MEM_CONFIG), SH_MEM_CONFIG_DEFAULT);
                // linux-lit: 0x60006000=DEFAULT_SH_MEM_BASES | (DEFAULT_SH_MEM_BASES << 16)
                io.write(l.reg(SH_MEM_BASES), 0x6000_6000);
            }
            grbm_select(io, l, 0, 0, 0, 0);
            let gds = |io: &mut I, vmid: u32| {
                // linux-lit: 2=mmGDS_VMID1_BASE - mmGDS_VMID0_BASE
                io.write(l.reg(GDS_VMID0_BASE) + u64::from(2 * vmid) * 4, 0);
                // linux-lit: 2=mmGDS_VMID1_SIZE - mmGDS_VMID0_SIZE
                io.write(l.reg(GDS_VMID0_SIZE) + u64::from(2 * vmid) * 4, 0);
                io.write(l.reg(GDS_GWS_VMID0) + u64::from(vmid) * 4, 0);
                io.write(l.reg(GDS_OA_VMID0) + u64::from(vmid) * 4, 0);
            };
            for vmid in FIRST_KFD_VMID..16 {
                gds(io, vmid);
            }
            // gfx_v10_0_debug_trap_config_init(8, 16)
            // linux-lit: 16=SPI_GDBG_TRAP_CONFIG__VMID_SEL__SHIFT; 15=15 * (SPI_GDBG_TRAP_CONFIG__TRAP_EN_MASK >> 15)
            io.write(l.reg(SPI_GDBG_TRAP_CONFIG), (0xff00 << 16) | (1 << 15));
            for reg in [SPI_GDBG_TRAP_MASK, SPI_GDBG_TRAP_DATA0, SPI_GDBG_TRAP_DATA1] {
                io.write(l.reg(reg), 0);
            }
            // gfx_v10_0_init_gds_vmid
            for vmid in 1..16 {
                // linux: n/a (AMDGPU_NUM_VMID 16, amdgpu_ids.h not in checker sets)
                gds(io, vmid);
            }
            Ok(remapped)
        })?;
        // gfx_v10_0_wait_for_rlc_autoload_complete (RlcBoot already waited;
        // re-sampled here so this owner never starts on an unbooted RLC).
        self.hw
            .poll(fence::Engine::Gfx, REG_TIMEOUT_MS, |io, l| {
                let cp = checked(io.read(l.reg(CP_STAT)))?;
                let boot = checked(io.read(l.reg(RLC_RLCS_BOOTLOAD_STATUS)))?;
                // linux-lit: 31=31 * (RLC_RLCS_BOOTLOAD_STATUS__BOOTLOAD_COMPLETE_MASK >> 31)
                Ok((cp == 0 && boot & (1 << 31) != 0).then_some(()))
            })
            .await?;
        let csib = self.queue.address(MQD);
        self.hw.access(|io, l| {
            // gfx_v10_0_init_csb
            io.write(l.reg(RLC_CSIB_ADDR_HI), (csib >> 32) as u32);
            // linux: n/a (literal 0xfffffffc in gfx_v10_0_init_csb)
            io.write(l.reg(RLC_CSIB_ADDR_LO), csib as u32 & !3);
            io.write(l.reg(RLC_CSIB_LENGTH), csb.len() as u32);
            // gfx_v10_0_update_spm_vmid_internal(0xf): write only on change
            let spm = checked(io.read(l.reg(RLC_SPM_MC_CNTL)))?;
            if spm & 0xf != 0xf {
                // linux-lit: 0xf=RLC_SPM_MC_CNTL__RLC_SPM_VMID_MASK
                io.write(l.reg(RLC_SPM_MC_CNTL), spm | 0xf);
            }
            // gfx_v10_0_rlc_enable_srm
            // linux-lit: 3=RLC_SRM_CNTL__AUTO_INCR_ADDR_MASK | RLC_SRM_CNTL__SRM_ENABLE_MASK
            update(io, l.reg(RLC_SRM_CNTL), 3, 3)?;
            // gfx_v10_0_enable_gui_idle_interrupt(false), ME0 pipes 0 and 1
            for reg in [CP_INT_CNTL_RING0, CP_INT_CNTL_RING1] {
                // linux-lit: 0x3c0000=CP_INT_CNTL_RING0__CNTX_BUSY_INT_ENABLE_MASK | CP_INT_CNTL_RING0__CNTX_EMPTY_INT_ENABLE_MASK | CP_INT_CNTL_RING0__CMP_BUSY_INT_ENABLE_MASK | CP_INT_CNTL_RING0__GFX_IDLE_INT_ENABLE_MASK
                update(io, l.reg(reg), 0x003c_0000, 0)?;
            }
            Ok(())
        })?;
        self.proof.cam_remapped = cam;
        self.proof.csb_dwords = csb.len() as u32;
        Ok(())
    }
    /// `gfx_v10_0_cp_gfx_resume` + `cp_gfx_start` + gfx ring test. Linux's
    /// second gfx ring (pipe 1) is not created.
    pub(crate) async fn start(&mut self) -> Result<(), Error> {
        self.begin(GfxState::Configured, GfxState::Starting)?;
        let result = self.start_inner().await;
        self.finish(result, GfxState::Running)
    }
    async fn start_inner(&mut self) -> Result<(), Error> {
        let q = &self.queue;
        let (base, rptr, wptr, index) =
            (q.address(0), q.address(RPTR), q.address(WPTR), q.doorbell);
        let cntl = RB_BUFSZ | ((RB_BUFSZ - 2) << 8); // linux-lit: 8=CP_RB0_CNTL__RB_BLKSZ__SHIFT
        self.hw.access(|io, l| {
            io.write(l.reg(CP_RB_WPTR_DELAY), 0);
            io.write(l.reg(CP_RB_VMID), 0);
            update(io, l.reg(GRBM_GFX_CNTL), 3, 0)?; // linux-lit: 3=GRBM_GFX_CNTL__PIPEID_MASK
            io.write(l.reg(CP_RB0_CNTL), cntl);
            io.write(l.reg(CP_RB0_WPTR), 0);
            io.write(l.reg(CP_RB0_WPTR_HI), 0);
            io.write(l.reg(CP_RB0_RPTR_ADDR), rptr as u32);
            // linux-lit: 0xffff=CP_RB_RPTR_ADDR_HI__RB_RPTR_ADDR_HI_MASK
            io.write(l.reg(CP_RB0_RPTR_ADDR_HI), (rptr >> 32) as u32 & 0xffff);
            io.write(l.reg(CP_RB_WPTR_POLL_ADDR_LO), wptr as u32);
            io.write(l.reg(CP_RB_WPTR_POLL_ADDR_HI), (wptr >> 32) as u32);
            Ok(())
        })?;
        delay(1000).await; // linux: n/a (mdelay(1) in gfx_v10_0_cp_gfx_resume)
        self.hw.access(|io, l| {
            io.write(l.reg(CP_RB0_CNTL), cntl);
            // linux: n/a (literal in gfx_v10_0_cp_gfx_resume)
            io.write(l.reg(CP_RB0_BASE), (base >> 8) as u32);
            // linux: n/a (literal in gfx_v10_0_cp_gfx_resume)
            io.write(l.reg(CP_RB0_BASE_HI), (base >> 40) as u32);
            io.write(l.reg(CP_RB_ACTIVE), 1);
            // gfx_v10_0_cp_gfx_set_doorbell, Sienna Cichlid range fields
            update(
                io,
                l.reg(CP_RB_DOORBELL_CONTROL),
                // linux: CP_RB_DOORBELL_CONTROL__DOORBELL_OFFSET_MASK | CP_RB_DOORBELL_CONTROL__DOORBELL_EN_MASK
                0x4fff_fffc,
                // linux-lit: 30=CP_RB_DOORBELL_CONTROL__DOORBELL_EN__SHIFT; 2=CP_RB_DOORBELL_CONTROL__DOORBELL_OFFSET__SHIFT
                (1 << 30) | (index << 2),
            )?;
            // linux-lit: 2=CP_RB_DOORBELL_RANGE_LOWER__DOORBELL_RANGE_LOWER_Sienna_Cichlid__SHIFT; 0xffc=CP_RB_DOORBELL_RANGE_LOWER__DOORBELL_RANGE_LOWER_Sienna_Cichlid_MASK
            io.write(l.reg(CP_RB_DOORBELL_RANGE_LOWER), (index << 2) & 0xffc);
            // linux-lit: 0xffc=CP_RB_DOORBELL_RANGE_UPPER__DOORBELL_RANGE_UPPER_Sienna_Cichlid_MASK
            io.write(l.reg(CP_RB_DOORBELL_RANGE_UPPER), 0xffc);
            update(io, l.reg(GRBM_GFX_CNTL), 3, 0)?; // linux-lit: 3=GRBM_GFX_CNTL__PIPEID_MASK
                                                     // gfx_v10_0_cp_gfx_start
                                                     // linux: n/a (max_hw_contexts literal 8 in gfx_v10_0_gpu_early_init)
            io.write(l.reg(CP_MAX_CONTEXT), 8 - 1);
            io.write(l.reg(CP_DEVICE_ID), 1);
            // linux-lit: 0x15000000=CP_ME_CNTL__ME_HALT_MASK | CP_ME_CNTL__PFP_HALT_MASK | CP_ME_CNTL__CE_HALT_MASK
            update(io, l.reg(CP_ME_CNTL), 0x1500_0000, 0)?;
            Ok(())
        })?;
        // cp_gfx_enable waits for CP_STAT idle but only logs a timeout; the
        // ring test below is the authoritative liveness check.
        let _ = self
            .hw
            .poll(fence::Engine::Gfx, REG_TIMEOUT_MS, |io, l| {
                Ok((checked(io.read(l.reg(CP_STAT)))? == 0).then_some(()))
            })
            .await;
        let csb = crate::amdgpu_clearstate_gfx10::csb(self.hw.layout.segment(1), 0)
            .ok_or(Error::Unsupported)?;
        let queue = &mut self.queue;
        self.hw.access(|io, l| {
            queue.emit(io, &csb)?;
            queue.emit(io, &pm4::ce_partition_base())?;
            queue.commit(io, l);
            Ok(())
        })?;
        ring_test(&mut self.hw, &mut self.queue).await?;
        self.proof.ring = true;
        // gfx_v10_0_hw_init ends with gfx_v10_3_set_power_brake_sequence for
        // GC >= 10.3 after cp_resume; the KIQ/KCQ halves ran before this ring.
        self.hw.access(|io, l| {
            // linux-lit: 0xe0000000=GRBM_GFX_INDEX__SA_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__INSTANCE_BROADCAST_WRITES_MASK | GRBM_GFX_INDEX__SE_BROADCAST_WRITES_MASK
            io.write(l.reg(GRBM_GFX_INDEX), 0xe000_0000);
            io.write(l.reg(GC_CAC_IND_INDEX), IX_PWRBRK_STALL_PATTERN_CTRL);
            io.write(l.reg(GC_CAC_IND_DATA), PWRBRK_STALL_PATTERN);
            io.write(l.reg(GC_THROTTLE_CTRL), PWRBRK_THROTTLE);
            io.write(l.reg(DIDT_IND_INDEX), IX_DIDT_SQ_THROTTLE_CTRL);
            io.write(l.reg(DIDT_IND_DATA), PWRBRK_DIDT_SQ);
            Ok(())
        })?;
        Ok(())
    }
    pub(crate) async fn test_ib(&mut self) -> Result<(), Error> {
        self.begin(GfxState::Running, GfxState::Testing)?;
        let result = ib_test(&mut self.hw, &mut self.queue).await;
        if let Ok(seq) = result {
            self.proof.ib_fence = seq;
        }
        self.finish(result.map(|_| ()), GfxState::Verified)
    }
}

/// Owner of GFX ring 0 on a Navi22 PF.
#[derive(Debug)]
pub struct Gfx {
    engine: GfxEngine<Mmio>,
}
impl Gfx {
    /// Reserve ring/writeback/CSB storage without device I/O.
    ///
    /// # Safety
    /// Caller exclusively owns this physical Navi22 GPU, its GC/RLC/CP,
    /// HDP, NBIF doorbell aperture, BAR2 doorbell page and the matching
    /// permanent VRAM pool. No other gfx queue owner may exist.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
    ) -> Result<Self, Error> {
        Self::with_layout(gpu, authority, pool, doorbells, Layout::resolve(gpu)?)
    }
    /// Reserve a privileged GFX ring for any validated discrete RDNA2 profile.
    /// Golden programming selects the exact ASIC table; no queue is started.
    ///
    /// # Safety
    /// Same exclusive physical GPU, GC/RLC/CP/HDP, doorbell and permanent pool
    /// contract as `new`. No other graphics owner or active client may exist.
    pub unsafe fn new_rdna2(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
    ) -> Result<Self, Error> {
        Self::with_layout(gpu, authority, pool, doorbells, Layout::resolve_rdna2(gpu)?)
    }
    fn with_layout(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: Doorbells,
        layout: Layout,
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: GfxEngine {
                hw: Hw {
                    layout,
                    io: Mmio::new(gpu, doorbells),
                    authority,
                },
                queue: Queue::new(pool, Kind::Cp, doorbell::GFX_RING0, fence::Engine::Gfx)?,
                state: GfxState::Prepared,
                proof: GfxProof::default(),
                golden: false,
            },
        })
    }
    /// Apply the ASIC's golden sequence ahead of SDMA bring-up, as Linux's
    /// GFX hw_init precedes SDMA's. No queue is touched.
    ///
    /// # Safety
    /// PSP/RLC autoload completed, no GC client runs, and `new`'s contract
    /// still holds. A failure leaves the owner Failed.
    pub unsafe fn golden(&mut self) -> Result<(), Error> {
        self.engine.golden()
    }
    /// # Safety
    /// PSP/RLC autoload completed, VMID0 hubs are ready, clock gating and
    /// GFXOFF are disabled, and `new`'s contract still holds. Failure or
    /// cancellation leaves the owner unusable until device reset.
    pub async unsafe fn configure(&mut self) -> Result<(), Error> {
        self.engine.configure().await
    }
    /// # Safety
    /// `configure` succeeded, the NBIF doorbell aperture is enabled and the
    /// KIQ was initialized first (Linux `cp_resume` order).
    pub async unsafe fn start(&mut self) -> Result<(), Error> {
        self.engine.start().await
    }
    pub async fn test_ib(&mut self) -> Result<(), Error> {
        self.engine.test_ib().await
    }
    pub fn state(&self) -> GfxState {
        self.engine.state
    }
    /// Queue client IBs under a user VMID (`amdgpu_navi22_submit`); only on
    /// a ring whose ring and IB tests passed. `Busy` means two submissions
    /// are outstanding: wait for [`Gfx::throttle_seq`] and retry.
    pub fn submit(
        &mut self,
        state: &mut crate::amdgpu_navi22_submit::RingState,
        vm: crate::amdgpu_navi22_submit::VmRef,
        context: u64,
        ibs: &[crate::amdgpu_navi22_submit::Ib],
    ) -> Result<u32, Error> {
        if self.engine.state != GfxState::Verified {
            return Err(Error::Busy);
        }
        let e = &mut self.engine;
        crate::amdgpu_navi22_submit::submit(
            &mut e.hw,
            &mut e.queue,
            state,
            crate::amdgpu_navi22_submit::Ring::Gfx,
            vm,
            context,
            ibs,
        )
    }
    /// Last fence sequence the ring wrote, and the one a new submission
    /// must wait for.
    pub fn fences(&mut self) -> Result<(u32, u32), Error> {
        let e = &mut self.engine;
        Ok((
            crate::amdgpu_navi22_submit::completed(&mut e.hw, &e.queue)?,
            crate::amdgpu_navi22_submit::throttle_seq(&e.queue),
        ))
    }
    pub fn proof(&self) -> GfxProof {
        self.engine.proof
    }
    /// Fence progress of the verified ring (hang detection only).
    pub(crate) fn progress(&mut self) -> Result<crate::amdgpu_navi22_tdr::Progress, Error> {
        if self.engine.state != GfxState::Verified {
            return Err(Error::Busy);
        }
        progress(&mut self.engine.hw, &self.engine.queue)
    }
}

/// Enable the NBIF doorbell and self-ring apertures once, before any queue
/// rings a doorbell.
///
/// # Safety
/// Caller exclusively owns this GPU's NBIF and `doorbells` maps its BAR2.
pub unsafe fn enable_doorbell_apertures(
    gpu: &AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    doorbells: Doorbells,
) -> Result<(), Error> {
    let mut hw = Hw {
        layout: Layout::resolve(gpu)?,
        io: Mmio::new(gpu, doorbells),
        authority,
    };
    hw.access(|io, l| enable_doorbells(io, l, doorbells.bus))
}

/// Enable the shared RDNA2 NBIF doorbell/self-ring apertures.
///
/// # Safety
/// Caller exclusively owns this physical GPU's NBIF; `doorbells` is its
/// permanent BAR2 page, and no other aperture writer or queue owner runs.
pub unsafe fn enable_doorbell_apertures_rdna2(
    gpu: &AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    doorbells: Doorbells,
) -> Result<(), Error> {
    let mut hw = Hw {
        layout: Layout::resolve_rdna2(gpu)?,
        io: Mmio::new(gpu, doorbells),
        authority,
    };
    hw.access(|io, l| enable_doorbells(io, l, doorbells.bus))
}

/// `TIME_STAMP_INT_ENABLE` in CP_INT_CNTL_RING0 / CP_ME1_PIPE0_INT_CNTL.
const TIME_STAMP_INT_ENABLE: u32 = 1 << 26; // linux: CP_INT_CNTL_RING0__TIME_STAMP_INT_ENABLE_MASK
/// `SDMA0_CNTL.TRAP_ENABLE`.
const SDMA_TRAP_ENABLE: u32 = 1; // linux: SDMA0_CNTL__TRAP_ENABLE_MASK@gc
                                 // linux-ctx: reset
/// The interrupt sources `amdgpu_fence_driver_hw_init` arms through
/// `amdgpu_irq_get` for the kernel rings created here:
/// `gfx_v10_0_set_gfx_eop_interrupt_state` (ME0 pipe 0),
/// `gfx_v10_0_set_compute_eop_interrupt_state` (MEC1 pipe 0) and
/// `sdma_v5_2_set_trap_irq_state` (both engines). The KIQ's MEC2 pipe is not
/// armed, as in Linux; its fences stay polled.
pub(crate) fn enable_fence_irqs<I: Io>(io: &mut I, l: Layout) -> Result<(), Error> {
    enable_fence_irqs_for(io, l, 2)
}
pub(crate) fn enable_fence_irqs_for<I: Io>(
    io: &mut I,
    l: Layout,
    count: usize,
) -> Result<(), Error> {
    for reg in [CP_INT_CNTL_RING0, CP_ME1_PIPE0_INT_CNTL] {
        update(io, l.reg(reg), TIME_STAMP_INT_ENABLE, TIME_STAMP_INT_ENABLE)?;
    }
    // Re-armed after SdmaQueues' soft reset cleared the IH proof's enable.
    for instance in 0..count as u32 {
        update(
            io,
            l.sdma(instance, SDMA0_CNTL),
            SDMA_TRAP_ENABLE,
            SDMA_TRAP_ENABLE,
        )?;
    }
    Ok(())
}
/// Arm fence completion interrupts once every kernel queue is verified.
/// Fence waits keep polling; interrupts only shorten them.
///
/// # Safety
/// Same exclusive-GPU contract as the queue owners. IH must be enabled and
/// routing these sources before the engines produce more fences, or the
/// interrupts are merely dropped by the ring's unclaimed-source path.
pub unsafe fn enable_fence_interrupts(
    gpu: &AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    doorbells: Doorbells,
) -> Result<(), Error> {
    let mut hw = Hw {
        layout: Layout::resolve(gpu)?,
        io: Mmio::new(gpu, doorbells),
        authority,
    };
    hw.access(enable_fence_irqs)
}

/// Arm GFX/compute and every discovered RDNA2 SDMA completion source.
///
/// # Safety
/// Caller owns all engines and doorbells exclusively; every kernel ring has
/// passed its proofs and IH is enabled and routing these sources.
pub unsafe fn enable_fence_interrupts_rdna2(
    gpu: &AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    doorbells: Doorbells,
) -> Result<(), Error> {
    let (layout, count) = crate::amdgpu_sdma_navi22_queues::resolve_rdna2(gpu)?;
    let mut hw = Hw {
        layout,
        io: Mmio::new(gpu, doorbells),
        authority,
    };
    hw.access(|io, l| enable_fence_irqs_for(io, l, count))
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_cp_navi22_tests.rs"]
pub(crate) mod tests;
