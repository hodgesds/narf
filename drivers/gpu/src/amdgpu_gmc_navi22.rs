//! Navi22 memory hubs: VMID0 bring-up for an owned VRAM test aperture, then
//! the GART (`gart` child) and per-client GPUVM contexts (`vm` child).
//! Linux gfxhub_v2_1.c / mmhub_v2_0.c / gmc_v10_0.c. No clock gating, KIQ/MES
//! invalidation, retry-fault recovery or implicit reset.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_gmc_navi22_gart.rs"]
mod gart;
#[path = "amdgpu_gmc_navi22_regs.rs"]
mod regs;
#[path = "amdgpu_gmc_navi22_vm.rs"]
mod vm;
pub use gart::{GartInfo, Gtt, GART_SIZE};
use regs::{HubRegs, GFX, MM};
pub use vm::{Buffer, Fault, FaultInfo, FaultOwner, Mapping, Vm, VmInfo};
const BYTES: u64 = 16384; // PT, default page, source page, destination page
const APERTURE_SIZE: u64 = 2 << 20; // 512 flat PTEs; only two are present
const LIMIT: u64 = 1 << 48;
const FOUR_GB: u64 = 4 << 30;
/// AMDGPU_GMC_HOLE_START; gmc_v10 mc_mask is 48 bits, so max_mc_address is
/// min(mc_mask, HOLE_START - 1).
const MAX_MC_ADDRESS: u64 = 0x0000_7fff_ffff_ffff;

/// amdgpu_gmc_gart_location(AMDGPU_GART_PLACEMENT_BEST_FIT), as called by
/// gmc_v10_0_vram_gtt_location. `fb_end` is exclusive here.
fn gart_location(fb_start: u64, fb_end: u64, gart_size: u64) -> Option<u64> {
    let size_bf = fb_start;
    let size_af = (MAX_MC_ADDRESS + 1).checked_sub(fb_end.checked_next_multiple_of(FOUR_GB)?)?;
    if gart_size > size_bf.max(size_af) {
        return None; // Linux would shrink the GART ("limiting GART").
    }
    let start = if (size_bf >= gart_size && size_bf < size_af) || size_af < gart_size {
        0
    } else {
        MAX_MC_ADDRESS - gart_size + 1
    };
    Some(start & !(FOUR_GB - 1))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    /// No free VMID, GART range or page-table budget.
    Exhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hub {
    Gfx,
    Mm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Invalidating(Hub),
    Ready,
    Failed,
}
/// Post-boot operation latch. A started GART/VM operation that fails or is
/// cancelled leaves `Failed`/`Busy`: translations it touched may still be
/// cached, so every later operation is refused and its memory is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    Idle,
    Busy,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aperture {
    pub start: u64,
    pub size: u64,
    pub source: u64,
    pub destination: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    bases: [u64; 2],
    nbio: u64,
    /// NBIO BASE_IDX 0 (PCIE_INDEX2/PCIE_DATA2) and HDP BASE_IDX 0.
    pcie: u64,
    hdp: u64,
}
/// nbio_v2_3.c smnPCIE_CONFIG_CNTL and its CI_SWUS_MAX_READ_REQUEST_SIZE_MODE
/// (bit 27) / _PRIV (bits 29:28) fields (nbio_2_3_sh_mask.h).
const SMN_PCIE_CONFIG_CNTL: u32 = 0x1118_0044;
const MAX_READ_REQUEST_MODE: u32 = 1 << 27;
const MAX_READ_REQUEST_PRIV: u32 = 3 << 28;
const PCIE_INDEX2: u64 = 0xe;
const PCIE_DATA2: u64 = 0xf;
/// hdp_5_0_0_offset.h HDP_MISC_CNTL (BASE_IDX 0), FLUSH_INVALIDATE_CACHE bit 0.
const HDP_MISC_CNTL: u64 = 0xd3;
const HDP_FLUSH_INVALIDATE_CACHE: u32 = 1;
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI22
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let reg = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        let nbif = [
            (2, 3, 0),
            (2, 3, 1),
            (2, 3, 2),
            (3, 3, 0),
            (3, 3, 1),
            (3, 3, 2),
            (3, 3, 3),
        ];
        Ok(Self {
            bases: [
                reg(ip::HW_ID_GC, &[(10, 3, 2)], 0, 0x1703)?,
                reg(ip::HW_ID_MMHUB, &[(2, 1, 0)], 0, 0x873)?,
            ],
            nbio: reg(ip::HW_ID_NBIF, &nbif, 2, 0x12d)?,
            pcie: reg(ip::HW_ID_NBIF, &nbif, 0, PCIE_DATA2 as u32)?,
            hdp: reg(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                HDP_MISC_CNTL as u32,
            )?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// One 64-bit BAR store (Linux `amdgpu_gmc_set_pte_pde` uses writeq), so
    /// the GPU never observes a torn PTE/PDE.
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds both complete hub banks and the HDP remap;
        // the exclusive owner calls this only inside live Cap::invoke.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded exclusive register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: initialize bounds every write to its owned BYTES allocation,
        // before publication and inside live authority.
        unsafe { map.write32(offset, value) };
    }
    fn memory64(&mut self, map: MmioRegion, offset: u64, value: u64) {
        // SAFETY: callers bound each 8-byte entry inside an owned, published
        // or still-private page-table reservation, inside live authority.
        unsafe { map.write64(offset, value) };
    }
}
/// Store entry `index` of a page table/GART page.
fn entry<I: Io>(io: &mut I, map: MmioRegion, index: u64, value: u64) {
    io.memory64(map, index * 8, value);
}
fn zero<I: Io>(io: &mut I, map: MmioRegion) {
    for offset in (0..map.len).step_by(8) {
        io.memory64(map, offset, 0);
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Clone, Copy, Debug)]
struct Geometry {
    fb: u64,
    end: u64,
    offset: u64,
    aperture: Aperture,
}
impl Geometry {
    /// `fields` are MC_VM_FB_LOCATION_BASE and MC_VM_FB_OFFSET. Like
    /// amdgpu_gmc_vram_location, the end is fb_start + mc_vram_size
    /// (RCC_CONFIG_MEMSIZE); FB_LOCATION_TOP is never consulted. The boot
    /// aperture is the first 2 MiB of the range Linux gives the GART, so
    /// enabling the GART later keeps its pages at the same addresses.
    fn new(fields: [u32; 2], bytes: u64, allocation: u64) -> Result<Self, Error> {
        if fields.contains(&u32::MAX) {
            return Err(Error::DeviceGone);
        }
        let [base, offset] = fields.map(|v| u64::from(v & 0xff_ffff) << 24);
        let end = base.checked_add(bytes).ok_or(Error::Invalid)?;
        if bytes == 0
            || end > LIMIT
            || allocation < base
            || allocation.checked_add(BYTES).is_none_or(|v| v > end)
            || allocation % 4096 != 0
        {
            return Err(Error::Invalid);
        }
        let start = gart_location(base, end, gart::GART_SIZE).ok_or(Error::Invalid)?;
        if start.checked_add(gart::GART_SIZE).is_none_or(|v| v > LIMIT)
            || (start < end && base < start + gart::GART_SIZE)
            || offset.checked_add(bytes).is_none_or(|v| v > LIMIT)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            fb: base,
            end,
            offset,
            aperture: Aperture {
                start,
                size: APERTURE_SIZE,
                source: start,
                destination: start + 4096,
            },
        })
    }
    fn physical(self, address: u64) -> u64 {
        address - self.fb + self.offset
    }
}
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn flush<I: Io>(io: &mut I, nbio: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(nbio + 0xc3 * 4);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}
/// nbio_v2_3_init_registers (nv_common_hw_init, before any GMC block):
/// RREG32_PCIE/WREG32_PCIE through PCIE_INDEX2/DATA2, written only on change.
fn init_nbio<I: Io>(io: &mut I, pcie: u64) -> Result<(), Error> {
    let index = pcie + PCIE_INDEX2 * 4;
    let data = pcie + PCIE_DATA2 * 4;
    io.write(index, SMN_PCIE_CONFIG_CNTL);
    io.read(index);
    let old = checked(io.read(data))?;
    let new = (old & !MAX_READ_REQUEST_PRIV) | MAX_READ_REQUEST_MODE | (1 << 28);
    if new != old {
        io.write(index, SMN_PCIE_CONFIG_CNTL);
        io.read(index);
        io.write(data, new);
        io.read(data);
    }
    Ok(())
}
/// hdp_v5_0_init_registers (gmc_v10_0_gart_enable, after both hubs).
fn init_hdp<I: Io>(io: &mut I, hdp: u64) -> Result<(), Error> {
    update(
        io,
        hdp,
        HDP_MISC_CNTL as u32,
        HDP_FLUSH_INVALIDATE_CACHE,
        HDP_FLUSH_INVALIDATE_CACHE,
    )
}
fn pair<I: Io>(io: &mut I, base: u64, reg: u32, value: u64) {
    io.write(base + u64::from(reg) * 4, value as u32);
    io.write(base + u64::from(reg + 1) * 4, (value >> 32) as u32);
}
fn update<I: Io>(io: &mut I, base: u64, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
    let address = base + u64::from(reg) * 4;
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | value);
    Ok(())
}
fn program<I: Io>(
    io: &mut I,
    base: u64,
    r: HubRegs,
    g: Geometry,
    address: u64,
) -> Result<(), Error> {
    let write = |io: &mut I, reg, value| io.write(base + u64::from(reg) * 4, value);
    pair(io, base, r.pt_base, g.physical(address) | 1); // valid VRAM PDE, byte address
    pair(io, base, r.pt_start, g.aperture.start >> 12);
    pair(
        io,
        base,
        r.pt_end,
        (g.aperture.start + g.aperture.size - 1) >> 12,
    );
    write(io, r.agp_base, 0);
    write(io, r.agp_bot, 0xffffff);
    write(io, r.agp_top, 0);
    write(io, r.sys_low, (g.fb >> 18) as u32);
    write(io, r.sys_high, ((g.end - 1) >> 18) as u32);
    let scratch = g.physical(address + 4096);
    write(io, r.sys_default_lo, (scratch >> 12) as u32);
    write(io, r.sys_default_hi, (scratch >> 44) as u32);
    write(io, r.fault_lo, (scratch >> 12) as u32);
    write(io, r.fault_hi, (scratch >> 44) as u32);
    update(io, base, r.fault_cntl2, 0x40000, 0x40000)?;
    // UC=3. System access mode 3, ADM on, unmapped aperture access off.
    update(io, base, r.l1, 0x3879, 0x1859)?;
    // Default fault page is owned VRAM, so OUT_TO_SYSTEM_MEMORY stays clear.
    update(io, base, r.l2, 0x03fc0903, 0x80001)?;
    update(io, base, r.l2_2, 3, 3)?;
    write(io, r.l2_3, (0x80100007 & !0xf803f) | 9 | (6 << 15));
    write(io, r.l2_4, 0xc1 & !0xc0);
    write(io, r.l2_5, 0x3fe0 & !0x1f);
    pair(io, base, r.identity_low, 0xf_ffffffff);
    pair(io, base, r.identity_high, 0);
    pair(io, base, r.identity_offset, 0);
    // Invalid translations return the VRAM default page. Leave fault IRQs off
    // until IH has an owner; no retry storm or host-memory fallback.
    update(io, base, r.fault_cntl, 0xffff_fffc, 0x1ffc)?;
    for index in 0..18 {
        pair(io, base, r.inv_range + index * 2, 0x1f_ffffffff);
    }
    // Only privileged VMID0: flat PT, no retry, default-page fault responses.
    write(io, r.ctx, 1 | 0x555400);
    Ok(())
}
/// Distinguishes owners so a GTT/VM/VRAM handle cannot be replayed against a
/// different GPU's tables or VMIDs.
static OWNERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
fn owner_token() -> u64 {
    OWNERS.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}
/// gfxhub_v2_1/mmhub_v2_0_get_invalidate_req(vmid, 0): legacy per-VMID
/// request invalidating L2 PTE/PDE0-2 and L1 caches, status address kept.
const fn invalidate_request(vmid: u8) -> u32 {
    (1 << vmid) | 0xf8_0000
}
fn invoke<I: Io, T>(
    authority: &Cap<BusDeviceCap, Write>,
    io: &mut I,
    f: impl FnOnce(&mut I) -> Result<T, Error>,
) -> Result<T, Error> {
    authority.invoke(Op(|| f(io))).map_err(|_| Error::Revoked)?
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    vram_size: u64,
    state: State,
    aperture: Option<Aperture>,
    pool: Pool,
    token: u64,
    geometry: Option<Geometry>,
    gart: Option<gart::Gart>,
    vms: vm::Vms,
    runtime: Runtime,
    fault_irqs: bool,
}
impl<I: Io> Engine<I> {
    fn new(
        io: I,
        authority: Cap<BusDeviceCap, Write>,
        layout: Layout,
        pool: &Pool,
        vram_size: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            io,
            authority,
            layout,
            memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
            vram_size,
            state: State::Prepared,
            aperture: None,
            pool: pool.clone(),
            token: owner_token(),
            geometry: None,
            gart: None,
            vms: vm::Vms::new(),
            runtime: Runtime::Idle,
            fault_irqs: false,
        })
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        invoke(&self.authority, &mut self.io, f)
    }
    async fn wait(&mut self, address: u64, mask: u32) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(100);
        loop {
            if self.access(|io| checked(io.read(address)))? & mask == mask {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    /// gmc_v10_0_flush_gpu_tlb(vmid, hub, 0) on engine 17 for each hub, GFX
    /// then MM: HDP flush, MMHUB-only semaphore acquire (a read returning 1),
    /// request, ACK bit `1 << vmid`, semaphore release. Linux logs and goes
    /// on after a timeout; here a timeout fails closed (no release/replay)
    /// because the invalidation may still be outstanding.
    async fn flush_tlb(&mut self, vmid: u8, boot: bool) -> Result<(), Error> {
        let layout = self.layout;
        for (index, hub, r) in [(0, Hub::Gfx, GFX), (1, Hub::Mm, MM)] {
            if boot {
                self.state = State::Invalidating(hub);
            }
            let base = layout.bases[index];
            if hub == Hub::Mm {
                self.wait(base + u64::from(r.inv_sem) * 4, 1).await?;
            }
            self.access(|io| {
                flush(io, layout.nbio);
                io.write(base + u64::from(r.inv_req) * 4, invalidate_request(vmid));
                Ok(())
            })?;
            self.wait(base + u64::from(r.inv_ack) * 4, 1 << vmid)
                .await?;
            if hub == Hub::Mm {
                self.access(|io| {
                    io.write(base + u64::from(r.inv_sem) * 4, 0);
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
    /// Admit one post-boot operation after its host-only validation and
    /// allocation succeeded. Only `finish` returns the latch to Idle.
    fn begin(&mut self) -> Result<(), Error> {
        if self.state != State::Ready || self.runtime != Runtime::Idle {
            return Err(Error::Busy);
        }
        self.runtime = Runtime::Busy;
        Ok(())
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        self.runtime = if result.is_ok() {
            Runtime::Idle
        } else {
            Runtime::Failed
        };
        result
    }
    fn idle(&self) -> Result<(), Error> {
        if self.state != State::Ready || self.runtime != Runtime::Idle {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    async fn initialize(&mut self) -> Result<Aperture, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner().await;
        self.state = if result.is_ok() {
            State::Ready
        } else {
            State::Failed
        };
        result
    }
    async fn initialize_inner(&mut self) -> Result<Aperture, Error> {
        let layout = self.layout;
        let address = self.memory.address();
        let size = self.vram_size;
        let geometry = self.access(|io| {
            if checked(io.read(layout.nbio + 0x12d * 4))? != 0x7f000 {
                return Err(Error::Invalid);
            }
            let g = Geometry::new(
                [
                    io.read(layout.bases[0] + u64::from(GFX.fb_base) * 4),
                    io.read(layout.bases[0] + 0x16e7 * 4),
                ],
                size,
                address,
            )?;
            for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
                // Both hubs must agree on the inherited FB base. TOP is not
                // read (gmc_v10_0_vram_gtt_location uses MEMSIZE).
                if u64::from(checked(io.read(base + u64::from(r.fb_base) * 4))? & 0xffffff) << 24
                    != g.fb
                {
                    return Err(Error::Invalid);
                }
                // VMID0 is the kernel context firmware/GOP may leave enabled;
                // gfxhub/mmhub gart_enable reprograms it, as Linux does. A
                // live user context (1..15) would have unknown tables.
                for context in 1..16 {
                    if checked(io.read(base + u64::from(r.ctx + context) * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
            Ok(g)
        })?;
        self.access(|io| init_nbio(io, layout.pcie))?;
        let map = self.memory.mapping();
        self.access(|io| {
            for offset in (0..BYTES).step_by(4) {
                io.memory(map, offset, 0);
            }
            for (index, offset) in [8192, 12288].into_iter().enumerate() {
                let pte = geometry.physical(address + offset) | 0x61; // V/R/W, NC VRAM
                io.memory(map, index as u64 * 8, pte as u32);
                io.memory(map, index as u64 * 8 + 4, (pte >> 32) as u32);
            }
            flush(io, layout.nbio);
            Ok(())
        })?;
        self.memory.publish(); // before either hub can retain a PT/default address
        self.aperture = Some(geometry.aperture);
        self.geometry = Some(geometry);
        self.access(|io| {
            for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
                program(io, base, r, geometry, address)?;
            }
            // flush_tlb's leading HDP flush is Linux's "Flush HDP after it is
            // initialized".
            init_hdp(io, layout.hdp)
        })?;
        self.flush_tlb(0, true).await?;
        Ok(geometry.aperture)
    }
}
#[derive(Debug)]
pub struct Gmc {
    engine: Engine<Mmio>,
}
impl Gmc {
    /// Reserve backing pages without I/O. Only the physical Navi22 PF is supported.
    /// # Safety
    /// Caller owns both hubs, HDP, VRAM and the matching permanent pool,
    /// with no active GPU queues/VMs, GFXOFF, hub gating, reset or PM transition.
    /// Keep this owner alive while any consumer can use its VMID0 translations.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        Ok(Self {
            engine: Engine::new(Mmio(gpu.regs), authority, layout, pool, gpu.vram.size)?,
        })
    }
    /// # Safety
    /// Requires trained VRAM, completed PSP/RLC startup and the same exclusive
    /// ownership as new, with automatic power gating still disabled.
    /// Cancellation/failure prevents replay and quarantines published backing pages.
    pub async unsafe fn initialize(&mut self) -> Result<Aperture, Error> {
        self.engine.initialize().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn runtime(&self) -> Runtime {
        self.engine.runtime
    }
    /// (MC_VM_FB_LOCATION_BASE, MC_VM_FB_OFFSET) as byte addresses: a pool
    /// address becomes the physical VRAM address entries carry as
    /// `address - fb + offset` (`gmc_v10_0_get_vm_pde`).
    pub fn framebuffer(&self) -> Option<(u64, u64)> {
        self.engine.geometry.map(|g| (g.fb, g.offset))
    }
    pub fn aperture(&self) -> Option<Aperture> {
        self.engine.aperture
    }
    /// Reserve the 1 MiB GART table and the shared empty user root before
    /// any hub programming. No I/O; dropping it unused returns the VRAM.
    pub fn prepare_gart(&mut self) -> Result<(), Error> {
        self.engine.prepare_gart()
    }
    pub fn gart_prepared(&self) -> bool {
        self.engine.gart.is_some()
    }
    /// Replace the flat VMID0 table with the GART and arm user contexts 1–15
    /// on an empty root. Requires `Ready`; keeps the boot `Aperture` mapped.
    /// # Safety
    /// Same exclusive ownership as `initialize`; no queue may be running in
    /// any VMID while the VMID0 table base changes.
    pub async unsafe fn enable_gart(&mut self) -> Result<GartInfo, Error> {
        self.engine.enable_gart().await
    }
    pub fn gart(&self) -> Option<GartInfo> {
        self.engine.gart.as_ref().and_then(gart::Gart::info)
    }
    /// Map one pinned, contiguous system DMA buffer into VMID0's GART.
    /// The buffer is owned by the returned handle; a dropped handle or a
    /// failed unbind quarantines the pages because the GPU may still use them.
    pub async fn bind_gtt(
        &mut self,
        buffer: narf_io::DmaBuffer,
        writable: bool,
    ) -> Result<Gtt, Error> {
        self.engine.bind_gtt(buffer, writable).await
    }
    /// Clear the GART entries, invalidate both hubs, then return the pages.
    pub async fn unbind_gtt(&mut self, gtt: Gtt) -> Result<narf_io::DmaBuffer, Error> {
        self.engine.unbind_gtt(gtt).await
    }
    /// Allocate zeroed, CPU-visible VRAM from this owner's pool for user VMs.
    pub fn allocate_vram(&mut self, size: u64, read_only: bool) -> Result<Buffer, Error> {
        self.engine.allocate_vram(size, read_only)
    }
    pub async fn create_vm(&mut self) -> Result<Vm, Error> {
        self.engine.create_vm().await
    }
    pub async fn map(
        &mut self,
        vm: &Vm,
        mapping: Mapping,
        buffer: alloc::sync::Arc<Buffer>,
    ) -> Result<(), Error> {
        self.engine.map(vm, mapping, buffer).await
    }
    pub async fn unmap(&mut self, vm: &Vm, va: u64) -> Result<(), Error> {
        self.engine.unmap(vm, va).await
    }
    pub async fn destroy_vm(&mut self, vm: Vm) -> Result<(), Error> {
        self.engine.destroy_vm(vm).await
    }
    pub fn vm_info(&self, vm: &Vm) -> Option<VmInfo> {
        self.engine.vm_info(vm)
    }
    /// Last fault recorded against this VM (Linux `vm->fault_info`).
    pub fn vm_fault(&self, vm: &Vm) -> Option<FaultInfo> {
        self.engine.vm_fault(vm)
    }
    /// Interrupt-handler hook for decoded VMC/UTCL2 fault IVs.
    pub fn handle_fault(&mut self, fault: Fault) -> Result<FaultOwner, Error> {
        self.engine.handle_fault(fault)
    }
    /// gmc_v10_0_vm_fault_interrupt_state. Enable only once an IH owner drains.
    pub fn set_fault_interrupts(&mut self, enable: bool) -> Result<(), Error> {
        self.engine.set_fault_interrupts(enable)
    }
    pub(crate) fn test_mapping(&mut self) -> Option<MmioRegion> {
        if self.state() != State::Ready {
            return None;
        }
        let map = self.engine.memory.mapping();
        Some(MmioRegion {
            phys: narf_memory::PhysAddr::new(map.phys.raw() + 8192),
            virt: map.virt + 8192,
            len: 8192,
            kind: map.kind,
        })
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gmc_navi22_tests.rs"]
mod tests;
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gmc_navi22_vm_tests.rs"]
mod vm_tests;
