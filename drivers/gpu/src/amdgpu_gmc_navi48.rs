//! Navi48 VMID0 bring-up for an owned VRAM-only test aperture.
//! Linux gfxhub_v12_0.c / mmhub_v4_1_0.c / gmc_v12_0.c. No system-memory PTEs,
//! host DMA, user VMIDs, fault IRQs, clock gating or implicit recovery.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_gmc_navi48_regs.rs"]
mod regs;
use regs::{HubRegs, GFX, MM};
#[path = "amdgpu_gmc_navi48_display.rs"]
mod display;
#[path = "amdgpu_gmc_navi48_handoff.rs"]
mod handoff;
pub(crate) use display::DisplayContext;
// PT, default page, source page, destination page, then the empty root
// directory every idle client context points at.
const BYTES: u64 = 20480;
const EMPTY_ROOT: u64 = 16384;
const APERTURE_SIZE: u64 = 2 << 20; // 512 flat PTEs; only two are present
const LIMIT: u64 = 1 << 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
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
    /// VMIDs 1..15 enabled on both hubs, each at the empty root until a
    /// submission's VM flush gives it a client's page tables.
    PreparingClients,
    /// Executable test-code PTE publication and GFX VMID0 TLB invalidation.
    PreparingShader,
    ClientsReady,
    Failed,
}
impl State {
    /// VMID0's translations are live: initialized, with or without the
    /// client contexts.
    pub fn vmid0_ready(self) -> bool {
        matches!(self, State::Ready | State::ClientsReady)
    }
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
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let reg = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        Ok(Self {
            bases: [
                // Include the final client VMID's page-table end high word.
                reg(ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x16ee)?,
                reg(ip::HW_ID_MMHUB, &[(4, 1, 0)], 0, 0x62e)?,
            ],
            nbio: reg(ip::HW_ID_NBIF, &[(7, 7, 0), (7, 7, 1), (6, 3, 1)], 2, 0x12d)?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32);
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
    fn new(fields: [u32; 3], bytes: u64, allocation: u64) -> Result<Self, Error> {
        if fields.contains(&u32::MAX) {
            return Err(Error::DeviceGone);
        }
        let [base, top, offset] = fields.map(|v| u64::from(v & 0xff_ffff) << 24);
        let end = top.checked_add(1 << 24).ok_or(Error::Invalid)?;
        if end.checked_sub(base) != Some(bytes)
            || allocation < base
            || allocation.checked_add(BYTES).is_none_or(|v| v > end)
            || allocation % 4096 != 0
        {
            return Err(Error::Invalid);
        }
        let start =
            end.checked_add(APERTURE_SIZE - 1).ok_or(Error::Invalid)? & !(APERTURE_SIZE - 1);
        if start.checked_add(APERTURE_SIZE).is_none_or(|v| v > LIMIT)
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
fn flush<I: Io>(io: &mut I, nbio: u64) -> Result<(), Error> {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    io.write(0x7f000, 0);
    checked(io.read(nbio + 0xc3 * 4))?;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
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
    // Disable all PRT/retry fault interrupts until IH ownership exists.
    update(io, base, r.fault_cntl2, 0xfffff, 0x40000)?;
    // UC=3. System access mode 3, ADM on, unmapped aperture access off.
    update(io, base, r.l1, 0x1ff9, 0x1859)?;
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
    write(io, r.ctx, 1 | 0xaaa800);
    Ok(())
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
    geometry: Option<Geometry>,
    shader_executable: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
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
    async fn prepare_shader_test(&mut self) -> Result<(), Error> {
        if !self.state.vmid0_ready() || self.shader_executable {
            return Err(Error::Busy);
        }
        let prior = self.state;
        self.state = State::PreparingShader;
        let result = async {
            let g = self.geometry.ok_or(Error::Invalid)?;
            let map = self.memory.mapping();
            let pte = g.physical(self.memory.address() + 8192) | 0x71; // V/R/W/X, NC
            let layout = self.layout;
            self.access(|io| {
                io.memory(map, 0, pte as u32);
                io.memory(map, 4, (pte >> 32) as u32);
                flush(io, layout.nbio)?;
                io.write(layout.bases[0] + u64::from(GFX.inv_req) * 4, 0xf80001);
                Ok(())
            })?;
            self.wait(layout.bases[0] + u64::from(GFX.inv_ack) * 4, 1)
                .await
        }
        .await;
        self.state = if result.is_ok() { prior } else { State::Failed };
        self.shader_executable = result.is_ok();
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
                    io.read(layout.bases[0] + u64::from(GFX.fb_top) * 4),
                    io.read(layout.bases[0] + 0x15a7 * 4),
                ],
                size,
                address,
            )?;
            if u64::from(checked(io.read(layout.bases[1] + 0x4c7 * 4))? & 0xffffff) << 24
                != g.offset
            {
                return Err(Error::Invalid);
            }
            for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
                if u64::from(checked(io.read(base + u64::from(r.fb_base) * 4))? & 0xffffff) << 24
                    != g.fb
                    || (u64::from(checked(io.read(base + u64::from(r.fb_top) * 4))? & 0xffffff) + 1)
                        << 24
                        != g.end
                {
                    return Err(Error::Invalid);
                }
                for context in 0..16 {
                    if checked(io.read(base + u64::from(r.ctx + context) * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
            Ok(g)
        })?;
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
            flush(io, layout.nbio)?;
            Ok(())
        })?;
        self.memory.publish(); // before either hub can retain a PT/default address
        self.aperture = Some(geometry.aperture);
        self.geometry = Some(geometry);
        self.access(|io| {
            for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
                program(io, base, r, geometry, address)?;
            }
            Ok(())
        })?;
        for (index, hub, r) in [(0, Hub::Gfx, GFX), (1, Hub::Mm, MM)] {
            self.state = State::Invalidating(hub);
            let base = layout.bases[index];
            if hub == Hub::Mm {
                self.wait(base + u64::from(r.inv_sem) * 4, 1).await?;
            }
            self.access(|io| {
                flush(io, layout.nbio)?;
                io.write(base + u64::from(r.inv_req) * 4, 0xf80001); // VMID0 + all PT caches
                Ok(())
            })?;
            self.wait(base + u64::from(r.inv_ack) * 4, 1).await?;
            if hub == Hub::Mm {
                self.access(|io| {
                    io.write(base + u64::from(r.inv_sem) * 4, 0);
                    // GMC12 additionally invalidates the MMHUB private cache.
                    update(io, base, 0x500, 1 << 25, 1 << 25)?;
                    checked(io.read(base + 0x500 * 4))?;
                    Ok(())
                })?;
            }
        }
        Ok(geometry.aperture)
    }
}
/// One hub's register bank as the shared VM hub programming sees it.
struct Bank<'a, I: Io> {
    io: &'a mut I,
    base: u64,
}
impl<I: Io> crate::amdgpu_vmhub_regs::VmHubMmio for Bank<'_, I> {
    fn read(&mut self, byte_off: u32) -> u32 {
        self.io.read(self.base + u64::from(byte_off))
    }
    fn write(&mut self, byte_off: u32, value: u32) {
        self.io.write(self.base + u64::from(byte_off), value);
    }
}
/// The client VMIDs, 1..=15 (VMID0 is the kernel's).
const CLIENT_VMIDS: u16 = 0xfffe;
impl<I: Io> Engine<I> {
    /// gfxhub_v12_0_setup_vmid_config / mmhub_v4_1_0_setup_vmid_config for
    /// VMIDs 1..15: each enabled with GMC 12's depth and block size, every
    /// protection-fault default and no retry (amdgpu_noretry), bounded to
    /// 0..max_pfn-1, and — where Linux leaves the base at whatever the last
    /// flush wrote — pointed at an owned root directory whose every entry is
    /// GMC 12's invalid pattern, so a context no submission has flushed
    /// faults instead of translating. Then one invalidation of all fifteen
    /// on each hub's kernel engine (17), the MMHUB semaphore held around it.
    async fn prepare_clients(&mut self) -> Result<(), Error> {
        use crate::amdgpu_vmhub_regs::{self as hub, KERNEL_INVALIDATE_ENGINE};
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        let geometry = self.geometry.ok_or(Error::Invalid)?;
        let layout = self.layout;
        let vm = crate::amdgpu_vm::Geometry::GMC12;
        let root = self.memory.address() + EMPTY_ROOT;
        let base = geometry.physical(root) | 1; // valid VRAM PDE, byte address
        let entries = vm.entries_at(vm.root_level);
        if entries * 8 > 4096 {
            return Err(Error::Invalid);
        }
        let empty = vm.format.pde_pte();
        let map = self.memory.mapping();
        self.state = State::PreparingClients;
        let result = async {
            self.access(|io| {
                for index in 0..entries {
                    io.memory(map, EMPTY_ROOT + index * 8, empty as u32);
                    io.memory(map, EMPTY_ROOT + index * 8 + 4, (empty >> 32) as u32);
                }
                flush(io, layout.nbio)?;
                for (bank, regs) in layout
                    .bases
                    .into_iter()
                    .zip([hub::GFXHUB_V12_0, hub::MMHUB_V4_1])
                {
                    let mut b = Bank { io, base: bank };
                    for vmid in 1..16 {
                        hub::write_vmid_pt_base(&mut b, &regs, vmid, base);
                        hub::write_vmid_aperture(&mut b, &regs, vmid, 0, vm.max_pfn - 1);
                        hub::write_vmid_cntl(
                            &mut b,
                            &regs,
                            vmid,
                            vm.num_level(),
                            vm.block_size as u8,
                            true,
                        );
                    }
                }
                Ok(())
            })?;
            for (index, h, regs) in [
                (0, Hub::Gfx, hub::GFXHUB_V12_0),
                (1, Hub::Mm, hub::MMHUB_V4_1),
            ] {
                let bank = layout.bases[index];
                let eng = regs.eng_distance * KERNEL_INVALIDATE_ENGINE;
                let at = |reg: u32| bank + u64::from(reg + eng) * 4;
                self.state = State::Invalidating(h);
                if regs.semaphore {
                    self.wait(at(regs.inv_eng0_sem), 1).await?;
                }
                // Every client VMID in one legacy request.
                let request = hub::invalidate_req(0, 0) & !1 | u32::from(CLIENT_VMIDS);
                self.access(|io| {
                    io.write(at(regs.inv_eng0_req), request);
                    Ok(())
                })?;
                let acked = self
                    .wait(at(regs.inv_eng0_ack), u32::from(CLIENT_VMIDS))
                    .await;
                if regs.semaphore {
                    self.access(|io| {
                        io.write(at(regs.inv_eng0_sem), 0);
                        Ok(())
                    })?;
                }
                acked?;
                self.state = State::PreparingClients;
            }
            // Read every context back.
            self.access(|io| {
                for (bank, regs) in layout
                    .bases
                    .into_iter()
                    .zip([hub::GFXHUB_V12_0, hub::MMHUB_V4_1])
                {
                    let cntl =
                        hub::vmid_cntl_value(&regs, vm.num_level(), vm.block_size as u8, true);
                    for vmid in 1..16u32 {
                        let reg = |r: u32, d: u32| bank + u64::from(r + d * vmid) * 4;
                        let lo =
                            checked(io.read(reg(regs.ctx0_pt_base_lo, regs.ctx_addr_distance)))?;
                        let hi =
                            checked(io.read(reg(regs.ctx0_pt_base_hi, regs.ctx_addr_distance)))?;
                        // max_pfn - 1 has an all-ones low word; the high
                        // word (0xf) is what proves the device answered.
                        let end_lo = io.read(reg(regs.ctx0_pt_end_lo, regs.ctx_addr_distance));
                        let end_hi =
                            checked(io.read(reg(regs.ctx0_pt_end_hi, regs.ctx_addr_distance)))?;
                        if u64::from(hi) << 32 | u64::from(lo) != base
                            || u64::from(end_hi) << 32 | u64::from(end_lo) != vm.max_pfn - 1
                            || checked(io.read(reg(regs.ctx0_cntl, regs.ctx_distance)))? != cntl
                        {
                            return Err(Error::Invalid);
                        }
                    }
                }
                Ok(())
            })
        }
        .await;
        self.state = if result.is_ok() {
            State::ClientsReady
        } else {
            State::Failed
        };
        result
    }
}
#[derive(Debug)]
pub struct Gmc {
    engine: Engine<Mmio>,
}
impl Gmc {
    /// Validate the pool mapping and reserve backing pages without writes. Only the physical Navi48 PF is supported.
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
        crate::amdgpu_psp_ring::navi48_layout(gpu)
            .and_then(|l| l.validate_pool(gpu, &authority, pool))
            .map_err(|e| match e {
                crate::amdgpu_psp_ring::Error::Revoked => Error::Revoked,
                crate::amdgpu_psp_ring::Error::DeviceGone => Error::DeviceGone,
                _ => Error::Invalid,
            })?;
        Ok(Self {
            engine: Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                vram_size: gpu.vram.size,
                state: State::Prepared,
                aperture: None,
                geometry: None,
                shader_executable: false,
            },
        })
    }
    /// # Safety
    /// Requires trained VRAM, completed PSP/RLC startup and the same exclusive
    /// ownership as new, with automatic power gating still disabled.
    /// Cancellation/failure prevents replay and quarantines published backing pages.
    pub async unsafe fn initialize(&mut self) -> Result<Aperture, Error> {
        self.engine.initialize().await
    }
    /// Enable the client VMIDs 1..15 on both hubs at an empty root, as
    /// Linux's GART enable does, so a submission's in-ring VM flush can
    /// point one at a client's page tables. No client runs yet.
    /// # Safety
    /// As for `initialize`, after it succeeded; no queue may use a client
    /// VMID until this returns.
    pub async unsafe fn prepare_client_contexts(&mut self) -> Result<(), Error> {
        self.engine.prepare_clients().await
    }
    /// Make only the owned source page executable, then invalidate GFX
    /// VMID0's translations. Destination and every unowned PTE stay unchanged.
    /// # Safety
    /// Both GC12 queues and SDMA must be drained and exclusively held. No
    /// other test-page user, reset or page-table writer may run. Retain on
    /// failure/cancellation; do not submit on the queues until success.
    pub(crate) async unsafe fn prepare_shader_test(&mut self) -> Result<(), Error> {
        self.engine.prepare_shader_test().await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn aperture(&self) -> Option<Aperture> {
        self.engine.aperture
    }
    pub(crate) fn test_mapping(&mut self) -> Option<MmioRegion> {
        if !self.state().vmid0_ready() {
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
#[path = "amdgpu_gmc_navi48_tests.rs"]
pub(crate) mod tests;
