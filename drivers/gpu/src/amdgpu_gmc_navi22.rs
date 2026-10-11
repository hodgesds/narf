//! Navi22 VMID0 bring-up for an owned VRAM-only test aperture.
//! Linux gfxhub_v2_1.c / mmhub_v2_0.c / gmc_v10_0.c. No system-memory PTEs,
//! host DMA, user VMIDs, fault IRQs, clock gating or implicit recovery.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_gmc_navi22_regs.rs"]
mod regs;
use regs::{HubRegs, GFX, MM};
const BYTES: u64 = 16384; // PT, default page, source page, destination page
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
}
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
        Ok(Self {
            bases: [
                reg(ip::HW_ID_GC, &[(10, 3, 2)], 0, 0x1703)?,
                reg(ip::HW_ID_MMHUB, &[(2, 1, 0)], 0, 0x873)?,
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
                0x12d,
            )?,
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
fn flush<I: Io>(io: &mut I, nbio: u64) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    io.write(0x7f000, 0);
    io.read(nbio + 0xc3 * 4);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
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
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    vram_size: u64,
    state: State,
    aperture: Option<Aperture>,
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
                    io.read(layout.bases[0] + 0x16e7 * 4),
                ],
                size,
                address,
            )?;
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
            flush(io, layout.nbio);
            Ok(())
        })?;
        self.memory.publish(); // before either hub can retain a PT/default address
        self.aperture = Some(geometry.aperture);
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
                flush(io, layout.nbio);
                io.write(base + u64::from(r.inv_req) * 4, 0xf80001); // VMID0 + all PT caches
                Ok(())
            })?;
            self.wait(base + u64::from(r.inv_ack) * 4, 1).await?;
            if hub == Hub::Mm {
                self.access(|io| {
                    io.write(base + u64::from(r.inv_sem) * 4, 0);
                    Ok(())
                })?;
            }
        }
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
            engine: Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                vram_size: gpu.vram.size,
                state: State::Prepared,
                aperture: None,
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
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn aperture(&self) -> Option<Aperture> {
        self.engine.aperture
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gmc_navi22_tests.rs"]
mod tests;
