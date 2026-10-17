//! GC12.0.1 cold-start constants, RLC clear-state storage and RS64 execution.
//! Sources: Linux gfx_v12_0.c, GC12 headers and NBIO7.7/NBIF6.3.1 headers.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
#[path = "amdgpu_gfx12_clearstate.rs"]
mod clearstate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Timeout,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Settling,
    Ready,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub revision: u8,
    pub clear_state_address: u64,
    pub clear_state_dwords: u32,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    hyp: u64,
    nbio: u64,
    strap: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI48
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let gc =
            bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x1fab).map_err(|_| Error::Unsupported)?;
        let hyp =
            bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 1, 0x4c80).map_err(|_| Error::Unsupported)?;
        let nbio = bank(
            gpu,
            ip::HW_ID_NBIF,
            &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
            2,
            0x12d,
        )
        .map_err(|_| Error::Unsupported)?;
        let nbif = ip::find_ip(&gpu.ip_blocks, ip::HW_ID_NBIF, 0).ok_or(Error::Unsupported)?;
        let strap = nbio + if nbif.major == 6 { 0x1c * 4 } else { 0x15 * 4 };
        Ok(Self {
            gc,
            hyp,
            nbio,
            strap,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    async fn delay(&mut self) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(50).as_instant()).await;
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: exact discovery banks bounded by Layout and live Cap::invoke.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same exclusive register ownership and current authority.
        unsafe { self.0.write32(address, value) };
    }
    fn memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: initialize bounds every dword to the retained, owned page.
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
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
fn write(io: &mut impl Io, at: u64, value: u32) -> Result<(), Error> {
    io.write(at, value);
    let got = io.read(at);
    if got != value {
        checked(got)?;
        return Err(Error::Readback);
    }
    Ok(())
}
fn update(io: &mut impl Io, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = checked(io.read(at))?;
    write(io, at, (old & !mask) | (value & mask))
}
fn indexed<T, I: Io>(
    io: &mut I,
    l: Layout,
    f: impl FnOnce(&mut I) -> Result<T, Error>,
) -> Result<T, Error> {
    let old = checked(io.read(l.hyp + 0x900 * 4))?;
    let result = f(io);
    write(io, l.hyp + 0x900 * 4, old)?;
    result
}
fn preflight(io: &mut impl Io, l: Layout) -> Result<u8, Error> {
    if checked(io.read(l.hyp + 0x2807 * 4))? & 0x0c000000 != 0
        || checked(io.read(l.gc + 0xf40 * 4))? != 0
    {
        return Err(Error::Busy);
    }
    indexed(io, l, |io| {
        write(io, l.hyp + 0x900 * 4, 0)?;
        if checked(io.read(l.gc + 0x1f40 * 4))? & 1 != 0 {
            return Err(Error::Busy);
        }
        for (me, pipes, queues, reg) in [(0, 1, 8, 0x1e80), (1, 2, 4, 0x1fab), (3, 2, 1, 0x1fab)] {
            for pipe in 0..pipes {
                for queue in 0..queues {
                    write(io, l.hyp + 0x900 * 4, (me << 2) | pipe | (queue << 8))?;
                    if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(((checked(io.read(l.strap))? >> 24) & 15) as u8)
}
fn constants(io: &mut impl Io, l: Layout, revision: u8) -> Result<(), Error> {
    let selector = l.hyp + 0x2200 * 4;
    let prior = checked(io.read(selector))?;
    let result = (|| {
        write(io, selector, 0xe0000000)?;
        update(io, l.gc + 0x13d2 * 4, 0x8000, 0x8000)?;
        if revision == 0 {
            update(io, l.gc + 0x13d2 * 4, 15, 15)?;
            update(io, l.gc + 0x1425 * 4, 0x03000000, 0x03000000)?;
            update(io, l.hyp + 0x2e19 * 4, 0x70, 0x20)?;
        }
        update(io, l.gc + 0xda0 * 4, 0xfff, 0xff)?;
        // One graphics pipe.
        update(io, l.gc + 0x13bb * 4, 3, 1)?;
        indexed(io, l, |io| {
            // gfx_v12_0_constants_init: every graphics VMID (0 up to
            // first_kfd_vmid, 8) gets DEFAULT_SH_MEM_CONFIG (64-bit
            // addressing, unaligned access, instruction prefetch 3); client
            // VMIDs also get gmc_v12_0's private (0x1000 << 48) and shared
            // (0x2000 << 48) apertures in SH_MEM_BASES.
            for vmid in 0..8 {
                write(io, l.hyp + 0x900 * 4, vmid << 4)?;
                write(io, l.hyp + 0x9e4 * 4, 0xc00c)?;
                if vmid != 0 {
                    write(io, l.hyp + 0x9e3 * 4, 0x2000 << 16 | 0x1000)?;
                }
            }
            write(io, l.hyp + 0x900 * 4, 0)?;
            // No IRQ source is installed; disable inherited GUI-idle interrupts.
            update(io, l.gc + 0x1e0a * 4, 0x003c0000, 0)?;
            // gfx_v12_0_gpu_early_init fixes GC12's context count at eight.
            write(io, l.gc + 0x1e4e * 4, 7)?;
            write(io, l.gc + 0x1deb * 4, 1)
        })
    })();
    write(io, selector, prior)?;
    result
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    clear: Reservation,
    state: State,
    report: Option<Report>,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn initialize(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner().await;
        self.state = match result {
            Ok(report) => {
                self.report = Some(report);
                State::Ready
            }
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn initialize_inner(&mut self) -> Result<Report, Error> {
        let l = self.layout;
        let address = self.clear.address();
        let map = self.clear.mapping();
        let revision = self.access(|io| {
            let fb = u64::from(checked(io.read(l.gc + 0x1614 * 4))? & 0xffffff) << 24;
            let end = (u64::from(checked(io.read(l.gc + 0x1615 * 4))? & 0xffffff) + 1) << 24;
            if address < fb
                || address.checked_add(4096).is_none_or(|a| a > end)
                || end >= 1 << 48
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            let revision = preflight(io, l)?;
            constants(io, l, revision)?;
            let clear = clearstate::image();
            for i in 0..1024 {
                io.memory(map, i * 4, clear.get(i as usize).copied().unwrap_or(0));
            }
            fence(Ordering::SeqCst);
            io.write(0x7f000, 0);
            io.read(l.nbio + 0xc3 * 4);
            fence(Ordering::SeqCst);
            Ok(revision)
        })?;
        self.clear.publish();
        self.access(|io| {
            // Source order: high, low, length, then enable RLC save/restore.
            write(io, l.hyp + 0x988 * 4, (address >> 32) as u32)?;
            write(io, l.hyp + 0x987 * 4, address as u32)?;
            write(io, l.hyp + 0x989 * 4, clearstate::DWORDS as u32)?;
            update(io, l.hyp + 0x4c80 * 4, 3, 3)?;
            // Activate four MEC firmware stacks without resetting any queue.
            update(io, l.hyp + 0x2904 * 4, 0x7c0f0010, 0x3c000000)?;
            update(io, l.hyp + 0x803 * 4, 0x14000000, 0)
        })?;
        self.state = State::Settling;
        self.io.delay().await;
        let deadline = narf_time::Deadline::after_us(2_100_000);
        loop {
            let status = self.access(|io| checked(io.read(l.gc + 0xf40 * 4)))?;
            if status == 0 {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.io.delay().await;
        }
        Ok(Report {
            revision,
            clear_state_address: address,
            clear_state_dwords: clearstate::DWORDS as u32,
        })
    }
}
#[derive(Debug)]
pub struct Setup(Engine<Mmio>);
impl Setup {
    /// # Safety
    /// Own this physical GPU, permanent register/VRAM mappings, all CP/MES
    /// queues, GRBM indexing and reset/PM transitions. Pool covers inventoried
    /// free VRAM only. Retain the owner until independently reset on failure.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        Ok(Self(Engine {
            io: Mmio(gpu.regs),
            authority,
            layout: Layout::resolve(gpu)?,
            clear: pool.reserve(4096).map_err(|_| Error::Allocation)?,
            state: State::Prepared,
            report: None,
        }))
    }
    /// # Safety
    /// The matching PSP/RLC firmware and RS64 entry points are installed,
    /// power policy excludes automatic gating, GMC and VRAM DMA proof are
    /// ready, and no CP/MES queue is active. This is one cold start, not recovery.
    pub async unsafe fn initialize(&mut self) -> Result<Report, Error> {
        self.0.initialize().await
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    pub fn report(&self) -> Option<Report> {
        self.0.report
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx12_setup_tests.rs"]
mod tests;
