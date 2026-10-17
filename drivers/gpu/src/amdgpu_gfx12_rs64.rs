//! GC12 RS64 program counters after PSP authentication/RLC autoload, following
//! Linux gfx_v12_0_config_gfx_rs64. No queue activation or execution claim.
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_navi48_firmware as fw,
    amdgpu_navi48_ucode::Source, amdgpu_psp_ring::bank,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Revoked,
    DeviceGone,
    Readback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Configured,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Starts {
    pub pfp: u64,
    pub me: u64,
    pub mec: u64,
}
impl Starts {
    fn from_firmware(firmware: &fw::Firmware) -> Result<Self, Error> {
        let images = firmware.images().map_err(|_| Error::Invalid)?;
        let entry = |source| {
            images
                .iter()
                .find(|i| i.source() == source)
                .and_then(|i| i.entry_points())
                .map(|p| p.code)
                .ok_or(Error::Invalid)
        };
        Ok(Self {
            pfp: entry(Source::Pfp)?,
            me: entry(Source::Me)?,
            mec: entry(Source::Mec)?,
        })
    }
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    hyp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI48 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            gc: bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 0, 0x1fab)
                .map_err(|_| Error::Unsupported)?,
            hyp: bank(gpu, ip::HW_ID_GC, &[(12, 0, 1)], 1, 0x2938)
                .map_err(|_| Error::Unsupported)?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: constructor bounds both banks, caller owns indexing and
        // configure invokes this entire finite sequence under live authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same bounded banks and exclusive register ownership.
        unsafe { self.0.write32(address, value) };
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
fn write_checked(io: &mut impl Io, address: u64, value: u32) -> Result<(), Error> {
    io.write(address, value);
    let actual = io.read(address);
    if actual != value {
        checked(actual)?;
        return Err(Error::Readback);
    }
    Ok(())
}
fn program(io: &mut impl Io, l: Layout, starts: Starts) -> Result<(), Error> {
    if [starts.pfp, starts.me, starts.mec]
        .iter()
        .any(|v| *v == 0 || v % 4 != 0)
    {
        return Err(Error::Invalid);
    }
    let selector = l.hyp + 0x900 * 4;
    let prior = checked(io.read(selector))?;
    let result = (|| {
        // Inherited execution must not be reset. GC12.0.1 exposes 1x8 gfx
        // HQDs and 2x4 compute HQDs (gfx_v12_0_sw_init), independently of
        // its two/four firmware-stack counter banks programmed below.
        if checked(io.read(l.gc + 0xf40 * 4))? != 0
            || checked(io.read(l.hyp + 0x2807 * 4))? & 0x0c000000 != 0
        {
            return Err(Error::Busy);
        }
        write_checked(io, selector, 0)?;
        if checked(io.read(l.gc + 0x1f40 * 4))? & 1 != 0 {
            return Err(Error::Busy);
        }
        for (me, pipes, queues, reg) in [(0, 1, 8, 0x1e80), (1, 2, 4, 0x1fab)] {
            for pipe in 0..pipes {
                for queue in 0..queues {
                    write_checked(io, selector, (me << 2) | pipe | (queue << 8))?;
                    if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
        }
        // No await is allowed while the selector is changed. All reset pulses
        // preserve halt/step/cache controls and touch only the named pipe bits.
        for (me, pipes, base, lo, hi, control, reset, entry) in [
            (0, 2, l.gc, 0x1e44, 0x1e59, 0x803, 0x000c0000, starts.pfp),
            (0, 2, l.gc, 0x1e45, 0x1e79, 0x803, 0x00300000, starts.me),
            (1, 4, l.hyp, 0x2900, 0x2938, 0x2904, 0x000f0000, starts.mec),
        ] {
            let dwords = entry >> 2;
            for pipe in 0..pipes {
                write_checked(io, selector, (me << 2) | pipe)?;
                write_checked(io, base + lo * 4, dwords as u32)?;
                write_checked(io, base + hi * 4, (dwords >> 32) as u32)?;
            }
            write_checked(io, selector, 0)?;
            let address = l.hyp + control * 4;
            let value = checked(io.read(address))?;
            write_checked(io, address, value | reset)?;
            write_checked(io, address, value & !reset)?;
        }
        Ok(())
    })();
    // Restore even on an inactive-queue check or counter readback failure.
    write_checked(io, selector, prior)?;
    result
}
#[derive(Debug)]
pub struct Rs64 {
    io: Mmio,
    layout: Layout,
    authority: Cap<BusDeviceCap, Write>,
    starts: Starts,
    state: State,
}
impl Rs64 {
    /// Pure preparation; validates the exact device and immutable firmware set.
    /// # Safety
    /// Caller owns permanent mappings, this GPU's GRBM selector and every
    /// CP/MEC/MES queue, firmware, power and reset operation exclusively.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        firmware: &fw::Firmware,
    ) -> Result<Self, Error> {
        if fw::Target::resolve(gpu).map_err(|_| Error::Unsupported)? != firmware.target() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            io: Mmio(gpu.regs),
            layout: Layout::resolve(gpu)?,
            authority,
            starts: Starts::from_firmware(firmware)?,
            state: State::Prepared,
        })
    }
    /// Set program counters for two PFP/ME and four MEC firmware stacks.
    /// # Safety
    /// The matching firmware has completed PSP authentication and RLC autoload.
    /// No active queues, index users, reset or power transitions may run. This
    /// is one cold-start configuration, not a recovery or firmware reload path.
    pub unsafe fn configure(&mut self) -> Result<Starts, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self
            .authority
            .invoke(Op(|| program(&mut self.io, self.layout, self.starts)))
            .map_err(|_| Error::Revoked)
            .and_then(core::convert::identity);
        self.state = match result {
            Ok(()) => State::Configured,
            Err(e) => State::Failed(e),
        };
        result.map(|()| self.starts)
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn starts(&self) -> Option<Starts> {
        (self.state == State::Configured).then_some(self.starts)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gfx12_rs64_tests.rs"]
mod tests;
