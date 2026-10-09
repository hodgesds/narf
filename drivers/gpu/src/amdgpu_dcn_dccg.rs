//! DCN 3.1.4 DCCG: the per-DPP clock dividers, the OTG pixel rate dividers and
//! the DP stream clock routing a USB4 DPIA needs. Register offsets and fields
//! are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at DCCG base index 1;
//! sequencing follows Linux `dcn314_dccg.c`, `dcn20_dccg.c` and
//! `dcn314_hwseq.c::dcn314_calculate_dccg_k1_k2_values`.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::{Clocks, Consumers, Error},
    amdgpu_discovery as discovery,
};
use core::future::Future;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// The DCN versions this module drives. Unusually, every offset below is
/// identical on DCN 3.5 at the same base index 1 — `DPSTREAMCLK_CNTL` 0x004a,
/// `DTBCLK_P_CNTL` 0x0068, `DENTIST_DISPCLK_CNTL` 0x0064,
/// `OTG_PIXEL_RATE_DIV` 0x006f, `DPPCLK0_DTO_PARAM` 0x0099 and
/// `DPPCLK_DTO_CTRL` 0x00b6 all match — so this table is portable where the
/// other DCN modules' are not.
///
/// The entry is still one, because the SEQUENCE is not portable: this follows
/// `dcn314_dccg.c`, and DCN 3.5 has its own `dcn35_dccg.c` with different root
/// clock gating and DTBCLK handling. Matching register ids are not a licence to
/// drive another generation; check the sequencer before adding a row.
const DCN_VERSIONS: &[(u8, u8, u8)] = &[(3, 1, 4)];

const DPSTREAMCLK_CNTL: u64 = 0x004a;
const DTBCLK_P_CNTL: u64 = 0x0068;
const DENTIST_DISPCLK_CNTL: u64 = 0x0064;
const OTG_PIXEL_RATE_DIV: u64 = 0x006f;
const DPPCLK0_DTO_PARAM: u64 = 0x0099;
const DPPCLK_DTO_CTRL: u64 = 0x00b6;
/// The highest DCCG register this module touches, for the bank bound.
const LAST_REG: u32 = DPPCLK_DTO_CTRL as u32;
/// One per pixel pipe; see [`crate::amdgpu_dcn::DCN_PIPES`].
const INSTANCES: u8 = crate::amdgpu_dcn::DCN_PIPES;
/// `dccg2_update_dpp_dto` always divides against a full 8-bit modulo.
const DTO_MODULO: u32 = 0xff;

/// `enum pixel_rate_div`. The encoding is not the divisor: four is 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Divider {
    By1,
    By2,
    By4,
}
impl Divider {
    fn code(self) -> u32 {
        match self {
            Divider::By1 => 0,
            Divider::By2 => 1,
            Divider::By4 => 3,
        }
    }
}
/// What drives a DPIA's stream clock. `Dtbclk` is the routing an 8b/10b SST
/// tunnel uses; disabling it parks the stream clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamClock {
    Disabled,
    Dtbclk,
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: MmioRegion,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds the DCCG bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole DCCG owner.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    /// The global DPPCLK the per-pipe dividers are taken against.
    reference_dppclk_khz: u32,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            let new = (old & !mask) | (value & mask);
            io.write(reg, new);
            if io.read(reg) & mask != value & mask {
                return Err(Error::Invalid);
            }
            Ok(())
        })?
    }
    /// Program one pipe's DPPCLK divider. `phase / modulo` is the ratio of the
    /// pipe clock to the global clock, rounded up so the pipe is never starved.
    fn dpp_dto(&mut self, pipe: u8, requested_khz: u32) -> Result<(), Error> {
        if pipe >= INSTANCES {
            return Err(Error::Invalid);
        }
        let enable = 1 << (pipe as u32 * 4);
        let double_buffer = 1 << (pipe as u32 * 4 + 1);
        let reference = self.reference_dppclk_khz;
        if reference == 0 || requested_khz == 0 {
            // No clock to divide: park the pipe rather than leave a stale ratio.
            return self.update(DPPCLK_DTO_CTRL, enable, 0);
        }
        let phase = (DTO_MODULO as u64 * requested_khz as u64).div_ceil(reference as u64);
        if phase > DTO_MODULO as u64 {
            // The pipe cannot be asked for more than the global clock.
            return Err(Error::Invalid);
        }
        self.access(|io| {
            io.write(
                DPPCLK0_DTO_PARAM + pipe as u64,
                phase as u32 | DTO_MODULO << 16,
            )
        })?;
        self.update(DPPCLK_DTO_CTRL, enable | double_buffer, enable)
    }
}

impl<I: Io> Engine<I> {
    /// The OTG pixel rate dividers. A DisplayPort 8b/10b stream with one pixel
    /// per container and no ODM combine divides by one then four.
    fn set_pixel_rate_div(&mut self, otg: u8, k1: Divider, k2: Divider) -> Result<(), Error> {
        if otg >= INSTANCES {
            return Err(Error::Invalid);
        }
        // K1 is one bit and K2 two, three bits per OTG.
        let shift = otg as u32 * 3;
        self.update(
            OTG_PIXEL_RATE_DIV,
            0x7 << shift,
            (k1.code() | k2.code() << 1) << shift,
        )
    }
    /// Point one OTG's `DTBCLK_P` mux at DTBCLK0, or park it on DPREFCLK.
    /// `dccg314_set_dtbclk_p_src`: the source select is 2 for DTBCLK0 — zero
    /// selects DPREFCLK, so an enable alone routes the wrong clock. Three bits
    /// per OTG, a two-bit select then the enable.
    fn set_dtbclk_p_src(&mut self, otg: u8, source: StreamClock) -> Result<(), Error> {
        if otg >= INSTANCES {
            return Err(Error::Invalid);
        }
        let shift = otg as u32 * 3;
        let value = match source {
            StreamClock::Disabled => 0,
            StreamClock::Dtbclk => 2 | 1 << 2,
        };
        self.update(DTBCLK_P_CNTL, 0x7 << shift, value << shift)
    }
    /// Route a DPIA's stream clock from one OTG's DTBCLK_P, or park it.
    ///
    /// `dccg314_set_dpstreamclk` does two things, in this order: it points the
    /// OTG's `DTBCLK_P` mux at DTBCLK0, then selects that OTG as the DPIA's
    /// stream-clock source. Without the first the mux stays on DPREFCLK and
    /// the DPIA is clocked by whatever that happens to be; without the second
    /// every DPIA takes OTG 0, so a stream on any other pipe runs at the wrong
    /// pixel rate. Four bits per DPIA, a three-bit OTG select then the enable.
    fn set_dp_stream_clock(&mut self, dpia: u8, otg: u8, source: StreamClock) -> Result<(), Error> {
        if dpia >= INSTANCES || otg >= INSTANCES {
            return Err(Error::Invalid);
        }
        self.set_dtbclk_p_src(otg, source)?;
        let shift = dpia as u32 * 4;
        let value = match source {
            StreamClock::Disabled => 0,
            StreamClock::Dtbclk => otg as u32 | 1 << 3,
        };
        self.update(DPSTREAMCLK_CNTL, 0xf << shift, value << shift)
    }
    fn dispclk_dividers(&mut self) -> Result<(u32, u32), Error> {
        let value = self.access(|io| io.read(DENTIST_DISPCLK_CNTL))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok((value & 0x7f, (value >> 8) & 0x7f))
    }
    fn resync_dio_fifo(&mut self) -> Result<(), Error> {
        let (_, read_divider) = self.dispclk_dividers()?;
        self.update(DENTIST_DISPCLK_CNTL, 0x7f, read_divider)
    }
}

/// The sole owner of the DCN314 clock generator. Holding it does not grant the
/// display clock mailbox: the global DISPCLK/DPPCLK still belong to
/// [`crate::amdgpu_dcn_clk::ClockManager`], and this only divides them.
#[derive(Debug)]
pub struct Dccg(Engine<Mmio>);
impl Dccg {
    /// # Safety
    /// Caller exclusively owns the DCCG register bank for this object's
    /// lifetime, holds matching PCI authority and a permanent register mapping,
    /// and must not let another client reprogram the same dividers.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let base =
            crate::amdgpu_psp_ring::bank(gpu, discovery::HW_ID_DCN, DCN_VERSIONS, 1, LAST_REG)
                .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: gpu.regs,
                base,
            },
            authority,
            reference_dppclk_khz: 0,
        }))
    }
    pub fn set_pixel_rate_div(&mut self, otg: u8, k1: Divider, k2: Divider) -> Result<(), Error> {
        self.0.set_pixel_rate_div(otg, k1, k2)
    }
    pub fn set_dp_stream_clock(
        &mut self,
        dpia: u8,
        otg: u8,
        source: StreamClock,
    ) -> Result<(), Error> {
        self.0.set_dp_stream_clock(dpia, otg, source)
    }
    /// The DISPCLK divider DENTIST has applied, and the one requested.
    pub fn dispclk_dividers(&mut self) -> Result<(u32, u32), Error> {
        self.0.dispclk_dividers()
    }
    /// `dccg314_trigger_dio_fifo_resync`: copy the divider DENTIST is really
    /// running into the request field so the DIO FIFOs restart against it.
    pub fn resync_dio_fifo(&mut self) -> Result<(), Error> {
        self.0.resync_dio_fifo()
    }
    /// Record the global DPPCLK the per-pipe dividers are taken against. The
    /// clock manager supplies it; a divider programmed against a stale
    /// reference would run its pipe at the wrong rate.
    pub fn set_reference_dppclk(&mut self, global_dppclk_khz: u32) {
        self.0.reference_dppclk_khz = global_dppclk_khz;
    }
    pub fn update_dpp_dto(&mut self, pipe: u8, requested_khz: u32) -> Result<(), Error> {
        self.0.dpp_dto(pipe, requested_khz)
    }
}

/// One active pipe driven at the full global DPPCLK, with the firmware
/// notification the clock manager owes DMCUB left to the loader.
#[derive(Debug)]
pub struct SinglePipe<'a> {
    pub dccg: &'a mut Dccg,
    pub pipe: u8,
}
impl Consumers for SinglePipe<'_> {
    fn dpp_dto(&mut self, global_dppclk_khz: u32) -> Result<(), Error> {
        self.dccg.set_reference_dppclk(global_dppclk_khz);
        self.dccg.update_dpp_dto(self.pipe, global_dppclk_khz)
    }
    fn notify(&mut self, _: Clocks) -> impl Future<Output = Result<(), Error>> + Send {
        // The DMCUB clock notification needs the firmware mailbox, which this
        // module does not own. The loader sends it.
        core::future::ready(Ok(()))
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_dccg_tests.rs"]
mod tests;
