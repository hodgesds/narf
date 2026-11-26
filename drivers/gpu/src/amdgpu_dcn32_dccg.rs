//! Navi31 / Navi32 (DCN 3.2.0) and Navi33 (DCN 3.2.1) DCCG: the per-DPP
//! clock dividers, the OTG pixel rate dividers, the DTBCLK DTO the HPO
//! stream encoder needs, and the SYMCLK32 routing a UHBR link needs.
//! Register offsets and fields are `dcn_3_2_0_offset.h` /
//! `dcn_3_2_0_sh_mask.h` at DCCG base index 1 (and base index 2 for the
//! DTBCLK DTO phase/modulo); sequencing follows Linux `dcn32_dccg.c` and
//! `dcn31_dccg.c` (`dccg32_funcs`).
//!
//! The shared [`crate::amdgpu_dcn_dccg::Dccg`] covers DCN 3.0 / 3.1.4 /
//! 3.1.5 only: its register layout is the same on 3.2, but it refuses the
//! pixel-rate-div, DTBCLK_P and DP-stream-clock operations anywhere but
//! 3.1.4, and it has no SYMCLK32 or DTBCLK-DTO surface at all — both exist
//! in `dccg32_funcs` and neither exists in `dccg31_funcs`. This owner is
//! therefore self-contained for DCN 3.2, reusing only the shared divider
//! encodings ([`crate::amdgpu_dcn_dccg::Divider`],
//! [`crate::amdgpu_dcn_dccg::StreamClock`]).
//!
//! DCN 3.2 differences that matter here, all verified against
//! `dcn_3_2_0_offset.h` / `_sh_mask.h`:
//! - the OTG pixel rate dividers exist (unlike dccg31): K1 one bit, K2 two
//!   bits, three bits per OTG;
//! - `set_dtbclk_dto` is the DP path on 3.2, not the DP DTO against
//!   DPREFCLK: the DTBCLK DTO divides the pixel clock by four
//!   (`pixclk / 4`), its phase/modulo live at base index 2, and the DTO
//!   source select is 2 for the HPO case (1 selects the DP DTO, 0 HDMI);
//! - SYMCLK32_SE_CNTL (0x65) and SYMCLK32_LE_CNTL (0x66) are new: a
//!   three-bit PHYD32CLK source select plus an enable, four bits per
//!   stream/link encoder. The `phyd32clk_clock_source` enum itself
//!   (PHYD32CLKA..G) is not in the Linux reference tree this lane
//!   grounded against, so the source is carried as a raw PHY index;
//! - the dentist dividers, DPPCLK DTO and DP stream clock keep the
//!   3.1.4 layout and encodings.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn_clk::{Clocks, Consumers, Error},
    amdgpu_dcn_dccg::{Divider, StreamClock},
    amdgpu_dcn_profile::Profile,
};
use core::future::Future;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=1
const DPSTREAMCLK_CNTL: u64 = 0x004a; // linux: regDPSTREAMCLK_CNTL
const SYMCLK32_SE_CNTL: u64 = 0x0065; // linux: regSYMCLK32_SE_CNTL
const SYMCLK32_LE_CNTL: u64 = 0x0066; // linux: regSYMCLK32_LE_CNTL
const DENTIST_DISPCLK_CNTL: u64 = 0x0064; // linux: regDENTIST_DISPCLK_CNTL
const DTBCLK_P_CNTL: u64 = 0x0068; // linux: regDTBCLK_P_CNTL
const OTG_PIXEL_RATE_DIV: u64 = 0x006f; // linux: regOTG_PIXEL_RATE_DIV
const OTG0_PIXEL_RATE_CNTL: u64 = 0x0080; // linux: regOTG0_PIXEL_RATE_CNTL
const DP_DTO0_PHASE: u64 = 0x0081; // linux: regDP_DTO0_PHASE
const DP_DTO0_MODULO: u64 = 0x0082; // linux: regDP_DTO0_MODULO
const DPPCLK0_DTO_PARAM: u64 = 0x0099; // linux: regDPPCLK0_DTO_PARAM
const DPPCLK_DTO_CTRL: u64 = 0x00b6; // linux: regDPPCLK_DTO_CTRL
/// The highest DCCG bank-1 register this module touches, for the bank bound.
const LAST_BANK1: u32 = DPPCLK_DTO_CTRL as u32;
// linux-ctx: hdr=dcn seg=2
const DTBCLK_DTO0_PHASE: u64 = 0x0018; // linux: regDTBCLK_DTO0_PHASE
const DTBCLK_DTO0_MODULO: u64 = 0x001f; // linux: regDTBCLK_DTO0_MODULO
/// The highest DCCG bank-2 register this module touches, for the bank bound.
const LAST_BANK2: u32 = 0x0022; // linux: regDTBCLK_DTO3_MODULO
/// One OTG's pixel clock source and its DP DTO, stride 4.
const DTO_STRIDE: u64 = 4; // linux: regOTG1_PIXEL_RATE_CNTL - regOTG0_PIXEL_RATE_CNTL
const DP_DTO0_ENABLE: u32 = 0x0000_0010; // linux: OTG0_PIXEL_RATE_CNTL__DP_DTO0_ENABLE_MASK
/// `PIPE0_DTO_SRC_SEL` is two bits on DCN 3.2 (0x3000).
const PIPE0_DTO_SRC_SEL_SHIFT: u32 = 12; // linux: OTG0_PIXEL_RATE_CNTL__PIPE0_DTO_SRC_SEL__SHIFT
/// `DTBCLK_DTO0_ENABLE` (bit 3) and `DTBCLKDTO0_ENABLE_STATUS` (bit 6).
const DTBCLK_DTO_ENABLE: u32 = 1 << 3; // linux: OTG0_PIXEL_RATE_CNTL__DTBCLK_DTO0_ENABLE__SHIFT
const DTBCLKDTO_ENABLE_STATUS: u32 = 1 << 6; // linux: OTG0_PIXEL_RATE_CNTL__DTBCLKDTO0_ENABLE_STATUS__SHIFT
/// `OTG0_ADD_PIXEL` (bit 8) and `OTG0_DROP_PIXEL` (bit 9).
const OTG_ADD_PIXEL: u32 = 1 << 8; // linux: OTG0_PIXEL_RATE_CNTL__OTG0_ADD_PIXEL__SHIFT
const OTG_DROP_PIXEL: u32 = 1 << 9; // linux: OTG0_PIXEL_RATE_CNTL__OTG0_DROP_PIXEL__SHIFT
/// `dccg2_update_dpp_dto` always divides against a full 8-bit modulo.
const DTO_MODULO: u32 = 0xff; // linux: n/a (literal in dcn20_dccg.c:dccg2_update_dpp_dto, modulo)

/// A DCCG register: bank 1 (the DCCG block) or bank 2 (the DTBCLK DTO
/// phase/modulo, which live outside the DCCG block on 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reg {
    Bank1(u64),
    Bank2(u64),
}

/// What drives a SYMCLK32 stream/link encoder clock. `Refclk` parks the
/// mux on the reference clock; `Phy(n)` selects PHYD32CLK n. The
/// `phyd32clk_clock_source` enum (PHYD32CLKA..G) is not in the sparse
/// Linux reference tree, so the PHY index is carried raw; the HPO owner
/// supplies the PHY its link encoder is routed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symclk32Source {
    Refclk,
    Phy(u8),
}
impl Symclk32Source {
    fn code(self) -> Result<u32, Error> {
        match self {
            Symclk32Source::Refclk => Ok(0),
            Symclk32Source::Phy(n) if n <= 6 => Ok(u32::from(n)),
            Symclk32Source::Phy(_) => Err(Error::Invalid),
        }
    }
}

trait Io: Send {
    fn read(&mut self, reg: Reg) -> u32;
    fn write(&mut self, reg: Reg, value: u32);
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base1: u64,
    base2: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: Reg) -> u32 {
        let (base, id) = match reg {
            Reg::Bank1(id) => (self.base1, id),
            Reg::Bank2(id) => (self.base2, id),
        };
        // SAFETY: constructor bounds both DCCG banks and retains the mapping.
        unsafe { self.regs.read32(base + id * 4) }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        let (base, id) = match reg {
            Reg::Bank1(id) => (self.base1, id),
            Reg::Bank2(id) => (self.base2, id),
        };
        // SAFETY: same bounded banks; this is the sole DCN 3.2 DCCG owner.
        unsafe { self.regs.write32(base + id * 4, value) };
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
    profile: Profile,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: Reg, mask: u32, value: u32) -> Result<(), Error> {
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
        if pipe >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        // linux-lit: 4=DPPCLK_DTO_CTRL__DPPCLK1_DTO_ENABLE__SHIFT - DPPCLK_DTO_CTRL__DPPCLK0_DTO_ENABLE__SHIFT
        let enable = 1 << (pipe as u32 * 4);
        // linux-lit: 1=DPPCLK_DTO_CTRL__DPPCLK0_DTO_DB_EN__SHIFT
        let double_buffer = 1 << (pipe as u32 * 4 + 1);
        let reference = self.reference_dppclk_khz;
        if reference == 0 || requested_khz == 0 {
            // No clock to divide: park the pipe rather than leave a stale ratio.
            return self.update(Reg::Bank1(DPPCLK_DTO_CTRL), enable, 0);
        }
        let phase = (DTO_MODULO as u64 * requested_khz as u64).div_ceil(reference as u64);
        if phase > DTO_MODULO as u64 {
            // The pipe cannot be asked for more than the global clock.
            return Err(Error::Invalid);
        }
        self.access(|io| {
            io.write(
                Reg::Bank1(DPPCLK0_DTO_PARAM + pipe as u64),
                // linux-lit: 16=DPPCLK0_DTO_PARAM__DPPCLK0_DTO_MODULO__SHIFT
                phase as u32 | DTO_MODULO << 16,
            )
        })?;
        self.update(Reg::Bank1(DPPCLK_DTO_CTRL), enable | double_buffer, enable)
    }
    /// The OTG pixel rate dividers. `dccg32_set_pixel_rate_div`: K1 is one
    /// bit and K2 two, three bits per OTG; a request that matches the
    /// current programming is a no-op (Linux reads back first).
    fn set_pixel_rate_div(&mut self, otg: u8, k1: Divider, k2: Divider) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let shift = otg as u32 * 3;
        let (cur_k1, cur_k2) = self.get_pixel_rate_div(otg)?;
        if cur_k1 == k1.code() && cur_k2 == k2.code() {
            return Ok(());
        }
        self.update(
            Reg::Bank1(OTG_PIXEL_RATE_DIV),
            0x7 << shift,
            (k1.code() | k2.code() << 1) << shift,
        )
    }
    fn get_pixel_rate_div(&mut self, otg: u8) -> Result<(u32, u32), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let value = self.access(|io| io.read(Reg::Bank1(OTG_PIXEL_RATE_DIV)))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        let shift = otg as u32 * 3;
        // linux-lit: 1=OTG_PIXEL_RATE_DIV__OTG0_PIXEL_RATE_DIVK1_MASK
        // linux-lit: 6=OTG_PIXEL_RATE_DIV__OTG0_PIXEL_RATE_DIVK2_MASK
        Ok(((value >> shift) & 0x1, (value >> (shift + 1)) & 0x3))
    }
    /// Point one OTG's `DTBCLK_P` mux at DTBCLK0, or park it on DPREFCLK.
    /// `dccg32_set_dtbclk_p_src`: the source select is 2 for DTBCLK0 — zero
    /// selects DPREFCLK, so an enable alone routes the wrong clock. Three bits
    /// per OTG, a two-bit select then the enable.
    fn set_dtbclk_p_src(&mut self, otg: u8, source: StreamClock) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let shift = otg as u32 * 3;
        let value = match source {
            StreamClock::Disabled => 0,
            StreamClock::Dtbclk => 2 | 1 << 2,
        };
        self.update(Reg::Bank1(DTBCLK_P_CNTL), 0x7 << shift, value << shift)
    }
    /// Route an HPO stream encoder's clock from one OTG's DTBCLK_P, or park
    /// it. `dccg32_set_dpstreamclk` does two things, in this order: it points
    /// the OTG's `DTBCLK_P` mux at DTBCLK0, then selects that OTG as the HPO
    /// instance's stream-clock source. Four bits per HPO instance, a
    /// three-bit OTG select then the enable.
    fn set_dp_stream_clock(&mut self, hpo: u8, otg: u8, source: StreamClock) -> Result<(), Error> {
        if hpo >= 4 || otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        self.set_dtbclk_p_src(otg, source)?;
        let shift = hpo as u32 * 4;
        let value = match source {
            StreamClock::Disabled => 0,
            StreamClock::Dtbclk => otg as u32 | 1 << 3,
        };
        self.update(Reg::Bank1(DPSTREAMCLK_CNTL), 0xf << shift, value << shift)
    }
    /// `dccg32_set_dtbclk_dto`: the DTBCLK DTO generates the pixel-valid
    /// signal for an OTG feeding an HPO stream encoder. The DTO output rate
    /// is a quarter of the pixel rate, so phase/modulo is
    /// `(pixclk / 4) / ref_dtbclk`; the source select is set only after the
    /// DTO is enabled, to 2. Disabling parks the select on 1 (DP DTO) for a
    /// DisplayPort stream or 0 (HDMI) and clears the ratio.
    async fn set_dtbclk_dto(
        &mut self,
        otg: u8,
        pixclk_khz: u32,
        ref_dtbclk_khz: u32,
        is_hdmi: bool,
    ) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let at = u64::from(otg) * DTO_STRIDE;
        let cntl = Reg::Bank1(OTG0_PIXEL_RATE_CNTL + at);
        if ref_dtbclk_khz != 0 && pixclk_khz != 0 {
            let req_dtbclk_khz = pixclk_khz / 4;
            if req_dtbclk_khz == 0 {
                return Err(Error::Invalid);
            }
            // phase / modulo = dtbclk / dtbclk ref, in Hz (x1000), not kHz.
            let modulo = ref_dtbclk_khz * 1000;
            let phase = req_dtbclk_khz * 1000;
            self.access(|io| {
                io.write(Reg::Bank2(DTBCLK_DTO0_MODULO + u64::from(otg)), modulo);
                io.write(Reg::Bank2(DTBCLK_DTO0_PHASE + u64::from(otg)), phase);
            })?;
            self.update(cntl, DTBCLK_DTO_ENABLE, DTBCLK_DTO_ENABLE)?;
            // linux-lit: 100=dccg32_set_dtbclk_dto REG_WAIT retries, 1 us apart
            let deadline = narf_time::Deadline::after_us(100);
            #[cfg(feature = "kernel-test")]
            let mut polls = self.io.wait_poll_limit();
            loop {
                let reg = self.access(|io| io.read(cntl))?;
                if reg == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                if reg & DTBCLKDTO_ENABLE_STATUS != 0 {
                    break;
                }
                #[cfg(feature = "kernel-test")]
                if let Some(left) = &mut polls {
                    if *left == 0 {
                        return Err(Error::Timeout);
                    }
                    *left -= 1;
                    narf_scheduler::yield_now().await;
                    continue;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
            }
            // Program the pixel rate dividers for DIVK1 and DIVK2, then set
            // the DTO source select to 2 (DTBCLK DTO).
            self.set_pixel_rate_div(otg, Divider::By1, Divider::By1)?;
            self.update(
                cntl,
                0x3 << PIPE0_DTO_SRC_SEL_SHIFT,
                2 << PIPE0_DTO_SRC_SEL_SHIFT,
            )
        } else {
            let select = if is_hdmi { 0 } else { 1 };
            self.update(
                cntl,
                DTBCLK_DTO_ENABLE | 0x3 << PIPE0_DTO_SRC_SEL_SHIFT,
                select << PIPE0_DTO_SRC_SEL_SHIFT,
            )?;
            self.access(|io| {
                io.write(Reg::Bank2(DTBCLK_DTO0_MODULO + u64::from(otg)), 0);
                io.write(Reg::Bank2(DTBCLK_DTO0_PHASE + u64::from(otg)), 0);
            })
        }
    }
    /// `dcn31_program_pix_clk` for a DisplayPort 8b/10b stream on the DIO:
    /// the OTG's DP DTO against DPREFCLK, with PIPE0_DTO_SRC_SEL = 1. (The
    /// HPO path uses [`Self::set_dtbclk_dto`] instead.)
    fn set_dp_dto(&mut self, otg: u8, pixel_khz: u32, reference_khz: u32) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        if pixel_khz == 0 || reference_khz == 0 {
            return Err(Error::Invalid);
        }
        let (phase, modulo) = crate::amdgpu_navi22_modeset::dp_dto_ratio(pixel_khz, reference_khz);
        // A DTO divides its reference; it cannot synthesise a faster clock.
        if phase > modulo {
            return Err(Error::Invalid);
        }
        let at = u64::from(otg) * DTO_STRIDE;
        self.access(|io| {
            io.write(Reg::Bank1(DP_DTO0_PHASE + at), phase);
            io.write(Reg::Bank1(DP_DTO0_MODULO + at), modulo);
        })?;
        self.update(
            Reg::Bank1(OTG0_PIXEL_RATE_CNTL + at),
            DP_DTO0_ENABLE | 0x3 << PIPE0_DTO_SRC_SEL_SHIFT,
            DP_DTO0_ENABLE | 1 << PIPE0_DTO_SRC_SEL_SHIFT,
        )
    }
    /// Route one HPO stream encoder's SYMCLK32 at PHYD32CLK `source`, or park
    /// it on the reference clock. `dccg31_enable_symclk32_se`: four bits per
    /// stream encoder, a three-bit source select then the enable. (The root
    /// clock gating Linux applies when `root_clock_optimization` asks for it
    /// lives in DCCG_GATE_DISABLE_CNTL3, which no in-tree owner programs;
    /// this owner does not gate the root clock.)
    fn set_symclk32_se(&mut self, se: u8, source: Symclk32Source) -> Result<(), Error> {
        if se >= 4 {
            return Err(Error::Invalid);
        }
        let code = source.code()?;
        let shift = se as u32 * 4;
        let value = match source {
            Symclk32Source::Refclk => 0,
            Symclk32Source::Phy(_) => code | 1 << 3,
        };
        self.update(Reg::Bank1(SYMCLK32_SE_CNTL), 0xf << shift, value << shift)
    }
    /// Route one HPO link encoder's SYMCLK32, as [`Self::set_symclk32_se`].
    /// Two link encoders on DCN 3.2.
    fn set_symclk32_le(&mut self, le: u8, source: Symclk32Source) -> Result<(), Error> {
        if le >= 2 {
            return Err(Error::Invalid);
        }
        let code = source.code()?;
        let shift = le as u32 * 4;
        let value = match source {
            Symclk32Source::Refclk => 0,
            Symclk32Source::Phy(_) => code | 1 << 3,
        };
        self.update(Reg::Bank1(SYMCLK32_LE_CNTL), 0xf << shift, value << shift)
    }
    fn dispclk_dividers(&mut self) -> Result<(u32, u32), Error> {
        let value = self.access(|io| io.read(Reg::Bank1(DENTIST_DISPCLK_CNTL)))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        // linux-lit: 0x7f=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_WDIVIDER_MASK
        // linux-lit: 8=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_RDIVIDER__SHIFT
        Ok((value & 0x7f, (value >> 8) & 0x7f))
    }
    async fn dentist(&mut self, disp: u8, dpp: u8) -> Result<(), Error> {
        if !(8..=127).contains(&disp) || !(8..=127).contains(&dpp) {
            return Err(Error::Invalid);
        }
        // dcn20_update_clocks_update_dentist. The caller has retired every
        // stream, so the DID127 FIFO add/drop-pixel loops have no consumers.
        // These are requests, not ordinary readback registers: wait for both
        // the completion bit and the actual DISP divider to settle.
        for (mask, value, done, timeout_us, interval_us) in [
            // linux-lit: 0x7f=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_WDIVIDER_MASK
            // linux-lit: 19=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_CHG_DONE__SHIFT
            (0x7f, u32::from(disp), 1 << 19, 100_000, 50),
            // linux-lit: 0x7f000000=DENTIST_DISPCLK_CNTL__DENTIST_DPPCLK_WDIVIDER_MASK
            // linux-lit: 24=DENTIST_DISPCLK_CNTL__DENTIST_DPPCLK_WDIVIDER__SHIFT
            // linux-lit: 20=DENTIST_DISPCLK_CNTL__DENTIST_DPPCLK_CHG_DONE__SHIFT
            (0x7f00_0000, u32::from(dpp) << 24, 1 << 20, 500, 5),
        ] {
            self.update(Reg::Bank1(DENTIST_DISPCLK_CNTL), mask, value)?;
            let deadline = narf_time::Deadline::after_us(timeout_us);
            #[cfg(feature = "kernel-test")]
            let mut polls = self.io.wait_poll_limit();
            loop {
                let reg = self.access(|io| io.read(Reg::Bank1(DENTIST_DISPCLK_CNTL)))?;
                if reg == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                // linux-lit: 19=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_CHG_DONE__SHIFT
                // linux-lit: 8=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_RDIVIDER__SHIFT
                // linux-lit: 0x7f=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_RDIVIDER_MASK >> DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_RDIVIDER__SHIFT
                if reg & done != 0 && (done != 1 << 19 || (reg >> 8) & 0x7f == u32::from(disp)) {
                    break;
                }
                #[cfg(feature = "kernel-test")]
                if let Some(left) = &mut polls {
                    if *left == 0 {
                        return Err(Error::Timeout);
                    }
                    *left -= 1;
                    narf_scheduler::yield_now().await;
                    continue;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(interval_us).as_instant())
                    .await;
            }
        }
        Ok(())
    }
    fn resync_dio_fifo(&mut self) -> Result<(), Error> {
        let (_, read_divider) = self.dispclk_dividers()?;
        // linux-lit: 0x7f=DENTIST_DISPCLK_CNTL__DENTIST_DISPCLK_WDIVIDER_MASK
        self.update(Reg::Bank1(DENTIST_DISPCLK_CNTL), 0x7f, read_divider)
    }
    /// `dccg32_otg_add_pixel` / `dccg32_otg_drop_pixel`: nudge one OTG's
    /// pixel counter, for the FIFO resync sequence.
    fn otg_add_pixel(&mut self, otg: u8) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        self.update(
            Reg::Bank1(OTG0_PIXEL_RATE_CNTL + u64::from(otg) * DTO_STRIDE),
            OTG_ADD_PIXEL,
            OTG_ADD_PIXEL,
        )
    }
    fn otg_drop_pixel(&mut self, otg: u8) -> Result<(), Error> {
        if otg >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        self.update(
            Reg::Bank1(OTG0_PIXEL_RATE_CNTL + u64::from(otg) * DTO_STRIDE),
            OTG_DROP_PIXEL,
            OTG_DROP_PIXEL,
        )
    }
}

/// The sole owner of the DCN 3.2 clock generator. Holding it does not grant the
/// display clock mailbox: the global DISPCLK/DPPCLK still belong to the
/// DCN 3.2 clock manager ([`crate::amdgpu_dcn32_clk::ClockManager`]), and
/// this only divides them.
#[derive(Debug)]
pub struct Dccg32(Engine<Mmio>);
impl Dccg32 {
    /// # Safety
    /// Caller exclusively owns the DCCG register banks for this object's
    /// lifetime, holds matching PCI authority and a permanent register mapping,
    /// and must not let another client reprogram the same dividers.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if !profile.is_dcn32() {
            return Err(Error::Unsupported);
        }
        let base1 = profile.bank(gpu, 1, LAST_BANK1)?;
        let base2 = profile.bank(gpu, 2, LAST_BANK2)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base1,
                base2,
            },
            authority,
            reference_dppclk_khz: 0,
            profile,
        }))
    }
    pub fn set_pixel_rate_div(&mut self, otg: u8, k1: Divider, k2: Divider) -> Result<(), Error> {
        self.0.set_pixel_rate_div(otg, k1, k2)
    }
    pub fn get_pixel_rate_div(&mut self, otg: u8) -> Result<(u32, u32), Error> {
        self.0.get_pixel_rate_div(otg)
    }
    pub fn set_dtbclk_p_src(&mut self, otg: u8, source: StreamClock) -> Result<(), Error> {
        self.0.set_dtbclk_p_src(otg, source)
    }
    pub fn set_dp_stream_clock(
        &mut self,
        hpo: u8,
        otg: u8,
        source: StreamClock,
    ) -> Result<(), Error> {
        self.0.set_dp_stream_clock(hpo, otg, source)
    }
    pub async fn set_dtbclk_dto(
        &mut self,
        otg: u8,
        pixclk_khz: u32,
        ref_dtbclk_khz: u32,
        is_hdmi: bool,
    ) -> Result<(), Error> {
        self.0
            .set_dtbclk_dto(otg, pixclk_khz, ref_dtbclk_khz, is_hdmi)
            .await
    }
    pub fn set_dp_dto(&mut self, otg: u8, pixel_khz: u32, dprefclk_khz: u32) -> Result<(), Error> {
        self.0.set_dp_dto(otg, pixel_khz, dprefclk_khz)
    }
    pub fn set_symclk32_se(&mut self, se: u8, source: Symclk32Source) -> Result<(), Error> {
        self.0.set_symclk32_se(se, source)
    }
    pub fn set_symclk32_le(&mut self, le: u8, source: Symclk32Source) -> Result<(), Error> {
        self.0.set_symclk32_le(le, source)
    }
    /// The DISPCLK divider DENTIST has applied, and the one requested.
    pub fn dispclk_dividers(&mut self) -> Result<(u32, u32), Error> {
        self.0.dispclk_dividers()
    }
    /// `dccg32_trigger_dio_fifo_resync`: copy the divider DENTIST is really
    /// running into the request field so the DIO FIFOs restart against it.
    pub fn resync_dio_fifo(&mut self) -> Result<(), Error> {
        self.0.resync_dio_fifo()
    }
    /// Called only by the DCN 3.2 clock owner after checking all OTGs and
    /// stream encoders are idle. Its persistent InFlight state excludes a
    /// second operation if this future is cancelled during a divider change.
    pub(crate) async fn dentist32(&mut self, disp: u8, dpp: u8) -> Result<(), Error> {
        self.0.dentist(disp, dpp).await
    }
    pub fn otg_add_pixel(&mut self, otg: u8) -> Result<(), Error> {
        self.0.otg_add_pixel(otg)
    }
    pub fn otg_drop_pixel(&mut self, otg: u8) -> Result<(), Error> {
        self.0.otg_drop_pixel(otg)
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
    pub dccg: &'a mut Dccg32,
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
pub(crate) mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fake {
        bank1: Vec<u32>,
        bank2: Vec<u32>,
        writes: Vec<(Reg, u32)>,
        gone: bool,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                bank1: vec![0; LAST_BANK1 as usize + 1],
                bank2: vec![0; LAST_BANK2 as usize + 1],
                writes: Vec::new(),
                gone: false,
            }
        }
    }
    impl Io for Fake {
        fn wait_poll_limit(&self) -> Option<u32> {
            // The model sets the DTBCLK DTO status bit synchronously in
            // write(), so the first poll after the enable already reads
            // done; sixteen polls is pure margin, and a stalled DTO reaches
            // its Timeout by count instead of burning the deadline under
            // the spin executor (#879).
            Some(16)
        }
        fn read(&mut self, reg: Reg) -> u32 {
            if self.gone {
                return u32::MAX;
            }
            match reg {
                Reg::Bank1(id) => self.bank1[id as usize],
                Reg::Bank2(id) => self.bank2[id as usize],
            }
        }
        fn write(&mut self, reg: Reg, value: u32) {
            self.writes.push((reg, value));
            match reg {
                Reg::Bank1(id) => {
                    self.bank1[id as usize] = value;
                    if id == OTG0_PIXEL_RATE_CNTL && value & DTBCLK_DTO_ENABLE != 0 {
                        self.bank1[id as usize] |= DTBCLKDTO_ENABLE_STATUS;
                    }
                    if id == DENTIST_DISPCLK_CNTL {
                        // Dentist is a request/status register, not ordinary RAM.
                        self.bank1[id as usize] =
                            (value & !0x7f00) | (value & 0x7f) << 8 | 0x180000;
                    }
                }
                Reg::Bank2(id) => self.bank2[id as usize] = value,
            }
        }
    }
    fn dccg32() -> Engine<Fake> {
        Engine {
            io: Fake::new(),
            authority: Cap::bootstrap(),
            reference_dppclk_khz: 0,
            profile: Profile::Dcn320,
        }
    }

    fn dccg32_pixel_rate_dividers_are_per_otg_three_bit_fields() -> TestResult {
        let mut dccg = dccg32();
        // DisplayPort 8b/10b, one pixel per container, no ODM: divide by 1 then 4.
        // The divide-by-four code is 3, not 4.
        if dccg
            .set_pixel_rate_div(0, Divider::By1, Divider::By4)
            .is_err()
        {
            return TestResult::Fail("OTG0 divider rejected");
        }
        if dccg.io.bank1[OTG_PIXEL_RATE_DIV as usize] != 0b110 {
            return TestResult::Fail("OTG0 divider encoding");
        }
        // Each OTG owns three bits, so programming one must not disturb another.
        if dccg
            .set_pixel_rate_div(2, Divider::By1, Divider::By2)
            .is_err()
        {
            return TestResult::Fail("OTG2 divider rejected");
        }
        if dccg.io.bank1[OTG_PIXEL_RATE_DIV as usize] != 0b110 | (0b011 << 6) {
            return TestResult::Fail("OTG2 divider clobbered OTG0");
        }
        // Reprogramming the same dividers is a no-op: Linux reads back first.
        let writes = dccg.io.writes.len();
        if dccg
            .set_pixel_rate_div(2, Divider::By1, Divider::By2)
            .is_err()
            || dccg.io.writes.len() != writes
        {
            return TestResult::Fail("identical divider reprogrammed");
        }
        // Pipe 4 does not exist on DCN 3.2.
        if dccg.set_pixel_rate_div(4, Divider::By1, Divider::By1) != Err(Error::Invalid) {
            return TestResult::Fail("OTG4 divider admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_pixel_rate_dividers_are_per_otg_three_bit_fields
    );

    fn dccg32_symclk32_routes_phy_per_encoder() -> TestResult {
        let mut dccg = dccg32();
        // Stream encoder 1 on PHYD32CLK 2: source select 2, enable set.
        if dccg.set_symclk32_se(1, Symclk32Source::Phy(2)).is_err() {
            return TestResult::Fail("SE1 symclk rejected");
        }
        if dccg.io.bank1[SYMCLK32_SE_CNTL as usize] != (2 | 1 << 3) << 4 {
            return TestResult::Fail("SE1 symclk encoding");
        }
        // Link encoder 0 on PHYD32CLK 0, then parked on refclk.
        if dccg.set_symclk32_le(0, Symclk32Source::Phy(0)).is_err() {
            return TestResult::Fail("LE0 symclk rejected");
        }
        if dccg.io.bank1[SYMCLK32_LE_CNTL as usize] != 1 << 3 {
            return TestResult::Fail("LE0 symclk encoding");
        }
        if dccg.set_symclk32_le(0, Symclk32Source::Refclk).is_err()
            || dccg.io.bank1[SYMCLK32_LE_CNTL as usize] != 0
        {
            return TestResult::Fail("LE0 symclk park failed");
        }
        // Four stream encoders, two link encoders, seven PHY sources.
        if dccg.set_symclk32_se(4, Symclk32Source::Refclk) != Err(Error::Invalid)
            || dccg.set_symclk32_le(2, Symclk32Source::Refclk) != Err(Error::Invalid)
            || dccg.set_symclk32_se(0, Symclk32Source::Phy(7)) != Err(Error::Invalid)
        {
            return TestResult::Fail("out-of-range symclk admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_symclk32_routes_phy_per_encoder
    );

    fn dccg32_dp_stream_clock_selects_otg_per_hpo() -> TestResult {
        let mut dccg = dccg32();
        // HPO instance 2 from OTG 1: DTBCLK_P mux first, then the stream clock.
        if dccg.set_dp_stream_clock(2, 1, StreamClock::Dtbclk).is_err() {
            return TestResult::Fail("HPO2 stream clock rejected");
        }
        if dccg.io.bank1[DTBCLK_P_CNTL as usize] != (2 | 1 << 2) << 3 {
            return TestResult::Fail("DTBCLK_P mux not pointed at DTBCLK0");
        }
        if dccg.io.bank1[DPSTREAMCLK_CNTL as usize] != (1 | 1 << 3) << 8 {
            return TestResult::Fail("HPO2 stream clock encoding");
        }
        if dccg.set_dp_stream_clock(4, 0, StreamClock::Dtbclk) != Err(Error::Invalid) {
            return TestResult::Fail("HPO4 stream clock admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_dp_stream_clock_selects_otg_per_hpo
    );

    fn dccg32_dtbclk_dto_divides_the_pixel_clock_by_four() -> TestResult {
        let mut dccg = dccg32();
        // 594 MHz pixel clock against a 100 MHz DTBCLK reference: the DTO
        // output rate is 148.5 MHz, so phase/modulo is 148500000/100000000.
        if narf_scheduler::block_on_spin(dccg.set_dtbclk_dto(0, 594_000, 100_000, false)).is_err() {
            return TestResult::Fail("OTG0 DTBCLK DTO rejected");
        }
        if dccg.io.bank2[DTBCLK_DTO0_MODULO as usize] != 100_000_000
            || dccg.io.bank2[DTBCLK_DTO0_PHASE as usize] != 148_500_000
        {
            return TestResult::Fail("OTG0 DTBCLK DTO phase/modulo");
        }
        // Enabled, source select 2 (DTBCLK DTO), dividers at divide-by-one.
        let cntl = dccg.io.bank1[OTG0_PIXEL_RATE_CNTL as usize];
        if cntl & (DTBCLK_DTO_ENABLE | 0x3 << PIPE0_DTO_SRC_SEL_SHIFT)
            != DTBCLK_DTO_ENABLE | 2 << PIPE0_DTO_SRC_SEL_SHIFT
            || dccg.io.bank1[OTG_PIXEL_RATE_DIV as usize] != 0
        {
            return TestResult::Fail("OTG0 DTBCLK DTO enable/select");
        }
        // Disabling parks the select on 1 (DP DTO) and clears the ratio.
        if narf_scheduler::block_on_spin(dccg.set_dtbclk_dto(0, 0, 100_000, false)).is_err() {
            return TestResult::Fail("OTG0 DTBCLK DTO disable rejected");
        }
        let cntl = dccg.io.bank1[OTG0_PIXEL_RATE_CNTL as usize];
        if cntl & (DTBCLK_DTO_ENABLE | 0x3 << PIPE0_DTO_SRC_SEL_SHIFT)
            != 1 << PIPE0_DTO_SRC_SEL_SHIFT
            || dccg.io.bank2[DTBCLK_DTO0_MODULO as usize] != 0
            || dccg.io.bank2[DTBCLK_DTO0_PHASE as usize] != 0
        {
            return TestResult::Fail("OTG0 DTBCLK DTO disable left state behind");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_dtbclk_dto_divides_the_pixel_clock_by_four
    );

    fn dccg32_dentist_waits_for_both_clock_changes() -> TestResult {
        let mut dccg = dccg32();
        // The DID127 FIFO loops are out of scope here; the dentist must still
        // refuse out-of-range dividers and complete both changes.
        if narf_scheduler::block_on_spin(dccg.dentist(7, 0x52)) != Err(Error::Invalid)
            || narf_scheduler::block_on_spin(dccg.dentist(0x51, 0x52)).is_err()
        {
            return TestResult::Fail("DCN32 dentist divider handling");
        }
        if dccg.io.bank1[DENTIST_DISPCLK_CNTL as usize] & 0x7f != 0x51 {
            return TestResult::Fail("DCN32 dentist DISP divider not applied");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_dentist_waits_for_both_clock_changes
    );

    fn dccg32_dpp_dto_divides_against_the_global_clock() -> TestResult {
        let mut dccg = dccg32();
        dccg.reference_dppclk_khz = 600_000;
        if dccg.dpp_dto(1, 300_000).is_err() {
            return TestResult::Fail("pipe-1 DTO rejected");
        }
        // phase = ceil(255 * 300000 / 600000) = 128, modulo 255.
        if dccg.io.bank1[(DPPCLK0_DTO_PARAM + 1) as usize] != 128 | 0xff << 16 {
            return TestResult::Fail("pipe-1 DTO phase/modulo");
        }
        if dccg.io.bank1[DPPCLK_DTO_CTRL as usize] & 0x30 != 0x10 {
            return TestResult::Fail("pipe-1 DTO enable without double-buffer");
        }
        if dccg.dpp_dto(1, 700_000) != Err(Error::Invalid) {
            return TestResult::Fail("DTO above the global clock admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-dccg",
        dccg32_dpp_dto_divides_against_the_global_clock
    );
}
