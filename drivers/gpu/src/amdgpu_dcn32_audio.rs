//! Navi31/32/33 DCN 3.2 audio: the DCCG audio wall clock and the DP/UHBR
//! LPCM blanking budget. The HD-Audio function beside the GPU owns the
//! controller and the ATI codec; what the display programs is the Azalia
//! endpoint the codec reports, the DCCG audio wall clock, and the stream
//! encoder's audio packets.
//!
//! What this owner does, in Linux DC's order for one stream:
//! - `Audio32::new` binds the 3.2 audio block: five Azalia endpoints
//!   (`res_cap_dcn32.num_audio = 5`, the profile's `streams()`), refusing
//!   any other DCN.
//! - `wall_dto` programs the DCCG audio wall clock (`dce_aud_wall_dto_setup`
//!   via `dce110_setup_audio_dto`): the lowest HDMI audio pipe wins and
//!   programs DTO0 from its pixel clock; with no HDMI audio the lowest DP
//!   audio pipe selects DTO1 from DPREFCLK. The DTO registers (bank 1
//!   0xab-0xaf) are verified identical on 3.2.0 in `dcn_3_2_0_offset.h`.
//! - `rates` budgets LPCM sample rates over a legacy DP link or a UHBR
//!   link (`check_audio_bandwidth_dp`), ported from the DCN 4.0.1 owner.
//!   The UHBR symbol clocks (312.5 / 421.875 / 625 MHz) and the 810 MHz
//!   symbol-clock bound come from that owner.
//!
//! HELD: the AFMT start/stop sequence (`audio_source`,
//! `hdmi_audio_setup` / `dp_audio_setup`, `dce_aud_az_configure`, the Audio
//! InfoFrame, `dce110_enable_audio_stream` / `dce110_disable_audio_stream`)
//! is NOT ported here. The dcn30 audio engine's DIG/AFMT/Azalia register
//! map was spot-checked against `dcn_3_2_0_offset.h` (eight pairs match)
//! but never verified register by register, and this lane does not
//! re-verify it. A stream's AFMT programming is a remainder for a later
//! lane with the full register verification in hand.
//!
//! Also held: the `BACO_AUDIO_D3_PME` DALSMC message. The in-tree dcn30
//! clock manager sends it with value 0x11, but dcn32's `dalsmc.h` says
//! BacoAudioD3PME is 0x10 and SetFclkSwitchAllow is 0x11; the 3.2 audio
//! owner must not send that message until the discrepancy is resolved.
//!
//! DPREFCLK: on 3.2 the clock manager reads DPREFCLK from hardware (DFS
//! slice 2, `dcn32_clk_mgr.c`), so there is no fixed constant to use for
//! DTO1 — `wall_dto` takes it in kHz from the caller, which gets it from
//! the 3.2 clock manager's Phy/DPREFCLK floor. The 730 MHz constant in the
//! dcn30 audio owner is that clock manager's value, not 3.2's.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn32_uhbr::{UhbrRate, UhbrSettings},
    amdgpu_dcn_profile::Profile,
    amdgpu_dml::Timing,
    amdgpu_dsc::Fixed as F,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// A dword register in the DCN 3.2.0 bank this owner touches (DCCG, base
/// index 1). The AFMT/Azalia registers (bank 2) belong to the held AFMT
/// sequence and are not named here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reg {
    /// DCN base index 1 (DCCG).
    Bank1(u64),
}

// DCCG audio wall clock, base index 1.
// linux-ctx: hdr=dcn seg=1
// linux-lit: 0x00ab=mmDCCG_AUDIO_DTO_SOURCE
const AUDIO_DTO_SOURCE: Reg = Reg::Bank1(0x00ab);
// linux-lit: 0x00ac=mmDCCG_AUDIO_DTO0_PHASE
const AUDIO_DTO0_PHASE: Reg = Reg::Bank1(0x00ac);
// linux-lit: 0x00ad=mmDCCG_AUDIO_DTO0_MODULE
const AUDIO_DTO0_MODULE: Reg = Reg::Bank1(0x00ad);
// linux-lit: 0x00ae=mmDCCG_AUDIO_DTO1_PHASE
const AUDIO_DTO1_PHASE: Reg = Reg::Bank1(0x00ae);
// linux-lit: 0x00af=mmDCCG_AUDIO_DTO1_MODULE
const AUDIO_DTO1_MODULE: Reg = Reg::Bank1(0x00af);
// linux: DCCG_AUDIO_DTO_SOURCE__DCCG_AUDIO_DTO0_SOURCE_SEL_MASK
const DTO0_SOURCE_SEL: u32 = 0x7;
// linux: DCCG_AUDIO_DTO_SOURCE__DCCG_AUDIO_DTO_SEL_MASK
const DTO_SEL: u32 = 0x30;
// linux: DCCG_AUDIO_DTO_SOURCE__DCCG_AUDIO_DTO2_USE_512FBR_DTO_MASK
const DTO2_USE_512FBR_DTO: u32 = 1 << 20;
/// `get_azalia_clock_info_*`: 24 MHz in 100 Hz units.
// linux: n/a (literal 24 * 10000 in dce_audio.c:get_azalia_clock_info_hdmi/_dp)
const DTO_PHASE: u32 = 24 * 10_000;
const LAST_BANK1: u64 = 0x00af; // linux: mmDCCG_AUDIO_DTO1_MODULE

/// The UHBR symbol clock, in MHz, for a 128b/132b rate. Linux's
/// `check_audio_bandwidth_dp` bounds both legacy and UHBR symbol clocks
/// by [`SYMBOL_CLOCK_MAX_MHZ`].
///
/// Consumed only by the kernel-test suite below, which clippy's lib/test
/// configs do not enable; the allow keeps the ported budget callable
/// from the tests without deleting the helper it is specified against.
#[allow(dead_code)]
pub(crate) fn uhbr_symbol_clock_mhz(rate: UhbrRate) -> F {
    match rate {
        UhbrRate::Uhbr10 => F::fraction(3125, 10),
        UhbrRate::Uhbr13_5 => F::fraction(421875, 1000),
        UhbrRate::Uhbr20 => F::int(625),
    }
}

/// The symbol-clock bound in `check_audio_bandwidth_dp`: 810 MHz for
/// both legacy and UHBR symbol clocks.
pub const SYMBOL_CLOCK_MAX_MHZ: u32 = 810;

/// The audio owner's errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A non-DCN 3.2 profile, or an audio stream this owner cannot serve.
    Unsupported,
    /// A register read returned the device-gone sentinel.
    DeviceGone,
    /// The bus-device authority was revoked.
    Revoked,
}

/// An audio stream's inputs to the wall clock: its OTG, its timing, and
/// whether it is HDMI (DTO0 from the pixel clock) or DP (DTO1 from
/// DPREFCLK). The DIG and endpoint belong to the held AFMT sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStream {
    pub otg: u8,
    pub timing: Timing,
    pub hdmi: bool,
}

pub(crate) trait Io: Send {
    fn read(&mut self, reg: Reg) -> u32;
    fn write(&mut self, reg: Reg, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    bank1: u64,
}
impl Mmio {
    fn at(&self, reg: Reg) -> u64 {
        match reg {
            Reg::Bank1(r) => self.bank1 + r * 4,
        }
    }
}
impl Io for Mmio {
    fn read(&mut self, reg: Reg) -> u32 {
        // SAFETY: the constructor bounded the bank and retains the mapping.
        unsafe { self.regs.read32(self.at(reg)) }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        // SAFETY: same bounded bank; this owner holds the audio DTO registers.
        unsafe { self.regs.write32(self.at(reg), value) };
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
    /// `res_cap_dcn32.num_audio`: five endpoints.
    endpoints: u8,
}
impl<I: Io> Engine<I> {
    fn read(&mut self, reg: Reg) -> Result<u32, Error> {
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(reg)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, reg: Reg, value: u32) -> Result<(), Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(reg, value)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: Reg, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.write(reg, (old & !mask) | (value & mask))
    }

    /// `dce110_setup_audio_dto`: one wall clock for every display. The
    /// lowest HDMI audio pipe wins and programs DTO0 from its pixel clock;
    /// with no HDMI audio the lowest DP audio pipe selects DTO1 from
    /// `dprefclk_khz` (the 3.2 clock manager's Phy/DPREFCLK floor). No
    /// audio leaves the clock as it is.
    fn wall_dto(&mut self, streams: &[AudioStream], dprefclk_khz: u32) -> Result<(), Error> {
        let lowest = |hdmi: bool| {
            streams
                .iter()
                .filter(|s| s.hdmi == hdmi)
                .min_by_key(|s| s.otg)
        };
        if let Some(s) = lowest(true) {
            // "These bits must be programmed first": source and DTO select,
            // then module, then phase.
            self.update(
                AUDIO_DTO_SOURCE,
                DTO0_SOURCE_SEL | DTO_SEL,
                u32::from(s.otg),
            )?;
            // linux: n/a (kHz to 100 Hz; dce_audio.c:get_azalia_clock_info_hdmi)
            self.update(AUDIO_DTO0_MODULE, u32::MAX, s.timing.pixel_clock_khz * 10)?;
            self.update(AUDIO_DTO0_PHASE, u32::MAX, DTO_PHASE)
        } else if lowest(false).is_some() {
            // linux-lit: 4=DCCG_AUDIO_DTO_SOURCE__DCCG_AUDIO_DTO_SEL__SHIFT
            self.update(AUDIO_DTO_SOURCE, DTO_SEL, 1 << 4)?;
            // linux: n/a (kHz to 100 Hz, literal * 10 in dce_audio.c:get_azalia_clock_info_dp)
            self.update(AUDIO_DTO1_MODULE, u32::MAX, dprefclk_khz * 10)?;
            self.update(AUDIO_DTO1_PHASE, u32::MAX, DTO_PHASE)?;
            self.update(AUDIO_DTO_SOURCE, DTO2_USE_512FBR_DTO, DTO2_USE_512FBR_DTO)
        } else {
            Ok(())
        }
    }
}

/// The DCN 3.2 audio owner: the DCCG audio wall clock. AFMT/Azalia
/// programming is held (see the module docs).
#[derive(Debug)]
pub struct Audio32(Engine<Mmio>);
impl Audio32 {
    /// Bind the 3.2 audio block on `gpu`. Refuses any other DCN.
    ///
    /// # Safety
    /// Caller exclusively owns the DCCG audio DTO registers for this
    /// object's lifetime, holds matching PCI authority and a permanent
    /// register mapping, and must not let another client reprogram the
    /// same DTOs.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu).map_err(|_| Error::Unsupported)?;
        if !matches!(profile, Profile::Dcn320 | Profile::Dcn321) {
            return Err(Error::Unsupported);
        }
        let bank1 = profile
            .bank(gpu, 1, LAST_BANK1 as u32)
            .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                bank1,
            },
            authority,
            endpoints: profile.streams(),
        }))
    }

    /// The Azalia endpoint count: five on 3.2.
    pub fn endpoints(&self) -> u8 {
        self.0.endpoints
    }

    /// `dce110_setup_audio_dto` (see [`Engine::wall_dto`]).
    pub fn wall_dto(&mut self, streams: &[AudioStream], dprefclk_khz: u32) -> Result<(), Error> {
        self.0.wall_dto(streams, dprefclk_khz)
    }
}

/// A DP link for the LPCM blanking budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioLink {
    /// A legacy 8b/10b link: per-lane rate in 27 MHz units (6 RBR, 10 HBR,
    /// 20 HBR2, 30 HBR3) and lane count. MST only.
    Legacy { rate_27mhz: u8, lanes: u8 },
    /// A 128b/132b link and the MST width in symbols (the 4.0.1 owner's
    /// `width` argument to `rates`).
    Uhbr {
        settings: UhbrSettings,
        hblank_symbols: u16,
    },
}

/// A compressed stream as `build_audio_output` describes it: the DSC
/// config's bits per pixel (1/16 bpp) and slices per line. The modeset
/// caller builds this from its DSC config.
///
/// Consumed only by the kernel-test suite below, which clippy's lib/test
/// configs do not enable; do not delete — the budget tests construct it.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AudioDsc {
    pub bpp_x16: u32,
    pub slices: u32,
}

/// Linux dce_audio's LPCM blanking budget for legacy MST and UHBR SST/MST
/// (`check_audio_bandwidth_dp`), ported from the DCN 4.0.1 owner.
/// Fixed-point order/rounding and the 1.1 margin follow Linux. A
/// compressed stream budgets its DSC bits per pixel and loses four symbols
/// per slice (EOC), as `build_audio_output`'s dsc_cfg feeds it.
///
/// Returns the kept sample-rate bits of `rates` (bits 0..6 for 32/44.1/48/
/// 88.2/96/176.4/192 kHz), or `None` for a malformed timing or link. The
/// legacy rate is validated to the four DP link rates; the 4.0.1 port
/// takes its legacy settings from a validated `DpPhySettings` instead.
///
/// Consumed only by the kernel-test suite below, which clippy's lib/test
/// configs do not enable; do not delete — the tests are the contract for
/// the ported budget.
#[allow(dead_code)]
pub(crate) fn rates(
    t: &Timing,
    bpc: u32,
    link: AudioLink,
    channels: u8,
    rates: u8,
    dsc: Option<AudioDsc>,
) -> Option<u8> {
    let lanes = match link {
        AudioLink::Legacy { lanes, .. } => lanes,
        AudioLink::Uhbr { settings, .. } => settings.lanes,
    };
    let blank = t.h_total.checked_sub(t.h_active)?;
    if t.h_active == 0
        || blank == 0
        || t.h_total > 65535
        || !(1..=6_000_000).contains(&t.pixel_clock_khz)
        || !matches!(bpc, 8 | 10 | 12)
        || !matches!(lanes, 1 | 2 | 4)
        || !(1..=8).contains(&channels)
        || dsc.is_some_and(|d| !(1..=1024).contains(&d.bpp_x16) || !(1..=64).contains(&d.slices))
    {
        return None;
    }
    // The Linux order multiplies blank duration by the symbol clock before
    // the video/link fraction cancels the pixel clock. Reject malformed low
    // clocks that exceed 31.32's integer range at that intermediate step;
    // 810 MHz bounds both legacy and UHBR symbol clocks.
    if u64::from(blank) * u64::from(SYMBOL_CLOCK_MAX_MHZ) * 1000
        >= u64::from(t.pixel_clock_khz) * i32::MAX as u64
    {
        return None;
    }
    let (link_kbps, sym_mhz, hblank_symbols, layout, overhead) = match link {
        AudioLink::Legacy { rate_27mhz, .. } => {
            if !matches!(rate_27mhz, 6 | 10 | 20 | 30) {
                return None;
            }
            let sym_mhz = i32::from(rate_27mhz) * 27;
            // Remove FEC for the pessimistic audio budget (populate_audio_dp_link_info).
            (
                sym_mhz * 8000 * i32::from(lanes),
                F::int(sym_mhz),
                0,
                40,
                16,
            )
        }
        AudioLink::Uhbr {
            settings,
            hblank_symbols,
        } => {
            let kbps = settings.rate.link_rate() * u32::from(lanes) * 9641;
            let kbps = F::int(kbps as i32).mul(F::fraction(10000, 9975)).floor();
            let sym = uhbr_symbol_clock_mhz(settings.rate);
            (kbps, sym, hblank_symbols, 10, 10)
        }
    };
    let hblank_ms = F::fraction(i64::from(blank), i64::from(t.pixel_clock_khz));
    let peak = match dsc {
        Some(d) => F::int(t.pixel_clock_khz as i32).mul(F::fraction(i64::from(d.bpp_x16), 16)),
        None => F::int(t.pixel_clock_khz as i32).mul_int((bpc * 3) as i32),
    };
    let frac = peak.div(F::int(link_kbps));
    let mut available =
        hblank_ms.mul_int(1000).mul(sym_mhz).mul(frac).floor() as u32 * u32::from(lanes);
    // EOC overhead, in Linux's unsigned arithmetic (a wrap passes the
    // minimum-width and main-link checks below exactly as it does there).
    available = available.wrapping_sub(dsc.map_or(0, |d| d.slices * 4));
    if available < u32::from(hblank_symbols) {
        available = 4 * u32::from(hblank_symbols);
    }
    available = available.saturating_sub(12); // main-link overhead
    let line_khz = F::fraction(i64::from(t.pixel_clock_khz), i64::from(t.h_total));
    let margin = F::fraction(110, 100);
    // Both transports map AV over four lanes, independent of physical lane
    // count. Conservatively use the eight-channel layout for 3..8 channels.
    let denom = if channels <= 2 { 4 } else { 1 };
    let align = |n: i32| ((n + 4) / 4 * 4) as u32;
    let full = align(F::int(layout + overhead).mul(margin).ceil());
    let mut kept = rates & 0x7f;
    for (bit, hz) in [32000, 44100, 48000, 88200, 96000, 176400, 192000]
        .into_iter()
        .enumerate()
    {
        let layouts = F::fraction(hz, 1000).div(line_khz).div_int(denom);
        let count = layouts.floor();
        let mut required = count as u32 * full;
        if count != layouts.ceil() {
            required += align(
                layouts
                    .sub_int(count)
                    .mul_int(layout)
                    .add_int(overhead)
                    .mul(margin)
                    .ceil(),
            );
        }
        if available < required {
            kept &= !(1 << bit);
        }
    }
    Some(kept)
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Default)]
    struct Fake {
        regs: [u32; 0x10],
        writes: alloc::vec::Vec<u32>,
    }
    impl Fake {
        fn reg(reg: Reg) -> usize {
            match reg {
                Reg::Bank1(r) => (r - 0xab) as usize,
            }
        }
    }
    impl Io for Fake {
        fn read(&mut self, reg: Reg) -> u32 {
            self.regs[Self::reg(reg)]
        }
        fn write(&mut self, reg: Reg, value: u32) {
            self.regs[Self::reg(reg)] = value;
            self.writes.push(Self::reg(reg) as u32);
        }
    }

    fn timing(pixel_clock_khz: u32, h: (u32, u32), v: (u32, u32)) -> Timing {
        Timing {
            pixel_clock_khz,
            h_active: h.0,
            h_total: h.1,
            h_front_porch: 88,
            h_sync_width: 44,
            v_active: v.0,
            v_total: v.1,
            v_front_porch: 4,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        }
    }
    fn stream(otg: u8, hdmi: bool) -> AudioStream {
        AudioStream {
            otg,
            timing: timing(148_500, (1920, 2200), (1080, 1125)),
            hdmi,
        }
    }
    fn engine() -> Engine<Fake> {
        Engine {
            io: Fake::default(),
            authority: Cap::bootstrap(),
            endpoints: 5,
        }
    }

    fn dcn32_audio_wall_dto_hdmi_lowest_wins() -> TestResult {
        let mut e = engine();
        let streams = [stream(2, true), stream(0, true)];
        if e.wall_dto(&streams, 730_000).is_err() {
            return TestResult::Fail("DCN32 audio DTO0 setup failed");
        }
        // DTO0 source is the lowest HDMI OTG (0), module is the pixel
        // clock in 100 Hz units, phase is the 24 MHz Azalia clock.
        if e.io.regs[Fake::reg(AUDIO_DTO_SOURCE)] != 0
            || e.io.regs[Fake::reg(AUDIO_DTO0_MODULE)] != 1_485_000
            || e.io.regs[Fake::reg(AUDIO_DTO0_PHASE)] != DTO_PHASE
        {
            return TestResult::Fail("DCN32 audio DTO0 registers wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_wall_dto_hdmi_lowest_wins
    );

    fn dcn32_audio_wall_dto_dp_from_dprefclk() -> TestResult {
        let mut e = engine();
        let streams = [stream(1, false)];
        if e.wall_dto(&streams, 600_000).is_err() {
            return TestResult::Fail("DCN32 audio DTO1 setup failed");
        }
        // DTO select is 1 (DTO1) plus the 512FBR DTO bit; the module is the
        // caller-supplied DPREFCLK in 100 Hz units, not a fixed constant.
        if e.io.regs[Fake::reg(AUDIO_DTO_SOURCE)] != (1 << 4) | DTO2_USE_512FBR_DTO
            || e.io.regs[Fake::reg(AUDIO_DTO1_MODULE)] != 6_000_000
            || e.io.regs[Fake::reg(AUDIO_DTO1_PHASE)] != DTO_PHASE
        {
            return TestResult::Fail("DCN32 audio DTO1 registers wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_wall_dto_dp_from_dprefclk
    );

    fn dcn32_audio_wall_dto_no_audio_no_writes() -> TestResult {
        let mut e = engine();
        if e.wall_dto(&[], 730_000).is_err() {
            return TestResult::Fail("DCN32 audio DTO no-audio failed");
        }
        if !e.io.writes.is_empty() {
            return TestResult::Fail("DCN32 audio DTO wrote with no audio");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_wall_dto_no_audio_no_writes
    );

    fn dcn32_audio_uhbr_symbol_clocks() -> TestResult {
        if uhbr_symbol_clock_mhz(UhbrRate::Uhbr10) != F::fraction(3125, 10)
            || uhbr_symbol_clock_mhz(UhbrRate::Uhbr13_5) != F::fraction(421875, 1000)
            || uhbr_symbol_clock_mhz(UhbrRate::Uhbr20) != F::int(625)
        {
            return TestResult::Fail("DCN32 audio UHBR symbol clocks wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32_audio", dcn32_audio_uhbr_symbol_clocks);

    fn dcn32_audio_rates_uhbr20_1080p_keeps_all() -> TestResult {
        let t = timing(148_500, (1920, 2200), (1080, 1125));
        let kept = rates(
            &t,
            8,
            AudioLink::Uhbr {
                settings: UhbrSettings {
                    lanes: 4,
                    rate: UhbrRate::Uhbr20,
                    mst: false,
                },
                hblank_symbols: 0,
            },
            2,
            0x7f,
            None,
        );
        if kept != Some(0x7f) {
            return TestResult::Fail("DCN32 audio UHBR20 budget dropped a rate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_rates_uhbr20_1080p_keeps_all
    );

    fn dcn32_audio_rates_rejects_malformed() -> TestResult {
        let t = timing(148_500, (1920, 2200), (1080, 1125));
        let no_blank = Timing { h_total: 1920, ..t };
        let uhbr = AudioLink::Uhbr {
            settings: UhbrSettings {
                lanes: 4,
                rate: UhbrRate::Uhbr10,
                mst: false,
            },
            hblank_symbols: 0,
        };
        if rates(&no_blank, 8, uhbr, 2, 0x7f, None).is_some()
            || rates(&t, 16, uhbr, 2, 0x7f, None).is_some()
            || rates(&t, 8, uhbr, 9, 0x7f, None).is_some()
            || rates(
                &t,
                8,
                AudioLink::Legacy {
                    rate_27mhz: 5,
                    lanes: 4,
                },
                2,
                0x7f,
                None,
            )
            .is_some()
            || rates(
                &t,
                8,
                uhbr,
                2,
                0x7f,
                Some(AudioDsc {
                    bpp_x16: 0,
                    slices: 1,
                }),
            )
            .is_some()
        {
            return TestResult::Fail("DCN32 audio budget accepted a malformed input");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_rates_rejects_malformed
    );

    fn dcn32_audio_rates_starved_subset_of_generous() -> TestResult {
        let generous = timing(148_500, (1920, 2200), (1080, 1125));
        let starved = timing(594_000, (3840, 4400), (2160, 2250));
        let g = rates(
            &generous,
            8,
            AudioLink::Uhbr {
                settings: UhbrSettings {
                    lanes: 4,
                    rate: UhbrRate::Uhbr20,
                    mst: false,
                },
                hblank_symbols: 0,
            },
            2,
            0x7f,
            None,
        );
        let s = rates(
            &starved,
            12,
            AudioLink::Uhbr {
                settings: UhbrSettings {
                    lanes: 1,
                    rate: UhbrRate::Uhbr10,
                    mst: false,
                },
                hblank_symbols: 0,
            },
            8,
            0x7f,
            None,
        );
        match (g, s) {
            (Some(g), Some(s)) if s & !g == 0 => TestResult::Pass,
            _ => TestResult::Fail("DCN32 audio budget not monotone in link width"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/dcn32_audio",
        dcn32_audio_rates_starved_subset_of_generous
    );
}
