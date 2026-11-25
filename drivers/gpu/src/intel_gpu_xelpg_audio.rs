//! Display 14+ HDMI and DP audio (`narf.intel.hdmi14_ext=1`): the codec
//! half of Linux 7.4 `intel_audio.c` for the external routes, and the audio
//! component (`intel_audio_component_ops`) the HDA driver reads ELDs and
//! sets N/CTS through.
//!
//! Linux 7.4 conveys the ELD only through the component: `hsw_audio_codec_enable`
//! raises `AUDIO_OUTPUT_ENABLE`, waits a vblank, invalidates
//! `AUDIO_ELD_VALID` and runs the timestamp update ("The audio component is
//! used to convey the ELD instead using of the hardware ELD buffer"); it
//! never writes `HSW_AUD_EDID_DATA` and never sets ELD_VALID.
//! `intel_audio_codec_enable` then stores the ELD in the transcoder's audio
//! state and calls the codec's `pin_eld_notify(port, pipe)` (pipe -1 unless
//! the stream is MST or UHBR SST, `intel_audio_needs_cpu_transcoder_id`);
//! the codec answers with `get_eld` and `sync_audio_rate`
//! (`snd_hdac_acomp_get_eld`, `snd_hdac_sync_audio_rate` over its
//! `pin2port`). This module is that sequence:
//!
//! - [`codec_enable`] / [`codec_disable`]: `hsw_audio_codec_enable` /
//!   `hsw_audio_codec_disable` with `enable_audio_dsc_wa` (DP:
//!   `HBLANK_EARLY_ENABLE_TGL` and, for a compressed 4K stream, the hblank
//!   start count and samples per line), `intel_audio_sdp_split_update`
//!   (`AUD_DP_2DOT0_CTRL`, UHBR with audio), Wa_14020863754
//!   (`AUD_CHICKENBIT_REG3`, display 20.00 and 30.00) and the DP / HDMI
//!   `AUD_CONFIG` updates (`hsw_dp_audio_config_update`,
//!   `hsw_hdmi_audio_config_update`: the `hdmi_audio_clock` pixel-clock
//!   field and the deep-colour aware N tables, `HSW_AUD_M_CTS_ENABLE`).
//! - [`audio_codec_enable`] / [`audio_codec_disable`]: the state store and
//!   the notification, plus the shared display-audio sink publication.
//! - [`compute_eld`]: `intel_audio_compute_config` over the shared ELD
//!   builder (`drm_edid_to_eld`'s baseline length and AI bit,
//!   `intel_audio_hdmi_eld_compute_config`'s SAD pruning against the HDMI
//!   blanking budget, `drm_av_sync_delay`).
//! - The component ([`XelpgAudioComponent`], bound in production by
//!   [`bind_production_component`]): `get_power` (refcount, the
//!   `AUD_FREQ_CNTRL` restore and `AUD_PIN_BUF_ENABLE`), `put_power`,
//!   `codec_wake_override` (`SKL_AUD_CODEC_WAKE_SIGNAL`), `get_cdclk_freq`,
//!   `sync_audio_rate` and `get_eld` over `find_audio_state`.
//! - [`cdclk_change_pre`] / [`cdclk_change_post`]: `AUD_TS_CDCLK_M/N`
//!   around a CDCLK change (display 13+), and [`AUDIO_MIN_CDCLK_KHZ`], the
//!   `intel_audio_min_cdclk` floor the Pipe B–D owner applies for a pipe
//!   with audio.
//!
//! Not modelled: the `POWER_DOMAIN_AUDIO_PLAYBACK` wakeref (on display 14
//! it is PW_2, which every live external route already holds; the
//! component does not request power wells itself), the LPE audio bridge
//! (Valleyview/Cherryview only) and Gemini Lake's forced CDCLK. MST audio
//! is not enabled (the MST route keeps audio off).

use core::sync::atomic::{compiler_fence, Ordering};

use narf_drivers_sound::display_audio::{
    self as acomp, ComponentError, DisplayAudioComponent, DisplayAudioPublication,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu_audio::{
    aud_cfg_off, aud_eld_valid, aud_output_enable, dp_audio_config_update,
    AUD_CONFIG_LOWER_N_MASK, AUD_CONFIG_N_PROG_ENABLE, AUD_CONFIG_N_VALUE_INDEX,
    AUD_CONFIG_PIXEL_CLOCK_MASK, AUD_CONFIG_UPPER_N_MASK, HSW_AUD_PIN_ELD_CP_VLD,
};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pipes::{Pipe, Transcoder};

// ── Registers (intel_audio_regs.h) ───────────────────────────────────

/// `HSW_AUD_M_CTS_ENABLE(trans)`.
pub const fn aud_m_cts_enable(trans: Transcoder) -> u64 {
    0x6_5028 + trans as u64 * 0x100
}
/// `AUD_M_CTS_M_VALUE_INDEX` and `AUD_M_CTS_M_PROG_ENABLE`.
pub const AUD_M_CTS_M_VALUE_INDEX: u32 = 1 << 21;
pub const AUD_M_CTS_M_PROG_ENABLE: u32 = 1 << 20;
/// `AUD_DP_2DOT0_CTRL(trans)` and `AUD_ENABLE_SDP_SPLIT`.
pub const fn aud_dp_2dot0_ctrl(trans: Transcoder) -> u64 {
    0x6_50BC + trans as u64 * 0x100
}
pub const AUD_ENABLE_SDP_SPLIT: u32 = 1 << 31;
/// `HSW_AUD_CHICKENBIT` and `SKL_AUD_CODEC_WAKE_SIGNAL`.
pub const HSW_AUD_CHICKENBIT: u64 = 0x6_5F10;
pub const SKL_AUD_CODEC_WAKE_SIGNAL: u32 = 1 << 15;
/// `AUD_FREQ_CNTRL`.
pub const AUD_FREQ_CNTRL: u64 = 0x6_5900;
/// `AUD_PIN_BUF_CTL` and `AUD_PIN_BUF_ENABLE`.
pub const AUD_PIN_BUF_CTL: u64 = 0x4_8414;
pub const AUD_PIN_BUF_ENABLE: u32 = 1 << 31;
/// `AUD_TS_CDCLK_M` (with `AUD_TS_CDCLK_M_EN`) and `AUD_TS_CDCLK_N`.
pub const AUD_TS_CDCLK_M: u64 = 0x6_5EA0;
pub const AUD_TS_CDCLK_M_EN: u32 = 1 << 31;
pub const AUD_TS_CDCLK_N: u64 = 0x6_5EA4;
/// `AUD_CONFIG_BE`.
pub const AUD_CONFIG_BE: u64 = 0x6_5EF0;
/// `AUD_CHICKENBIT_REG3` and `DACBE_DISABLE_MIN_HBLANK_FIX`.
pub const AUD_CHICKENBIT_REG3: u64 = 0x6_5F1C;
pub const DACBE_DISABLE_MIN_HBLANK_FIX: u32 = 1 << 18;

/// `HBLANK_EARLY_ENABLE_TGL(pipe)` (indexed by the CPU transcoder).
pub const fn hblank_early_enable_tgl(trans: Transcoder) -> u32 {
    1 << (24 + trans as u32)
}
const fn hblank_start_count_mask(trans: Transcoder) -> u32 {
    0x7 << (3 + trans as u32 * 6)
}
/// `HBLANK_START_COUNT(pipe, val)`.
pub const fn hblank_start_count(trans: Transcoder, val: u32) -> u32 {
    (val & 0x7) << (3 + trans as u32 * 6)
}
const fn number_samples_per_line_mask(trans: Transcoder) -> u32 {
    0x3 << (trans as u32 * 6)
}
/// `NUMBER_SAMPLES_PER_LINE(pipe, val)`.
pub const fn number_samples_per_line(trans: Transcoder, val: u32) -> u32 {
    (val & 0x3) << (trans as u32 * 6)
}
/// `HBLANK_START_COUNT_32` .. `_128`.
pub const HBLANK_START_COUNT_32: u32 = 2;
pub const HBLANK_START_COUNT_64: u32 = 3;
pub const HBLANK_START_COUNT_96: u32 = 4;
pub const HBLANK_START_COUNT_128: u32 = 5;

/// `AUD_FREQ_GEN12`: `AUD_FREQ_8T | AUD_FREQ_PULLCLKS(0) | AUD_FREQ_BCLK_96M`,
/// what `intel_audio_component_init` keeps for display 12+ outside
/// Tiger Lake and Rocket Lake.
pub const AUD_FREQ_GEN12: u32 = (2 << 14) | (1 << 4);

/// `intel_audio_min_cdclk` on display 9+: twice the 96 MHz Azalia BCLK.
pub const AUDIO_MIN_CDCLK_KHZ: u32 = 2 * 96_000;

/// Linux's ELD buffer (`MAX_ELD_BYTES`, `crtc_state->eld`).
pub const MAX_ELD_BYTES: usize = 128;

/// `intel_display_wa(INTEL_DISPLAY_WA_14020863754)`: display 30.00, 20.00
/// and 14.01 (Battlemage, not a [`crate::intel_gpu_xe2lpd::DisplayIp`]).
pub(crate) const fn needs_wa_14020863754(ip: crate::intel_gpu_xe2lpd::DisplayIp) -> bool {
    matches!(
        ip,
        crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd | crate::intel_gpu_xe2lpd::DisplayIp::Xe3Lpd
    )
}

/// `PIPE_FRMCOUNT_G4X` relative to [`Pipe::base`].
const FRMCOUNT: u64 = 0x040;

// ── The stream (crtc_state) ──────────────────────────────────────────

/// One audio stream as `crtc_state` describes it to `intel_audio.c`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AudioStream {
    /// `crtc_state->cpu_transcoder` (A–D).
    pub trans: Transcoder,
    /// The pipe (vblank waits).
    pub pipe: Pipe,
    /// `encoder->port` (Linux `enum port`).
    pub port: i32,
    /// `intel_crtc_has_dp_encoder`.
    pub dp: bool,
    /// `intel_dp_is_uhbr`.
    pub uhbr: bool,
    /// `adjusted_mode.crtc_clock` in kHz.
    pub crtc_clock_khz: u32,
    /// `crtc_state->port_clock` in kHz.
    pub port_clock_khz: u32,
    /// `crtc_state->pipe_bpp`.
    pub pipe_bpp: u32,
    /// `crtc_state->lane_count`.
    pub lane_count: u8,
    /// `crtc_hdisplay`, `crtc_htotal`, `crtc_vdisplay`.
    pub h_active: u16,
    pub h_total: u16,
    pub v_active: u16,
    /// `crtc_state->dsc.compressed_bpp_x16` when the stream compresses.
    pub dsc_bpp_x16: Option<u32>,
    /// `crtc_state->output_format` is YCbCr 4:2:0.
    pub ycbcr420: bool,
    /// `INTEL_DISPLAY_WA_14020863754` (display 30.00, 20.00 and 14.01).
    pub wa_14020863754: bool,
}

impl AudioStream {
    /// `crtc_state->sdp_split_enable`: DP audio on a UHBR link
    /// (`intel_dp_audio_compute_config`).
    pub const fn sdp_split_enable(&self) -> bool {
        self.dp && self.uhbr
    }

    /// `intel_audio_needs_cpu_transcoder_id` (MST is never an audio route
    /// here): UHBR SST.
    pub const fn needs_cpu_transcoder_id(&self) -> bool {
        self.dp && self.uhbr
    }

    /// The `pipe` argument of `pin_eld_notify`: the CPU transcoder when it
    /// is needed, -1 otherwise.
    pub const fn notify_pipe(&self) -> i32 {
        if self.needs_cpu_transcoder_id() {
            self.trans as i32
        } else {
            -1
        }
    }
}

/// Typed audio failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AudioError {
    /// Register authority was lost or a read was all-ones.
    AccessLost,
    /// The transcoder has no `HSW_AUD_PIN_ELD_CP_VLD` field (eDP).
    Transcoder,
}

fn rmw<M: MmioWindow + ?Sized>(
    io: &M,
    reg: u64,
    clear: u32,
    set: u32,
) -> Result<(), AudioError> {
    let cur = io.read32(reg);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(AudioError::AccessLost);
    }
    io.write32(reg, (cur & !clear) | set);
    compiler_fence(Ordering::SeqCst);
    Ok(())
}

/// `intel_crtc_wait_for_next_vblank`: the frame counter advances, bounded
/// at 100 ms (`drm_crtc_wait_one_vblank`'s timeout, after which Linux only
/// warns).
fn wait_for_next_vblank<M: MmioWindow + ?Sized>(io: &M, pipe: Pipe) {
    let start = io.read32(pipe.base() + FRMCOUNT);
    let _ = narf_scheduler::responsive_spin_until(
        || io.read32(pipe.base() + FRMCOUNT) != start || !io.display_access_ok(),
        narf_time::Deadline::after_ns(100_000_000),
    );
}

fn sleep_us(us: u64) {
    let _ = narf_scheduler::responsive_spin_until(
        || false,
        narf_time::Deadline::after_ns(us * 1_000),
    );
}

// ── AUD_CONFIG (hsw_*_audio_config_update) ───────────────────────────

/// `hdmi_audio_clock[]`: (mode clock kHz, `AUD_CONFIG_PIXEL_CLOCK_HDMI_*`).
const HDMI_AUDIO_CLOCK: [(u32, u32); 14] = [
    (25_175, 0),
    (25_200, 1),
    (27_000, 2),
    (27_027, 3),
    (54_000, 4),
    (54_054, 5),
    (74_176, 6),
    (74_250, 7),
    (148_352, 8),
    (148_500, 9),
    (296_703, 10),
    (297_000, 11),
    (593_407, 12),
    (594_000, 13),
];

/// `audio_config_hdmi_pixel_clock` on display 12+: the field for the
/// mode's `crtc_clock` (the pixel clock, not the deep-colour TMDS clock),
/// or 25.2 MHz's ("default per bspec") when the table has none.
pub fn audio_config_hdmi_pixel_clock(crtc_clock_khz: u32) -> u32 {
    let field = HDMI_AUDIO_CLOCK
        .iter()
        .find(|(clock, _)| *clock == crtc_clock_khz)
        .map_or(HDMI_AUDIO_CLOCK[1].1, |(_, field)| *field);
    field << 16
}

/// `hdmi_aud_ncts_24bpp[]`: (sample rate, TMDS clock kHz, N).
const NCTS_24BPP: [(u32, u32, u32); 28] = [
    (32_000, 296_703, 5824),
    (32_000, 297_000, 3072),
    (32_000, 593_407, 5824),
    (32_000, 594_000, 3072),
    (44_100, 296_703, 4459),
    (44_100, 297_000, 4704),
    (44_100, 593_407, 8918),
    (44_100, 594_000, 9408),
    (88_200, 296_703, 8918),
    (88_200, 297_000, 9408),
    (88_200, 593_407, 17836),
    (88_200, 594_000, 18816),
    (176_400, 296_703, 17836),
    (176_400, 297_000, 18816),
    (176_400, 593_407, 35672),
    (176_400, 594_000, 37632),
    (48_000, 296_703, 5824),
    (48_000, 297_000, 5120),
    (48_000, 593_407, 5824),
    (48_000, 594_000, 6144),
    (96_000, 296_703, 11648),
    (96_000, 297_000, 10240),
    (96_000, 593_407, 11648),
    (96_000, 594_000, 12288),
    (192_000, 296_703, 23296),
    (192_000, 297_000, 20480),
    (192_000, 593_407, 23296),
    (192_000, 594_000, 24576),
];

/// `hdmi_aud_ncts_30bpp[]` (HDMI 2.0 Appendix C, 10 bpc deep colour).
const NCTS_30BPP: [(u32, u32, u32); 14] = [
    (32_000, 370_878, 5824),
    (32_000, 371_250, 6144),
    (44_100, 370_878, 8918),
    (44_100, 371_250, 4704),
    (88_200, 370_878, 17836),
    (88_200, 371_250, 9408),
    (176_400, 370_878, 35672),
    (176_400, 371_250, 18816),
    (48_000, 370_878, 11648),
    (48_000, 371_250, 5120),
    (96_000, 370_878, 23296),
    (96_000, 371_250, 10240),
    (192_000, 370_878, 46592),
    (192_000, 371_250, 20480),
];

/// `hdmi_aud_ncts_36bpp[]` (12 bpc deep colour).
const NCTS_36BPP: [(u32, u32, u32); 14] = [
    (32_000, 445_054, 5824),
    (32_000, 445_500, 4096),
    (44_100, 445_054, 8918),
    (44_100, 445_500, 4704),
    (88_200, 445_054, 17836),
    (88_200, 445_500, 9408),
    (176_400, 445_054, 35672),
    (176_400, 445_500, 18816),
    (48_000, 445_054, 5824),
    (48_000, 445_500, 5120),
    (96_000, 445_054, 11648),
    (96_000, 445_500, 10240),
    (192_000, 445_054, 23296),
    (192_000, 445_500, 20480),
];

/// `audio_config_hdmi_get_n`: the table for the pipe bpp (36, 30, else
/// 24), matched on the sample rate and the port (TMDS) clock; 0 means
/// automatic N.
pub fn audio_config_hdmi_get_n(pipe_bpp: u32, port_clock_khz: u32, rate: u32) -> u32 {
    let table: &[(u32, u32, u32)] = match pipe_bpp {
        36 => &NCTS_36BPP,
        30 => &NCTS_30BPP,
        _ => &NCTS_24BPP,
    };
    table
        .iter()
        .find(|(r, clock, _)| *r == rate && *clock == port_clock_khz)
        .map_or(0, |(_, _, n)| *n)
}

/// `AUD_CONFIG_N(n)`: N bits 19:12 in the upper field, 11:0 in the lower.
pub const fn aud_config_n(n: u32) -> u32 {
    (((n >> 12) << 20) & AUD_CONFIG_UPPER_N_MASK) | (((n & 0xFFF) << 4) & AUD_CONFIG_LOWER_N_MASK)
}

/// `hsw_hdmi_audio_config_update` for `rate` (the component's
/// `aud_sample_rate[port]`, 0 before any `sync_audio_rate`).
pub fn hdmi_audio_config_update<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    rate: u32,
) -> Result<(), AudioError> {
    let off = aud_cfg_off(s.trans);
    let cur = io.read32(off);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(AudioError::AccessLost);
    }
    let mut tmp = cur & !(AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_PIXEL_CLOCK_MASK | AUD_CONFIG_N_PROG_ENABLE);
    tmp |= audio_config_hdmi_pixel_clock(s.crtc_clock_khz);
    let n = audio_config_hdmi_get_n(s.pipe_bpp, s.port_clock_khz, rate);
    if n != 0 {
        tmp &= !(AUD_CONFIG_UPPER_N_MASK | AUD_CONFIG_LOWER_N_MASK);
        tmp |= aud_config_n(n) | AUD_CONFIG_N_PROG_ENABLE;
    }
    io.write32(off, tmp);
    compiler_fence(Ordering::SeqCst);
    // "Let's disable "Enable CTS or M Prog bit" and let HW calculate the
    // value".
    rmw(
        io,
        aud_m_cts_enable(s.trans),
        AUD_M_CTS_M_PROG_ENABLE | AUD_M_CTS_M_VALUE_INDEX,
        0,
    )
}

/// `hsw_audio_config_update`.
pub fn config_update<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    rate: u32,
) -> Result<(), AudioError> {
    if s.dp {
        dp_audio_config_update(io, s.trans);
        if io.display_access_ok() {
            Ok(())
        } else {
            Err(AudioError::AccessLost)
        }
    } else {
        hdmi_audio_config_update(io, s, rate)
    }
}

// ── enable_audio_dsc_wa ──────────────────────────────────────────────

/// `calc_hblank_early_prog` (the FEC coefficient 0.972261 at a 10^6
/// rounding multiplier); 0 where Linux WARNs on a zero input.
pub fn calc_hblank_early_prog(s: &AudioStream, cdclk_khz: u32) -> u32 {
    let h_active = u64::from(s.h_active);
    let h_total = u64::from(s.h_total);
    let pixel_clk = u64::from(s.crtc_clock_khz);
    let vdsc_bppx16 = u64::from(s.dsc_bpp_x16.unwrap_or(0));
    let cdclk = u64::from(cdclk_khz);
    let fec_coeff: u64 = 972_261;
    let link_clk = u64::from(s.port_clock_khz);
    let lanes = u64::from(s.lane_count);
    if link_clk == 0 || pixel_clk == 0 || lanes == 0 || vdsc_bppx16 == 0 || cdclk == 0 {
        return 0;
    }
    // Linux computes these in unsigned int: the available count wraps when
    // the blanking is shorter than 28 link clocks.
    let available = (h_total.saturating_sub(h_active) * link_clk / pixel_clk) as u32;
    let link_clks_available = available.wrapping_sub(28);
    let link_clks_required =
        ((192_000 * h_total).div_ceil(1000 * pixel_clk) * (48 / lanes + 2)) as u32;
    let hblank_delta: u64 = if link_clks_available > link_clks_required {
        32
    } else {
        (5 * (link_clk + cdclk) * pixel_clk).div_ceil(link_clk * cdclk)
    };
    let tu_data = (pixel_clk * vdsc_bppx16 * 8 * 1_000_000) / (link_clk * lanes * 16 * fec_coeff);
    let tu_line = (h_active * link_clk * fec_coeff) / (64 * pixel_clk * 1_000_000);
    let link_clks_active = (tu_line.wrapping_sub(1)).wrapping_mul(64).wrapping_add(tu_data);
    let hblank_rise =
        (link_clks_active + 6 * link_clks_active.div_ceil(250) + 4) * pixel_clk / link_clk;
    (h_active.wrapping_sub(hblank_rise).wrapping_add(hblank_delta)) as u32
}

/// `calc_samples_room`.
pub fn calc_samples_room(s: &AudioStream) -> u32 {
    let h_active = u64::from(s.h_active);
    let h_total = u64::from(s.h_total);
    let pixel_clk = u64::from(s.crtc_clock_khz);
    let link_clk = u64::from(s.port_clock_khz);
    let lanes = u64::from(s.lane_count.max(1));
    if pixel_clk == 0 {
        return 0;
    }
    let num = (h_total.saturating_sub(h_active) * link_clk).saturating_sub(12 * pixel_clk);
    (num / (pixel_clk * (48 / lanes + 2))) as u32
}

/// `enable_audio_dsc_wa` on display 12+: `HBLANK_EARLY_ENABLE_TGL`, and
/// for a compressed stream of at least 3840x2160 the hblank start count
/// and the samples per line.
pub fn enable_audio_dsc_wa<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    cdclk_khz: u32,
) -> Result<(), AudioError> {
    let trans = s.trans;
    let mut val = io.read32(AUD_CONFIG_BE);
    if val == u32::MAX || !io.display_access_ok() {
        return Err(AudioError::AccessLost);
    }
    val |= hblank_early_enable_tgl(trans);
    if s.dsc_bpp_x16.is_some() && s.h_active >= 3840 && s.v_active >= 2160 {
        val &= !hblank_start_count_mask(trans);
        let prog = calc_hblank_early_prog(s, cdclk_khz);
        val |= hblank_start_count(
            trans,
            match prog {
                0..=31 => HBLANK_START_COUNT_32,
                32..=63 => HBLANK_START_COUNT_64,
                64..=95 => HBLANK_START_COUNT_96,
                _ => HBLANK_START_COUNT_128,
            },
        );
        val &= !number_samples_per_line_mask(trans);
        let room = calc_samples_room(s);
        val |= number_samples_per_line(trans, if room < 3 { room } else { 0 });
    }
    io.write32(AUD_CONFIG_BE, val);
    compiler_fence(Ordering::SeqCst);
    Ok(())
}

/// `intel_audio_sdp_split_update` (`HAS_DP20`: display 14+).
fn sdp_split_update<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    enable: bool,
) -> Result<(), AudioError> {
    rmw(
        io,
        aud_dp_2dot0_ctrl(s.trans),
        AUD_ENABLE_SDP_SPLIT,
        if enable && s.sdp_split_enable() {
            AUD_ENABLE_SDP_SPLIT
        } else {
            0
        },
    )
}

// ── hsw_audio_codec_enable / _disable ────────────────────────────────

fn check_trans(s: &AudioStream) -> Result<(), AudioError> {
    if matches!(s.trans, Transcoder::Edp) {
        Err(AudioError::Transcoder)
    } else {
        Ok(())
    }
}

/// `hsw_audio_codec_enable`: (DP) `enable_audio_dsc_wa`, the SDP split,
/// Wa_14020863754's `DACBE_DISABLE_MIN_HBLANK_FIX`, `AUDIO_OUTPUT_ENABLE`,
/// one vblank, `AUDIO_ELD_VALID` invalidated, then the timestamp update at
/// `rate`. The ELD goes through the component, never the hardware buffer.
pub fn codec_enable<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    cdclk_khz: u32,
    rate: u32,
) -> Result<(), AudioError> {
    check_trans(s)?;
    if s.dp {
        enable_audio_dsc_wa(io, s, cdclk_khz)?;
    }
    sdp_split_update(io, s, true)?;
    if s.wa_14020863754 {
        rmw(io, AUD_CHICKENBIT_REG3, 0, DACBE_DISABLE_MIN_HBLANK_FIX)?;
    }
    rmw(io, HSW_AUD_PIN_ELD_CP_VLD, 0, aud_output_enable(s.trans))?;
    wait_for_next_vblank(io, s.pipe);
    rmw(io, HSW_AUD_PIN_ELD_CP_VLD, aud_eld_valid(s.trans), 0)?;
    let _guard = AUDIO.lock();
    config_update(io, s, rate)
}

/// `hsw_audio_codec_disable`: timestamps off (`N_PROG_ENABLE`, plus
/// `N_VALUE_INDEX` for DP, N cleared), `AUDIO_ELD_VALID` cleared, two
/// vblanks, `AUDIO_OUTPUT_ENABLE` cleared, Wa_14020863754 undone and the
/// SDP split off.
pub fn codec_disable<M: MmioWindow + ?Sized>(io: &M, s: &AudioStream) -> Result<(), AudioError> {
    check_trans(s)?;
    {
        let _guard = AUDIO.lock();
        rmw(
            io,
            aud_cfg_off(s.trans),
            AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_UPPER_N_MASK | AUD_CONFIG_LOWER_N_MASK,
            AUD_CONFIG_N_PROG_ENABLE
                | if s.dp {
                    AUD_CONFIG_N_VALUE_INDEX
                } else {
                    0
                },
        )?;
    }
    rmw(io, HSW_AUD_PIN_ELD_CP_VLD, aud_eld_valid(s.trans), 0)?;
    wait_for_next_vblank(io, s.pipe);
    wait_for_next_vblank(io, s.pipe);
    rmw(io, HSW_AUD_PIN_ELD_CP_VLD, aud_output_enable(s.trans), 0)?;
    if s.wa_14020863754 {
        rmw(io, AUD_CHICKENBIT_REG3, DACBE_DISABLE_MIN_HBLANK_FIX, 0)?;
    }
    sdp_split_update(io, s, false)
}

// ── intel_audio_compute_config ───────────────────────────────────────

/// `DRM_ELD_SUPPORTS_AI` in `DRM_ELD_SAD_COUNT_CONN_TYPE` (byte 5).
const DRM_ELD_SUPPORTS_AI: u8 = 1 << 1;
/// `HDMI_TMDS_AUDIO_PACKETS_LINE_MAX`.
const HDMI_TMDS_AUDIO_PACKETS_LINE_MAX: u64 = 18;
/// `sad_freqs[]`: the CTA SAD rate bits.
const SAD_FREQS: [u32; 7] = [32_000, 44_100, 48_000, 88_200, 96_000, 176_400, 192_000];

/// `hdmi_audio_rate_supported`: the audio packets one line carries at
/// `audio_rate` with `channels` fit the blanking's TMDS budget
/// (`available_tmds`) beside the HDCP 1.x worst-case overhead (74), and
/// no more than 18 per line.
pub fn hdmi_audio_rate_supported(
    crtc_clock_khz: u32,
    h_total: u16,
    available_tmds: u32,
    audio_rate: u32,
    channels: u8,
) -> bool {
    let pixel_clk_max_hz = u64::from(crtc_clock_khz) * 1005;
    if pixel_clk_max_hz == 0 {
        return false;
    }
    let factor: u64 = if channels <= 2 { 1 } else { 4 };
    let rate_x4_x1000 = (u64::from(audio_rate) * factor + 12_000) * 1001;
    let packets_line = (rate_x4_x1000 * u64::from(h_total)).div_ceil(4 * 1000 * pixel_clk_max_hz);
    let hblank_audio_min = 32 * packets_line + 74;
    hblank_audio_min <= u64::from(available_tmds) && packets_line <= HDMI_TMDS_AUDIO_PACKETS_LINE_MAX
}

/// The HDMI VSDB's audio facts (`drm_parse_hdmi_vsdb_audio`): AI support
/// and the progressive (audio, video) latency, if present.
fn hdmi_vsdb_audio(edid: &[u8]) -> (bool, Option<(u8, u8)>) {
    const OUI: [u8; 3] = [0x03, 0x0C, 0x00];
    for block in edid.chunks_exact(128).skip(1) {
        if block[0] != 0x02 {
            continue;
        }
        let limit = match block[2] {
            0 => 127usize,
            n => (n as usize).min(127),
        };
        let mut pos = 4usize;
        while pos < limit {
            let header = block[pos];
            let (tag, len) = (header >> 5, (header & 0x1F) as usize);
            if pos + 1 + len > 128 {
                break;
            }
            let db = &block[pos..pos + 1 + len];
            if tag == 3 && len >= 3 && db[1..4] == OUI {
                let ai = len >= 6 && db[6] & (1 << 7) != 0;
                let latency = (len >= 10 && db[8] & (1 << 7) != 0).then(|| (db[10], db[9]));
                return (ai, latency);
            }
            pos += 1 + len;
        }
    }
    (false, None)
}

/// `drm_av_sync_delay` (progressive mode) in ms from the VSDB's
/// (audio, video) latency fields.
pub fn av_sync_delay_ms(latency: Option<(u8, u8)>) -> u32 {
    let Some((a, v)) = latency else {
        return 0;
    };
    if a == 255 || v == 255 {
        return 0;
    }
    let ms = |raw: u8| -> i32 {
        if raw == 0 {
            0
        } else {
            (2 * (i32::from(raw) - 1)).min(500)
        }
    };
    (ms(v) - ms(a)).max(0) as u32
}

/// `intel_audio_compute_config` for `publication` (the shared builder's
/// ELD of `edid`): the ELD with `drm_edid_to_eld`'s baseline length
/// (`drm_eld_calc_baseline_block_size`, which excludes the 4-byte header),
/// for HDMI the VSDB's AI bit and `intel_audio_hdmi_eld_compute_config`
/// (each SAD keeps the rates `hdmi_audio_rate_supported` admits within
/// `DIV_ROUND_UP(hblank * bpc, 8 * K_420)` TMDS clocks; SADs left with none
/// are dropped and the count and length recomputed), then
/// `drm_av_sync_delay / 2` in byte 6. Port ID stays 0 as `drm_edid_to_eld`
/// leaves it.
pub fn compute_eld(
    publication: &DisplayAudioPublication,
    edid: &[u8],
    s: &AudioStream,
) -> [u8; MAX_ELD_BYTES] {
    let mut eld = [0u8; MAX_ELD_BYTES];
    let src = publication.eld_bytes();
    let n = src.len().min(MAX_ELD_BYTES);
    eld[..n].copy_from_slice(&src[..n]);
    eld[8..16].fill(0);
    let mnl = usize::from(eld[4] & 0x1F);
    let mut sad_count = usize::from(eld[5] >> 4);
    let (ai, latency) = hdmi_vsdb_audio(edid);
    if !s.dp {
        if ai {
            eld[5] |= DRM_ELD_SUPPORTS_AI;
        }
        let hblank = u32::from(s.h_total.saturating_sub(s.h_active));
        let bpc = s.pipe_bpp / 3;
        let divider = if s.ycbcr420 { 2 } else { 1 };
        let available_tmds = (hblank * bpc).div_ceil(8 * divider);
        let mut dst = 0usize;
        for src in 0..sad_count {
            let at = 20 + mnl + 3 * src;
            let sad = [eld[at], eld[at + 1], eld[at + 2]];
            let channels = (sad[0] & 7) + 1;
            let mut freq = 0u8;
            for (bit, rate) in SAD_FREQS.iter().enumerate() {
                if sad[1] & (1 << bit) != 0
                    && hdmi_audio_rate_supported(
                        s.crtc_clock_khz,
                        s.h_total,
                        available_tmds,
                        *rate,
                        channels,
                    )
                {
                    freq |= 1 << bit;
                }
            }
            if freq == 0 {
                continue;
            }
            let to = 20 + mnl + 3 * dst;
            eld[to..to + 3].copy_from_slice(&[sad[0], freq, sad[2]]);
            dst += 1;
        }
        let tail = 20 + mnl + 3 * dst;
        eld[tail..20 + mnl + 3 * sad_count].fill(0);
        sad_count = dst;
        eld[5] = (eld[5] & 0x0F) | ((sad_count as u8) << 4);
    }
    eld[2] = (16 + mnl + 3 * sad_count).div_ceil(4) as u8;
    eld[6] = (av_sync_delay_ms(latency) / 2) as u8;
    eld
}

/// `drm_eld_size`: the header plus the baseline block.
pub const fn eld_size(eld: &[u8; MAX_ELD_BYTES]) -> usize {
    4 + eld[2] as usize * 4
}

// ── Audio state and the component (intel_audio_component_ops) ────────

/// `display->audio.state[cpu_transcoder]`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct AudioState {
    stream: AudioStream,
    eld: [u8; MAX_ELD_BYTES],
}

/// `display->audio`.
#[derive(Debug)]
struct Audio {
    state: [Option<AudioState>; 4],
    /// `acomp->aud_sample_rate[port]` (`MAX_PORTS` 9).
    aud_sample_rate: [u32; 9],
    power_refcount: u32,
    /// `display->audio.freq_cntrl`.
    freq_cntrl: u32,
}

static AUDIO: IrqSafeSpinLock<Audio> = IrqSafeSpinLock::new(Audio {
    state: [None; 4],
    aud_sample_rate: [0; 9],
    power_refcount: 0,
    freq_cntrl: AUD_FREQ_GEN12,
});

fn sample_rate(port: i32) -> u32 {
    usize::try_from(port)
        .ok()
        .and_then(|p| AUDIO.lock().aud_sample_rate.get(p).copied())
        .unwrap_or(0)
}

/// `find_audio_state`: an MST/UHBR stream by its CPU transcoder, a legacy
/// SST stream by its port alone (the first transcoder carrying it).
fn find_audio_state(audio: &Audio, port: i32, cpu_transcoder: i32) -> Option<AudioState> {
    if cpu_transcoder >= 0 {
        if let Some(state) = audio.state.get(cpu_transcoder as usize).and_then(|s| *s) {
            if state.stream.port == port && state.stream.needs_cpu_transcoder_id() {
                return Some(state);
            }
        }
    }
    if cpu_transcoder > 0 {
        return None;
    }
    audio
        .state
        .iter()
        .flatten()
        .find(|state| state.stream.port == port && !state.stream.needs_cpu_transcoder_id())
        .copied()
}

/// `intel_audio_codec_enable` for the route's `stream` with `eld`
/// ([`compute_eld`]): [`codec_enable`] at the port's current sample rate,
/// the state store, the shared display-audio sink publication (sink id
/// `port + 1`) and the codec's `pin_eld_notify`.
pub fn audio_codec_enable<M: MmioWindow + ?Sized>(
    io: &M,
    s: &AudioStream,
    eld: &[u8; MAX_ELD_BYTES],
    publication: DisplayAudioPublication,
) -> Result<(), AudioError> {
    let cdclk = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io);
    codec_enable(io, s, cdclk, sample_rate(s.port))?;
    if let Some(slot) = AUDIO.lock().state.get_mut(s.trans as usize) {
        *slot = Some(AudioState {
            stream: *s,
            eld: *eld,
        });
    }
    acomp::publish_display_audio(sink_id(s.port), publication);
    acomp::notify_pin_eld(s.port, s.notify_pipe());
    Ok(())
}

/// `intel_audio_codec_disable`: [`codec_disable`], the state cleared, the
/// sink publication cleared and the codec notified. The state is cleared
/// even when a register step failed, so no codec reads a stale ELD.
pub fn audio_codec_disable<M: MmioWindow + ?Sized>(io: &M, s: &AudioStream) -> Result<(), AudioError> {
    let result = codec_disable(io, s);
    if let Some(slot) = AUDIO.lock().state.get_mut(s.trans as usize) {
        *slot = None;
    }
    acomp::clear_display_audio(sink_id(s.port));
    acomp::notify_pin_eld(s.port, s.notify_pipe());
    result
}

/// The shared display-audio sink id of a display-14 port: `enum port + 1`
/// (0 reserved), the Gen12 publisher's numbering.
pub const fn sink_id(port: i32) -> acomp::DisplaySinkId {
    acomp::DisplaySinkId((port + 1) as u32)
}

/// `get_aud_ts_cdclk_m_n`: M = 60, N = cdclk × M / 24000.
pub const fn aud_ts_cdclk_m_n(cdclk_khz: u32) -> (u32, u32) {
    (60, cdclk_khz * 60 / 24_000)
}

/// `intel_audio_cdclk_change_pre` (display 13+): `AUD_TS_CDCLK_M_EN` off
/// before a CDCLK change.
pub fn cdclk_change_pre<M: MmioWindow + ?Sized>(io: &M) -> Result<(), AudioError> {
    rmw(io, AUD_TS_CDCLK_M, AUD_TS_CDCLK_M_EN, 0)
}

/// `intel_audio_cdclk_change_post` (display 13+): N, then M with the
/// enable, for the CDCLK now running.
pub fn cdclk_change_post<M: MmioWindow + ?Sized>(io: &M) -> Result<(), AudioError> {
    let (m, n) = aud_ts_cdclk_m_n(crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io));
    io.write32(AUD_TS_CDCLK_N, n);
    io.write32(AUD_TS_CDCLK_M, m | AUD_TS_CDCLK_M_EN);
    compiler_fence(Ordering::SeqCst);
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(AudioError::AccessLost)
    }
}

/// `intel_audio_component_init` on display 12+ outside Tiger and Rocket
/// Lake: `AUD_FREQ_GEN12` is the frequency control `get_power` restores,
/// and the timestamp M/N follow the current CDCLK.
pub fn component_init<M: MmioWindow + ?Sized>(io: &M) -> Result<(), AudioError> {
    AUDIO.lock().freq_cntrl = AUD_FREQ_GEN12;
    cdclk_change_post(io)
}

/// `intel_audio_component_get_power`: the first reference restores
/// `AUD_FREQ_CNTRL` (display 9+) and sets `AUD_PIN_BUF_ENABLE` (display
/// 10+). The cookie is the reference count it took (never 0).
pub fn component_get_power<M: MmioWindow + ?Sized>(io: &M) -> u64 {
    let (first, freq, count) = {
        let mut audio = AUDIO.lock();
        audio.power_refcount += 1;
        (audio.power_refcount == 1, audio.freq_cntrl, audio.power_refcount)
    };
    if first {
        io.write32(AUD_FREQ_CNTRL, freq);
        compiler_fence(Ordering::SeqCst);
        let _ = rmw(io, AUD_PIN_BUF_CTL, 0, AUD_PIN_BUF_ENABLE);
    }
    u64::from(count)
}

/// `intel_audio_component_put_power`.
pub fn component_put_power() {
    let mut audio = AUDIO.lock();
    audio.power_refcount = audio.power_refcount.saturating_sub(1);
}

/// `intel_audio_component_codec_wake_override` (display 9+): under a power
/// reference, `SKL_AUD_CODEC_WAKE_SIGNAL` cleared, 1 ms, and for `enable`
/// set again and another 1 ms.
pub fn component_codec_wake_override<M: MmioWindow + ?Sized>(io: &M, enable: bool) {
    let _cookie = component_get_power(io);
    let _ = rmw(io, HSW_AUD_CHICKENBIT, SKL_AUD_CODEC_WAKE_SIGNAL, 0);
    sleep_us(1_000);
    if enable {
        let _ = rmw(io, HSW_AUD_CHICKENBIT, 0, SKL_AUD_CODEC_WAKE_SIGNAL);
        sleep_us(1_000);
    }
    component_put_power();
}

/// `intel_audio_component_sync_audio_rate`: the stream on (`port`,
/// `cpu_transcoder`) records `rate` and reruns its timestamp update.
pub fn component_sync_audio_rate<M: MmioWindow + ?Sized>(
    io: &M,
    port: i32,
    cpu_transcoder: i32,
    rate: u32,
) -> Result<(), ComponentError> {
    let _cookie = component_get_power(io);
    let result = (|| {
        let mut audio = AUDIO.lock();
        let state = find_audio_state(&audio, port, cpu_transcoder).ok_or(ComponentError::NoDevice)?;
        let slot = usize::try_from(port)
            .ok()
            .and_then(|p| audio.aud_sample_rate.get_mut(p))
            .ok_or(ComponentError::Invalid)?;
        *slot = rate;
        config_update(io, &state.stream, rate).map_err(|_| ComponentError::NoDevice)
    })();
    component_put_power();
    result
}

/// `intel_audio_component_get_eld`: whether the stream on (`port`,
/// `cpu_transcoder`) has an encoder, and its ELD (`drm_eld_size` bytes,
/// at most `buf.len()` copied).
pub fn component_get_eld(
    port: i32,
    cpu_transcoder: i32,
    buf: &mut [u8],
) -> Result<(bool, usize), ComponentError> {
    let audio = AUDIO.lock();
    let state = find_audio_state(&audio, port, cpu_transcoder).ok_or(ComponentError::Invalid)?;
    let size = eld_size(&state.eld);
    let n = size.min(buf.len());
    buf[..n].copy_from_slice(&state.eld[..n]);
    Ok((true, size))
}

/// The component over an explicit register window (the production binding
/// opens the display's window per call).
pub struct XelpgAudioComponent<'a, M: MmioWindow + ?Sized> {
    /// The display's registers.
    pub io: &'a M,
}

impl<M: MmioWindow + ?Sized> core::fmt::Debug for XelpgAudioComponent<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XelpgAudioComponent").finish_non_exhaustive()
    }
}

impl<M: MmioWindow + ?Sized> DisplayAudioComponent for XelpgAudioComponent<'_, M> {
    fn get_power(&self) -> u64 {
        component_get_power(self.io)
    }
    fn put_power(&self, _cookie: u64) {
        component_put_power();
    }
    fn codec_wake_override(&self, enable: bool) {
        component_codec_wake_override(self.io, enable);
    }
    fn get_cdclk_freq(&self) -> Result<u32, ComponentError> {
        Ok(crate::intel_gpu_modeset_xelpg::cdclk_current_khz(self.io))
    }
    fn sync_audio_rate(&self, port: i32, pipe: i32, rate: u32) -> Result<(), ComponentError> {
        component_sync_audio_rate(self.io, port, pipe, rate)
    }
    fn get_eld(
        &self,
        port: i32,
        pipe: i32,
        buf: &mut [u8],
    ) -> Result<(bool, usize), ComponentError> {
        component_get_eld(port, pipe, buf)
    }
}

/// The production component: each op runs on the display's current
/// window; with no display it is `-ENODEV` (power ops are no-ops).
struct ProductionComponent;

fn with_window<R>(f: impl FnOnce(&crate::intel_gpu::ModeWindow) -> R) -> Option<R> {
    crate::intel_gpu::with_display_info(|gpu| f(&gpu.mode_window()))
}

impl DisplayAudioComponent for ProductionComponent {
    fn get_power(&self) -> u64 {
        with_window(component_get_power).unwrap_or(1)
    }
    fn put_power(&self, _cookie: u64) {
        component_put_power();
    }
    fn codec_wake_override(&self, enable: bool) {
        let _ = with_window(|io| component_codec_wake_override(io, enable));
    }
    fn get_cdclk_freq(&self) -> Result<u32, ComponentError> {
        with_window(crate::intel_gpu_modeset_xelpg::cdclk_current_khz)
            .ok_or(ComponentError::NoDevice)
    }
    fn sync_audio_rate(&self, port: i32, pipe: i32, rate: u32) -> Result<(), ComponentError> {
        with_window(|io| component_sync_audio_rate(io, port, pipe, rate))
            .unwrap_or(Err(ComponentError::NoDevice))
    }
    fn get_eld(
        &self,
        port: i32,
        pipe: i32,
        buf: &mut [u8],
    ) -> Result<(bool, usize), ComponentError> {
        component_get_eld(port, pipe, buf)
    }
}

static PRODUCTION: ProductionComponent = ProductionComponent;

/// `intel_audio_component_init` and `intel_audio_component_bind` for the
/// production display under `narf.intel.hdmi14_ext=1`; idempotent (a bound
/// component stays bound).
pub fn bind_production_component<M: MmioWindow + ?Sized>(io: &M) {
    if acomp::display_audio_component().is_some() {
        return;
    }
    let _ = component_init(io);
    let _ = acomp::bind_display_audio_component(&PRODUCTION);
}

/// Forget every stream and sample rate (fixtures only).
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn reset_for_test() {
    let mut audio = AUDIO.lock();
    audio.state = [None; 4];
    audio.aud_sample_rate = [0; 9];
    audio.power_refcount = 0;
    audio.freq_cntrl = AUD_FREQ_GEN12;
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_xelpg_audio_tests.rs"]
pub mod tests;
