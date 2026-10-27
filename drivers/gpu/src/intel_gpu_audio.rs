//! Intel display-audio codec programming — Gen12 (TGL/ADL/RPL).
//!
//! The display engine's half of DP/HDMI audio: per-transcoder
//! `AUD_CONFIG` timestamp setup and the `AUD_PIN_ELD_CP_VLD`
//! output/ELD-valid bits. The *data* half — the ELD itself and
//! its publication to the HDA/ALSA consumer — lives behind the
//! shared display-audio sink in `narf_drivers_sound::
//! display_audio` (see that module for the seam; #1019's HDMI
//! lane reuses both this codec shape and that sink).
//!
//! Register definitions and sequences follow PRM Vol. 12
//! §"Audio" and are cross-checked against Linux
//! `drivers/gpu/drm/i915/display/intel_audio.c`
//! (`hsw_audio_codec_enable` / `hsw_audio_codec_disable` /
//! `hsw_dp_audio_config_update`) and `intel_audio_regs.h`
//! (GPL-2.0-or-later — compatible with NARF's post-2026-05-20
//! relicense):
//!
//!   - `HSW_AUD_CFG(trans)` = `0x65000 + trans * 0x100`.
//!     For DP, the config update clears the N-value fields and
//!     the HDMI pixel-clock field and sets `N_VALUE_INDEX`, so
//!     hardware generates Maud/Naud from the link clock itself
//!     ("enable time stamps"). For disable, the N fields are
//!     cleared and `N_PROG_ENABLE` is set (plus `N_VALUE_INDEX`
//!     when the old configuration was DP).
//!   - `HSW_AUD_PIN_ELD_CP_VLD` = `0x650C0`, a per-transcoder
//!     4-bit field at shift `(trans & 3) * 4`: +0 ELD valid,
//!     +1 CP ready, +2 output enable, +3 inactive. Enable sets
//!     OUTPUT_ENABLE, then invalidates ELD_VALID while the new
//!     ELD is published (the invalidate-after-vblank ordering
//!     i915 uses is the caller's to sequence with publication —
//!     in this driver the session publishes the ELD to the
//!     sound sink *before* raising ELD_VALID again, see
//!     `intel_gpu_dp`).

use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pipes::Transcoder;

/// `HSW_AUD_CFG` base (transcoder A); stride 0x100 per
/// transcoder.
pub const HSW_AUD_CFG_BASE: u64 = 0x6_5000;
/// `HSW_AUD_PIN_ELD_CP_VLD` — one register, per-transcoder
/// 4-bit fields.
pub const HSW_AUD_PIN_ELD_CP_VLD: u64 = 0x6_50C0;

/// AUD_CONFIG bit 29 — N value index ("enable time stamps"
/// for DP when set with the N fields cleared).
pub const AUD_CONFIG_N_VALUE_INDEX: u32 = 1 << 29;
/// AUD_CONFIG bit 28 — program N value (used on the disable
/// path to latch the cleared N).
pub const AUD_CONFIG_N_PROG_ENABLE: u32 = 1 << 28;
/// AUD_CONFIG bits[27:20] — upper N value.
pub const AUD_CONFIG_UPPER_N_MASK: u32 = 0xFF << 20;
/// AUD_CONFIG bits[19:16] — HDMI pixel-clock encoding.
pub const AUD_CONFIG_PIXEL_CLOCK_MASK: u32 = 0x0F << 16;
/// AUD_CONFIG bits[15:4] — lower N value.
pub const AUD_CONFIG_LOWER_N_MASK: u32 = 0xFFF << 4;

/// Per-transcoder field shift inside `HSW_AUD_PIN_ELD_CP_VLD`.
fn pin_eld_shift(trans: Transcoder) -> u32 {
    (trans as u32 & 0x3) * 4
}

/// `AUD_PIN_ELD_CP_VLD` bit: ELD data for this transcoder is
/// valid for the codec to read.
pub fn aud_eld_valid(trans: Transcoder) -> u32 {
    1 << pin_eld_shift(trans)
}

/// `AUD_PIN_ELD_CP_VLD` bit: the audio output for this
/// transcoder is enabled.
pub fn aud_output_enable(trans: Transcoder) -> u32 {
    1 << (pin_eld_shift(trans) + 2)
}

/// MMIO offset of `AUD_CFG` for `trans`.
pub fn aud_cfg_off(trans: Transcoder) -> u64 {
    HSW_AUD_CFG_BASE + (trans as u64) * 0x100
}

/// DP audio config update (`hsw_dp_audio_config_update`):
/// clear the N-value fields, the HDMI pixel-clock field and
/// `N_PROG_ENABLE`, then set `N_VALUE_INDEX` so the hardware
/// computes Maud/Naud from the DP link clock.
pub fn dp_audio_config_update<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let off = aud_cfg_off(trans);
    let cur = mmio.read32(off);
    let cleared = cur
        & !(AUD_CONFIG_N_VALUE_INDEX
            | AUD_CONFIG_PIXEL_CLOCK_MASK
            | AUD_CONFIG_UPPER_N_MASK
            | AUD_CONFIG_LOWER_N_MASK
            | AUD_CONFIG_N_PROG_ENABLE);
    mmio.write32(off, cleared | AUD_CONFIG_N_VALUE_INDEX);
    compiler_fence(Ordering::SeqCst);
}

/// Enable the audio codec path for a DP stream on `trans`
/// (`hsw_audio_codec_enable`, display side): raise
/// OUTPUT_ENABLE, invalidate ELD_VALID (the caller publishes
/// the fresh ELD into the sound sink, then calls
/// [`set_eld_valid`] to raise it), and run the DP config
/// update.
pub fn audio_codec_enable<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let cur = mmio.read32(HSW_AUD_PIN_ELD_CP_VLD);
    mmio.write32(
        HSW_AUD_PIN_ELD_CP_VLD,
        (cur | aud_output_enable(trans)) & !aud_eld_valid(trans),
    );
    compiler_fence(Ordering::SeqCst);
    dp_audio_config_update(mmio, trans);
}

/// Raise or clear ELD_VALID for `trans`. The session raises it
/// only after the ELD bytes are published in the shared
/// display-audio sink, so a codec reading on ELD_VALID never
/// observes a half-written publication.
pub fn set_eld_valid<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder, valid: bool) {
    let cur = mmio.read32(HSW_AUD_PIN_ELD_CP_VLD);
    let next = if valid {
        cur | aud_eld_valid(trans)
    } else {
        cur & !aud_eld_valid(trans)
    };
    mmio.write32(HSW_AUD_PIN_ELD_CP_VLD, next);
    compiler_fence(Ordering::SeqCst);
}

/// Disable the audio codec path for `trans`
/// (`hsw_audio_codec_disable`): latch the cleared-N config
/// with `N_PROG_ENABLE` (and `N_VALUE_INDEX`, since the old
/// configuration was DP), then drop ELD_VALID and
/// OUTPUT_ENABLE.
pub fn audio_codec_disable<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let off = aud_cfg_off(trans);
    let cur = mmio.read32(off);
    let cleared = cur
        & !(AUD_CONFIG_UPPER_N_MASK
            | AUD_CONFIG_PIXEL_CLOCK_MASK
            | AUD_CONFIG_LOWER_N_MASK
            | AUD_CONFIG_N_VALUE_INDEX
            | AUD_CONFIG_N_PROG_ENABLE);
    mmio.write32(
        off,
        cleared | AUD_CONFIG_N_PROG_ENABLE | AUD_CONFIG_N_VALUE_INDEX,
    );
    compiler_fence(Ordering::SeqCst);
    let cur = mmio.read32(HSW_AUD_PIN_ELD_CP_VLD);
    mmio.write32(
        HSW_AUD_PIN_ELD_CP_VLD,
        cur & !aud_eld_valid(trans) & !aud_output_enable(trans),
    );
    compiler_fence(Ordering::SeqCst);
}

// ── HDMI audio (#1019) ─────────────────────────────────────────
//
// The HDMI branch of `hsw_audio_codec_enable` differs from DP
// in the AUD_CONFIG programming: instead of N_VALUE_INDEX
// (hardware timestamps from the DP link clock), the config
// carries the TMDS pixel-clock encoding in bits[19:16] so the
// hardware derives Maud/Naud from the TMDS clock, the N fields
// are cleared, and `N_PROG_ENABLE` latches the result. The
// pixel-clock field encodings are the AUD_CONFIG field table
// (PRM Vol. 12 §"AUD_CONFIG"; i915 `intel_audio_regs.h`
// AUD_CONFIG_PIXEL_CLOCK_HDMI_*): the standard TMDS clocks of
// the CEA mode set, in ascending order.

/// (TMDS clock kHz, AUD_CONFIG pixel-clock field value) — the
/// documented HDMI pixel-clock encodings.
const AUD_CONFIG_PIXEL_CLOCK_HDMI_TABLE: &[(u32, u32)] = &[
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

/// The `AUD_CONFIG` pixel-clock field bits for a TMDS clock,
/// or `None` when the clock has no documented encoding (the
/// caller then latches the config with the field cleared —
/// the sink keeps the stream muted rather than running with a
/// guessed clock code).
pub fn aud_config_pixel_clock_hdmi(tmds_khz: u32) -> Option<u32> {
    AUD_CONFIG_PIXEL_CLOCK_HDMI_TABLE
        .iter()
        .find(|(khz, _)| *khz == tmds_khz)
        .map(|(_, field)| field << 16)
}

/// HDMI audio config update: clear the N-value fields, the
/// pixel-clock field and both program/index bits, then set
/// the TMDS pixel-clock encoding and `N_PROG_ENABLE` to latch
/// it (the HDMI counterpart of [`dp_audio_config_update`]).
pub fn hdmi_audio_config_update<M: MmioWindow + ?Sized>(
    mmio: &M,
    trans: Transcoder,
    tmds_khz: u32,
) {
    let off = aud_cfg_off(trans);
    let cur = mmio.read32(off);
    let cleared = cur
        & !(AUD_CONFIG_N_VALUE_INDEX
            | AUD_CONFIG_PIXEL_CLOCK_MASK
            | AUD_CONFIG_UPPER_N_MASK
            | AUD_CONFIG_LOWER_N_MASK
            | AUD_CONFIG_N_PROG_ENABLE);
    let pixel_clock = aud_config_pixel_clock_hdmi(tmds_khz).unwrap_or(0);
    mmio.write32(off, cleared | pixel_clock | AUD_CONFIG_N_PROG_ENABLE);
    compiler_fence(Ordering::SeqCst);
}

/// Enable the audio codec path for an HDMI stream on `trans`:
/// same PIN_ELD shape as [`audio_codec_enable`] (OUTPUT_ENABLE
/// raised, ELD_VALID held down until the caller publishes the
/// ELD), with the HDMI config update for `tmds_khz`.
pub fn hdmi_audio_codec_enable<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder, tmds_khz: u32) {
    let cur = mmio.read32(HSW_AUD_PIN_ELD_CP_VLD);
    mmio.write32(
        HSW_AUD_PIN_ELD_CP_VLD,
        (cur | aud_output_enable(trans)) & !aud_eld_valid(trans),
    );
    compiler_fence(Ordering::SeqCst);
    hdmi_audio_config_update(mmio, trans, tmds_khz);
}

/// Disable the audio codec path for an HDMI stream: latch the
/// cleared-N config with `N_PROG_ENABLE` only —
/// `N_VALUE_INDEX` is *not* set, because unlike
/// [`audio_codec_disable`] the configuration being torn down
/// was not a DP one (`hsw_audio_codec_disable` conditions that
/// bit on the old configuration being DP). Then drop
/// ELD_VALID and OUTPUT_ENABLE.
pub fn hdmi_audio_codec_disable<M: MmioWindow + ?Sized>(mmio: &M, trans: Transcoder) {
    let off = aud_cfg_off(trans);
    let cur = mmio.read32(off);
    let cleared = cur
        & !(AUD_CONFIG_UPPER_N_MASK
            | AUD_CONFIG_PIXEL_CLOCK_MASK
            | AUD_CONFIG_LOWER_N_MASK
            | AUD_CONFIG_N_VALUE_INDEX
            | AUD_CONFIG_N_PROG_ENABLE);
    mmio.write32(off, cleared | AUD_CONFIG_N_PROG_ENABLE);
    compiler_fence(Ordering::SeqCst);
    let cur = mmio.read32(HSW_AUD_PIN_ELD_CP_VLD);
    mmio.write32(
        HSW_AUD_PIN_ELD_CP_VLD,
        cur & !aud_eld_valid(trans) & !aud_output_enable(trans),
    );
    compiler_fence(Ordering::SeqCst);
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::intel_gpu_aux::tests::MockMmio;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_dp_audio_config_update_encoding() -> TestResult {
        let mmio = MockMmio::default();
        // Dirty config: N fields + pixel-clock + prog-enable set.
        mmio.set_read(
            aud_cfg_off(Transcoder::A),
            AUD_CONFIG_N_PROG_ENABLE
                | AUD_CONFIG_UPPER_N_MASK
                | AUD_CONFIG_PIXEL_CLOCK_MASK
                | AUD_CONFIG_LOWER_N_MASK
                | 0x3, // unrelated low bits must survive
        );
        dp_audio_config_update(&mmio, Transcoder::A);
        let writes = mmio.writes_to(aud_cfg_off(Transcoder::A));
        if writes != alloc::vec![AUD_CONFIG_N_VALUE_INDEX | 0x3] {
            return TestResult::Fail("DP config update must clear N fields and set N_VALUE_INDEX");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_audio",
        smoke_dp_audio_config_update_encoding
    );

    fn smoke_audio_enable_disable_pin_eld_fields() -> TestResult {
        let mmio = MockMmio::default();
        mmio.set_read(HSW_AUD_PIN_ELD_CP_VLD, 0);
        audio_codec_enable(&mmio, Transcoder::A);
        // MockMmio serves scripted reads (always 0), so check the
        // individual writes rather than a read-modify-write chain:
        // enable must set OUTPUT_ENABLE (bit 2 of field 0) and
        // must not set ELD_VALID (bit 0) in the same write.
        let writes = mmio.writes_to(HSW_AUD_PIN_ELD_CP_VLD);
        if writes.len() != 1 || writes[0] != aud_output_enable(Transcoder::A) {
            return TestResult::Fail("enable must set OUTPUT_ENABLE only");
        }
        set_eld_valid(&mmio, Transcoder::A, true);
        let writes = mmio.writes_to(HSW_AUD_PIN_ELD_CP_VLD);
        if writes.len() != 2 || writes[1] != aud_eld_valid(Transcoder::A) {
            return TestResult::Fail("set_eld_valid(true) must raise ELD_VALID");
        }
        // Transcoder B lives at field shift 4 — no crosstalk.
        if aud_output_enable(Transcoder::B) != 1 << 6 || aud_eld_valid(Transcoder::B) != 1 << 4 {
            return TestResult::Fail("transcoder B field must sit at shift 4");
        }
        audio_codec_disable(&mmio, Transcoder::A);
        let cfg_writes = mmio.writes_to(aud_cfg_off(Transcoder::A));
        let last = cfg_writes[cfg_writes.len() - 1];
        if last & (AUD_CONFIG_N_PROG_ENABLE | AUD_CONFIG_N_VALUE_INDEX)
            != AUD_CONFIG_N_PROG_ENABLE | AUD_CONFIG_N_VALUE_INDEX
        {
            return TestResult::Fail("disable must latch cleared N with PROG_ENABLE + VALUE_INDEX");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_audio",
        smoke_audio_enable_disable_pin_eld_fields
    );

    fn smoke_hdmi_audio_config_update_encoding() -> TestResult {
        // Pixel-clock field encodings (AUD_CONFIG table):
        // 297_000 -> 11, 594_000 -> 13, unlisted -> None.
        if aud_config_pixel_clock_hdmi(297_000) != Some(11 << 16) {
            return TestResult::Fail("297 MHz TMDS must encode pixel-clock field 11");
        }
        if aud_config_pixel_clock_hdmi(594_000) != Some(13 << 16) {
            return TestResult::Fail("594 MHz TMDS must encode pixel-clock field 13");
        }
        if aud_config_pixel_clock_hdmi(123_456).is_some() {
            return TestResult::Fail("unlisted TMDS clock must not encode");
        }
        let mmio = MockMmio::default();
        mmio.set_read(
            aud_cfg_off(Transcoder::A),
            AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_UPPER_N_MASK | AUD_CONFIG_LOWER_N_MASK | 0x3, // unrelated low bits must survive
        );
        hdmi_audio_codec_enable(&mmio, Transcoder::A, 297_000);
        let writes = mmio.writes_to(aud_cfg_off(Transcoder::A));
        let want = (11 << 16) | AUD_CONFIG_N_PROG_ENABLE | 0x3;
        if writes != alloc::vec![want] {
            return TestResult::Fail(
                "HDMI config update must clear N fields, set pixel clock + PROG_ENABLE",
            );
        }
        // Disable: the latch carries PROG_ENABLE without
        // VALUE_INDEX (the old configuration was not DP).
        hdmi_audio_codec_disable(&mmio, Transcoder::A);
        let writes = mmio.writes_to(aud_cfg_off(Transcoder::A));
        let last = writes[writes.len() - 1];
        if last & AUD_CONFIG_N_PROG_ENABLE == 0 || last & AUD_CONFIG_N_VALUE_INDEX != 0 {
            return TestResult::Fail("HDMI disable must latch with PROG_ENABLE only");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_audio",
        smoke_hdmi_audio_config_update_encoding
    );
}
