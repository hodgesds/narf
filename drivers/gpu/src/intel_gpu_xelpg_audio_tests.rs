//! Native fixtures for the display-14+ audio codec and component
//! (`narf.intel.hdmi14_ext`). Values are derived from Linux 7.4
//! `intel_audio.c`, `intel_audio_regs.h`, `drm_edid.c`, `drm_eld.h` and the
//! HDA side (`sound/hda/core/component.c`,
//! `sound/hda/codecs/hdmi/intelhdmi.c`), not recorded from this code.
extern crate alloc;

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicI32, AtomicU32};
use narf_drivers_sound::display_audio::{
    acomp_get_eld, acomp_sync_audio_rate, build_eld, DisplayAudioCodec, DisplayConnector,
    DisplayPower,
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Stateful display registers: reads return the last write; the frame
/// counter of every pipe advances on each read (so vblank waits return);
/// the CDCLK PLL reads enabled and locked at ratio 16 with the CD2X
/// divider 2, which `bxt_get_cdclk` reads as 307.2 MHz.
pub(crate) struct AudioFake {
    regs: RefCell<BTreeMap<u64, u32>>,
    pub(crate) writes: RefCell<Vec<(u64, u32)>>,
}

impl AudioFake {
    pub(crate) fn new() -> Self {
        let fake = Self {
            regs: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
        };
        fake.regs
            .borrow_mut()
            .insert(0x4_6070, (1 << 31) | (1 << 30) | 16);
        fake
    }
    pub(crate) fn set(&self, off: u64, val: u32) {
        self.regs.borrow_mut().insert(off, val);
    }
    pub(crate) fn writes_to(&self, off: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == off)
            .map(|(_, v)| *v)
            .collect()
    }
}

impl MmioWindow for AudioFake {
    fn read32(&self, off: u64) -> u32 {
        let mut regs = self.regs.borrow_mut();
        let v = regs.get(&off).copied().unwrap_or(0);
        if (off & 0xFFF) == FRMCOUNT && (0x7_0000..0x7_4000).contains(&off) {
            regs.insert(off, v.wrapping_add(1));
        }
        v
    }
    fn write32(&self, off: u64, val: u32) {
        self.regs.borrow_mut().insert(off, val);
        self.writes.borrow_mut().push((off, val));
    }
}

/// A 1080p reduced-blanking HDMI stream on DDI B, Transcoder B: 138.5 MHz,
/// 1920 of 2080 (160 clocks of blanking), 8 bpc RGB.
fn hdmi_stream() -> AudioStream {
    AudioStream {
        trans: Transcoder::B,
        pipe: Pipe::B,
        port: 1,
        dp: false,
        uhbr: false,
        crtc_clock_khz: 138_500,
        port_clock_khz: 138_500,
        pipe_bpp: 24,
        lane_count: 4,
        h_active: 1920,
        h_total: 2080,
        v_active: 1080,
        dsc_bpp_x16: None,
        ycbcr420: false,
        wa_14020863754: false,
    }
}

/// `hdmi_audio_clock[]`, the N tables (`audio_config_hdmi_get_n` by pipe
/// bpp), `AUD_CONFIG_N` and the HDMI / DP config updates.
fn smoke_xelpg_audio_tables_and_config_update() -> TestResult {
    // The pixel-clock field takes the mode clock; 138.5 MHz is not in the
    // table and falls back to 25.2 MHz's field 1.
    if audio_config_hdmi_pixel_clock(148_500) != 9 << 16
        || audio_config_hdmi_pixel_clock(594_000) != 13 << 16
        || audio_config_hdmi_pixel_clock(138_500) != 1 << 16
    {
        return TestResult::Fail("audio_config_hdmi_pixel_clock differs from Linux");
    }
    for (bpp, clock, rate, n) in [
        (24u32, 297_000u32, 48_000u32, 5120u32),
        (24, 594_000, 44_100, 9408),
        (24, 593_407, 192_000, 23296),
        (30, 371_250, 48_000, 5120),
        (30, 370_878, 192_000, 46592),
        (36, 445_500, 32_000, 4096),
        (36, 445_054, 96_000, 11648),
        // Not in the deep-colour table, nor a table clock: automatic N.
        (30, 297_000, 48_000, 0),
        (24, 148_500, 48_000, 0),
    ] {
        if audio_config_hdmi_get_n(bpp, clock, rate) != n {
            return TestResult::Fail("audio_config_hdmi_get_n differs from Linux's tables");
        }
    }
    // AUD_CONFIG_N(6144): N[19:12] = 1 at bit 20, N[11:0] = 2048 at bit 4.
    if aud_config_n(6144) != (1 << 20) | (2048 << 4) {
        return TestResult::Fail("AUD_CONFIG_N differs from intel_audio_regs.h");
    }
    // hsw_hdmi_audio_config_update for 4K30 (297 MHz) at 48 kHz: pixel
    // clock 11, N 5120 with N_PROG_ENABLE, N_VALUE_INDEX cleared, the
    // unrelated low bits kept; M/CTS programming handed to hardware.
    let io = AudioFake::new();
    let cfg = aud_cfg_off(Transcoder::B);
    io.set(
        cfg,
        AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_PIXEL_CLOCK_MASK | 0x3,
    );
    io.set(
        aud_m_cts_enable(Transcoder::B),
        AUD_M_CTS_M_PROG_ENABLE | AUD_M_CTS_M_VALUE_INDEX | 0x5,
    );
    let s = AudioStream {
        crtc_clock_khz: 297_000,
        port_clock_khz: 297_000,
        h_active: 3840,
        h_total: 4400,
        v_active: 2160,
        ..hdmi_stream()
    };
    if hdmi_audio_config_update(&io, &s, 48_000).is_err()
        || io.writes_to(cfg) != [0x3 | (11 << 16) | aud_config_n(5120) | AUD_CONFIG_N_PROG_ENABLE]
        || io.writes_to(aud_m_cts_enable(Transcoder::B)) != [0x5]
    {
        return TestResult::Fail("hsw_hdmi_audio_config_update differs from Linux");
    }
    // No table N (rate 0 before any sync): automatic N, no N_PROG_ENABLE.
    let io = AudioFake::new();
    io.set(cfg, AUD_CONFIG_N_PROG_ENABLE);
    if hdmi_audio_config_update(&io, &hdmi_stream(), 0).is_err() || io.writes_to(cfg) != [1 << 16] {
        return TestResult::Fail("automatic N must leave N_PROG_ENABLE clear");
    }
    // DP: N_VALUE_INDEX ("enable time stamps").
    let io = AudioFake::new();
    io.set(cfg, AUD_CONFIG_PIXEL_CLOCK_MASK | AUD_CONFIG_N_PROG_ENABLE);
    let dp = AudioStream {
        dp: true,
        ..hdmi_stream()
    };
    if config_update(&io, &dp, 48_000).is_err() || io.writes_to(cfg) != [AUD_CONFIG_N_VALUE_INDEX] {
        return TestResult::Fail("hsw_dp_audio_config_update must only set N_VALUE_INDEX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_tables_and_config_update
);

/// `hsw_audio_codec_enable` / `_disable` on DP: `HBLANK_EARLY_ENABLE_TGL`
/// in `AUD_CONFIG_BE`, Wa_14020863754's `DACBE_DISABLE_MIN_HBLANK_FIX`,
/// the SDP split for UHBR, `AUDIO_OUTPUT_ENABLE` before the ELD invalidate,
/// never ELD_VALID, and the disable's timestamp latch; plus the
/// compressed-4K `calc_hblank_early_prog` / `calc_samples_room` values
/// computed from Linux's unsigned arithmetic (4K, htotal 4000, 533.25 MHz,
/// HBR3 x4, 12 bpp DSC, CDCLK 652.8 MHz: 103 and 16, so
/// HBLANK_START_COUNT_128 and "all samples available").
fn smoke_xelpg_audio_codec_enable_disable_dp() -> TestResult {
    let s = AudioStream {
        dp: true,
        port: 3,
        port_clock_khz: 270_000,
        wa_14020863754: true,
        ..hdmi_stream()
    };
    let io = AudioFake::new();
    if codec_enable(&io, &s, 307_200, 0).is_err() {
        return TestResult::Fail("DP codec enable must run");
    }
    let pin = io.writes_to(HSW_AUD_PIN_ELD_CP_VLD);
    if io.writes_to(AUD_CONFIG_BE) != [1 << 25]
        || io.writes_to(AUD_CHICKENBIT_REG3) != [DACBE_DISABLE_MIN_HBLANK_FIX]
        || io.writes_to(aud_dp_2dot0_ctrl(Transcoder::B)) != [0]
        || pin
            != [
                aud_output_enable(Transcoder::B),
                aud_output_enable(Transcoder::B),
            ]
        || pin.iter().any(|v| v & aud_eld_valid(Transcoder::B) != 0)
        || io.writes_to(aud_cfg_off(Transcoder::B)) != [AUD_CONFIG_N_VALUE_INDEX]
    {
        return TestResult::Fail("hsw_audio_codec_enable's DP sequence differs from Linux");
    }
    // OUTPUT_ENABLE, a vblank, then the invalidate, before the config.
    let writes = io.writes.borrow().clone();
    let at = |reg: u64| writes.iter().position(|(o, _)| *o == reg);
    match (
        at(AUD_CHICKENBIT_REG3),
        at(HSW_AUD_PIN_ELD_CP_VLD),
        at(aud_cfg_off(Transcoder::B)),
    ) {
        (Some(a), Some(b), Some(c)) if a < b && b < c => {}
        _ => return TestResult::Fail("the WA, presence and timestamps must run in order"),
    }
    if codec_disable(&io, &s).is_err()
        || io.writes_to(aud_cfg_off(Transcoder::B)).last()
            != Some(&(AUD_CONFIG_N_VALUE_INDEX | AUD_CONFIG_N_PROG_ENABLE))
        || io.writes_to(HSW_AUD_PIN_ELD_CP_VLD).last() != Some(&0)
        || io.writes_to(AUD_CHICKENBIT_REG3).last() != Some(&0)
    {
        return TestResult::Fail("hsw_audio_codec_disable's DP sequence differs from Linux");
    }
    // UHBR: the SDP split, and the CPU transcoder in the notification.
    let uhbr = AudioStream { uhbr: true, ..s };
    let io = AudioFake::new();
    if codec_enable(&io, &uhbr, 307_200, 0).is_err()
        || io.writes_to(aud_dp_2dot0_ctrl(Transcoder::B)) != [AUD_ENABLE_SDP_SPLIT]
        || uhbr.notify_pipe() != 1
        || s.notify_pipe() != -1
    {
        return TestResult::Fail("UHBR audio must split SDPs and name its transcoder");
    }
    // The compressed 4K hblank workaround.
    let dsc = AudioStream {
        h_active: 3840,
        h_total: 4000,
        v_active: 2160,
        crtc_clock_khz: 533_250,
        port_clock_khz: 810_000,
        dsc_bpp_x16: Some(192),
        ..s
    };
    if calc_hblank_early_prog(&dsc, 652_800) != 103 || calc_samples_room(&dsc) != 16 {
        return TestResult::Fail("calc_hblank_early_prog / calc_samples_room differ from Linux");
    }
    let io = AudioFake::new();
    if enable_audio_dsc_wa(&io, &dsc, 652_800).is_err()
        || io.writes_to(AUD_CONFIG_BE)
            != [(1 << 25) | hblank_start_count(Transcoder::B, HBLANK_START_COUNT_128)]
    {
        return TestResult::Fail("the compressed 4K audio workaround differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_codec_enable_disable_dp
);

/// The sink: 1080p reduced blanking (138.5 MHz, 1920 + 48/32/80) with an
/// HDMI VSDB declaring AI and progressive latency (video 21, audio 11:
/// 40 ms and 20 ms), an audio data block (LPCM 2 ch and 8 ch at every
/// rate, AC-3 6 ch at 192 kHz only) and a speaker allocation.
pub(crate) fn audio_edid() -> Vec<u8> {
    let blocks = [
        // HDMI VSDB, payload 10: PA 1.0.0.0, AI (bit 7 of byte 6), max
        // TMDS 0, latency fields present, video 21, audio 11.
        (3 << 5) | 10,
        0x03,
        0x0C,
        0x00,
        0x10,
        0x00,
        0x80,
        0x00,
        0x80,
        21,
        11,
        // Audio data block: three SADs.
        (1 << 5) | 9,
        0x09,
        0x7F,
        0x07,
        0x0F,
        0x7F,
        0x07,
        0x15,
        0x40,
        0x50,
        // Speaker allocation: FL/FR, LFE, FC, RL/RR, RLC/RRC.
        (4 << 5) | 3,
        0x4F,
        0,
        0,
    ];
    crate::intel_gpu_xelpg_external::color::tests::with_cta(
        crate::intel_gpu_xelpg_external::tests::edid_for(
            138_500, 1920, 160, 48, 32, 1080, 31, 3, 5,
        ),
        &blocks,
    )
}

/// `drm_edid_to_eld` and `intel_audio_compute_config` for HDMI: the
/// baseline length (16 + 3 x SADs, header excluded) and the VSDB's AI bit,
/// then `intel_audio_hdmi_eld_compute_config` with 160 TMDS clocks of
/// blanking: 2-channel LPCM keeps every rate (one packet per line, 106
/// clocks), the 8-channel SAD loses 176.4 and 192 kHz (three packets, 170
/// clocks), the 6-channel 192 kHz-only AC-3 SAD is dropped;
/// `drm_av_sync_delay` is 40 - 20 = 20 ms, so byte 6 is 10. On DP no SAD is
/// pruned, and `drm_parse_hdmi_vsdb_audio`'s AI bit applies there too.
fn smoke_xelpg_audio_eld_compute_config() -> TestResult {
    let edid = audio_edid();
    if !edid_has_audio(&edid) {
        return TestResult::Fail("an audio data block is display_info.has_audio");
    }
    let connector_eld = eld_from_edid(&edid, false);
    // The shared builder's ELD agrees with Linux's on the SADs.
    match build_eld(&edid, DisplayConnector::Hdmi, 0) {
        Some(p) if p.eld_bytes()[20..29] == connector_eld[20..29] => {}
        _ => return TestResult::Fail("drm_edid_to_eld and the shared builder must agree"),
    }
    if !hdmi_audio_rate_supported(138_500, 2080, 160, 192_000, 2)
        || hdmi_audio_rate_supported(138_500, 2080, 160, 176_400, 8)
        || !hdmi_audio_rate_supported(138_500, 2080, 160, 96_000, 8)
        || hdmi_audio_rate_supported(138_500, 2080, 105, 32_000, 2)
    {
        return TestResult::Fail("hdmi_audio_rate_supported differs from Linux");
    }
    let eld = compute_eld(&connector_eld, &edid, &hdmi_stream());
    let mnl = usize::from(eld[4] & 0x1F);
    if eld[5] != (2 << 4) | DRM_ELD_SUPPORTS_AI
        || eld[2] as usize != (16 + mnl + 6).div_ceil(4)
        || eld[6] != 10
        || eld[8..16] != [0; 8]
        || eld[20 + mnl..20 + mnl + 9] != [0x09, 0x7F, 0x07, 0x0F, 0x1F, 0x07, 0, 0, 0]
        || eld_size(&eld) != 4 + 4 * eld[2] as usize
    {
        return TestResult::Fail("the HDMI ELD differs from intel_audio_compute_config");
    }
    // DP: no pruning; the connection type is DP and the AI bit stays.
    let dp = AudioStream {
        dp: true,
        ..hdmi_stream()
    };
    let eld = compute_eld(&eld_from_edid(&edid, true), &edid, &dp);
    if eld[5] != (3 << 4) | (1 << 2) | DRM_ELD_SUPPORTS_AI
        || eld[2] as usize != (16 + mnl + 9).div_ceil(4)
        || av_sync_delay_ms(Some((11, 21))) != 20
        || av_sync_delay_ms(Some((255, 21))) != 0
        || av_sync_delay_ms(Some((21, 11))) != 0
    {
        return TestResult::Fail("the DP ELD or drm_av_sync_delay differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_eld_compute_config
);

/// A basic-audio sink (CTA byte 3 bit 6, no audio data block) has
/// `display_info.has_audio`, and Linux enables audio with its connector ELD:
/// no SAD, baseline length 16 bytes (`drm_eld_size` 20). A sink with
/// neither has no audio; the shared builder publishes nothing for either.
fn smoke_xelpg_audio_basic_audio_sink_gets_linux_eld() -> TestResult {
    fn with_basic_audio(mut edid: Vec<u8>) -> Vec<u8> {
        edid[128 + 3] |= 1 << 6;
        let sum: u32 = edid[128..255].iter().map(|&b| u32::from(b)).sum();
        edid[255] = ((256 - sum % 256) % 256) as u8;
        edid
    }
    // An HDMI VSDB only (PA 1.0.0.0).
    let vsdb = [(3 << 5) | 5, 0x03, 0x0C, 0x00, 0x10, 0x00];
    let base = || {
        crate::intel_gpu_xelpg_external::tests::edid_for(138_500, 1920, 160, 48, 32, 1080, 31, 3, 5)
    };
    let plain = crate::intel_gpu_xelpg_external::color::tests::with_cta(base(), &vsdb);
    let basic = with_basic_audio(plain.clone());
    if edid_has_audio(&plain) || !edid_has_audio(&basic) {
        return TestResult::Fail("has_audio must follow the basic-audio bit");
    }
    let eld = compute_eld(&eld_from_edid(&basic, false), &basic, &hdmi_stream());
    if eld[0] != 2 << 3
        || eld[4] != 3 << 5
        || eld[5] != 0
        || eld[2] != 4
        || eld_size(&eld) != 20
        || eld[16..20] != basic[8..12]
        || build_eld(&basic, DisplayConnector::Hdmi, 0).is_some()
    {
        return TestResult::Fail("a basic-audio sink must get drm_edid_to_eld's SAD-less ELD");
    }
    // The component hands that ELD to the codec once the stream runs.
    reset_for_test();
    let io = AudioFake::new();
    let s = hdmi_stream();
    let mut buf = [0u8; 128];
    let result = if audio_codec_enable(&io, &s, &eld, None).is_err() {
        TestResult::Fail("a basic-audio stream must enable")
    } else {
        match component_get_eld(1, 0, &mut buf) {
            Ok((true, 20)) if buf[..20] == eld[..20] => TestResult::Pass,
            _ => TestResult::Fail("get_eld must return the 20-byte ELD"),
        }
    };
    reset_for_test();
    result
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_basic_audio_sink_gets_linux_eld
);

/// The scripted HDA codec: Tiger Lake+ / ADL-P+ `intel_pin2port` (port
/// index into `{0x4, 0x6, 0x8, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}`) and a
/// `pin_eld_notify` log.
pub(crate) struct ScriptedIntelHdmi;

pub(crate) static NOTIFY_COUNT: AtomicU32 = AtomicU32::new(0);
pub(crate) static NOTIFY_PORT: AtomicI32 = AtomicI32::new(i32::MIN);
pub(crate) static NOTIFY_PIPE: AtomicI32 = AtomicI32::new(i32::MIN);

/// `probe_i915_tgl_hdmi`'s map.
const PORT_MAP: [u32; 9] = [0x4, 0x6, 0x8, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];

impl DisplayAudioCodec for ScriptedIntelHdmi {
    fn pin2port(&self, pin_nid: u32) -> Option<i32> {
        PORT_MAP
            .iter()
            .position(|&pin| pin == pin_nid)
            .map(|port| port as i32)
    }
    fn pin_eld_notify(&self, port: i32, pipe: i32) {
        NOTIFY_PORT.store(port, Ordering::SeqCst);
        NOTIFY_PIPE.store(pipe, Ordering::SeqCst);
        NOTIFY_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) static SCRIPTED_HDA: ScriptedIntelHdmi = ScriptedIntelHdmi;

/// The ELD/audio enable sequence against a scripted HDA side:
/// `intel_audio_codec_enable` on an HDMI stream notifies
/// `pin_eld_notify(PORT_B, -1)`; the codec maps pin 0x6 to port 1
/// (`intel_pin2port`) and reads the ELD with `dev_id` 0
/// (`snd_hdac_acomp_get_eld`, the legacy-SST `find_audio_state`); dev 1
/// names no SST stream. `snd_hdac_display_power` takes the component's
/// power (`AUD_FREQ_CNTRL` = `AUD_FREQ_GEN12`, `AUD_PIN_BUF_ENABLE`) and
/// pulses the codec wake (`SKL_AUD_CODEC_WAKE_SIGNAL`); `get_cdclk_freq` is
/// 307.2 MHz and the component init's `AUD_TS_CDCLK` M/N 60/768;
/// `sync_audio_rate` reruns the config update; the disable notifies again
/// and the ELD is gone.
fn smoke_xelpg_audio_component_with_scripted_hda() -> TestResult {
    reset_for_test();
    acomp::register_display_audio_codec(&SCRIPTED_HDA);
    let result = scripted_hda_sequence();
    acomp::unregister_display_audio_codec();
    reset_for_test();
    result
}

fn scripted_hda_sequence() -> TestResult {
    let io = AudioFake::new();
    if component_init(&io).is_err()
        || io.writes_to(AUD_TS_CDCLK_N) != [768]
        || io.writes_to(AUD_TS_CDCLK_M) != [60 | AUD_TS_CDCLK_M_EN]
    {
        return TestResult::Fail("intel_audio_cdclk_change_post must program 60/768");
    }
    let component = XelpgAudioComponent { io: &io };
    let codec = &SCRIPTED_HDA;
    // snd_hdac_display_power: get_power, wake on, wake off.
    let mut power = DisplayPower::default();
    power.set(Some(&component), 0, true);
    if io.writes_to(AUD_FREQ_CNTRL) != [AUD_FREQ_GEN12]
        || io.writes_to(AUD_PIN_BUF_CTL) != [AUD_PIN_BUF_ENABLE]
        || io.writes_to(HSW_AUD_CHICKENBIT) != [0, SKL_AUD_CODEC_WAKE_SIGNAL, 0]
        || component.get_cdclk_freq() != Ok(307_200)
    {
        return TestResult::Fail("get_power / codec_wake_override differ from Linux");
    }
    let edid = audio_edid();
    let s = hdmi_stream();
    let publication = build_eld(&edid, DisplayConnector::Hdmi, 0);
    let eld = compute_eld(&eld_from_edid(&edid, false), &edid, &s);
    let before = NOTIFY_COUNT.load(Ordering::SeqCst);
    if audio_codec_enable(&io, &s, &eld, publication).is_err() {
        return TestResult::Fail("the HDMI audio enable must run");
    }
    if NOTIFY_COUNT.load(Ordering::SeqCst) != before + 1
        || NOTIFY_PORT.load(Ordering::SeqCst) != 1
        || NOTIFY_PIPE.load(Ordering::SeqCst) != -1
    {
        return TestResult::Fail("the enable must notify pin_eld_notify(PORT_B, -1)");
    }
    // HDMI: pixel clock field 1 (138.5 MHz falls back), automatic N.
    if io.writes_to(aud_cfg_off(Transcoder::B)) != [1 << 16]
        || !io.writes_to(AUD_CONFIG_BE).is_empty()
    {
        return TestResult::Fail("the HDMI enable must take the HDMI config update only");
    }
    // The codec reads the ELD back through pin 0x6, dev 0.
    let mut buf = [0u8; 128];
    let size = eld_size(&eld);
    match acomp_get_eld(Some(&component), Some(codec), 0x6, 0, &mut buf) {
        Ok((true, n)) if n == size && buf[..n] == eld[..n] => {}
        _ => return TestResult::Fail("snd_hdac_acomp_get_eld must return the stored ELD"),
    }
    if acomp_get_eld(Some(&component), Some(codec), 0x6, 1, &mut buf)
        != Err(ComponentError::Invalid)
        || acomp_get_eld(Some(&component), Some(codec), 0xa, 0, &mut buf)
            != Err(ComponentError::Invalid)
        || acomp_get_eld(Some(&component), Some(codec), 0x5, 0, &mut buf)
            != Err(ComponentError::Invalid)
    {
        return TestResult::Fail("find_audio_state must match the port and SST dev only");
    }
    // sync_audio_rate at 48 kHz: 138.5 MHz has no table N, the update reruns.
    let cfg_writes = io.writes_to(aud_cfg_off(Transcoder::B)).len();
    if acomp_sync_audio_rate(Some(&component), Some(codec), 0x6, 0, 48_000) != Ok(())
        || io.writes_to(aud_cfg_off(Transcoder::B)).len() != cfg_writes + 1
        || acomp_sync_audio_rate(Some(&component), Some(codec), 0xa, 0, 48_000)
            != Err(ComponentError::NoDevice)
    {
        return TestResult::Fail("sync_audio_rate must rerun the update on its stream only");
    }
    power.set(Some(&component), 0, false);
    // The disable: timestamps latched (HDMI: N_PROG_ENABLE only), ELD gone.
    if audio_codec_disable(&io, &s).is_err()
        || io.writes_to(aud_cfg_off(Transcoder::B)).last()
            != Some(&((1 << 16) | AUD_CONFIG_N_PROG_ENABLE))
        || NOTIFY_COUNT.load(Ordering::SeqCst) != before + 2
        || acomp_get_eld(Some(&component), Some(codec), 0x6, 0, &mut buf)
            != Err(ComponentError::Invalid)
        || acomp::current_display_audio(sink_id(1)).is_some()
    {
        return TestResult::Fail("the disable must latch, notify and drop the ELD");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_component_with_scripted_hda
);

/// The display side of `snd_hdac_i915_init`'s deferral: the driver names,
/// at its registration, the display functions whose probe binds the audio
/// component (display 14, 20 and 30 under `narf.intel.hdmi14_ext=1`, the
/// generations `bind_production_component` runs for), so an HDA controller
/// probed first waits for the bind. Without the option, on a Tiger Lake
/// display (no display-14+ component) and for another vendor it names none.
fn smoke_xelpg_audio_component_provider_names_bound_displays() -> TestResult {
    use crate::intel_gpu::audio_component_provided_for as provided;
    use crate::intel_gpu::{MTL_7D55, TGL_U_GT2_9A49};
    if !provided(true, 0x8086, MTL_7D55) || !provided(true, 0x8086, 0x64a0) {
        return TestResult::Fail("Meteor and Lunar Lake bind the component under the option");
    }
    if provided(false, 0x8086, MTL_7D55)
        || provided(true, 0x8086, TGL_U_GT2_9A49)
        || provided(true, 0x1002, MTL_7D55)
    {
        return TestResult::Fail("no option, a pre-14 display or another vendor binds none");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_audio",
    smoke_xelpg_audio_component_provider_names_bound_displays
);
