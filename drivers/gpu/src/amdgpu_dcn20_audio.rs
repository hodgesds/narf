//! Display audio for the laptop DCN path (DCN 2.0 / DCN 3.1.4):
//! the DTO / AFMT / ACR / Azalia programming that turns a modeset on
//! an external HDMI/DP connector into a live audio endpoint.
//!
//! The dGPU paths have stateful owners for this (`amdgpu_dcn30_audio`,
//! the DCN 4.0.1 modules). The laptop path is a pure write-list codec
//! (`amdgpu_dcn::dcn20_modeset_sequence`), so this module is the same
//! shape: pure builders returning `DcnWrite` lists the KMS plan layer
//! (`amdgpu_modeset`) appends after the video writes — audio starts
//! after scanout — and emits on teardown before the caller's
//! OTG master-enable clear.
//!
//! ## References
//!
//! - Linux `drivers/gpu/drm/amd/display/dc/dce/dce_stream_encoder.c`
//!   — `dce110_se_hdmi_audio_setup` / `dce110_se_setup_hdmi_audio`,
//!   `dce110_se_dp_audio_enable` / `dce110_se_disable_dp_audio`,
//!   `dce110_se_audio_setup`, `dce110_se_audio_mute_control`,
//!   `get_audio_clock_info`. DCN 2.0 runs this encoder.
//! - Linux `drivers/gpu/drm/amd/display/dc/dce/dce_audio.c` —
//!   `dce_aud_wall_dto_setup`, `dce_aud_az_configure`,
//!   `dce_aud_az_enable` / `dce_aud_az_disable`.
//! - Linux `asic_reg/dcn/dcn_2_0_0_offset.h` + `dcn_2_0_0_sh_mask.h`
//!   — every register id and field below. The DCCG audio DTO block
//!   (BASE_IDX 1) and the Azalia endpoint block (BASE_IDX 2) sit at
//!   the same ids on DCN 3.1.4, so one map serves both generations
//!   the laptop sequence covers.
//! - In-tree: `amdgpu_dcn30_audio` (the dGPU owner's sequence shape
//!   and Azalia field values), `amdgpu_hdmi_audio` (DTO math),
//!   `amdgpu_dcn401_hdmi_audio::acr` / `::channels` (ACR tables and
//!   the speaker→channel-enable conversion, shared rather than
//!   re-derived).
//!
//! ## Write-list discipline
//!
//! `DcnWrite` is a full-register write; there is no read-modify-write
//! in a plan. Registers this sequence owns outright are written whole
//! (the AFMT block, the ACR block, `DP_SEC_CNTL`'s audio enables —
//! nothing else in the laptop path programs them). Two shared
//! registers are written with the single-stream values the path can
//! stand behind, the same simplification `amdgpu_hdmi_audio::
//! program_audio_dto` already makes: `DCCG_AUDIO_DTO_SOURCE` (DTO1
//! unused here) and the Azalia `HOT_PLUG_CONTROL` endpoint register
//! (whose driver-owned content is the clock-gating-disable and
//! audio-enabled bits `dce_aud_az_enable` toggles). The 60958
//! channel-status update bit is a hardware strobe: it is written in
//! the setup position and the final sample-send write does not
//! re-assert it.
//!
//! ## Scope
//!
//! The stream programmed is the baseline every sink must accept:
//! LPCM stereo at 48 kHz from the sink's speaker allocation byte.
//! EDID SAD negotiation (`amdgpu_hdmi_audio::AudioEngine`) and the
//! Azalia audio-descriptor words — which are the SADs re-encoded, so
//! they belong with that negotiation — are the follow-up that feeds
//! richer requests into these builders; the builders already take
//! rate / speaker inputs. The HDA-side half of the endpoint (the
//! Renoir function's bind and ELD path) is `audio::hda`.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

/// Which external signal the stream rides. eDP/internal panels are
/// not modelled as audio endpoints on this path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DisplayAudioSignal {
    Hdmi,
    Dp,
}

/// One display-audio stream to program, in plan-layer terms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dcn20AudioRequest {
    /// OTG (CRTC pipe) the DIG is bound to; the DTO source select.
    pub otg: u8,
    /// DIG / DP instance index (0..6 on DCN 2.0).
    pub dig: u8,
    /// Azalia endpoint index (0..8); on this path the endpoint
    /// follows the DIG.
    pub endpoint: u8,
    pub signal: DisplayAudioSignal,
    /// TMDS / link pixel clock of the mode, kHz.
    pub pixel_clock_khz: u32,
    /// Mode timing totals, for the HDMI packets-per-line budget.
    pub h_total: u16,
    pub h_active: u16,
    /// CEA speaker-allocation byte from the sink (0x01 = FL/FR).
    pub speakers: u8,
    /// Stream sample rate; the baseline path uses 48 000.
    pub sample_rate_hz: u32,
}

// ── Register map (dcn_2_0_0_offset.h) ──────────────────────────

/// Dword distance between DIG blocks (and between DP blocks, which
/// live inside the same window).
pub const DIG_STRIDE: u32 = 0x100;

/// `regDCCG_AUDIO_DTO_SOURCE`, BASE_IDX 1 — folds against the same
/// base as the video sequence. `DCCG_AUDIO_DTO0_SOURCE_SEL` is the
/// low three bits; `DCCG_AUDIO_DTO_SEL` (bit 4) stays 0 for DTO0.
pub const DCCG_AUDIO_DTO_SOURCE: u32 = 0x00ab;
/// `regDCCG_AUDIO_DTO0_PHASE`, BASE_IDX 1.
pub const DCCG_AUDIO_DTO0_PHASE: u32 = 0x00ac;
/// `regDCCG_AUDIO_DTO0_MODULE`, BASE_IDX 1.
pub const DCCG_AUDIO_DTO0_MODULE: u32 = 0x00ad;

/// Azalia F0 endpoint indirect pair, BASE_IDX 2. Endpoint `n`'s
/// index register is `AZF0ENDPOINT0_INDEX + n * AZ_ENDPOINT_STRIDE`.
pub const AZF0ENDPOINT0_INDEX: u32 = 0x0386;
pub const AZF0ENDPOINT0_DATA: u32 = 0x0387;
pub const AZ_ENDPOINT_STRIDE: u32 = 6;
pub const AZ_ENDPOINTS: u8 = 8;
/// Endpoint-register indices (`ixAZALIA_F0_CODEC_PIN_CONTROL_*`).
pub const IX_PIN_CONTROL_CHANNEL_SPEAKER: u32 = 0x25;
pub const IX_PIN_CONTROL_MULTICHANNEL_ENABLE: u32 = 0x36;
pub const IX_PIN_CONTROL_HOT_PLUG_CONTROL: u32 = 0x54;
/// `AZALIA_F0_CODEC_PIN_CONTROL_HOT_PLUG_CONTROL__AUDIO_ENABLED`.
pub const AZ_AUDIO_ENABLED: u32 = 1 << 31;
/// `..._HOT_PLUG_CONTROL__CLOCK_GATING_DISABLE`.
pub const AZ_CLOCK_GATING_DISABLE: u32 = 1 << 0;
/// `AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__HDMI_CONNECTION`.
pub const AZ_HDMI_CONNECTION: u32 = 1 << 16;
/// `AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__DP_CONNECTION`.
pub const AZ_DP_CONNECTION: u32 = 1 << 17;

// DIG-relative ids (BASE_IDX 2), DIG 0 values; add `dig * DIG_STRIDE`.
/// `mmDIG0_HDMI_AUDIO_PACKET_CONTROL`.
pub const HDMI_AUDIO_PACKET_CONTROL: u32 = 0x2073;
/// `mmDIG0_HDMI_ACR_PACKET_CONTROL`.
pub const HDMI_ACR_PACKET_CONTROL: u32 = 0x2074;
/// `mmDIG0_HDMI_INFOFRAME_CONTROL0`.
pub const HDMI_INFOFRAME_CONTROL0: u32 = 0x2076;
/// `mmDIG0_HDMI_INFOFRAME_CONTROL1`.
pub const HDMI_INFOFRAME_CONTROL1: u32 = 0x2077;
/// `mmDIG0_AFMT_AUDIO_PACKET_CONTROL2`.
pub const AFMT_AUDIO_PACKET_CONTROL2: u32 = 0x207c;
/// `mmDIG0_HDMI_ACR_32_0` — the 32/44.1/48 kHz (CTS, N) pairs follow
/// at +0/+1, +2/+3, +4/+5.
pub const HDMI_ACR_32_0: u32 = 0x2096;
/// `mmDIG0_AFMT_60958_0` / `_1` / `_2`.
pub const AFMT_60958_0: u32 = 0x20a0;
pub const AFMT_60958_1: u32 = 0x20a1;
pub const AFMT_60958_2: u32 = 0x20a7;
/// `mmDIG0_AFMT_AUDIO_PACKET_CONTROL`.
pub const AFMT_AUDIO_PACKET_CONTROL: u32 = 0x20aa;
/// `mmDIG0_AFMT_INFOFRAME_CONTROL0`.
pub const AFMT_INFOFRAME_CONTROL0: u32 = 0x20ac;
/// `mmDIG0_AFMT_AUDIO_SRC_CONTROL` — full-register write of the
/// Azalia instance (`dce110_se_audio_setup` uses REG_SET).
pub const AFMT_AUDIO_SRC_CONTROL: u32 = 0x20ad;
/// `mmDIG0_AFMT_CNTL`.
pub const AFMT_CNTL: u32 = 0x20e6;
/// `mmDP0_DP_SEC_CNTL` (per-DP-instance, same stride).
pub const DP_SEC_CNTL: u32 = 0x212b;
/// `mmDP0_DP_SEC_AUD_N`.
pub const DP_SEC_AUD_N: u32 = 0x2131;
/// `mmDP0_DP_SEC_TIMESTAMP`.
pub const DP_SEC_TIMESTAMP: u32 = 0x2135;

// Field values (dcn_2_0_0_sh_mask.h).
/// `AFMT_CNTL__AFMT_AUDIO_CLOCK_EN` (shift 0).
const AFMT_AUDIO_CLOCK_EN: u32 = 1 << 0;
/// `AFMT_AUDIO_PACKET_CONTROL__AFMT_AUDIO_SAMPLE_SEND` (shift 0).
const AFMT_AUDIO_SAMPLE_SEND: u32 = 1 << 0;
/// `AFMT_AUDIO_PACKET_CONTROL__AFMT_60958_CS_UPDATE` (shift 26).
const AFMT_60958_CS_UPDATE: u32 = 1 << 26;
/// `HDMI_AUDIO_PACKET_CONTROL__HDMI_AUDIO_DELAY_EN` (shift 4).
const HDMI_AUDIO_DELAY_EN: u32 = 1 << 4;
/// `HDMI_AUDIO_PACKET_CONTROL__HDMI_AUDIO_PACKETS_PER_LINE`
/// (shift 16, mask 0x1f).
const HDMI_PACKETS_PER_LINE_SHIFT: u32 = 16;
/// `HDMI_ACR_PACKET_CONTROL`: SEND (0) | CONT (1) | AUTO_SEND (12),
/// SOURCE = 0, AUDIO_PRIORITY = 0 — `dce110_se_setup_hdmi_audio`
/// programs AUTO_SEND/SOURCE/PRIORITY; SEND/CONT are the stream
/// attribute half of the same register.
const HDMI_ACR_PACKET_CONTROL_ENABLE: u32 = (1 << 0) | (1 << 1) | (1 << 12);
/// `HDMI_ACR_32_0__HDMI_ACR_CTS_32` shift; N registers are unshifted.
const HDMI_ACR_CTS_SHIFT: u32 = 12;
/// `AFMT_60958_0__AFMT_60958_CS_CHANNEL_NUMBER_L` (shift 20) = 1,
/// clock accuracy (shift 28) = 0.
const AFMT_60958_0_STEREO: u32 = 1 << 20;
/// `AFMT_60958_1__AFMT_60958_CS_CHANNEL_NUMBER_R` (shift 20) = 2.
const AFMT_60958_1_STEREO: u32 = 2 << 20;
/// `AFMT_60958_2` channel numbers 3..8 packed (the value the DCN 3.0
/// owner carries as `AFMT_60958_CHANNELS_2_7`).
const AFMT_60958_2_CHANNELS: u32 = 0x0087_6543;
/// `HDMI_INFOFRAME_CONTROL0__HDMI_AUDIO_INFO_SEND` (4) | `_CONT` (5):
/// a valid recurring packet in `dce110_update_hdmi_info_packet`
/// terms (cont = send = 1). The hardware fills the frame from the
/// codec's channel allocation.
const HDMI_AUDIO_INFO_SEND_CONT: u32 = (1 << 4) | (1 << 5);
/// `AFMT_INFOFRAME_CONTROL0__AFMT_AUDIO_INFO_UPDATE` (shift 7).
const AFMT_AUDIO_INFO_UPDATE: u32 = 1 << 7;
/// `HDMI_INFOFRAME_CONTROL1__HDMI_AUDIO_INFO_LINE` (shift 8) = 2.
const HDMI_AUDIO_INFO_LINE_2: u32 = 2 << 8;
/// `DP_SEC_AUD_N__DP_SEC_AUD_N__DEFAULT`.
const DP_SEC_AUD_N_DEFAULT: u32 = 0x8000;
/// `DP_SEC_TIMESTAMP__DP_SEC_TIMESTAMP_MODE__AUTO_CALC` (shift 0).
const DP_SEC_TIMESTAMP_MODE_AUTO_CALC: u32 = 1;
/// `DP_SEC_CNTL` audio enables: ASP (4), ATP (8), AIP (12),
/// STREAM (0) — stream enable lands last, after every other.
const DP_SEC_ASP: u32 = 1 << 4;
const DP_SEC_ATP_AIP: u32 = 0x1100;
const DP_SEC_STREAM: u32 = 1 << 0;

fn dig(base2: u32, dig_idx: u8, reg: u32) -> u32 {
    base2 + reg + (dig_idx as u32) * DIG_STRIDE
}

fn az_push(writes: &mut Vec<DcnWrite>, base2: u32, endpoint: u8, index: u32, value: u32) {
    let at = base2 + (endpoint as u32) * AZ_ENDPOINT_STRIDE;
    writes.push(DcnWrite {
        addr: at + AZF0ENDPOINT0_INDEX,
        value: index,
    });
    writes.push(DcnWrite {
        addr: at + AZF0ENDPOINT0_DATA,
        value,
    });
}

fn valid(req: &Dcn20AudioRequest) -> bool {
    req.dig < 6 && req.endpoint < AZ_ENDPOINTS && req.pixel_clock_khz != 0
}

/// The wall-clock DTO half, shared by both signals
/// (`dce_aud_wall_dto_setup`): source select first — "these bits must
/// be programmed before DTO modulo and DTO phase" — then module,
/// then phase. Values from `amdgpu_hdmi_audio::compute_audio_dto`.
fn dto_writes(base1: u32, req: &Dcn20AudioRequest) -> Option<Vec<DcnWrite>> {
    let (phase, module) =
        crate::amdgpu_hdmi_audio::compute_audio_dto(req.pixel_clock_khz, req.sample_rate_hz)?;
    Some(vec![
        DcnWrite {
            addr: base1 + DCCG_AUDIO_DTO_SOURCE,
            value: u32::from(req.otg) & 0x7,
        },
        DcnWrite {
            addr: base1 + DCCG_AUDIO_DTO0_MODULE,
            value: module,
        },
        DcnWrite {
            addr: base1 + DCCG_AUDIO_DTO0_PHASE,
            value: phase,
        },
    ])
}

/// The Azalia endpoint configuration + enable, shared by both
/// signals (`dce_aud_az_configure`'s EDID-free subset, then
/// `dce_aud_az_enable`).
fn az_enable_writes(base2: u32, req: &Dcn20AudioRequest) -> Vec<DcnWrite> {
    let mut writes = Vec::new();
    let connection = match req.signal {
        DisplayAudioSignal::Hdmi => AZ_HDMI_CONNECTION,
        DisplayAudioSignal::Dp => AZ_DP_CONNECTION,
    };
    az_push(
        &mut writes,
        base2,
        req.endpoint,
        IX_PIN_CONTROL_CHANNEL_SPEAKER,
        u32::from(req.speakers) | connection,
    );
    let channel_mask = crate::amdgpu_dcn401_hdmi_audio::channels(req.speakers);
    az_push(
        &mut writes,
        base2,
        req.endpoint,
        IX_PIN_CONTROL_MULTICHANNEL_ENABLE,
        u32::from(channel_mask.count_ones() > 2),
    );
    // az_enable: set AUDIO_ENABLED with clock gating disabled, then
    // re-enable clock gating with the stream left enabled.
    az_push(
        &mut writes,
        base2,
        req.endpoint,
        IX_PIN_CONTROL_HOT_PLUG_CONTROL,
        AZ_AUDIO_ENABLED | AZ_CLOCK_GATING_DISABLE,
    );
    az_push(
        &mut writes,
        base2,
        req.endpoint,
        IX_PIN_CONTROL_HOT_PLUG_CONTROL,
        AZ_AUDIO_ENABLED,
    );
    writes
}

/// `dce_aud_az_disable` as full writes: gating disabled while
/// AUDIO_ENABLED clears in the same write, then gating restored.
fn az_disable_writes(base2: u32, endpoint: u8) -> Vec<DcnWrite> {
    let mut writes = Vec::new();
    az_push(
        &mut writes,
        base2,
        endpoint,
        IX_PIN_CONTROL_HOT_PLUG_CONTROL,
        AZ_CLOCK_GATING_DISABLE,
    );
    az_push(
        &mut writes,
        base2,
        endpoint,
        IX_PIN_CONTROL_HOT_PLUG_CONTROL,
        0,
    );
    writes
}

/// HDMI packets-per-line budget (`calc_max_audio_packets_per_line`):
/// horizontal blanking, minus 58 for other HDMI features and 16 for
/// the control period, 32 clocks per audio packet.
fn packets_per_line(req: &Dcn20AudioRequest) -> u32 {
    let blank = u32::from(req.h_total).saturating_sub(u32::from(req.h_active));
    (blank.saturating_sub(58 + 16) / 32) & 0x1f
}

/// Enable sequence for one stream. Append to the plan AFTER the
/// video writes: every write here assumes scanout is live (the last
/// video write is OTG_MASTER_EN). Returns an empty list for an
/// out-of-range request — the plan layer treats empty as no audio.
pub fn dcn20_audio_enable_sequence(
    dcn_base: u32,
    dcn_base2: u32,
    req: &Dcn20AudioRequest,
) -> Vec<DcnWrite> {
    if !valid(req) {
        return Vec::new();
    }
    let Some(mut writes) = dto_writes(dcn_base, req) else {
        return Vec::new();
    };
    let d = req.dig;
    let channel_enable = u32::from(crate::amdgpu_dcn401_hdmi_audio::channels(req.speakers)) << 8;
    // AFMT clock first — the encoder blocks are unclocked until this.
    writes.push(DcnWrite {
        addr: dig(dcn_base2, d, AFMT_CNTL),
        value: AFMT_AUDIO_CLOCK_EN,
    });
    match req.signal {
        DisplayAudioSignal::Hdmi => {
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, HDMI_AUDIO_PACKET_CONTROL),
                value: (packets_per_line(req) << HDMI_PACKETS_PER_LINE_SHIFT) | HDMI_AUDIO_DELAY_EN,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL),
                value: AFMT_60958_CS_UPDATE,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL2),
                value: channel_enable,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, HDMI_ACR_PACKET_CONTROL),
                value: HDMI_ACR_PACKET_CONTROL_ENABLE,
            });
            // ACR (N, CTS) pairs for 32 / 44.1 / 48 kHz, 8 bpc tables.
            let acr = crate::amdgpu_dcn401_hdmi_audio::acr(
                crate::amdgpu_dmub_navi48::TmdsDepth::Bpc8,
                req.pixel_clock_khz,
            );
            for (pair, rate) in acr.chunks_exact(2).enumerate() {
                let base = HDMI_ACR_32_0 + 2 * pair as u32;
                writes.push(DcnWrite {
                    addr: dig(dcn_base2, d, base),
                    value: rate[1] << HDMI_ACR_CTS_SHIFT,
                });
                writes.push(DcnWrite {
                    addr: dig(dcn_base2, d, base + 1),
                    value: rate[0],
                });
            }
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_60958_0),
                value: AFMT_60958_0_STEREO,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_60958_1),
                value: AFMT_60958_1_STEREO,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_60958_2),
                value: AFMT_60958_2_CHANNELS,
            });
        }
        DisplayAudioSignal::Dp => {
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_AUD_N),
                value: DP_SEC_AUD_N_DEFAULT,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_TIMESTAMP),
                value: DP_SEC_TIMESTAMP_MODE_AUTO_CALC,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL),
                value: AFMT_60958_CS_UPDATE,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL2),
                value: channel_enable,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_60958_0),
                value: 0,
            });
        }
    }
    // Audio source select: this DIG presents the Azalia endpoint.
    writes.push(DcnWrite {
        addr: dig(dcn_base2, d, AFMT_AUDIO_SRC_CONTROL),
        value: u32::from(req.endpoint),
    });
    if req.signal == DisplayAudioSignal::Hdmi {
        // Audio InfoFrame: send continuously, latch the AFMT copy,
        // on line 2 — the shape `amdgpu_dcn30_audio` uses.
        writes.push(DcnWrite {
            addr: dig(dcn_base2, d, HDMI_INFOFRAME_CONTROL0),
            value: HDMI_AUDIO_INFO_SEND_CONT,
        });
        writes.push(DcnWrite {
            addr: dig(dcn_base2, d, HDMI_INFOFRAME_CONTROL1),
            value: HDMI_AUDIO_INFO_LINE_2,
        });
    }
    writes.push(DcnWrite {
        addr: dig(dcn_base2, d, AFMT_INFOFRAME_CONTROL0),
        value: AFMT_AUDIO_INFO_UPDATE,
    });
    writes.extend(az_enable_writes(dcn_base2, req));
    match req.signal {
        DisplayAudioSignal::Hdmi => {
            // Samples flow last (`dce110_se_audio_mute_control`
            // un-mutes after setup in the Linux call order).
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL),
                value: AFMT_AUDIO_SAMPLE_SEND,
            });
        }
        DisplayAudioSignal::Dp => {
            // `dce110_se_enable_dp_audio`: ASP, then ATP/AIP, then the
            // stream enable after every other — as cumulative writes.
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_CNTL),
                value: DP_SEC_ASP,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_CNTL),
                value: DP_SEC_ASP | DP_SEC_ATP_AIP,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_CNTL),
                value: DP_SEC_ASP | DP_SEC_ATP_AIP | DP_SEC_STREAM,
            });
        }
    }
    writes
}

/// Disable sequence for one stream. The caller executes this BEFORE
/// its OTG master-enable clear: samples stop first, then the encoder
/// enables, then the Azalia endpoint, then the DTO source — the
/// reverse dependency order of the enable sequence, matching the
/// dGPU owners' stop shape (mute → encoder disable → InfoFrame off →
/// az_disable).
pub fn dcn20_audio_disable_sequence(
    dcn_base: u32,
    dcn_base2: u32,
    req: &Dcn20AudioRequest,
) -> Vec<DcnWrite> {
    // Only the routing fields are read here — no DTO/ACR values are
    // recomputed — so the range check is the routing half of
    // `valid` and a zero pixel clock (teardown has no timing) is fine.
    if req.dig >= 6 || req.endpoint >= AZ_ENDPOINTS {
        return Vec::new();
    }
    let d = req.dig;
    let mut writes = Vec::new();
    match req.signal {
        DisplayAudioSignal::Hdmi => {
            // Mute: sample send off before anything else moves.
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL),
                value: 0,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, HDMI_AUDIO_PACKET_CONTROL),
                value: 0,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, HDMI_INFOFRAME_CONTROL0),
                value: 0,
            });
        }
        DisplayAudioSignal::Dp => {
            // One write clears ASP/ATP/AIP/ACM/STREAM together
            // (`dce110_se_disable_dp_audio`'s REG_UPDATE_5).
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, DP_SEC_CNTL),
                value: 0,
            });
            writes.push(DcnWrite {
                addr: dig(dcn_base2, d, AFMT_AUDIO_PACKET_CONTROL),
                value: 0,
            });
        }
    }
    writes.push(DcnWrite {
        addr: dig(dcn_base2, d, AFMT_INFOFRAME_CONTROL0),
        value: 0,
    });
    writes.extend(az_disable_writes(dcn_base2, req.endpoint));
    // AFMT clock off (`dce110_se_hdmi_audio_disable` /
    // `dce110_se_dp_audio_disable` both end here).
    writes.push(DcnWrite {
        addr: dig(dcn_base2, d, AFMT_CNTL),
        value: 0,
    });
    // DTO source released last.
    writes.push(DcnWrite {
        addr: dcn_base + DCCG_AUDIO_DTO_SOURCE,
        value: 0,
    });
    writes
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    const B1: u32 = 0x1000;
    const B2: u32 = 0x8000;

    fn hdmi_req() -> Dcn20AudioRequest {
        Dcn20AudioRequest {
            otg: 1,
            dig: 2,
            endpoint: 2,
            signal: DisplayAudioSignal::Hdmi,
            pixel_clock_khz: 148_500,
            h_total: 2200,
            h_active: 1920,
            speakers: 0x01,
            sample_rate_hz: 48_000,
        }
    }

    fn find(writes: &[DcnWrite], addr: u32) -> Option<u32> {
        writes.iter().find(|w| w.addr == addr).map(|w| w.value)
    }

    fn dcn20_audio_hdmi_enable_sequence() -> TestResult {
        let req = hdmi_req();
        let writes = dcn20_audio_enable_sequence(B1, B2, &req);
        // DTO first: source select carries the OTG, then module, then
        // phase — the wall-DTO order.
        if writes.len() < 3
            || writes[0]
                != (DcnWrite {
                    addr: B1 + DCCG_AUDIO_DTO_SOURCE,
                    value: 1,
                })
            || writes[1]
                != (DcnWrite {
                    addr: B1 + DCCG_AUDIO_DTO0_MODULE,
                    value: 148_500_000,
                })
            || writes[2]
                != (DcnWrite {
                    addr: B1 + DCCG_AUDIO_DTO0_PHASE,
                    value: 48_000,
                })
        {
            return TestResult::Fail("DTO writes must lead, source/module/phase");
        }
        let dig2 = |reg: u32| B2 + reg + 2 * DIG_STRIDE;
        // (2200 - 1920 - 74) / 32 = 6 packets per line, delay enabled.
        if find(&writes, dig2(HDMI_AUDIO_PACKET_CONTROL)) != Some(0x0006_0010) {
            return TestResult::Fail("HDMI audio packet control");
        }
        // ACR pairs for 148.5 MHz from the shared table: CTS is
        // shifted 12 in the even register, N unshifted in the odd.
        if find(&writes, dig2(HDMI_ACR_32_0)) != Some(148_500 << 12)
            || find(&writes, dig2(HDMI_ACR_32_0 + 1)) != Some(4096)
            || find(&writes, dig2(HDMI_ACR_32_0 + 2)) != Some(165_000 << 12)
            || find(&writes, dig2(HDMI_ACR_32_0 + 3)) != Some(6272)
            || find(&writes, dig2(HDMI_ACR_32_0 + 4)) != Some(148_500 << 12)
            || find(&writes, dig2(HDMI_ACR_32_0 + 5)) != Some(6144)
        {
            return TestResult::Fail("ACR N/CTS pairs");
        }
        if find(&writes, dig2(HDMI_ACR_PACKET_CONTROL)) != Some(HDMI_ACR_PACKET_CONTROL_ENABLE) {
            return TestResult::Fail("ACR packet control");
        }
        // Azalia speaker write: endpoint 2's data register carries the
        // speaker byte plus the HDMI connection bit.
        let az_data = B2 + AZF0ENDPOINT0_DATA + 2 * AZ_ENDPOINT_STRIDE;
        if find(&writes, az_data) != Some(0x01 | AZ_HDMI_CONNECTION) {
            return TestResult::Fail("azalia speaker/connection");
        }
        // Samples flow last: the final write is SAMPLE_SEND on this DIG.
        if writes.last().copied()
            != Some(DcnWrite {
                addr: dig2(AFMT_AUDIO_PACKET_CONTROL),
                value: AFMT_AUDIO_SAMPLE_SEND,
            })
        {
            return TestResult::Fail("sample send must be the last write");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", dcn20_audio_hdmi_enable_sequence);

    fn dcn20_audio_dp_enable_and_disable() -> TestResult {
        let mut req = hdmi_req();
        req.signal = DisplayAudioSignal::Dp;
        req.dig = 1;
        req.endpoint = 1;
        let writes = dcn20_audio_enable_sequence(B1, B2, &req);
        let dig1 = |reg: u32| B2 + reg + DIG_STRIDE;
        if find(&writes, dig1(DP_SEC_AUD_N)) != Some(DP_SEC_AUD_N_DEFAULT)
            || find(&writes, dig1(DP_SEC_TIMESTAMP)) != Some(DP_SEC_TIMESTAMP_MODE_AUTO_CALC)
        {
            return TestResult::Fail("DP secondary timestamp setup");
        }
        // The DP_SEC_CNTL ladder is the tail: ASP, +ATP/AIP, +STREAM.
        let n = writes.len();
        if n < 3
            || writes[n - 3]
                != (DcnWrite {
                    addr: dig1(DP_SEC_CNTL),
                    value: DP_SEC_ASP,
                })
            || writes[n - 2]
                != (DcnWrite {
                    addr: dig1(DP_SEC_CNTL),
                    value: DP_SEC_ASP | DP_SEC_ATP_AIP,
                })
            || writes[n - 1]
                != (DcnWrite {
                    addr: dig1(DP_SEC_CNTL),
                    value: DP_SEC_ASP | DP_SEC_ATP_AIP | DP_SEC_STREAM,
                })
        {
            return TestResult::Fail("DP stream enable must land last, stepped");
        }
        let az_data = B2 + AZF0ENDPOINT0_DATA + AZ_ENDPOINT_STRIDE;
        if find(&writes, az_data) != Some(0x01 | AZ_DP_CONNECTION) {
            return TestResult::Fail("azalia speaker/DP connection");
        }
        // Disable: DP_SEC_CNTL clears first, DTO source releases last,
        // and the Azalia endpoint sees the gating-disable pair between.
        let off = dcn20_audio_disable_sequence(B1, B2, &req);
        if off.first().copied()
            != Some(DcnWrite {
                addr: dig1(DP_SEC_CNTL),
                value: 0,
            })
            || off.last().copied()
                != Some(DcnWrite {
                    addr: B1 + DCCG_AUDIO_DTO_SOURCE,
                    value: 0,
                })
        {
            return TestResult::Fail("DP disable order");
        }
        let az_values: Vec<u32> = off
            .iter()
            .filter(|w| w.addr == az_data)
            .map(|w| w.value)
            .collect();
        if az_values != [AZ_CLOCK_GATING_DISABLE, 0] {
            return TestResult::Fail("azalia disable pair");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", dcn20_audio_dp_enable_and_disable);

    fn dcn20_audio_hdmi_disable_and_invalid() -> TestResult {
        let req = hdmi_req();
        let off = dcn20_audio_disable_sequence(B1, B2, &req);
        let dig2 = |reg: u32| B2 + reg + 2 * DIG_STRIDE;
        // Mute precedes teardown: the first write silences sample send.
        if off.first().copied()
            != Some(DcnWrite {
                addr: dig2(AFMT_AUDIO_PACKET_CONTROL),
                value: 0,
            })
        {
            return TestResult::Fail("HDMI disable must mute first");
        }
        if off.last().copied()
            != Some(DcnWrite {
                addr: B1 + DCCG_AUDIO_DTO_SOURCE,
                value: 0,
            })
        {
            return TestResult::Fail("HDMI disable must release the DTO last");
        }
        // Out-of-range requests program nothing.
        let mut bad = req;
        bad.dig = 6;
        if !dcn20_audio_enable_sequence(B1, B2, &bad).is_empty()
            || !dcn20_audio_disable_sequence(B1, B2, &bad).is_empty()
        {
            return TestResult::Fail("DIG 6 must not program");
        }
        let mut bad = req;
        bad.pixel_clock_khz = 0;
        if !dcn20_audio_enable_sequence(B1, B2, &bad).is_empty() {
            return TestResult::Fail("zero pixel clock must not program");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", dcn20_audio_hdmi_disable_and_invalid);
}
