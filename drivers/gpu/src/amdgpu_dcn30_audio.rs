//! Navi22 DCN3.0 HDMI and DP SST audio: the display half only. The HD-Audio
//! function beside the GPU (1002:ab28 at 03:00.1, `narf_audio::hda`) owns the
//! controller and the ATI codec; what the display programs is the Azalia
//! endpoint the codec reports as ELD and jack, the DCCG audio wall clock and
//! the stream encoder's audio packets.
//!
//! Start runs, in Linux DC's order for one stream:
//! `dce_aud_hw_init` (once), `find_first_free_audio`,
//! `dce110_setup_audio_dto` → `dce_aud_wall_dto_setup` (HDMI: DTO0 from the
//! pixel clock of the lowest HDMI pipe; DP only: DTO1 from DPREFCLK; DCN30's
//! DCCG has no `set_audio_dtbclk_dto`), `setup_dio_audio_output`
//! (`enc3_se_hdmi_audio_setup`: AFMT clock, `afmt3_setup_hdmi_audio`, ACR
//! N/CTS, `afmt3_se_audio_setup`; or `enc3_se_dp_audio_setup`),
//! `dce_aud_az_configure` (ELD fields from the sink's EDID), the Audio
//! InfoFrame part of `enc3_stream_encoder_hdmi_set_stream_attribute`, then
//! `dce110_enable_audio_stream` (PME workaround, `dce_aud_az_enable`,
//! `enable_dio_audio_packet`: `enc3_se_dp_audio_enable` for DP, then
//! `enc3_audio_mute_control(false)`). Linux splits the first half before link
//! enable and the second after unblank (`link_set_dpms_on`); this owner runs
//! all of it after unblank, as the Navi48 owner does. Stop is
//! `dce110_disable_audio_stream` (mute, `enc1_se_hdmi_audio_disable` /
//! `enc1_se_dp_audio_disable`, PME workaround), the Audio InfoFrame off, then
//! `dce_aud_az_disable` (`dcn20_reset_back_end_for_pipe`), and must run
//! before the stream blanks.
//!
//! Offsets and masks are `dcn_3_0_0_offset.h` / `_sh_mask.h`: DCCG audio DTO
//! at DCN base index 1, everything else at base index 2; DIG, AFMT and DP
//! instances stride 0x100, Azalia endpoints six dwords. The endpoint's
//! indirect `ix*` indices are dce_11_0_d.h's, which dce_audio.c uses for
//! every DCN. Nothing waits on hardware here; the only asynchronous step is
//! the caller's PME workaround (an SMU message).
//!
//! Failure and cancellation retain the stream's record (and its endpoint) in
//! the step that failed. Nothing is retried; `stop` quiesces a failed record
//! keeping going past failing steps.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn401_otg::{self as otg, AudioInfo, DisplayAudio},
    amdgpu_dcn_profile::Profile,
    amdgpu_dml::Timing,
    amdgpu_dmub_navi48::TmdsDepth,
    amdgpu_navi22_display::Signal,
};
use core::future::Future;
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

/// A dword register in one of the two DCN 3.0.0 banks this owner touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reg {
    /// DCN base index 1 (DCCG).
    Bank1(u64),
    /// DCN base index 2.
    Bank2(u64),
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
/// `dcn3_clk_mgr_construct`'s DPREFCLK: the dump it would refine is never
/// filled on DCN3.0, and atomfirmware reports no GPU_PLL spread, so
/// `dce12_get_dp_ref_freq_khz` returns this constant.
// linux: n/a (literal in dcn30_clk_mgr.c:dcn3_clk_mgr_construct)
pub const DPREFCLK_KHZ: u32 = 730_000;
const LAST_BANK1: u32 = 0x00af; // linux: mmDCCG_AUDIO_DTO1_MODULE

// Azalia, base index 2.
// linux-ctx: hdr=dcn seg=2
// linux: mmAZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_INDEX
const AZ_ENDPOINT_INDEX: u64 = 0x0386;
// linux: mmAZF0ENDPOINT1_AZALIA_F0_CODEC_ENDPOINT_INDEX - mmAZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_INDEX
const AZ_ENDPOINT_STRIDE: u64 = 6;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_INDEX__AZALIA_ENDPOINT_REG_INDEX_MASK
const AZ_REG_INDEX: u32 = 0x3fff;
/// `res_cap_dcn3.num_audio`; the header has an eighth endpoint DC never uses.
// linux: n/a (res_cap_dcn3.num_audio = 6, literal in dcn30_resource.c)
pub const ENDPOINTS: u8 = 6;
// linux-lit: 0x040b=mmAZALIA_F0_CODEC_FUNCTION_PARAMETER_SUPPORTED_SIZE_RATES
const SUPPORTED_SIZE_RATES: Reg = Reg::Bank2(0x040b);
// linux-lit: 0x040c=mmAZALIA_F0_CODEC_FUNCTION_PARAMETER_STREAM_FORMATS
const STREAM_FORMATS: Reg = Reg::Bank2(0x040c);
// linux-lit: 0x040d=mmAZALIA_F0_CODEC_FUNCTION_PARAMETER_POWER_STATES
const POWER_STATES: Reg = Reg::Bank2(0x040d);
// linux: AZALIA_F0_CODEC_FUNCTION_PARAMETER_SUPPORTED_SIZE_RATES__AUDIO_RATE_CAPABILITIES_MASK
const AUDIO_RATE_CAPABILITIES: u32 = 0xfff;
// linux: AZALIA_F0_CODEC_FUNCTION_PARAMETER_POWER_STATES__CLKSTOP_MASK | AZALIA_F0_CODEC_FUNCTION_PARAMETER_POWER_STATES__EPSS_MASK
const CLKSTOP_EPSS: u32 = 0xc000_0000;
// Endpoint indirect indices (dce_11_0_d.h ixAZALIA_F0_CODEC_PIN_CONTROL_*).
// linux-ctx: hdr=dcn
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER
const AZ_SPEAKER: u32 = 0x25;
// linux: n/a (ixAZALIA_F0_CODEC_PIN_CONTROL_ACP_DATA = 0x27 in dce_11_0_d.h; absent from dcn_3_0_0 and the checker sets)
const AZ_ACP: u32 = 0x27;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_AUDIO_DESCRIPTOR0
const AZ_DESCRIPTOR0: u32 = 0x28;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_LIPSYNC
const AZ_LIPSYNC: u32 = 0x37;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_HBR
const AZ_HBR: u32 = 0x38;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0
const AZ_SINK_INFO0: u32 = 0x3a;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_HOT_PLUG_CONTROL
const AZ_HOT_PLUG: u32 = 0x54;
// linux: ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_CONFIGURATION_DEFAULT
const AZ_CONFIG_DEFAULT: u32 = 0x56;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_HOT_PLUG_CONTROL__CLOCK_GATING_DISABLE_MASK
const CLOCK_GATING_DISABLE: u32 = 1 << 0;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_HOT_PLUG_CONTROL__AUDIO_ENABLED_MASK
const AUDIO_ENABLED: u32 = 1 << 31;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__SPEAKER_ALLOCATION_MASK
const SPEAKER_ALLOCATION: u32 = 0x7f;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__HDMI_CONNECTION_MASK
const HDMI_CONNECTION: u32 = 1 << 16;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__DP_CONNECTION_MASK
const DP_CONNECTION: u32 = 1 << 17;
/// EXTRA_CONNECTION_INFO bit 0.
// linux: 1 << AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__EXTRA_CONNECTION_INFO__SHIFT
const EXTRA_CONNECTION_INFO0: u32 = 1 << 18;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_CHANNEL_SPEAKER__LFE_PLAYBACK_LEVEL_MASK
const LFE_PLAYBACK_LEVEL: u32 = 0x0300_0000;
// linux: n/a (AZALIA_F0_CODEC_PIN_CONTROL_ACP_DATA__SUPPORTS_AI_MASK = 0x40 in dce_11_0_sh_mask.h; not in checker sets)
const SUPPORTS_AI: u32 = 0x40;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_HBR__HBR_CAPABLE_MASK
const HBR_CAPABLE: u32 = 1;
// linux: AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_CONFIGURATION_DEFAULT__PORT_CONNECTIVITY__SHIFT
const PORT_CONNECTIVITY_SHIFT: u32 = 30;
/// amdgpu_dm's hard-coded `audio_info.port_id` when no container id exists.
// linux: n/a (literals 0x5558859e / 0xd989449 in dc_stream.c:dc_stream_construct)
const PORT_ID: [u32; 2] = [0x5558_859e, 0x0d98_9449];

// Timing generator and DIG frontend, base index 2.
// linux-ctx: hdr=dcn seg=2
// linux: mmOTG0_OTG_CONTROL
const OTG_CONTROL: u64 = 0x1b41;
// linux: mmOTG1_OTG_CONTROL - mmOTG0_OTG_CONTROL
const OTG_STRIDE: u64 = 0x80;
// linux: OTG0_OTG_CONTROL__OTG_MASTER_EN_MASK
const OTG_MASTER_EN: u32 = 1;
// linux: mmDIG1_DIG_FE_CNTL - mmDIG0_DIG_FE_CNTL
const STRIDE: u64 = 0x100;
// linux: mmDIG0_DIG_FE_CNTL
const DIG_FE_CNTL: u64 = 0x208b;
// linux: DIG0_DIG_FE_CNTL__DIG_SOURCE_SELECT_MASK
const DIG_SOURCE_SELECT: u32 = 0x7;
// linux: mmDIG0_HDMI_AUDIO_PACKET_CONTROL
const HDMI_AUDIO_PACKET_CONTROL: u64 = 0x2095;
// linux: mmDIG0_HDMI_ACR_PACKET_CONTROL
const HDMI_ACR_PACKET_CONTROL: u64 = 0x2096;
// linux: mmDIG0_HDMI_INFOFRAME_CONTROL0
const HDMI_INFOFRAME_CONTROL0: u64 = 0x2098;
// linux: mmDIG0_HDMI_INFOFRAME_CONTROL1
const HDMI_INFOFRAME_CONTROL1: u64 = 0x2099;
/// HDMI_ACR_32_0/1, 44_0/1, 48_0/1.
// linux: mmDIG0_HDMI_ACR_32_0
const HDMI_ACR_32_0: u64 = 0x20a7;
// linux: mmDIG0_AFMT_CNTL
const AFMT_CNTL: u64 = 0x20af;
// linux: DIG0_HDMI_AUDIO_PACKET_CONTROL__HDMI_AUDIO_DELAY_EN_MASK
const HDMI_AUDIO_DELAY_EN: u32 = 0x30;
/// HDMI_ACR_AUDIO_PRIORITY, HDMI_ACR_AUTO_SEND and HDMI_ACR_SOURCE.
// linux: DIG0_HDMI_ACR_PACKET_CONTROL__HDMI_ACR_AUDIO_PRIORITY_MASK | DIG0_HDMI_ACR_PACKET_CONTROL__HDMI_ACR_AUTO_SEND_MASK | DIG0_HDMI_ACR_PACKET_CONTROL__HDMI_ACR_SOURCE_MASK
const ACR_CONTROL: u32 = 0x8000_1100;
// linux: DIG0_HDMI_ACR_PACKET_CONTROL__HDMI_ACR_AUTO_SEND_MASK
const HDMI_ACR_AUTO_SEND: u32 = 1 << 12;
// linux: DIG0_HDMI_ACR_32_0__HDMI_ACR_CTS_32_MASK
const ACR_CTS: u32 = 0xffff_f000;
// linux: DIG0_HDMI_ACR_32_1__HDMI_ACR_N_32_MASK
const ACR_N: u32 = 0x000f_ffff;
// linux: DIG0_HDMI_INFOFRAME_CONTROL0__HDMI_AUDIO_INFO_SEND_MASK
const HDMI_AUDIO_INFO_SEND: u32 = 1 << 4;
// linux: DIG0_HDMI_INFOFRAME_CONTROL0__HDMI_AUDIO_INFO_CONT_MASK
const HDMI_AUDIO_INFO_CONT: u32 = 1 << 5;
// linux: DIG0_HDMI_INFOFRAME_CONTROL1__HDMI_AUDIO_INFO_LINE_MASK
const HDMI_AUDIO_INFO_LINE: u32 = 0x3f00;
/// `VBI_LINE_0 + 2`.
// linux: n/a (VBI_LINE_0 + 2, local #define in dcn30_dio_stream_encoder.c)
const AUDIO_INFO_LINE: u32 = 2;
// linux: DIG0_AFMT_CNTL__AFMT_AUDIO_CLOCK_EN_MASK
const AFMT_AUDIO_CLOCK_EN: u32 = 1;
// AFMT instance (per DIG), base index 2.
// linux: mmAFMT0_AFMT_AUDIO_PACKET_CONTROL2
const AFMT_AUDIO_PACKET_CONTROL2: u64 = 0x2075;
// linux: mmAFMT0_AFMT_60958_0
const AFMT_60958_0: u64 = 0x2078;
// linux: mmAFMT0_AFMT_60958_1
const AFMT_60958_1: u64 = 0x2079;
// linux: mmAFMT0_AFMT_60958_2
const AFMT_60958_2: u64 = 0x207f;
// linux: mmAFMT0_AFMT_AUDIO_PACKET_CONTROL
const AFMT_AUDIO_PACKET_CONTROL: u64 = 0x2082;
// linux: mmAFMT0_AFMT_INFOFRAME_CONTROL0
const AFMT_INFOFRAME_CONTROL0: u64 = 0x2083;
// linux: mmAFMT0_AFMT_AUDIO_SRC_CONTROL
const AFMT_AUDIO_SRC_CONTROL: u64 = 0x2085;
// linux: mmAFMT0_AFMT_MEM_PWR
const AFMT_MEM_PWR: u64 = 0x2087;
// linux: AFMT0_AFMT_AUDIO_PACKET_CONTROL__AFMT_AUDIO_SAMPLE_SEND_MASK
const AFMT_AUDIO_SAMPLE_SEND: u32 = 1;
// linux: AFMT0_AFMT_AUDIO_PACKET_CONTROL__AFMT_60958_CS_UPDATE_MASK
const AFMT_60958_CS_UPDATE: u32 = 1 << 26;
/// AFMT_AUDIO_LAYOUT_OVRD and AFMT_60958_OSF_OVRD.
// linux: AFMT0_AFMT_AUDIO_PACKET_CONTROL2__AFMT_AUDIO_LAYOUT_OVRD_MASK | AFMT0_AFMT_AUDIO_PACKET_CONTROL2__AFMT_60958_OSF_OVRD_MASK
const AFMT_OVERRIDES: u32 = 0x1000_0001;
// linux: AFMT0_AFMT_AUDIO_PACKET_CONTROL2__AFMT_AUDIO_CHANNEL_ENABLE_MASK
const AFMT_AUDIO_CHANNEL_ENABLE: u32 = 0xff00;
// linux: AFMT0_AFMT_60958_0__AFMT_60958_CS_CHANNEL_NUMBER_L_MASK
const AFMT_60958_CS_CHANNEL_NUMBER_L: u32 = 0x00f0_0000;
// linux: AFMT0_AFMT_60958_0__AFMT_60958_CS_CLOCK_ACCURACY_MASK
const AFMT_60958_CS_CLOCK_ACCURACY: u32 = 0x3000_0000;
// linux: AFMT0_AFMT_60958_1__AFMT_60958_CS_CHANNEL_NUMBER_R_MASK
const AFMT_60958_CS_CHANNEL_NUMBER_R: u32 = 0x00f0_0000;
/// CS channel numbers 2..7 as 3..8.
// linux: (3 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_2__SHIFT) | (4 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_3__SHIFT) | (5 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_4__SHIFT) | (6 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_5__SHIFT) | (7 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_6__SHIFT) | (8 << AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_7__SHIFT)
const AFMT_60958_CHANNELS_2_7: u32 = 0x0087_6543;
// linux: AFMT0_AFMT_INFOFRAME_CONTROL0__AFMT_AUDIO_INFO_UPDATE_MASK
const AFMT_AUDIO_INFO_UPDATE: u32 = 1 << 7;
// linux: AFMT0_AFMT_AUDIO_SRC_CONTROL__AFMT_AUDIO_SRC_SELECT_MASK
const AFMT_AUDIO_SRC_SELECT: u32 = 0x7;
// linux: AFMT0_AFMT_MEM_PWR__AFMT_MEM_PWR_FORCE_MASK
const AFMT_MEM_PWR_FORCE: u32 = 0x30;
// DP stream encoder secondary data, base index 2.
// linux: mmDP0_DP_SEC_CNTL
const DP_SEC_CNTL: u64 = 0x212b;
// linux: mmDP0_DP_SEC_AUD_N
const DP_SEC_AUD_N: u64 = 0x2131;
// linux: mmDP0_DP_SEC_TIMESTAMP
const DP_SEC_TIMESTAMP: u64 = 0x2135;
// linux: DP0_DP_SEC_CNTL__DP_SEC_STREAM_ENABLE_MASK
const DP_SEC_STREAM_ENABLE: u32 = 1;
// linux: DP0_DP_SEC_CNTL__DP_SEC_ASP_ENABLE_MASK
const DP_SEC_ASP_ENABLE: u32 = 1 << 4;
/// DP_SEC_ATP_ENABLE and DP_SEC_AIP_ENABLE.
// linux: DP0_DP_SEC_CNTL__DP_SEC_ATP_ENABLE_MASK | DP0_DP_SEC_CNTL__DP_SEC_AIP_ENABLE_MASK
const DP_SEC_ATP_AIP: u32 = 0x1100;
// linux: DP0_DP_SEC_CNTL__DP_SEC_ACM_ENABLE_MASK
const DP_SEC_ACM_ENABLE: u32 = 1 << 16;
/// The DP_SEC_CNTL enables DP audio owns (ASP, ATP, AIP, ACM).
const DP_SEC_AUDIO: u32 = DP_SEC_ASP_ENABLE | DP_SEC_ATP_AIP | DP_SEC_ACM_ENABLE;
/// What a running stream's audio leaves set: ASP, ATP, AIP and the master.
const DP_SEC_AUDIO_LIVE: u32 = DP_SEC_ASP_ENABLE | DP_SEC_ATP_AIP | DP_SEC_STREAM_ENABLE;
// linux: n/a (DP_SEC_AUD_N__DP_SEC_AUD_N__DEFAULT, local #define in dcn30_dio_stream_encoder.c)
const DP_SEC_AUD_N_DEFAULT: u32 = 0x8000;
// linux: n/a (DP_SEC_TIMESTAMP__DP_SEC_TIMESTAMP_MODE__AUTO_CALC, local #define in dcn30_dio_stream_encoder.c)
const DP_SEC_TIMESTAMP_MODE_AUTO_CALC: u32 = 1;
// linux: mmDP5_DP_SEC_TIMESTAMP
const LAST_BANK2: u32 = (DP_SEC_TIMESTAMP + 5 * STRIDE) as u32;
// linux: n/a (NARF bound: six DIG stream encoders)
const STREAMS: usize = 6;
// linux-ctx: reset

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    /// The stream already has audio (or a retained failed record), or the
    /// encoder's audio is already live.
    Busy,
    Revoked,
    DeviceGone,
    /// The stream's OTG is not running or the DIG is not routed to it.
    NotRunning,
    /// Every valid Azalia endpoint is taken.
    NoEndpoint,
    /// The sink declares no LPCM the transport can carry.
    NoLpcm,
    /// A register did not read back what this owner programmed.
    Readback(Reg),
}

/// One running stream audio can ride on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStream {
    pub signal: Signal,
    /// The pipe's OTG, which is also the DTO0 source (`translate_to_dto_source`).
    pub otg: u8,
    /// DIG frontend (stream encoder, `engine_id`) and its AFMT/DP instance.
    pub dig: u8,
    pub timing: Timing,
}
impl AudioStream {
    pub fn hdmi(otg: u8, dig: u8, timing: Timing) -> Self {
        Self {
            signal: Signal::Hdmi,
            otg,
            dig,
            timing,
        }
    }
    pub fn dp(otg: u8, dig: u8, timing: Timing) -> Self {
        Self {
            signal: Signal::DisplayPort,
            otg,
            dig,
            timing,
        }
    }
    fn hdmi_signal(&self) -> bool {
        self.signal == Signal::Hdmi
    }
}

/// Where a stream's audio sequence is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    WallClock,
    Encoder,
    Endpoint,
    InfoFrame,
    Enable,
    Packets,
    Verify,
    Disable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// In flight; a cancelled start stays here and is retained.
    Programming(Step),
    Running,
    Failed {
        step: Step,
        error: Error,
    },
}
/// What the owner holds for one DIG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub stream: AudioStream,
    pub audio: DisplayAudio,
    pub state: State,
}

/// `clk_mgr->funcs->enable_pme_wa` (`dcn3_enable_pme_wa`): the DAL SMU
/// message `DALSMC_MSG_BacoAudioD3PME` (0x11) that wakes the Azalia from D3
/// before its endpoint is touched. Linux ignores the result; so does this
/// owner. The DAL mailbox has a single owner (`amdgpu_dcn30_clk`), which is
/// expected to implement this.
pub trait AzaliaWake {
    fn wake_azalia(&mut self) -> impl Future<Output = ()> + Send;
}

pub(crate) trait Io: Send {
    fn read(&mut self, reg: Reg) -> u32;
    fn write(&mut self, reg: Reg, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    bank1: u64,
    bank2: u64,
}
impl Mmio {
    fn at(&self, reg: Reg) -> u64 {
        match reg {
            Reg::Bank1(r) => self.bank1 + r * 4,
            Reg::Bank2(r) => self.bank2 + r * 4,
        }
    }
}
impl Io for Mmio {
    fn read(&mut self, reg: Reg) -> u32 {
        // SAFETY: the constructor bounded both banks and retains the mapping.
        unsafe { self.regs.read32(self.at(reg)) }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        // SAFETY: same bounded banks; this owner holds the audio registers.
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

fn dig_reg(dig: u8, reg: u64) -> Reg {
    Reg::Bank2(reg + u64::from(dig) * STRIDE)
}
fn otg_control(otg: u8) -> Reg {
    Reg::Bank2(OTG_CONTROL + u64::from(otg) * OTG_STRIDE)
}

/// `dce_aud_az_configure`'s inputs for `stream`: the per-format descriptor
/// words, AC-3 and HBR capability, with HDMI's blanking rate filter
/// (`check_audio_bandwidth_hdmi`, 8 bpc as this pipeline drives) or none
/// for DP SST over 8b/10b (`check_audio_bandwidth_dp` skips that case).
pub fn plan(
    stream: &AudioStream,
    info: &AudioInfo,
    endpoint: u8,
) -> Result<(DisplayAudio, bool), Error> {
    // linux-lit: 16=DC_MAX_AUDIO_DESC_COUNT
    if info.mode_count == 0 || info.mode_count > 16 {
        return Err(Error::Invalid);
    }
    let depth = stream.hdmi_signal().then_some(TmdsDepth::Bpc8);
    let (descriptors, ac3, hbr) = otg::descriptors(info, &stream.timing, depth);
    if descriptors[0] == 0 {
        return Err(Error::NoLpcm);
    }
    Ok((
        DisplayAudio {
            info: *info,
            dp: !stream.hdmi_signal(),
            endpoint,
            channels: otg::channels(info.speakers),
            descriptors,
            hbr,
        },
        ac3,
    ))
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    authority: Cap<BusDeviceCap, Write>,
    /// `pool->audio_count`: endpoints up to the first one with no physical
    /// connection, known after `dce_aud_hw_init`.
    endpoints: Option<u8>,
    records: [Option<Record>; STREAMS],
}
impl<I: Io> Engine<I> {
    pub(crate) fn new_with(io: I, authority: Cap<BusDeviceCap, Write>) -> Self {
        Self {
            io,
            authority,
            endpoints: None,
            records: [None; STREAMS],
        }
    }
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
    fn expect(&mut self, reg: Reg, mask: u32, value: u32) -> Result<(), Error> {
        if self.read(reg)? & mask != value {
            return Err(Error::Readback(reg));
        }
        Ok(())
    }
    fn az_index(endpoint: u8) -> Reg {
        Reg::Bank2(AZ_ENDPOINT_INDEX + u64::from(endpoint) * AZ_ENDPOINT_STRIDE)
    }
    fn az_data(endpoint: u8) -> Reg {
        // linux-lit: 1=mmAZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_DATA - mmAZF0ENDPOINT0_AZALIA_F0_CODEC_ENDPOINT_INDEX
        Reg::Bank2(AZ_ENDPOINT_INDEX + 1 + u64::from(endpoint) * AZ_ENDPOINT_STRIDE)
    }
    /// `read_indirect_azalia_reg`: index (REG_SET), then the data port.
    fn az_read(&mut self, endpoint: u8, index: u32) -> Result<u32, Error> {
        self.write(Self::az_index(endpoint), index & AZ_REG_INDEX)?;
        self.read(Self::az_data(endpoint))
    }
    /// `write_indirect_azalia_reg`.
    fn az_write(&mut self, endpoint: u8, index: u32, value: u32) -> Result<(), Error> {
        self.write(Self::az_index(endpoint), index & AZ_REG_INDEX)?;
        self.write(Self::az_data(endpoint), value)
    }
    fn az_update(&mut self, endpoint: u8, index: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.az_read(endpoint, index)?;
        self.az_write(endpoint, index, (old & !mask) | (value & mask))
    }
    pub(crate) fn record(&self, dig: u8) -> Option<Record> {
        self.records.get(usize::from(dig)).copied().flatten()
    }
    fn set_state(&mut self, dig: u8, state: State) {
        if let Some(r) = self.records[usize::from(dig)].as_mut() {
            r.state = state;
        }
    }

    /// `dce_aud_hw_init` (it acts only for instance 0) and the
    /// `resource_construct` endpoint count: stop at the first endpoint whose
    /// default configuration reports no physical connection.
    fn hw_init(&mut self) -> Result<u8, Error> {
        if let Some(n) = self.endpoints {
            return Ok(n);
        }
        self.az_update(0, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, CLOCK_GATING_DISABLE)?;
        // linux: n/a (AUDIO_RATE_CAPABILITIES 0x70, literal in dce_audio.c:dce_aud_hw_init)
        self.update(SUPPORTED_SIZE_RATES, AUDIO_RATE_CAPABILITIES, 0x70)?;
        self.update(POWER_STATES, CLKSTOP_EPSS, CLKSTOP_EPSS)?;
        self.az_update(0, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, 0)?;
        let mut count = 0;
        while count < ENDPOINTS {
            // linux: n/a (PORT_CONNECTIVITY == 1, literal in dce_audio.c:dce_aud_endpoint_valid)
            if self.az_read(count, AZ_CONFIG_DEFAULT)? >> PORT_CONNECTIVITY_SHIFT == 1 {
                break;
            }
            count += 1;
        }
        self.endpoints = Some(count);
        Ok(count)
    }
    /// `find_first_free_audio`: the endpoint matching the stream encoder,
    /// else the first free one.
    fn pick_endpoint(&self, dig: u8, count: u8) -> Option<u8> {
        let free = |e: u8| self.records.iter().flatten().all(|r| r.audio.endpoint != e);
        if dig < count && free(dig) {
            return Some(dig);
        }
        (0..count).find(|&e| free(e))
    }
    /// `dce110_setup_audio_dto`: one wall clock for every display. The
    /// lowest HDMI audio pipe wins and programs DTO0 from its pixel clock;
    /// with no HDMI audio the lowest DP audio pipe selects DTO1 from
    /// DPREFCLK. No audio leaves the clock as it is.
    fn wall_dto(&mut self) -> Result<(), Error> {
        let lowest = |hdmi: bool| {
            self.records
                .iter()
                .flatten()
                .filter(|r| r.stream.hdmi_signal() == hdmi)
                .min_by_key(|r| r.stream.otg)
                .map(|r| r.stream)
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
            self.update(AUDIO_DTO1_MODULE, u32::MAX, DPREFCLK_KHZ * 10)?;
            self.update(AUDIO_DTO1_PHASE, u32::MAX, DTO_PHASE)?;
            self.update(AUDIO_DTO_SOURCE, DTO2_USE_512FBR_DTO, DTO2_USE_512FBR_DTO)
        } else {
            Ok(())
        }
    }
    /// `afmt3_se_audio_setup`: endpoint → DIG mapping (REG_SET), channel
    /// enables, and forced memory power-off released.
    fn audio_source(&mut self, dig: u8, a: &DisplayAudio) -> Result<(), Error> {
        self.write(dig_reg(dig, AFMT_AUDIO_SRC_CONTROL), u32::from(a.endpoint))?;
        self.update(
            dig_reg(dig, AFMT_AUDIO_PACKET_CONTROL2),
            AFMT_AUDIO_CHANNEL_ENABLE,
            // linux-lit: 8=AFMT0_AFMT_AUDIO_PACKET_CONTROL2__AFMT_AUDIO_CHANNEL_ENABLE__SHIFT
            u32::from(a.channels) << 8,
        )?;
        self.update(dig_reg(dig, AFMT_MEM_PWR), AFMT_MEM_PWR_FORCE, 0)
    }
    /// `enc3_se_hdmi_audio_setup`.
    fn hdmi_audio_setup(&mut self, s: &AudioStream, a: &DisplayAudio) -> Result<(), Error> {
        let at = |r| dig_reg(s.dig, r);
        // enc1_se_enable_audio_clock (no AFMT_AUDIO_CLOCK_ON wait, as Linux).
        self.update(at(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, AFMT_AUDIO_CLOCK_EN)?;
        // afmt3_setup_hdmi_audio.
        self.update(
            at(AFMT_AUDIO_PACKET_CONTROL),
            AFMT_60958_CS_UPDATE,
            AFMT_60958_CS_UPDATE,
        )?;
        self.update(at(AFMT_AUDIO_PACKET_CONTROL2), AFMT_OVERRIDES, 0)?;
        self.update(
            at(AFMT_60958_0),
            AFMT_60958_CS_CHANNEL_NUMBER_L | AFMT_60958_CS_CLOCK_ACCURACY,
            1 << 20, // linux-lit: 20=AFMT0_AFMT_60958_0__AFMT_60958_CS_CHANNEL_NUMBER_L__SHIFT
        )?;
        // linux-lit: 20=AFMT0_AFMT_60958_1__AFMT_60958_CS_CHANNEL_NUMBER_R__SHIFT
        self.update(at(AFMT_60958_1), AFMT_60958_CS_CHANNEL_NUMBER_R, 2 << 20)?;
        // linux-lit: 0x00ff_ffff=AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_2_MASK | AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_3_MASK | AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_4_MASK | AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_5_MASK | AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_6_MASK | AFMT0_AFMT_60958_2__AFMT_60958_CS_CHANNEL_NUMBER_7_MASK
        self.update(at(AFMT_60958_2), 0x00ff_ffff, AFMT_60958_CHANNELS_2_7)?;
        // linux-lit: 4=DIG0_HDMI_AUDIO_PACKET_CONTROL__HDMI_AUDIO_DELAY_EN__SHIFT
        self.update(at(HDMI_AUDIO_PACKET_CONTROL), HDMI_AUDIO_DELAY_EN, 1 << 4)?;
        self.update(at(HDMI_ACR_PACKET_CONTROL), ACR_CONTROL, HDMI_ACR_AUTO_SEND)?;
        // get_audio_clock_info with requested = calculated pixel clock.
        let nc = otg::acr(TmdsDepth::Bpc8, s.timing.pixel_clock_khz);
        for (i, rate) in nc.chunks_exact(2).enumerate() {
            // linux-lit: 2=mmDIG0_HDMI_ACR_44_0 - mmDIG0_HDMI_ACR_32_0
            let base = HDMI_ACR_32_0 + 2 * i as u64;
            // linux-lit: 12=DIG0_HDMI_ACR_32_0__HDMI_ACR_CTS_32__SHIFT
            self.update(at(base), ACR_CTS, rate[1] << 12)?;
            // linux-lit: 1=mmDIG0_HDMI_ACR_32_1 - mmDIG0_HDMI_ACR_32_0
            self.update(at(base + 1), ACR_N, rate[0])?;
        }
        self.audio_source(s.dig, a)
    }
    /// `dce_aud_az_configure`.
    fn az_configure(&mut self, a: &DisplayAudio, ac3: bool) -> Result<(), Error> {
        let e = a.endpoint;
        let info = &a.info;
        self.az_update(e, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, CLOCK_GATING_DISABLE)?;
        let connection = if a.dp { DP_CONNECTION } else { HDMI_CONNECTION };
        self.az_update(
            e,
            AZ_SPEAKER,
            SPEAKER_ALLOCATION
                | HDMI_CONNECTION
                | DP_CONNECTION
                | EXTRA_CONNECTION_INFO0
                | LFE_PLAYBACK_LEVEL,
            u32::from(info.speakers) & SPEAKER_ALLOCATION | connection,
        )?;
        // linux: n/a (SUPPORTS_AI__SHIFT 6 in dce_11_0_sh_mask.h, not in checker sets; bit 7 is NARF AudioInfo flags)
        self.az_update(e, AZ_ACP, SUPPORTS_AI, u32::from(info.speakers >> 7) << 6)?;
        // linux-lit: 14=AUDIO_FORMAT_CODE_COUNT
        for code in 1u32..=14 {
            // One-bit audio and DST are never programmed.
            // linux-lit: 9=AUDIO_FORMAT_CODE_1BITAUDIO; 13=AUDIO_FORMAT_CODE_DST
            if code == 9 || code == 13 {
                continue;
            }
            let word = a.descriptors[(code - 1) as usize];
            self.az_write(e, AZ_DESCRIPTOR0 + code - 1, word)?;
        }
        if ac3 {
            // Global, as Linux's own TODO notes.
            // linux: n/a (literal 0x05 in dce_audio.c:dce_aud_az_configure)
            self.write(STREAM_FORMATS, 0x05)?;
        }
        self.az_update(e, AZ_HBR, HBR_CAPABLE, u32::from(a.hbr))?;
        // linux-lit: 0xff=AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_LIPSYNC__VIDEO_LIPSYNC_MASK
        self.az_update(e, AZ_LIPSYNC, 0xff, u32::from(info.video_latency))?;
        // linux-lit: 0xff00=AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_LIPSYNC__AUDIO_LIPSYNC_MASK; 8=AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_RESPONSE_LIPSYNC__AUDIO_LIPSYNC__SHIFT
        self.az_update(e, AZ_LIPSYNC, 0xff00, u32::from(info.audio_latency) << 8)?;
        // linux-lit: 16=AZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0__PRODUCT_ID__SHIFT
        let id = u32::from(info.manufacturer_id) | u32::from(info.product_id) << 16;
        self.az_write(e, AZ_SINK_INFO0, id)?;
        let len = info
            .name
            .iter()
            .position(|b| *b == 0)
            // linux: n/a (MAX_HW_AUDIO_INFO_DISPLAY_NAME_SIZE_IN_CHARS = 18, include/audio_types.h; not in checker sets)
            .map_or(18, |n| (n + 1).min(18));
        // linux-lit: 1=ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO1 - ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0
        self.az_write(e, AZ_SINK_INFO0 + 1, len as u32)?;
        // linux-lit: 2=ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO2 - ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0
        self.az_write(e, AZ_SINK_INFO0 + 2, PORT_ID[0])?;
        // linux-lit: 3=ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO3 - ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0
        self.az_write(e, AZ_SINK_INFO0 + 3, PORT_ID[1])?;
        // linux: n/a (four DESCRIPTIONn bytes per SINK_INFO4..8 dword, dce_aud_az_configure)
        for (i, chunk) in info.name.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b[..chunk.len()].copy_from_slice(chunk);
            // linux-lit: 4=ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO4 - ixAZF0ENDPOINT0_AZALIA_F0_CODEC_PIN_CONTROL_SINK_INFO0
            self.az_write(e, AZ_SINK_INFO0 + 4 + i as u32, u32::from_le_bytes(b))?;
        }
        self.az_update(e, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, 0)
    }
    /// The Audio InfoFrame half of `enc3_stream_encoder_hdmi_set_stream_attribute`:
    /// send it (the hardware fills it from the codec's channel allocation),
    /// latch the double-buffered AUDIO_INFO now, on line 2.
    fn audio_infoframe(&mut self, dig: u8) -> Result<(), Error> {
        let at = |r| dig_reg(dig, r);
        self.update(
            at(HDMI_INFOFRAME_CONTROL0),
            HDMI_AUDIO_INFO_SEND,
            HDMI_AUDIO_INFO_SEND,
        )?;
        self.update(
            at(AFMT_INFOFRAME_CONTROL0),
            AFMT_AUDIO_INFO_UPDATE,
            AFMT_AUDIO_INFO_UPDATE,
        )?;
        self.update(
            at(HDMI_INFOFRAME_CONTROL1),
            HDMI_AUDIO_INFO_LINE,
            // linux-lit: 8=DIG0_HDMI_INFOFRAME_CONTROL1__HDMI_AUDIO_INFO_LINE__SHIFT
            AUDIO_INFO_LINE << 8,
        )
    }
    /// `dce_aud_az_enable`.
    fn az_enable(&mut self, endpoint: u8) -> Result<(), Error> {
        self.az_update(
            endpoint,
            AZ_HOT_PLUG,
            AUDIO_ENABLED | CLOCK_GATING_DISABLE,
            AUDIO_ENABLED | CLOCK_GATING_DISABLE,
        )?;
        self.az_update(endpoint, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, 0)
    }
    /// `dce_aud_az_disable`.
    fn az_disable(&mut self, endpoint: u8) -> Result<(), Error> {
        self.az_update(
            endpoint,
            AZ_HOT_PLUG,
            CLOCK_GATING_DISABLE,
            CLOCK_GATING_DISABLE,
        )?;
        self.az_update(endpoint, AZ_HOT_PLUG, AUDIO_ENABLED, 0)?;
        self.az_update(endpoint, AZ_HOT_PLUG, CLOCK_GATING_DISABLE, 0)
    }
    /// `enc3_se_dp_audio_enable`: AFMT clock, ATP N default and auto-calc
    /// timestamps (both REG_SET), `afmt3_setup_dp_audio`, then
    /// `enc1_se_enable_dp_audio` (ASP, then ATP/AIP, then the stream enable
    /// after every other).
    fn dp_audio_enable(&mut self, dig: u8) -> Result<(), Error> {
        let at = |r| dig_reg(dig, r);
        self.update(at(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, AFMT_AUDIO_CLOCK_EN)?;
        self.write(at(DP_SEC_AUD_N), DP_SEC_AUD_N_DEFAULT)?;
        self.write(at(DP_SEC_TIMESTAMP), DP_SEC_TIMESTAMP_MODE_AUTO_CALC)?;
        self.update(
            at(AFMT_AUDIO_PACKET_CONTROL),
            AFMT_60958_CS_UPDATE,
            AFMT_60958_CS_UPDATE,
        )?;
        self.update(at(AFMT_AUDIO_PACKET_CONTROL2), AFMT_OVERRIDES, 0)?;
        self.update(
            at(AFMT_INFOFRAME_CONTROL0),
            AFMT_AUDIO_INFO_UPDATE,
            AFMT_AUDIO_INFO_UPDATE,
        )?;
        self.update(at(AFMT_60958_0), AFMT_60958_CS_CLOCK_ACCURACY, 0)?;
        self.update(at(DP_SEC_CNTL), DP_SEC_ASP_ENABLE, DP_SEC_ASP_ENABLE)?;
        self.update(at(DP_SEC_CNTL), DP_SEC_ATP_AIP, DP_SEC_ATP_AIP)?;
        self.update(at(DP_SEC_CNTL), DP_SEC_STREAM_ENABLE, DP_SEC_STREAM_ENABLE)
    }
    /// The owner's live registers for a running stream.
    fn verify(&mut self, s: &AudioStream, a: &DisplayAudio) -> Result<(), Error> {
        let at = |r| dig_reg(s.dig, r);
        self.expect(at(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, AFMT_AUDIO_CLOCK_EN)?;
        self.expect(
            at(AFMT_AUDIO_PACKET_CONTROL),
            AFMT_AUDIO_SAMPLE_SEND,
            AFMT_AUDIO_SAMPLE_SEND,
        )?;
        self.expect(
            at(AFMT_AUDIO_SRC_CONTROL),
            AFMT_AUDIO_SRC_SELECT,
            u32::from(a.endpoint),
        )?;
        self.expect(
            at(AFMT_AUDIO_PACKET_CONTROL2),
            AFMT_AUDIO_CHANNEL_ENABLE,
            // linux-lit: 8=AFMT0_AFMT_AUDIO_PACKET_CONTROL2__AFMT_AUDIO_CHANNEL_ENABLE__SHIFT
            u32::from(a.channels) << 8,
        )?;
        if s.hdmi_signal() {
            self.expect(
                at(HDMI_INFOFRAME_CONTROL0),
                HDMI_AUDIO_INFO_SEND,
                HDMI_AUDIO_INFO_SEND,
            )?;
            self.expect(at(HDMI_ACR_PACKET_CONTROL), ACR_CONTROL, HDMI_ACR_AUTO_SEND)?;
        } else {
            self.expect(at(DP_SEC_CNTL), DP_SEC_AUDIO_LIVE, DP_SEC_AUDIO_LIVE)?;
            // linux-lit: 1=DP0_DP_SEC_TIMESTAMP__DP_SEC_TIMESTAMP_MODE_MASK
            self.expect(at(DP_SEC_TIMESTAMP), 1, DP_SEC_TIMESTAMP_MODE_AUTO_CALC)?;
        }
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(Self::az_data(a.endpoint)));
        }
        Ok(())
    }
    /// The stream's OTG runs and its DIG frontend is routed to it.
    fn check_live(&mut self, s: &AudioStream) -> Result<(), Error> {
        if self.read(otg_control(s.otg))? & OTG_MASTER_EN == 0
            || self.read(dig_reg(s.dig, DIG_FE_CNTL))? & DIG_SOURCE_SELECT != u32::from(s.otg)
        {
            return Err(Error::NotRunning);
        }
        Ok(())
    }

    pub(crate) async fn start(
        &mut self,
        s: AudioStream,
        info: AudioInfo,
        wake: &mut impl AzaliaWake,
    ) -> Result<DisplayAudio, Error> {
        if usize::from(s.dig) >= STREAMS || usize::from(s.otg) >= STREAMS {
            return Err(Error::Invalid);
        }
        if self.record(s.dig).is_some() {
            return Err(Error::Busy);
        }
        // Validate everything before the first write.
        plan(&s, &info, 0)?;
        self.check_live(&s)?;
        // Quiet: no samples, and (DP) none of the audio secondary packets.
        let at = |r| dig_reg(s.dig, r);
        self.expect(at(AFMT_AUDIO_PACKET_CONTROL), AFMT_AUDIO_SAMPLE_SEND, 0)
            .map_err(|_| Error::Busy)?;
        if !s.hdmi_signal() {
            self.expect(at(DP_SEC_CNTL), DP_SEC_AUDIO, 0)
                .map_err(|_| Error::Busy)?;
        }
        let count = self.hw_init()?;
        let endpoint = self.pick_endpoint(s.dig, count).ok_or(Error::NoEndpoint)?;
        if self.az_read(endpoint, AZ_HOT_PLUG)? & AUDIO_ENABLED != 0 {
            return Err(Error::Busy);
        }
        let (a, ac3) = plan(&s, &info, endpoint)?;
        // Recorded first: the wall clock is chosen from every record, and a
        // failure or cancellation from here retains the endpoint.
        self.records[usize::from(s.dig)] = Some(Record {
            stream: s,
            audio: a,
            state: State::Programming(Step::WallClock),
        });
        let mut step = Step::WallClock;
        let result = self.program(&s, &a, ac3, wake, &mut step).await;
        self.set_state(
            s.dig,
            match result {
                Ok(()) => State::Running,
                Err(error) => State::Failed { step, error },
            },
        );
        result.map(|()| a)
    }
    async fn program(
        &mut self,
        s: &AudioStream,
        a: &DisplayAudio,
        ac3: bool,
        wake: &mut impl AzaliaWake,
        step: &mut Step,
    ) -> Result<(), Error> {
        let mut at = |engine: &mut Self, next: Step| {
            *step = next;
            engine.set_state(s.dig, State::Programming(next));
        };
        self.wall_dto()?;
        at(self, Step::Encoder);
        if s.hdmi_signal() {
            self.hdmi_audio_setup(s, a)?;
        } else {
            self.audio_source(s.dig, a)?;
        }
        at(self, Step::Endpoint);
        self.az_configure(a, ac3)?;
        if s.hdmi_signal() {
            at(self, Step::InfoFrame);
            self.audio_infoframe(s.dig)?;
        }
        at(self, Step::Enable);
        wake.wake_azalia().await;
        self.az_enable(a.endpoint)?;
        at(self, Step::Packets);
        if !s.hdmi_signal() {
            self.dp_audio_enable(s.dig)?;
        }
        // enc3_audio_mute_control(false).
        self.update(
            dig_reg(s.dig, AFMT_AUDIO_PACKET_CONTROL),
            AFMT_AUDIO_SAMPLE_SEND,
            AFMT_AUDIO_SAMPLE_SEND,
        )?;
        at(self, Step::Verify);
        self.verify(s, a)
    }
    /// Quiesce and release `dig`'s audio, running or retained after a
    /// failure. Every step runs; the first error is returned and the record
    /// retained as failed.
    pub(crate) async fn stop(&mut self, dig: u8, wake: &mut impl AzaliaWake) -> Result<(), Error> {
        let r = self.record(dig).ok_or(Error::Invalid)?;
        self.set_state(dig, State::Programming(Step::Disable));
        let s = r.stream;
        let at = |reg| dig_reg(dig, reg);
        let mut first = Ok(());
        let mut record = |res: Result<(), Error>| {
            if first.is_ok() {
                first = res;
            }
        };
        // disable_dio_audio_packet: mute first.
        record(self.update(at(AFMT_AUDIO_PACKET_CONTROL), AFMT_AUDIO_SAMPLE_SEND, 0));
        if !s.hdmi_signal() {
            // enc1_se_disable_dp_audio: the master enable stays on while any
            // other secondary packet (owned by the video) still needs it.
            record(self.update(at(DP_SEC_CNTL), DP_SEC_AUDIO | DP_SEC_STREAM_ENABLE, 0));
            match self.read(at(DP_SEC_CNTL)) {
                Ok(0) => {}
                Ok(_) => {
                    record(self.update(at(DP_SEC_CNTL), DP_SEC_STREAM_ENABLE, DP_SEC_STREAM_ENABLE))
                }
                Err(e) => record(Err(e)),
            }
        }
        // enc1_se_enable_audio_clock(false).
        record(self.update(at(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, 0));
        wake.wake_azalia().await;
        if s.hdmi_signal() {
            record(self.update(
                at(HDMI_INFOFRAME_CONTROL0),
                HDMI_AUDIO_INFO_SEND | HDMI_AUDIO_INFO_CONT,
                0,
            ));
        }
        record(self.az_disable(r.audio.endpoint));
        match first {
            Ok(()) => {
                self.records[usize::from(dig)] = None;
                // The next display's audio, if any, takes the wall clock.
                self.wall_dto()
            }
            Err(error) => {
                self.set_state(
                    dig,
                    State::Failed {
                        step: Step::Disable,
                        error,
                    },
                );
                Err(error)
            }
        }
    }
}

/// The DCN3.0 audio owner: the DCCG audio DTO, every Azalia endpoint and,
/// per stream it starts, that DIG's AFMT, HDMI audio and DP audio packets.
#[derive(Debug)]
pub struct Audio(Engine<Mmio>);
impl Audio {
    /// # Safety
    /// Caller exclusively owns this Navi22 GPU's DCCG audio DTO registers,
    /// the Azalia endpoint and function-parameter registers, and the audio
    /// fields of every DIG's AFMT/HDMI/DP_SEC block for the object's
    /// lifetime (the video owners keep the rest of those registers), with
    /// matching PCI authority and a permanent register mapping. The HD-Audio
    /// controller and codec are separate owners.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        if Profile::resolve(gpu).map_err(|_| Error::Unsupported)? != Profile::Navi22 {
            return Err(Error::Unsupported);
        }
        let bank = |index, last| {
            Profile::Navi22
                .bank(gpu, index, last)
                .map_err(|_| Error::Unsupported)
        };
        Ok(Self(Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                bank1: bank(1, LAST_BANK1)?, // linux-lit: 1=mmDCCG_AUDIO_DTO_SOURCE_BASE_IDX
                bank2: bank(2, LAST_BANK2)?, // linux-lit: 2=mmDIG0_DIG_FE_CNTL_BASE_IDX
            },
            authority,
        )))
    }
    pub fn record(&self, dig: u8) -> Option<Record> {
        self.0.record(dig)
    }
    /// Start audio on a running stream (after unblank) for a sink whose
    /// audio Linux's `amdgpu_dm_fill_audio_info` would describe as `info`.
    ///
    /// # Safety
    /// `stream` is live and stays live until [`Audio::stop`]; no other agent
    /// programs its DIG's audio fields, the wall clock or the chosen endpoint.
    pub async unsafe fn start(
        &mut self,
        stream: AudioStream,
        info: AudioInfo,
        wake: &mut impl AzaliaWake,
    ) -> Result<DisplayAudio, Error> {
        self.0.start(stream, info, wake).await
    }
    /// The modeset hook: build the ELD fields from the sink's EDID (the
    /// Navi48 builder) and start, or `Ok(None)` when the sink declares no
    /// audio mode (Linux then assigns no endpoint).
    ///
    /// # Safety
    /// As [`Audio::start`].
    pub async unsafe fn start_for_sink(
        &mut self,
        stream: AudioStream,
        edid: &[u8],
        wake: &mut impl AzaliaWake,
    ) -> Result<Option<DisplayAudio>, Error> {
        match crate::amdgpu_navi48_boot::sink_audio_info(edid) {
            None => Ok(None),
            Some(info) => self.0.start(stream, info, wake).await.map(Some),
        }
    }
    /// Mute and release `dig`'s audio. Call before the stream blanks.
    pub async fn stop(&mut self, dig: u8, wake: &mut impl AzaliaWake) -> Result<(), Error> {
        self.0.stop(dig, wake).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_audio_tests.rs"]
mod tests;
