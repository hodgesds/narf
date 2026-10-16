//! Native DCN401 timing preparation and retirement. Register layout comes
//! from dcn_4_1_0; sequencing from Linux dcn401_optc.c/dcn10_optc.c.
//! Progressive RGB, fixed refresh and one OPP per OTG only. Internal black
//! timing and owned legacy DP black video can run with fetchers stopped;
//! surface scanout still needs its owners.
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn401_clk as clocks, amdgpu_dcn401_dccg as dccg,
    amdgpu_dcn401_dml as dml, amdgpu_discovery as ip, amdgpu_dml::Timing,
};
use alloc::boxed::Box;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[path = "amdgpu_dcn401_opp.rs"]
mod opp;
pub use opp::{BlankApplied, BlankRequest, BlankRunning, ColorDepth};
#[path = "amdgpu_dcn401_fetch.rs"]
mod fetch;
pub use fetch::{
    CursorApplied, DeadlinesApplied, DppApplied, FlipDone, HubpPower, MemoryApplied, MpcApplied,
    PlanesRetired, RequestorApplied, ScanoutPosition, ScanoutRunning, ScanoutUnderflow,
    SurfaceApplied, SurfaceFormat, SurfaceRequest, VblankPhase, CURSOR_MAX,
};
#[path = "amdgpu_dcn401_stream.rs"]
mod stream;
pub use stream::{DpBlanked, DpEncoderRetired, DpStream};
#[path = "amdgpu_dcn401_link.rs"]
mod link;
pub use link::DpSstDisabled;
#[path = "amdgpu_dcn401_dp_phy.rs"]
mod dp_phy;
pub use dp_phy::{
    DpDriveSettings, DpFrontendReady, DpFrontendRequest, DpLinkStatus, DpLinkTrained, DpPhyReady,
    DpPhySettings, DpTrainingError, DpVideoRunning, UhbrLinkTrained, UhbrPayload, UhbrRate,
    UhbrSettings, UhbrVideoRunning,
};
#[path = "amdgpu_dcn401_hpo_link.rs"]
mod hpo_link;
pub use hpo_link::{HpoDpDisabled, HpoLinkRetired};
#[path = "amdgpu_dcn401_hdmi.rs"]
mod hdmi;
pub use hdmi::HdmiTmdsRetired;
#[path = "amdgpu_dcn401_hdmi_link.rs"]
mod hdmi_link;
pub use hdmi_link::audio::MstAudioPayload;
pub(crate) use hdmi_link::audio::{frl_audio_info, mst_audio_info, uhbr_audio_info};
pub use hdmi_link::{
    AudioInfo, AudioMode, Avi, DisplayAudio, HdmiLinkReady, HdmiLinkRequest, HdmiVideoRunning,
    TMDS_MAX_KHZ, TMDS_SCRAMBLE_KHZ,
};
#[path = "amdgpu_dcn401_tmds_timing.rs"]
mod tmds_timing;
pub use tmds_timing::TmdsTimingRetired;
#[path = "amdgpu_dcn401_tmds_phy.rs"]
mod tmds_phy;
pub use tmds_phy::TmdsDisabled;
#[path = "amdgpu_dcn401_dsc_hw.rs"]
mod dsc_hw;
#[path = "amdgpu_dcn401_mst.rs"]
mod mst;
pub use mst::{vc_rate, MstAllocation};
#[path = "amdgpu_dcn401_frl.rs"]
mod frl;
pub use frl::{
    FrlDisabled, FrlEncoderRetired, FrlLinkRetired, FrlLinkUp, FrlVideoRequest, FrlVideoRunning,
};

const H_TOTAL: u64 = 0x1b2a;
const H_BLANK: u64 = 0x1b2b;
const H_SYNC: u64 = 0x1b2c;
const H_POL: u64 = 0x1b2d;
const H_TIMING: u64 = 0x1b2e;
const V_TOTAL: u64 = 0x1b2f;
const V_MIN: u64 = 0x1b30;
const V_MAX: u64 = 0x1b31;
const V_CONTROL: u64 = 0x1b33;
const V_BLANK: u64 = 0x1b38;
const V_SYNC: u64 = 0x1b39;
const V_POL: u64 = 0x1b3a;
const CONTROL: u64 = 0x1b43;
const INTERLACE: u64 = 0x1b45;
const CLOCK: u64 = 0x1b84;
const STARTUP: u64 = 0x1b85;
const UPDATE: u64 = 0x1b86;
const READY: u64 = 0x1b87;
const LOCK: u64 = 0x1b89;
const PSTATE: u64 = 0x1b9f;
const SOURCE: u64 = 0x1acb;
const FORMAT: u64 = 0x1acc;
const INPUT_CLOCK: u64 = 0x1ad0;
const MEMORY: u64 = 0x1ad1;
const GLOBAL_TIMER: u64 = 0x527; // DCHUBBUB_GLOBAL_TIMER_CNTL

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Allocation,
    Busy,
    Revoked,
    DeviceGone,
    Readback(u64),
    Timeout(u64),
    Clocks(clocks::Error),
    PipeClocks(dccg::Error),
    Firmware(crate::amdgpu_dmub_navi48::Error),
    DpTraining(DpTrainingError),
    Memory(crate::amdgpu_gmc_navi48::Error),
    Admission(dml::Error),
    /// HUBP or OPTC underflow observed at this register during scanout.
    Underflow(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Preparing(u8),
    Prepared,
    PreparingBlank(u8),
    BlankPrepared,
    StartingBlank(u8),
    RunningBlank(u8),
    BlankingDp(DpStream),
    DpBlanked,
    RetiringDpEncoder(DpStream),
    DpEncoderRetired,
    DisablingDpSst(u8),
    DpSstDisabled,
    EnablingDpPhy(u8),
    DpPhyReady(u8),
    DisablingDpPhy(u8),
    DpPhyDisabled,
    TrainingDp(u8),
    DpLinkTrained(u8),
    /// The sink refused training and the source is proven back at idle;
    /// only stop_dp_link may follow, before a fallback re-enables the PHY.
    DpLinkRefused(u8),
    StoppingDpLink(u8),
    /// A 128b/132b link on this transmitter: being enabled and trained,
    /// trained (link idle, no stream), refused by the sink after training
    /// exited, or stopping.
    TrainingUhbr(u8),
    UhbrLinkTrained(u8),
    UhbrLinkRefused(u8),
    StoppingUhbrLink(u8),
    /// 128b/132b video on HPO stream encoder n: starting, running, stopping.
    StartingUhbrVideo(u8),
    UhbrVideoRunning(u8),
    /// APG reset in progress; cancellation retains ownership and blocks reuse.
    StartingUhbrAudio(u8),
    StoppingUhbrVideo(u8),
    PreparingDpFrontend(u8),
    DpFrontendReady(u8),
    StoppingDpFrontend(u8),
    StartingDpVideo(u8),
    DpVideoRunning(u8),
    StoppingDpVideo(u8),
    RetiringHpoLink(u8),
    HpoLinkRetired,
    DisablingHpoDp(u8),
    HpoDpDisabled,
    RetiringHdmiTmds(u8),
    HdmiTmdsRetired,
    PreparingHdmiLink(u8),
    HdmiLinkReady(u8),
    StoppingHdmiLink(u8),
    /// The owned TMDS transmitter and frontend are off; reusable.
    HdmiLinkStopped,
    StartingHdmiVideo(u8),
    HdmiVideoRunning(u8),
    StoppingHdmiVideo(u8),
    RetiringTmdsTiming(u8),
    TmdsTimingRetired,
    DisablingTmds(u8),
    TmdsDisabled,
    RetiringHdmiFrl,
    HdmiFrlRetired,
    RetiringFrlLink(u8),
    FrlLinkRetired,
    /// This owner's FRL link on this transmitter: firmware-enabled and
    /// sending training patterns, or trained and sending FRL output.
    FrlLinkTraining(u8),
    FrlLinkActive(u8),
    /// Pattern/FFE update in flight; cancellation retains the link and video.
    UpdatingFrlLink(u8),
    /// FRL video from pipe n: starting, running, stopping.
    StartingFrlVideo(u8),
    FrlVideoRunning(u8),
    StoppingFrlVideo(u8),
    DisablingFrl(u8),
    FrlDisabled,
    RetiringPlanes,
    PlanesRetired,
    ChangingHubpPower(u8),
    HubpPowerChanged,
    PreparingSurface(u8),
    SurfacePrepared,
    PreparingMemory(u8),
    MemoryPrepared,
    PreparingDpp(u8),
    DppPrepared,
    PreparingMpc(u8),
    MpcPrepared,
    PreparingRequestor(u8),
    RequestorPrepared,
    PreparingDeadlines(u8),
    DeadlinesPrepared,
    StartingScanout(u8),
    ScanoutRunning(u8),
    StoppingScanout(u8),
    Flipping(u8),
    Cursor(u8),
    Retiring(u8),
    Retired,
    Failed(Error),
}
impl State {
    pub(crate) fn reusable(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::Prepared
                | Self::BlankPrepared
                | Self::Retired
                | Self::PlanesRetired
                | Self::HubpPowerChanged
                | Self::SurfacePrepared
                | Self::MemoryPrepared
                | Self::DppPrepared
                | Self::MpcPrepared
                | Self::RequestorPrepared
                | Self::DeadlinesPrepared
                | Self::DpBlanked
                | Self::DpEncoderRetired
                | Self::DpSstDisabled
                | Self::DpPhyDisabled
                | Self::HpoLinkRetired
                | Self::HpoDpDisabled
                | Self::HdmiTmdsRetired
                | Self::HdmiLinkStopped
                | Self::TmdsTimingRetired
                | Self::TmdsDisabled
                | Self::HdmiFrlRetired
                | Self::FrlLinkRetired
                | Self::FrlDisabled
        )
    }
}
impl State {
    /// A state another display may be selected from: idle, or video
    /// running with or without scanout. Anything mid-operation or failed
    /// keeps the selection (a failure quarantines every display).
    pub(crate) fn settled(self) -> bool {
        self.reusable()
            || matches!(
                self,
                Self::ScanoutRunning(_)
                    | Self::DpVideoRunning(_)
                    | Self::HdmiVideoRunning(_)
                    | Self::UhbrVideoRunning(_)
                    | Self::FrlVideoRunning(_)
            )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    DisplayPort,
    HpoDisplayPort,
    Tmds,
    HdmiFrl,
}
impl Signal {
    fn control(self) -> u32 {
        match self {
            Self::DisplayPort => 0x1000,
            Self::HpoDisplayPort => 0x201000,
            Self::Tmds => 0,
            // Native FRL shares HPO mux 2 with DP; mux 1 is reserved.
            Self::HdmiFrl => 0x200000,
        }
    }
}
/// Caller-supplied bandwidth/DLG results. Field validation is not a proof
/// that a mode can fetch its surfaces within these windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalSync {
    pub vstartup: u32,
    pub vupdate_offset: u32,
    pub vupdate_width: u32,
    pub vready_offset: u32,
    pub pstate_keepout: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub pipe: u8,
    pub timing: Timing,
    pub sync: GlobalSync,
    pub signal: Signal,
    /// HDMI YCbCr 4:2:0 output: two pixels per container, so the OTG
    /// divides its horizontal timing by two and formats 4:2:0 data.
    pub ycbcr420: bool,
    /// Compressed by the pipe's own DSC (8-bit RGB 8b/10b DP only).
    pub dsc: Option<crate::amdgpu_dsc::DscConfig>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    pub request: Request,
    pub clock: dccg::Applied,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    /// Historical programming, not permission to start scanout. A clock
    /// change invalidates the recorded snapshot; failure/cancellation is sticky.
    pub pipes: [Option<Applied>; 4],
    /// Staged OPP/FMT programming; never a proof of active blanking.
    pub blanks: [Option<BlankApplied>; 4],
    /// Historical internal blank completion, valid only in RunningBlank.
    /// Does not prove link output or authorize scanout allocation reuse.
    pub running_blank: Option<BlankRunning>,
    /// Historical fetch-stop evidence. Never grants allocation reuse or proves
    /// retirement of GPUVM, writeback, or other GPU engines.
    pub planes_retired: Option<PlanesRetired>,
    /// Historical domain power evidence, never memory-reuse or scanout authority.
    pub hubp_power: [Option<HubpPower>; 4],
    /// Staged owned surfaces, not evidence of a latched flip or active scanout.
    pub surfaces: [Option<SurfaceApplied>; 4],
    /// Historical aperture/VMID0 setup, never fetch or flip completion evidence.
    pub memory: [Option<MemoryApplied>; 4],
    /// Staged RGB conversion/scaler state, never a latch or scanout proof.
    pub dpps: [Option<DppApplied>; 4],
    /// Staged opaque RGB composition; selectors remain detached, not latched.
    pub mpcs: [Option<MpcApplied>; 4],
    /// Native single-pipe storage/request geometry. Not bandwidth admission.
    pub requestor: Option<RequestorApplied>,
    /// Admitted DLG/TTU/watermark programming for the staged requestor.
    /// Fetch stays stopped; never evidence of activation or presentation.
    pub deadlines: Option<DeadlinesApplied>,
    /// Current only in ScanoutRunning: the owned surface is the live source.
    /// Stopping returns to black video with fetch drained and clocks gated.
    pub scanout: Option<ScanoutRunning>,
    /// Last underflow that returned a live scanout to black. Retained across
    /// later starts as a diagnostic until another underflow replaces it.
    pub underflow: Option<ScanoutUnderflow>,
    /// The owned cursor on the live pipe; cleared when scanout stops.
    pub cursor: Option<CursorApplied>,
    /// Historical DP video blanking only; never PHY, timing or memory retirement.
    pub dp_blanked: Option<DpBlanked>,
    /// Historical stream-encoder shutdown only; PHYs and memory stay retained.
    pub dp_encoder_retired: Option<DpEncoderRetired>,
    /// Historical legacy DP firmware-disable/backend-off evidence only.
    /// Does not prove analog PHY power gating, sink or memory retirement.
    pub dp_sst_disabled: Option<DpSstDisabled>,
    /// Historical untrained PHY evidence; valid only in DpPhyReady. No sink,
    /// training, stream or scanout completion is implied.
    pub dp_phy_ready: Option<DpPhyReady>,
    /// Historical source/sink training evidence; current only in DpLinkTrained
    /// (or, for a refused link awaiting stop_dp_link, DpLinkRefused).
    /// Video, timing and scanout remain stopped.
    pub dp_link_trained: Option<DpLinkTrained>,
    /// The 128b/132b link; current in UhbrLinkTrained/UhbrLinkRefused.
    pub uhbr_link: Option<UhbrLinkTrained>,
    /// Black 128b/132b video; current only in UhbrVideoRunning (or beneath
    /// a live scanout).
    pub uhbr_video_running: Option<UhbrVideoRunning>,
    /// APG and Azalia audio owner; retained across failed/cancelled reset.
    pub uhbr_audio: Option<DisplayAudio>,
    /// Historical blank frontend setup; current only in DpFrontendReady.
    /// Timing, video and scanout remain stopped.
    pub dp_frontend_ready: Option<DpFrontendReady>,
    /// Historical external RGB black video. Current only in DpVideoRunning;
    /// never proves surface scanout, sink presentation or memory retirement.
    pub dp_video_running: Option<DpVideoRunning>,
    /// Historical HPO digital-link stop only; PHY and its root clock remain owned.
    pub hpo_link_retired: Option<HpoLinkRetired>,
    /// Historical lane-disable/TX-clock/root-route evidence, not analog power gating.
    pub hpo_dp_disabled: Option<HpoDpDisabled>,
    /// Historical TMDS frontend stop only; backend/PHY/OTG remain owned.
    pub hdmi_tmds_retired: Option<HdmiTmdsRetired>,
    /// The owned, transmitting TMDS link; current in HdmiLinkReady (and under
    /// HdmiVideoRunning's record). Timing stopped; no sink presentation implied.
    pub hdmi_link_ready: Option<HdmiLinkReady>,
    /// External RGB black video on the owned HDMI link. Current only in
    /// HdmiVideoRunning (or beneath a live scanout); never memory retirement.
    pub hdmi_video_running: Option<HdmiVideoRunning>,
    /// Audio on the running HDMI video; must stop before the video does.
    pub hdmi_audio: Option<DisplayAudio>,
    /// Audio on the running DP video; must stop before the video does.
    pub dp_audio: Option<DisplayAudio>,
    /// Retained MST allocation/VC-rate witness for this stream's audio.
    pub mst_audio_payload: Option<MstAudioPayload>,
    /// Historical timing/input clock-off only; all PHYs and memory stay retained.
    pub tmds_timing_retired: Option<TmdsTimingRetired>,
    /// Historical TMDS backend/lane/TX-clock stop, never memory retirement.
    pub tmds_disabled: Option<TmdsDisabled>,
    /// Historical FRL frontend stop only; link/PHY/timing and memory stay owned.
    pub frl_encoder_retired: Option<FrlEncoderRetired>,
    /// Historical FRL digital-link stop only; PHY, root clocks and memory stay owned.
    pub frl_link_retired: Option<FrlLinkRetired>,
    /// This owner's FRL link, including live training-pattern and FFE state.
    pub frl_link: Option<FrlLinkUp>,
    /// Black FRL video; current only in FrlVideoRunning (or beneath a live
    /// scanout).
    pub frl_video_running: Option<FrlVideoRunning>,
    /// Owned AFMT4/ACR and Azalia endpoint; stop before FRL video/link.
    pub frl_audio: Option<DisplayAudio>,
    /// The display whose MST link this one's stream rides (attached, not
    /// trained, by this display); its link record is a copy of theirs.
    pub mst_owner: Option<u8>,
    /// Historical lane/TX-clock/character-root stop; forced input clocks stay owned.
    pub frl_disabled: Option<FrlDisabled>,
    /// Timing retirement only. Does not prove HUBP/VM or surface retirement.
    pub retired: u8,
}
impl Status {
    fn new() -> Self {
        Self {
            state: State::Ready,
            pipes: [None; 4],
            blanks: [None; 4],
            running_blank: None,
            planes_retired: None,
            hubp_power: [None; 4],
            surfaces: [None; 4],
            memory: [None; 4],
            dpps: [None; 4],
            mpcs: [None; 4],
            requestor: None,
            deadlines: None,
            scanout: None,
            underflow: None,
            cursor: None,
            dp_blanked: None,
            dp_encoder_retired: None,
            dp_sst_disabled: None,
            dp_phy_ready: None,
            dp_link_trained: None,
            uhbr_link: None,
            uhbr_video_running: None,
            uhbr_audio: None,
            dp_frontend_ready: None,
            dp_video_running: None,
            hpo_link_retired: None,
            hpo_dp_disabled: None,
            hdmi_tmds_retired: None,
            hdmi_link_ready: None,
            hdmi_video_running: None,
            hdmi_audio: None,
            dp_audio: None,
            mst_audio_payload: None,
            tmds_timing_retired: None,
            tmds_disabled: None,
            frl_encoder_retired: None,
            frl_link_retired: None,
            frl_link: None,
            frl_video_running: None,
            frl_audio: None,
            mst_owner: None,
            frl_disabled: None,
            retired: 0,
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Plan {
    request: Request,
    h_blank: u32,
    v_blank: u32,
    vtg: u32,
}
impl Plan {
    fn registers(self) -> [(u64, u32, u32); 16] {
        let Request {
            timing: t,
            sync: s,
            signal,
            ..
        } = self.request;
        [
            (H_TOTAL, 0x7fff, t.h_total - 1),
            (H_SYNC, 0x7fff7fff, t.h_sync_width << 16),
            (H_BLANK, 0x7fff7fff, self.h_blank),
            (H_POL, 1, u32::from(!t.h_sync_positive)),
            (V_TOTAL, 0x7fff, t.v_total - 1),
            (V_MIN, 0x7fff, t.v_total - 1),
            (V_MAX, 0x7fff, t.v_total - 1),
            (V_SYNC, 0x7fff7fff, t.v_sync_width << 16),
            (V_BLANK, 0x7fff7fff, self.v_blank),
            (V_POL, 1, u32::from(!t.v_sync_positive)),
            (INTERLACE, 1, 0),
            (CONTROL, 0x303000, signal.control()),
            (STARTUP, 0x3ff, s.vstartup),
            (UPDATE, 0x3ffffff, s.vupdate_offset | s.vupdate_width << 16),
            (READY, 0xffff, s.vready_offset),
            (PSTATE, 0x7fff, s.pstate_keepout),
        ]
    }
    /// OTG_H_TIMING_CNTL: optc401_set_odm_bypass divides by two for two
    /// pixels per container (4:2:0, whose horizontal timing `plan` requires
    /// even); otherwise no divide, the hardware's automatic choice unless
    /// a horizontal boundary is odd, when the manual no-divide mode is set.
    fn h_divider(self) -> u32 {
        if self.request.ycbcr420 {
            return 1;
        }
        ((self.request.timing.h_total
            | self.request.timing.h_sync_width
            | self.h_blank
            | (self.h_blank >> 16))
            & 1)
            << 8
    }
}
impl Request {
    fn plan(self) -> Result<Plan, Error> {
        let t = self.timing;
        let s = self.sync;
        if self.pipe >= 4
            || t.pixel_clock_khz == 0
            || t.h_active == 0
            || t.v_active == 0
            || t.h_total > 32768
            || t.v_total > 32768
            || t.h_sync_width < 4
            || t.v_sync_width == 0
            || t.v_front_porch == 0
            || s.vstartup == 0
            || s.vstartup > 0x3ff
            || s.vstartup >= t.v_total
            || s.vupdate_offset > 0xffff
            || s.vupdate_width > 0x3ff
            || s.vready_offset > 0xffff
            || s.pstate_keepout > 0x7fff
        {
            return Err(Error::Invalid);
        }
        let blank = |total: u32, active: u32, front: u32, sync: u32, min: u32| {
            let width = total.checked_sub(active).ok_or(Error::Invalid)?;
            let start = total.checked_sub(front).ok_or(Error::Invalid)?;
            let end = start.checked_sub(active).ok_or(Error::Invalid)?;
            if width < min || start > 0x7fff || end < sync {
                return Err(Error::Invalid);
            }
            Ok((start, end))
        };
        let (hs, he) = blank(t.h_total, t.h_active, t.h_front_porch, t.h_sync_width, 32)?;
        let (vs, ve) = blank(t.v_total, t.v_active, t.v_front_porch, t.v_sync_width, 3)?;
        // 4:2:0 is HDMI only, and every horizontal boundary must divide by
        // two (Linux would switch to the manual mode; this owner refuses).
        if self.ycbcr420
            && (!matches!(self.signal, Signal::Tmds | Signal::HdmiFrl)
                || t.h_active > dml::FMT_420_BUFFER_WIDTH
                || (t.h_total | t.h_sync_width | hs | he) & 1 != 0)
        {
            return Err(Error::Unsupported);
        }
        if let Some(cfg) = &self.dsc {
            dsc_hw::dsc_registers(&self, cfg)?;
        }
        Ok(Plan {
            request: self,
            h_blank: hs | he << 16,
            v_blank: vs | ve << 16,
            vtg: vs << 16 | s.vstartup.saturating_sub(ve + 1),
        })
    }
    fn validate_clock(self, clock: dccg::Applied) -> Result<(), Error> {
        let hz = u64::from(self.timing.pixel_clock_khz) * 1000;
        let signal_matches = match (self.signal, clock.request.pixel) {
            (
                Signal::DisplayPort | Signal::HpoDisplayPort,
                dccg::PixelClock::DisplayPort { pixel_hz },
            )
            | (Signal::HdmiFrl, dccg::PixelClock::HdmiFrl { pixel_hz }) => pixel_hz == hz,
            (Signal::Tmds, dccg::PixelClock::Tmds { .. }) => true,
            _ => false,
        };
        if !signal_matches
            || clock.request.pipe != self.pipe
            || self.timing.pixel_clock_khz > clock.global.display_khz
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    base: u64,
    nbio: u64,
    mpc_base: u64,
    link_clock: u64,
    dio_clock: u64,
    idle: [(u64, u32); clocks::IDLE_REG_COUNT],
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        let display = clocks::Layout::resolve(gpu).map_err(Error::Clocks)?;
        let base = crate::amdgpu_psp_ring::bank(
            gpu,
            ip::HW_ID_DCN,
            &[(4, 0, 1), (4, 1, 0)],
            2,
            0x3947, // includes all six native SAT status rows on HPO link 3
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            base,
            nbio: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_NBIF,
                &[(7, 7, 0), (7, 7, 1), (6, 3, 1)],
                2,
                0x12d,
            )
            .map_err(|_| Error::Unsupported)?,
            link_clock: display.hpo_link_clock(),
            dio_clock: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                1,
                0xad, // through DCCG_AUDIO_DTO0_MODULE
            )
            .map_err(|_| Error::Unsupported)?
                + 0xa0 * 4,
            mpc_base: crate::amdgpu_psp_ring::bank(
                gpu,
                ip::HW_ID_DCN,
                &[(4, 0, 1), (4, 1, 0)],
                3,
                0xe59, // MPC and four independent HPO stream-to-link mappers
            )
            .map_err(|_| Error::Unsupported)?,
            idle: display.idle_registers(),
        })
    }
    fn otg(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x80) * 4
    }
    fn odm(self, pipe: u8, reg: u64) -> u64 {
        self.base + (reg + u64::from(pipe) * 0x10) * 4
    }
    fn vtg(self, pipe: u8) -> u64 {
        self.base + (0x530 + u64::from(pipe)) * 4
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
    /// Models can suspend at a missing acknowledgement without racing the
    /// host clock. Real MMIO never requests this test-only suspension.
    #[cfg(feature = "kernel-test")]
    fn pause_wait(&self) -> bool {
        false
    }
    /// Read-driven register models can use a bounded number of cooperative
    /// polls instead of a wall-clock deadline. Real MMIO always uses time.
    #[cfg(feature = "kernel-test")]
    fn wait_poll_limit(&self) -> Option<u32> {
        None
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: bounded discovery, permanent mapping and serialized owner.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same bounds/ownership; caller invokes live write authority.
        unsafe { self.0.write32(at, value) };
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
/// What the displays other than the selected one hold, by instance bit:
/// the registers each idle check must leave to them, and their live
/// scanouts (pipe-indexed: surface address and cursor visibility), which are
/// verified as live rather than stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Siblings {
    pub pipes: u8,
    /// Pipes holding a DET allocation (a staged requestor).
    pub det: u8,
    pub transmitters: u8,
    pub streams: u8,
    /// Displays running 128b/132b: their HPO link and stream encoders (the
    /// display's own index, like its pipe) and SYMCLK32 routes.
    pub hpo: u8,
    /// A display running FRL: the single HPO FRL encoder and its clocks.
    pub frl: bool,
    /// Transmitters whose running link is 8b/10b MST: others' streams may
    /// share them.
    pub mst: u8,
    pub live: [Option<(u64, bool)>; 4],
}
/// An instance's bit in a `Siblings` mask; none for an instance past 7.
pub(crate) fn bit(instance: u8) -> u8 {
    1u8.checked_shl(u32::from(instance)).unwrap_or(0)
}
impl Siblings {
    /// The resources one display's records hold. Pipes count from the first
    /// staged record until retirement; a link only while its video runs
    /// (with or without scanout), the one state a display may be left in
    /// while another is selected besides an idle one.
    fn of(s: &Status) -> Self {
        let mut out = Self::default();
        for p in 0..4u8 {
            let i = usize::from(p);
            let staged = s.pipes[i].is_some()
                || s.blanks[i].is_some()
                || s.surfaces[i].is_some()
                || s.dpps[i].is_some()
                || s.mpcs[i].is_some()
                || s.requestor.is_some_and(|r| r.pipe == p)
                || s.deadlines.is_some_and(|d| d.pipe == p);
            if staged {
                out.pipes |= 1 << p;
            }
        }
        if let Some(r) = s.requestor {
            out.det |= bit(r.pipe);
        }
        let uhbr = |stream: u8| {
            s.uhbr_video_running
                .filter(|v| v.stream == stream)
                .map(|v| v.link.path)
        };
        let frl = |pipe: u8| {
            s.frl_video_running
                .filter(|v| v.request.pipe == pipe)
                .map(|v| v.link.path)
        };
        let (stream, link) = match s.state {
            State::HdmiVideoRunning(stream) => (stream, s.hdmi_video_running.map(|v| v.link.path)),
            State::UhbrVideoRunning(stream) => (stream, uhbr(stream)),
            State::FrlVideoRunning(pipe) => (pipe, frl(pipe)),
            State::DpVideoRunning(stream) => {
                (stream, s.dp_video_running.map(|v| v.frontend.link.phy.path))
            }
            State::ScanoutRunning(p) => {
                let Some(live) = s.scanout else {
                    return out;
                };
                out.pipes |= bit(p);
                if let Some(slot) = out.live.get_mut(usize::from(p)) {
                    *slot = Some((
                        live.address,
                        s.cursor.is_some_and(|c| c.pipe == p && c.visible),
                    ));
                }
                let hdmi = s
                    .hdmi_video_running
                    .filter(|v| v.link.request.stream == live.stream)
                    .map(|v| v.link.path);
                let dp = s
                    .dp_video_running
                    .filter(|v| v.frontend.request.stream == live.stream)
                    .map(|v| v.frontend.link.phy.path);
                (
                    live.stream,
                    hdmi.or(dp).or(uhbr(live.stream)).or(frl(live.pipe)),
                )
            }
            _ => return out,
        };
        let mst = s.dp_video_running.is_some_and(|v| {
            v.frontend.link.phy.settings.mst && v.frontend.request.stream == stream
        });
        if let Some(path) = link {
            out.transmitters |= bit(path.transmitter);
            if mst {
                out.mst |= bit(path.transmitter);
            }
            out.streams |= bit(stream);
            if uhbr(stream).is_some() {
                out.hpo |= bit(stream);
            }
            out.frl |= s.frl_video_running.is_some();
        }
        out
    }
    fn union(self, other: Self) -> Self {
        let mut live = self.live;
        for (slot, other) in live.iter_mut().zip(other.live) {
            *slot = slot.or(other);
        }
        Self {
            pipes: self.pipes | other.pipes,
            det: self.det | other.det,
            transmitters: self.transmitters | other.transmitters,
            streams: self.streams | other.streams,
            hpo: self.hpo | other.hpo,
            frl: self.frl || other.frl,
            mst: self.mst | other.mst,
            live,
        }
    }
}
/// Whether an idle-check register belongs to another display: its pipe's
/// timing generator, its transmitter's backend and PHY, or its DIO
/// frontend. Those are that display's to verify, not foreign.
fn held_by_sibling(s: Siblings, l: Layout, at: u64) -> bool {
    let phy = |i: u8, r: u64| l.base + (r + u64::from(i) * 0xd8) * 4;
    // The FRL display's HPO FRL stream and link encoders and its
    // character-clock root.
    if s.frl
        && (clocks::FRL_IDLE
            .iter()
            .any(|&(r, _)| at == l.mpc_base + r * 4)
            || at == l.base + 0x4a * 4)
    {
        return true;
    }
    (0..4u8).any(|i| {
        let b = bit(i);
        let dio = |r| stream::DpStream::Dio(i).at(l, r);
        (s.pipes & b != 0 && (at == l.otg(i, CONTROL) || at == l.otg(i, CLOCK)))
            || (s.transmitters & b != 0
                && [dio(0x20bb), dio(0x20bd), phy(i, 0x2943), phy(i, 0x2931)].contains(&at))
            || (s.streams & b != 0
                && [0x2094, 0x2095, 0x209b, 0x2122]
                    .iter()
                    .any(|&r| at == dio(r)))
            // A 128b/132b display's HPO link and stream encoders, and the
            // SYMCLK32 route registers its nibble shares (each display's own
            // checks verify the other nibbles).
            || (s.hpo & b != 0
                && ([0x3623, 0x365d, 0x367b, 0x3685, 0x369f, 0x36b4, 0x36b5]
                    .iter()
                    .any(|&r| at == stream::DpStream::Hpo(i).at(l, r))
                    || at == l.link_clock
                    || at == l.link_clock - 4))
    })
}
/// The records of every display this owner drives. The selected display's
/// are `Engine::status`; `parked[selected]` is stale while it is selected.
#[derive(Debug)]
struct Displays {
    selected: u8,
    /// Four records, built on the heap: together they would fill much of
    /// a 64 KiB aarch64 stack.
    parked: Box<[Status]>,
    /// The other displays' resources, fixed while this one is selected.
    siblings: Siblings,
}
impl Displays {
    fn new() -> Box<Self> {
        Box::new(Self {
            selected: 0,
            parked: alloc::vec![Status::new(); 4].into_boxed_slice(),
            siblings: Siblings::default(),
        })
    }
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    // Per-pipe historical reports are large. Keep them out of async owner
    // moves and nested call frames, including the 64 KiB aarch64 boot stack.
    status: Box<Status>,
    displays: Box<Displays>,
}
impl<I: Io> Engine<I> {
    /// Make `display`'s records current, parking the selected display's,
    /// and recompute what the others hold. Only between operations, from a
    /// settled state.
    fn select_display(&mut self, display: u8) -> Result<(), Error> {
        if display >= 4 {
            return Err(Error::Invalid);
        }
        if display == self.displays.selected {
            return Ok(());
        }
        if !self.status.state.settled() {
            return Err(Error::Busy);
        }
        let d = &mut *self.displays;
        d.parked[usize::from(d.selected)] = *self.status;
        *self.status = d.parked[usize::from(display)];
        d.selected = display;
        d.siblings = (0..4u8)
            .filter(|&k| k != display)
            .fold(Siblings::default(), |acc, k| {
                acc.union(Siblings::of(&d.parked[usize::from(k)]))
            });
        Ok(())
    }
    /// Whether an idle-check register belongs to another display.
    fn sibling_register(&self, at: u64) -> bool {
        held_by_sibling(self.displays.siblings, self.layout, at)
    }
    /// What `held_by_sibling` needs, for the clock owners' idle checks.
    fn held(&self) -> (Siblings, Layout) {
        (self.displays.siblings, self.layout)
    }
    /// `hubbub2_get_dchub_ref_freq`: the DCHUB global timer divides the DCCG
    /// reference (the VBIOS crystal on DCN401) by its REFDIV. Firmware set it
    /// up; this owner never reprograms it. Linux treats a stopped timer or a
    /// reference outside 40-60 MHz as critical, and so is it refused here.
    fn dchub_refclk_khz(&mut self, crystal_khz: u32) -> Result<u32, Error> {
        let timer = self.read(self.layout.base + GLOBAL_TIMER * 4)?;
        if timer & 0x1000 == 0 {
            return Err(Error::Unsupported);
        }
        let khz = if timer & 0xf == 2 {
            crystal_khz / 2
        } else {
            crystal_khz
        };
        if !(40_000..=60_000).contains(&khz) {
            return Err(Error::Unsupported);
        }
        Ok(khz)
    }
    fn admission_soc(
        &mut self,
        levels: &clocks::Levels,
        dentist_vco_khz: u32,
        crystal_khz: u32,
    ) -> Result<dml::Soc, Error> {
        let range = |clock| levels.range(clock);
        Ok(dml::Soc {
            umc_channels: levels.umc_channels,
            uclk_khz: range(clocks::Clock::Memory).max_khz(),
            fclk_khz: [
                range(clocks::Clock::Fabric).min_khz(),
                range(clocks::Clock::Fabric).max_khz(),
            ],
            dcfclk_khz: [
                range(clocks::Clock::Dcf).min_khz(),
                range(clocks::Clock::Dcf).max_khz(),
            ],
            socclk_khz: range(clocks::Clock::Soc).min_khz(),
            dispclk_max_khz: range(clocks::Clock::Display).max_khz(),
            dppclk_max_khz: range(clocks::Clock::Dpp).max_khz(),
            dentist_vco_khz,
            dchub_refclk_khz: self.dchub_refclk_khz(crystal_khz)?,
        })
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    fn read(&mut self, at: u64) -> Result<u32, Error> {
        self.access(|io| checked(io.read(at)))
    }
    fn update(&mut self, at: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io| {
            let old = checked(io.read(at))?;
            io.write(at, (old & !mask) | (value & mask));
            Ok(())
        })?;
        if self.read(at)? & mask != value & mask {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    fn preflight(&mut self, pipe: u8, retire: bool) -> Result<(), Error> {
        if !(self.status.state.reusable()
            || retire && self.status.state == State::RunningBlank(pipe))
        {
            return Err(Error::Busy);
        }
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        // Another display's pipe is never this operation's to retire or
        // program, and its consumers are its own.
        if self.displays.siblings.pipes & 1 << pipe != 0 {
            return Err(Error::Busy);
        }
        let l = self.layout;
        for (at, mask) in l.idle {
            let timing = (0..4).any(|p| at == l.otg(p, CONTROL) || at == l.otg(p, CLOCK));
            if !(self.sibling_register(at) || retire && timing) && self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // Never steal an inherited master-update transaction or program an
        // OTG held in soft reset. FAMS/firmware writers are excluded by ownership.
        if self.read(l.otg(pipe, LOCK))? & 0x101 != 0 || self.read(l.otg(pipe, CLOCK))? & 0x10 != 0
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    async fn wait(&mut self, at: u64, mask: u32, value: u32, us: u64) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_us(us);
        #[cfg(feature = "kernel-test")]
        let mut polls = self.io.wait_poll_limit();
        loop {
            if self.read(at)? & mask == value {
                return Ok(());
            }
            #[cfg(feature = "kernel-test")]
            if self.io.pause_wait() {
                core::future::pending::<()>().await;
            }
            #[cfg(feature = "kernel-test")]
            if let Some(left) = &mut polls {
                if *left == 0 {
                    return Err(Error::Timeout(at));
                }
                *left -= 1;
                narf_scheduler::yield_now().await;
                continue;
            }
            if deadline.expired() {
                return Err(Error::Timeout(at));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
        }
    }
    async fn program(&mut self, plan: Plan) -> Result<(), Error> {
        let l = self.layout;
        let pipe = plan.request.pipe;
        let odm = |r| l.odm(pipe, r);
        let otg = |r| l.otg(pipe, r);
        self.update(odm(INPUT_CLOCK), 3, 3)?;
        self.wait(odm(INPUT_CLOCK), 4, 4, 1000).await?;
        self.update(otg(CLOCK), 3, 3)?;
        self.wait(otg(CLOCK), 0x100, 0x100, 1000).await?;
        self.update(l.vtg(pipe), 0x80000000, 0)?;
        // Native ODM bypass: no legacy segment-width programming. One OPP,
        // all unused segments disconnected, no ODM combining memory.
        self.update(odm(SOURCE), u32::MAX, 0xfff00000 | u32::from(pipe) << 16)?;
        // Native HW may select divide-by-two automatically only if every
        // horizontal boundary is even. Odd timings require manual no-divide.
        self.update(otg(H_TIMING), 0x103, plan.h_divider())?;
        self.update(odm(MEMORY), 0xffff, 0)?;
        // Fixed refresh; clear inherited DRR selectors before setting equal
        // total/min/max. No DMUB FAMS delegation is active under this owner.
        self.update(otg(V_CONTROL), 0xffff0013, 0)?;
        for (r, mask, value) in plan.registers() {
            self.update(otg(r), mask, value)?;
        }
        self.update(l.vtg(pipe), 0x7fff7fff, plan.vtg)?;
        // OPTC_DATA_FORMAT: RGB/4:4:4, or 4:2:0; DSC disabled.
        let format = if plan.request.ycbcr420 { 2 } else { 0 };
        self.update(odm(FORMAT), 0x33, format)?;
        // link_set_dsc_on_stream: the pipe's DSC (any earlier one on this
        // stopped pipe turned off first), then the OPTC's DSC mode.
        self.stop_dsc(pipe).await?;
        if let Some(cfg) = plan.request.dsc {
            self.start_dsc(&plan.request, &cfg).await?;
        } else {
            self.dsc_idle(pipe)?;
        }
        Ok(())
    }
    async fn prepare(&mut self, request: Request, clock: dccg::Applied) -> Result<Applied, Error> {
        let plan = request.plan()?;
        request.validate_clock(clock)?;
        self.preflight(request.pipe, false)?;
        self.status.state = State::Preparing(request.pipe);
        self.status.dpps[usize::from(request.pipe)] = None;
        self.status.mpcs[usize::from(request.pipe)] = None;
        self.status.requestor = None;
        self.status.deadlines = None;
        match self.program(plan).await {
            Ok(()) => {
                let applied = Applied { request, clock };
                self.status.pipes[usize::from(request.pipe)] = Some(applied);
                self.status.blanks[usize::from(request.pipe)] = None;
                self.status.retired &= !(1 << request.pipe);
                self.status.state = State::Prepared;
                Ok(applied)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn disable(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        self.update(l.odm(pipe, SOURCE), 0xffff0003, 0xffff0000)?;
        self.update(l.odm(pipe, MEMORY), 0xffff, 0)?;
        self.update(l.otg(pipe, CONTROL), 1, 0)?;
        self.update(l.vtg(pipe), 0x80000000, 0)?;
        self.wait(l.otg(pipe, CONTROL), 0x10001, 0, 150_000).await?;
        self.wait(l.otg(pipe, CLOCK), 0x10000, 0, 150_000).await
    }
    fn running_timing(&mut self) -> Result<u8, Error> {
        let mut running = 0;
        for p in 0..4 {
            if self.read(self.layout.otg(p, CONTROL))? & 0x10001 != 0 {
                running |= 1 << p;
            }
        }
        Ok(running)
    }
    async fn retire(&mut self, pipe: u8) -> Result<(), Error> {
        self.preflight(pipe, true)?;
        self.status.state = State::Retiring(pipe);
        self.status.dpps[usize::from(pipe)] = None;
        self.status.mpcs[usize::from(pipe)] = None;
        self.status.requestor = None;
        self.status.deadlines = None;
        // A stopped stream keeps its DSC for a restart; retiring the timing
        // turns it off first, as link_set_dsc_on_stream(false) precedes the
        // timing's disable.
        let result = async {
            self.stop_dsc(pipe).await?;
            self.disable(pipe).await?;
            // Linux resets the HPO output mux after link shutdown. Native
            // retirement also waits for the timing to stop before switching
            // it, so neither UHBR nor FRL leaves a stale HPO route behind.
            self.update(self.layout.otg(pipe, CONTROL), 0x300000, 0)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.pipes[usize::from(pipe)] = None;
                self.status.blanks[usize::from(pipe)] = None;
                self.status.running_blank = None;
                self.status.retired |= 1 << pipe;
                self.status.state = State::Retired;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
#[derive(Debug)]
pub struct Otg(Engine<Mmio>, fetch::Surfaces);
impl Otg {
    /// # Safety
    /// Retain permanent mappings and exclusive display/PM/reset ownership.
    /// Exclude firmware/FAMS and concurrent timing or clock writers. Retain
    /// this owner after partial failure/cancellation until independent reset.
    /// Construction only validates metadata and live authority; it writes nothing.
    pub unsafe fn new(gpu: &AmdGpu, authority: Cap<BusDeviceCap, Write>) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        Ok(Self(
            Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                status: Box::new(Status::new()),
                displays: Displays::new(),
            },
            fetch::Surfaces::new(),
        ))
    }
    pub fn status(&self) -> Status {
        *self.0.status
    }
    /// Make `display` (0-3) the one every following operation addresses.
    /// Each display keeps its own records; the other displays' pipes,
    /// links and live scanouts are left to them by every idle check. Refused
    /// while the selected display is mid-operation or failed.
    pub fn select_display(&mut self, display: u8) -> Result<(), Error> {
        self.0.select_display(display)
    }
    pub fn selected_display(&self) -> u8 {
        self.0.displays.selected
    }
    /// Any display's records, the selected one's current.
    pub fn display_status(&self, display: u8) -> Option<Status> {
        let d = &self.0.displays;
        if display == d.selected {
            Some(*self.0.status)
        } else {
            d.parked.get(usize::from(display)).copied()
        }
    }
    /// What the displays other than the selected one hold.
    pub fn siblings(&self) -> Siblings {
        self.0.displays.siblings
    }
    /// Prepare disabled fixed-refresh RGB timing against matching current
    /// clocks. No OPP/plane/PHY setup, bandwidth proof or scanout enable.
    pub async fn prepare(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        request: Request,
    ) -> Result<Applied, Error> {
        request.plan()?;
        if !self.0.status.state.reusable() {
            return Err(Error::Busy);
        }
        let (held, layout) = self.0.held();
        let clock = dccg
            .timing_clock_except(self.0.io.0, clocks, request.pipe, &|at| {
                held_by_sibling(held, layout, at)
            })
            .map_err(Error::PipeClocks)?;
        self.0.prepare(request, clock).await
    }
    /// Board inputs for native scanout admission: PMFW DPM ranges with their
    /// DC-mode caps, the UMC channel count, the DENTIST VCO, and the live
    /// DCHUB reference. UCLK is the floor `ClockManager::prepare` pins (the
    /// capped maximum); admission binds the plan to it. Reads one register.
    pub fn admission_soc(
        &mut self,
        levels: &clocks::Levels,
        dentist_vco_khz: u32,
        crystal_khz: u32,
    ) -> Result<dml::Soc, Error> {
        self.0.admission_soc(levels, dentist_vco_khz, crystal_khz)
    }
    /// Retire one inherited or prepared timing generator after every display
    /// stream/link clock is stopped. Leaves clocks on for later reprogramming.
    /// # Safety
    /// Stop CPU scanout writers and retain all associated surfaces, page
    /// tables, HUBP and OPP resources. Timing retirement does not prove memory
    /// fetch retirement and must never authorize freeing/reusing those resources.
    pub async unsafe fn retire(&mut self, pipe: u8) -> Result<(), Error> {
        self.0.retire(pipe).await
    }
    /// Read-only: pipes whose OTG master enable or its status is set, by bit.
    pub fn running_timing(&mut self) -> Result<u8, Error> {
        self.0.running_timing()
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_otg_tests.rs"]
mod tests;
