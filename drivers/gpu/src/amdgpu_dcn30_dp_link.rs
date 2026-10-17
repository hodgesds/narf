//! Navi22 DCN3.0 DisplayPort 8b/10b link policy, as Linux DC's link layer
//! runs it on a DIO link encoder:
//!
//! - capabilities: `retrieve_link_cap` (LTTPR probe under the extended AUX
//!   timeout, receiver caps with the post-OUI retries, the extended receiver
//!   caps and DPRX feature list), `dp_retrieve_lttpr_cap`,
//!   `dp_is_lttpr_present` and `dp_get_max_link_cap`;
//! - the repeater mode: `dp_decide_8b_10b_lttpr_mode` with the VBIOS
//!   DCE_INFO LTTPR bits as `dcn30_resource.c` reads them;
//! - training: `dp_perform_link_training`,
//!   `link_dp_training_8b_10b.c` (`decide_8b_10b_training_settings`, the CR
//!   and EQ sequences, hop-by-hop non-transparent repeater training),
//!   `dp_transition_to_video_idle` and `perform_post_lt_adj_req_sequence`;
//! - retries and fallback: `perform_link_training_with_retries` (no
//!   fallback on a commit, as for every non-DPIA link),
//!   `dp_verify_link_cap_with_retries` / `dp_verify_link_cap` and
//!   `decide_fallback_link_setting` (rate first on a CR failure, lanes first
//!   on an EQ failure);
//! - the stream's link: `decide_dp_link_settings` and
//!   `dp_validate_mode_timing` against the verified link;
//! - short pulses: `dp_read_hpd_rx_irq_data`, `dp_parse_link_loss_status`
//!   and the SST part of `dp_handle_hpd_rx_irq`.
//!
//! Deviations, all conservative: an AUX transport failure aborts the
//! operation (Linux mostly ignores DPCD write status and reads zeros) and the
//! source is disabled; FEC is never set ready (this owner has no DSC; Linux
//! trains FEC-capable sinks FEC-ready); the source-specific OUI is not
//! written; no eDP, DPIA, fixed-VS retimer or early-TPS2 paths; an automated
//! test request is acknowledged but not run.
use crate::{
    amdgpu_dcn30_dp::Aux,
    amdgpu_dp_training::Error as Lt,
    amdgpu_navi22_modeset::{DpLink, Error},
};

/// DPCD link-rate codes (`enum dc_link_rate`).
pub const RBR: u8 = 0x06;
pub const HBR: u8 = 0x0a;
pub const HBR2: u8 = 0x14;
pub const HBR3: u8 = 0x1e;
/// `dcn10_link_encoder_get_max_link_cap` for DCN3.0's DIO (`link_enc_feature`
/// is HBR3 capable): HBR3 on four lanes.
pub const ENCODER_MAX: DpLink = DpLink {
    rate: HBR3,
    lanes: 4,
};
/// `fail_safe_link_settings`.
pub const FAIL_SAFE: DpLink = DpLink {
    rate: RBR,
    lanes: 1,
};

const DPCD_REV: u32 = 0x000;
const TRAINING_AUX_RD_INTERVAL: u32 = 0x00e;
const LINK_BW_SET: u32 = 0x100;
const LANE_COUNT_SET: u32 = 0x101;
const TRAINING_PATTERN_SET: u32 = 0x102;
const DOWNSPREAD_CTRL: u32 = 0x107;
const MAIN_LINK_CHANNEL_CODING_SET: u32 = 0x108;
const SINK_COUNT: u32 = 0x200;
const DEVICE_SERVICE_IRQ_VECTOR: u32 = 0x201;
const LANE0_1_STATUS: u32 = 0x202;
const SET_POWER: u32 = 0x600;
const SINK_COUNT_ESI: u32 = 0x2002;
const DP13_DPCD_REV: u32 = 0x2200;
const DPRX_FEATURE_ENUMERATION_LIST: u32 = 0x2210;
const LTTPR_CAPS: u32 = 0xf0000;
const PHY_REPEATER_MODE: u32 = 0xf0003;
const PHY_REPEATER_EXTENDED_WAIT_TIMEOUT: u32 = 0xf0005;
const TOTAL_LTTPR_CNT: u32 = 0xf000a;
const TRAINING_PATTERN_SET_PHY_REPEATER1: u32 = 0xf0010;
const TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1: u32 = 0xf0020;
const LANE0_1_STATUS_PHY_REPEATER1: u32 = 0xf0030;
/// `DP_REPEATER_CONFIGURATION_AND_STATUS_SIZE`.
const REPEATER_SIZE: u32 = 0x50;
const MODE_TRANSPARENT: u8 = 0x55;
const MODE_NON_TRANSPARENT: u8 = 0xaa;
const POWER_D0: u8 = 1;
const POWER_D3: u8 = 2;
/// `LINK_SPREAD_05_DOWNSPREAD_30KHZ`: DCN3.0 links never set `dp_ss_off`.
const DOWNSPREAD_05: u8 = 0x10;
/// `LANE_COUNT_SET` bits.
const ENHANCED_FRAMING: u8 = 0x80;
const POST_LT_ADJ_REQ_GRANTED: u8 = 0x20;
/// `LANE_ALIGN_STATUS_UPDATED` bits.
const INTERLANE_ALIGN_DONE: u8 = 0x01;
const POST_LT_ADJ_REQ_IN_PROGRESS: u8 = 0x02;
/// `DEVICE_SERVICE_IRQ_VECTOR` bits.
const AUTOMATED_TEST: u8 = 0x02;

/// `LINK_AUX_DEFAULT_LTTPR_TIMEOUT_PERIOD` / `LINK_AUX_DEFAULT_TIMEOUT_PERIOD`.
pub const AUX_TIMEOUT_LTTPR_US: u32 = 3200;
pub const AUX_TIMEOUT_DEFAULT_US: u32 = 552;
/// `retrieve_link_cap`'s `read_dpcd_retry_cnt` and `post_oui_delay`.
const READ_RETRIES: u32 = 20;
const POST_OUI_DELAY_US: u64 = 30_000;
/// `wake_up_aux_channel`'s retries, 1 ms apart.
const WAKE_RETRIES: u32 = 10;
/// `LINK_TRAINING_MAX_RETRY_COUNT` / `LINK_TRAINING_MAX_CR_RETRY`.
const MAX_RETRY_COUNT: u32 = 5;
const MAX_CR_RETRY: u32 = 100;
/// `POST_LT_ADJ_REQ_LIMIT` / `POST_LT_ADJ_REQ_TIMEOUT` (1 ms polls).
const POST_LT_ADJ_REQ_LIMIT: u32 = 6;
const POST_LT_ADJ_REQ_TIMEOUT: u32 = 200;
/// `LINK_TRAINING_ATTEMPTS` (link_dpms.c) and `LINK_TRAINING_RETRY_DELAY`.
pub const LINK_TRAINING_ATTEMPTS: u32 = 4;
const RETRY_DELAY_MS: u64 = 50;
/// `LINK_TRAINING_MAX_VERIFY_RETRY` (link_detection.c).
pub const MAX_VERIFY_RETRY: u32 = 2;

/// The board's VBIOS LTTPR policy (`atom_display_controller_info_v4_*`
/// `display_caps`, read by `dcn30_resource_construct`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VbiosLttpr {
    /// `vbios_lttpr_aware`: DCE_INFO_CAPS_VBIOS_LTTPR_TRANSPARENT_ENABLE.
    pub aware: bool,
    /// `vbios_lttpr_enable`: DCE_INFO_CAPS_LTTPR_SUPPORT_ENABLE.
    pub enable: bool,
}
impl VbiosLttpr {
    /// A missing or unreadable table leaves both clear, as a failed
    /// `bios_parser_get_lttpr_caps` / `_interop` query does.
    pub fn from_vbios(vbios: &[u8]) -> Self {
        crate::amdgpu_dcn_inventory::lttpr_caps(vbios)
            .map(|(aware, enable)| Self { aware, enable })
            .unwrap_or_default()
    }
}

/// `enum lttpr_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LttprMode {
    NonLttpr,
    Transparent,
    NonTransparent,
}

/// The repeater chain's capability block (DPCD 0xF0000..0xF0009).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lttpr {
    pub revision: u8,
    pub max_rate: u8,
    /// `PHY_REPEATER_CNT` as read, echoed to `TOTAL_LTTPR_CNT`.
    pub raw_count: u8,
    pub count: u8,
    pub max_lanes: u8,
    pub ext_timeout: u8,
}
/// `dp_parse_lttpr_repeater_count`.
fn repeater_count(raw: u8) -> u8 {
    match raw {
        0x80 => 1,
        0x40 => 2,
        0x20 => 3,
        0x10 => 4,
        0x08 => 5,
        0x04 => 6,
        0x02 => 7,
        0x01 => 8,
        _ => 0,
    }
}
impl Lttpr {
    /// `dp_is_lttpr_present`: a valid count and one to four lanes; the
    /// revision is not checked (some repeaters report a bad one).
    fn parse(d: [u8; 10]) -> Option<Self> {
        let count = repeater_count(d[2]);
        (count > 0 && (1..=4).contains(&d[4])).then_some(Self {
            revision: d[0],
            max_rate: d[1],
            raw_count: d[2],
            count,
            max_lanes: d[4],
            ext_timeout: d[5],
        })
    }
}

/// `decide_8b_10b`'s LTTPR mode (`dp_decide_8b_10b_lttpr_mode`). Without
/// VBIOS awareness the default `amdgpu_dc_feature_mask` leaves
/// `allow_lttpr_non_transparent_mode.DP1_4A` clear: no LTTPR mode.
fn decide_lttpr_mode(lttpr: Option<Lttpr>, vbios: VbiosLttpr) -> LttprMode {
    match (lttpr, vbios.aware, vbios.enable) {
        (None, _, _) | (_, false, _) => LttprMode::NonLttpr,
        (Some(_), true, true) => LttprMode::NonTransparent,
        (Some(_), true, false) => LttprMode::Transparent,
    }
}

/// What `retrieve_link_cap` learned about one DP sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Receiver caps 0x0..0xF, from the extended field when the sink has it.
    pub dpcd: [u8; 16],
    pub ext_caps: bool,
    /// DPRX_FEATURE_ENUMERATION_LIST (read only with extended caps).
    pub dprx_feature: u8,
    pub lttpr: Option<Lttpr>,
    pub mode: LttprMode,
}
impl Caps {
    /// The receiver caps detection read, without the LTTPR probe: what
    /// `verify_link_capability_non_destructive` bounds a sink by.
    pub fn from_dpcd(dpcd: [u8; 16]) -> Self {
        Self {
            dpcd,
            ext_caps: false,
            dprx_feature: 0,
            lttpr: None,
            mode: LttprMode::NonLttpr,
        }
    }
    pub fn rev(&self) -> u8 {
        self.dpcd[0]
    }
    /// `get_link_rate_from_max_link_bw`: the highest standard rate at or
    /// below MAX_LINK_RATE.
    fn reported_rate(&self) -> Option<u8> {
        match self.dpcd[1] {
            r if r >= HBR3 => Some(HBR3),
            r if r >= HBR2 => Some(HBR2),
            r if r >= HBR => Some(HBR),
            r if r >= RBR => Some(RBR),
            _ => None,
        }
    }
    /// `dp_get_max_link_cap`: the encoder's, bounded by the sink's and (for a
    /// DPCD 1.4 repeater block) the chain's. None for caps no link fits.
    pub fn max_link(&self) -> Option<DpLink> {
        let mut rate = self.reported_rate()?.min(ENCODER_MAX.rate);
        let mut lanes = (self.dpcd[2] & 0x1f).min(ENCODER_MAX.lanes);
        if let Some(r) = self.lttpr.filter(|r| r.revision >= 0x14) {
            lanes = lanes.min(r.max_lanes);
            if matches!(r.max_rate, RBR | HBR | HBR2 | HBR3) {
                rate = rate.min(r.max_rate);
            }
        }
        matches!(lanes, 1 | 2 | 4).then_some(DpLink { rate, lanes })
    }
    /// `decide_eq_training_pattern`: the DCN3.0 DIO is TPS3 and TPS4 capable,
    /// so the sink's support alone chooses, whatever the link rate.
    pub fn eq_pattern(&self) -> Tps {
        if self.dpcd[3] & 0x80 != 0 {
            Tps::Tps4
        } else if self.dpcd[2] & 0x40 != 0 {
            Tps::Tps3
        } else {
            Tps::Tps2
        }
    }
    /// `MAX_LANE_COUNT.POST_LT_ADJ_REQ_SUPPORTED`.
    fn post_lt_adj_supported(&self) -> bool {
        self.dpcd[2] & 0x20 != 0
    }
}

/// Training patterns (`enum dc_dp_training_pattern`, 8b/10b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tps {
    Tps1,
    Tps2,
    Tps3,
    Tps4,
}
impl Tps {
    /// `dp_training_pattern_to_dpcd_training_pattern` with
    /// `dp_initialize_scrambling_data_symbols`: scrambling off for TPS1..3.
    fn set_byte(self) -> u8 {
        match self {
            Tps::Tps1 => 0x21,
            Tps::Tps2 => 0x22,
            Tps::Tps3 => 0x23,
            Tps::Tps4 => 0x07,
        }
    }
}

/// `enum link_training_result` as the 8b/10b SST path produces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    CrFailLane0,
    CrFailLane1,
    CrFailLane23,
    EqFailCr,
    EqFailCrPartial,
    EqFailEq,
    LqaFail,
    LinkLoss,
}
impl Outcome {
    fn error(self) -> Lt {
        match self {
            Outcome::CrFailLane0 | Outcome::CrFailLane1 | Outcome::CrFailLane23 => {
                Lt::ClockRecovery
            }
            _ => Lt::Equalization,
        }
    }
}

/// The source half of a DIO DP link, as the link layer drives it.
pub trait Source: Send {
    /// `enable_dp_output`: encoder lane count, then TRANSMITTER ENABLE.
    fn enable(&mut self, link: DpLink) -> Result<(), Error>;
    /// `dp_set_hw_training_pattern`.
    fn pattern(&mut self, tps: Tps) -> Result<(), Error>;
    /// `dp_set_hw_test_pattern(DP_TEST_PATTERN_VIDEO_MODE)`.
    fn video(&mut self) -> Result<(), Error>;
    /// `dp_set_hw_lane_settings` with one swing/pre-emphasis on every lane.
    fn drive(&mut self, link: DpLink, swing: u8, pre: u8) -> Result<(), Error>;
    /// `disable_link_output` (nothing for an idle DIG).
    fn disable(&mut self) -> Result<(), Error>;
}

async fn write_ignored<A: Aux + Send>(aux: &mut A, address: u32, data: &[u8]) {
    let _ = aux.write(address, data).await;
}

/// `wake_up_aux_channel`: up to ten SET_POWER reads 1 ms apart; a sink that
/// never answers gets D0 then D3 and the link is refused.
async fn wake_up_aux_channel<A: Aux + Send>(aux: &mut A) -> Result<(), Error> {
    for _ in 0..WAKE_RETRIES {
        let mut state = [0];
        match aux.read(SET_POWER, &mut state).await {
            Ok(()) => {
                if state[0] == POWER_D3 {
                    aux.delay_us(1000).await;
                }
                return Ok(());
            }
            Err(_) => aux.delay_us(1000).await,
        }
    }
    write_ignored(aux, SET_POWER, &[POWER_D0]).await;
    write_ignored(aux, SET_POWER, &[POWER_D3]).await;
    Err(Error::Aux)
}

/// `dp_retrieve_lttpr_cap`'s read; false when the read failed (its zeros
/// mean no chain).
async fn probe_lttpr<A: Aux + Send>(aux: &mut A, out: &mut Option<Lttpr>) -> bool {
    let mut data = [0u8; 10];
    if aux.read(LTTPR_CAPS, &mut data).await.is_err() {
        return false;
    }
    *out = Lttpr::parse(data);
    true
}

/// `retrieve_link_cap`'s link half for a sink detection found connected:
/// the LTTPR probe under the extended AUX timeout (VBIOS-aware boards only),
/// transparent mode and the echoed count for a chain, the receiver caps,
/// the default timeout again without a chain, then the extended caps and
/// the DPRX feature list.
pub async fn retrieve_caps<A: Aux + Send>(aux: &mut A, vbios: VbiosLttpr) -> Result<Caps, Error> {
    aux.set_timeout_us(AUX_TIMEOUT_LTTPR_US).await?;
    // dp_retrieve_lttpr_cap (DCN3.0 has extended_aux_timeout_support); a
    // failed read is zeros, i.e. no chain.
    let mut lttpr = None;
    let probed = vbios.aware && probe_lttpr(aux, &mut lttpr).await;
    if !probed {
        wake_up_aux_channel(aux).await?;
        if vbios.aware {
            probe_lttpr(aux, &mut lttpr).await;
        }
    }
    if let Some(r) = lttpr {
        write_ignored(aux, PHY_REPEATER_MODE, &[MODE_TRANSPARENT]).await;
        write_ignored(aux, TOTAL_LTTPR_CNT, &[r.raw_count]).await;
    }
    let mut dpcd = [0u8; 16];
    let mut read = false;
    for _ in 0..READ_RETRIES {
        aux.delay_us(POST_OUI_DELAY_US).await;
        if aux.read(DPCD_REV, &mut dpcd).await.is_ok() {
            read = true;
            break;
        }
    }
    if !read {
        return Err(Error::Aux);
    }
    if lttpr.is_none() {
        aux.set_timeout_us(AUX_TIMEOUT_DEFAULT_US).await?;
    }
    let ext_caps = dpcd[TRAINING_AUX_RD_INTERVAL as usize] & 0x80 != 0;
    let mut dprx_feature = 0;
    if ext_caps {
        let mut ext = [0u8; 16];
        for _ in 0..READ_RETRIES {
            if aux.read(DP13_DPCD_REV, &mut ext).await.is_ok() {
                dpcd = ext;
                break;
            }
        }
        for _ in 0..READ_RETRIES {
            let mut feature = [0u8];
            if aux
                .read(DPRX_FEATURE_ENUMERATION_LIST, &mut feature)
                .await
                .is_ok()
            {
                dprx_feature = feature[0];
                break;
            }
        }
    }
    // "It is impossible for Sink to report Max Lane Count = 0."
    if dpcd[2] & 0x1f == 0 {
        return Err(Error::NoSink);
    }
    Ok(Caps {
        dpcd,
        ext_caps,
        dprx_feature,
        lttpr,
        mode: decide_lttpr_mode(lttpr, vbios),
    })
}

/// `struct link_training_settings` for one 8b/10b attempt.
#[derive(Clone, Copy, Debug)]
struct Training {
    link: DpLink,
    mode: LttprMode,
    repeaters: u8,
    eq: Tps,
    cr_us: u64,
    eq_us: u64,
    /// Each repeater's EQ AUX_RD_INTERVAL (non-transparent only).
    intervals: [u8; 8],
    post_lt_adj_granted: bool,
    /// The common hardware (and, `always_match_dpcd_with_hw_lane_settings`,
    /// DPCD) voltage swing and pre-emphasis.
    swing: u8,
    pre: u8,
}
impl Training {
    /// `dp_hw_to_dpcd_lane_settings`: TRAINING_LANEx_SET.
    fn lane_set(&self) -> u8 {
        self.swing
            | self.pre << 3
            | if self.swing == 3 { 0x04 } else { 0 }
            | if self.pre == 3 { 0x20 } else { 0 }
    }
    fn repeater(&self, hop: u8) -> bool {
        self.mode == LttprMode::NonTransparent && hop != 0
    }
    fn offset(hop: u8) -> u32 {
        REPEATER_SIZE * u32::from(hop - 1)
    }
}

/// `dp_translate_training_aux_read_interval` (the EQ reading).
fn eq_interval_us(interval: u8) -> u64 {
    match interval & 0x7f {
        1 => 4000,
        2 => 8000,
        3 => 12000,
        4 => 16000,
        5 => 32000,
        6 => 64000,
        _ => 400,
    }
}

/// `decide_8b_10b_training_settings`: TPS1 for CR, the EQ pattern by sink
/// support, enhanced framing, common lane settings, the LTTPR mode, and the
/// CR/EQ read intervals from a fresh TRAINING_AUX_RD_INTERVAL (DPCD 1.2+;
/// an LTTPR's mandatory 0x4 before that).
async fn decide_training<A: Aux + Send>(aux: &mut A, caps: &Caps, link: DpLink) -> Training {
    let mut raw = 0u8;
    if caps.rev() >= 0x12 {
        let mut data = [0u8];
        if aux.read(TRAINING_AUX_RD_INTERVAL, &mut data).await.is_ok() {
            raw = data[0];
        }
    } else if caps.lttpr.is_some() {
        raw = 0x4;
    }
    let mode = caps.mode;
    let mut cr_us = 100;
    if raw != 0 {
        if mode != LttprMode::NonTransparent {
            cr_us = 400;
        }
        if raw & 0x7f != 0 {
            cr_us = u64::from(raw & 0x7f) * 4000;
        }
    }
    let eq = caps.eq_pattern();
    Training {
        link,
        mode,
        repeaters: caps.lttpr.map_or(0, |r| r.count),
        eq,
        cr_us,
        eq_us: eq_interval_us(raw),
        intervals: [0; 8],
        // dpcd_set_link_settings on a PHY endpoint below TPS4.
        post_lt_adj_granted: eq != Tps::Tps4 && caps.post_lt_adj_supported(),
        swing: 0,
        pre: 0,
    }
}

fn nibble(status: &[u8; 6], lane: u8) -> u8 {
    (status[usize::from(lane / 2)] >> (4 * (lane % 2))) & 0xf
}
fn adjust(status: &[u8; 6], lane: u8) -> (u8, u8) {
    let request = (status[4 + usize::from(lane / 2)] >> (4 * (lane % 2))) & 0xf;
    (request & 3, (request >> 2) & 3)
}
fn cr_done(status: &[u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| nibble(status, l) & 1 != 0)
}
fn eq_locked(status: &[u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| nibble(status, l) & 0x6 == 0x6) && status[2] & INTERLANE_ALIGN_DONE != 0
}
/// `dp_get_cr_failure`.
fn cr_failure(status: &[u8; 6], lanes: u8) -> Outcome {
    let done = |l| nibble(status, l) & 1 != 0;
    if !done(0) {
        Outcome::CrFailLane0
    } else if lanes >= 2 && !done(1) {
        Outcome::CrFailLane1
    } else if lanes >= 4 && (!done(2) || !done(3)) {
        Outcome::CrFailLane23
    } else {
        Outcome::Success
    }
}
/// `dp_decide_lane_settings` with `disallow_per_lane_settings`
/// (`maximize_lane_settings`): the highest request on any lane, pre-emphasis
/// capped by the swing (VS0..3 allow PE3..0).
fn decide_lane_settings(lt: &mut Training, status: &[u8; 6]) {
    let (mut swing, mut pre) = (0, 0);
    for lane in 0..lt.link.lanes {
        let (s, p) = adjust(status, lane);
        swing = swing.max(s);
        pre = pre.max(p);
    }
    lt.swing = swing;
    lt.pre = pre.min(3 - swing);
}

/// The hop's lane status, alignment and adjust requests in the sink's
/// layout (`dp_get_lane_status_and_lane_adjust`): DPCD 0x202..0x207, or a
/// repeater's 0xF0030.. with its adjust requests three bytes in.
async fn lane_status<A: Aux + Send>(aux: &mut A, lt: &Training, hop: u8) -> Result<[u8; 6], Error> {
    let mut buf = [0u8; 6];
    if lt.repeater(hop) {
        aux.read(
            LANE0_1_STATUS_PHY_REPEATER1 + Training::offset(hop),
            &mut buf,
        )
        .await?;
        Ok([buf[0], buf[1], buf[2], 0, buf[3], buf[4]])
    } else {
        aux.read(LANE0_1_STATUS, &mut buf).await?;
        Ok(buf)
    }
}

/// `dp_set_hw_lane_settings`: in non-transparent mode only the hop nearest
/// the source sees the source's drive change.
fn set_hw_lanes<S: Source>(src: &mut S, lt: &Training, hop: u8) -> Result<(), Error> {
    if lt.mode == LttprMode::NonTransparent && hop != lt.repeaters {
        return Ok(());
    }
    src.drive(lt.link, lt.swing, lt.pre)
}

/// `dpcd_set_lt_pattern_and_lane_settings` (the 1 + lanes burst) or
/// `dpcd_set_lane_settings`.
async fn dpcd_lanes<A: Aux + Send>(
    aux: &mut A,
    lt: &Training,
    hop: u8,
    pattern: Option<Tps>,
) -> Result<(), Error> {
    let base = if lt.repeater(hop) {
        TRAINING_PATTERN_SET_PHY_REPEATER1 + Training::offset(hop)
    } else {
        TRAINING_PATTERN_SET
    };
    let lanes = usize::from(lt.link.lanes);
    let mut buf = [lt.lane_set(); 5];
    match pattern {
        Some(p) => {
            buf[0] = p.set_byte();
            aux.write(base, &buf[..1 + lanes]).await
        }
        None => aux.write(base + 1, &buf[..lanes]).await,
    }
}

/// `perform_8b_10b_clock_recovery_sequence`.
async fn clock_recovery<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    lt: &mut Training,
    hop: u8,
) -> Result<Outcome, Error> {
    src.pattern(Tps::Tps1)?;
    let lanes = lt.link.lanes;
    let (mut retries_cr, mut retry_count) = (0, 0);
    let mut status = [0u8; 6];
    while retries_cr < MAX_RETRY_COUNT && retry_count < MAX_CR_RETRY {
        set_hw_lanes(src, lt, hop)?;
        dpcd_lanes(aux, lt, hop, (retry_count == 0).then_some(Tps::Tps1)).await?;
        aux.delay_us(lt.cr_us).await;
        status = lane_status(aux, lt, hop).await?;
        if cr_done(&status, lanes) {
            return Ok(Outcome::Success);
        }
        // dp_is_max_vs_reached.
        if lt.swing == 3 {
            break;
        }
        // Same swing requested on lane 0 again.
        if lt.swing == adjust(&status, 0).0 {
            retries_cr += 1;
        } else {
            retries_cr = 0;
        }
        decide_lane_settings(lt, &status);
        retry_count += 1;
    }
    Ok(cr_failure(&status, lanes))
}

/// `perform_8b_10b_channel_equalization_sequence`: repeaters always
/// equalize on TPS4 at their own read interval.
async fn channel_equalization<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    lt: &mut Training,
    hop: u8,
) -> Result<Outcome, Error> {
    let (pattern, wait) = if lt.repeater(hop) {
        (
            Tps::Tps4,
            eq_interval_us(lt.intervals[usize::from(hop - 1)]),
        )
    } else {
        (lt.eq, lt.eq_us)
    };
    src.pattern(pattern)?;
    let lanes = lt.link.lanes;
    for retries in 0..=MAX_RETRY_COUNT {
        set_hw_lanes(src, lt, hop)?;
        dpcd_lanes(aux, lt, hop, (retries == 0).then_some(pattern)).await?;
        aux.delay_us(wait).await;
        let status = lane_status(aux, lt, hop).await?;
        if !cr_done(&status, lanes) {
            return Ok(if nibble(&status, 0) & 1 != 0 {
                Outcome::EqFailCrPartial
            } else {
                Outcome::EqFailCr
            });
        }
        if eq_locked(&status, lanes) {
            return Ok(Outcome::Success);
        }
        decide_lane_settings(lt, &status);
    }
    Ok(Outcome::EqFailEq)
}

/// `dpcd_configure_lttpr_mode`: transparent, or transparent then
/// non-transparent with every repeater's EQ interval read.
async fn configure_lttpr<A: Aux + Send>(aux: &mut A, lt: &mut Training) {
    match lt.mode {
        LttprMode::NonLttpr => {}
        LttprMode::Transparent => write_ignored(aux, PHY_REPEATER_MODE, &[MODE_TRANSPARENT]).await,
        LttprMode::NonTransparent => {
            write_ignored(aux, PHY_REPEATER_MODE, &[MODE_TRANSPARENT]).await;
            write_ignored(aux, PHY_REPEATER_MODE, &[MODE_NON_TRANSPARENT]).await;
            for id in (1..=lt.repeaters.min(8)).rev() {
                let mut interval = [0u8];
                let at = TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1 + Training::offset(id);
                if aux.read(at, &mut interval).await.is_ok() {
                    lt.intervals[usize::from(id - 1)] = interval[0] & 0x7f;
                }
            }
        }
    }
}

/// `dp_perform_8b_10b_link_training`: the link settings, every repeater
/// (farthest first, told training is done even on failure, lane settings
/// back to level 0 after each), then the sink.
async fn train_8b_10b<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    lt: &mut Training,
) -> Result<Outcome, Error> {
    // dpcd_set_link_settings.
    aux.write(DOWNSPREAD_CTRL, &[DOWNSPREAD_05]).await?;
    let grant = if lt.post_lt_adj_granted {
        POST_LT_ADJ_REQ_GRANTED
    } else {
        0
    };
    aux.write(LANE_COUNT_SET, &[lt.link.lanes | ENHANCED_FRAMING | grant])
        .await?;
    aux.write(LINK_BW_SET, &[lt.link.rate]).await?;
    let mut status = Outcome::Success;
    if lt.mode == LttprMode::NonTransparent {
        for id in (1..=lt.repeaters).rev() {
            status = clock_recovery(aux, src, lt, id).await?;
            if status == Outcome::Success {
                status = channel_equalization(aux, src, lt, id).await?;
            }
            // repeater_training_done.
            aux.write(
                TRAINING_PATTERN_SET_PHY_REPEATER1 + Training::offset(id),
                &[0],
            )
            .await?;
            if status != Outcome::Success {
                break;
            }
            lt.swing = 0;
            lt.pre = 0;
        }
    }
    if status == Outcome::Success {
        status = clock_recovery(aux, src, lt, 0).await?;
        if status == Outcome::Success {
            status = channel_equalization(aux, src, lt, 0).await?;
        }
    }
    Ok(status)
}

/// `dp_check_link_loss_status`: every trained lane keeps CR, EQ and symbol
/// lock, interlane aligned (DPCD 0x200..0x205).
async fn check_link_loss<A: Aux + Send>(aux: &mut A, lanes: u8) -> Result<Outcome, Error> {
    let mut buf = [0u8; 6];
    aux.read(SINK_COUNT, &mut buf).await?;
    let status = [buf[2], buf[3], buf[4], 0, 0, 0];
    Ok(if cr_done(&status, lanes) && eq_locked(&status, lanes) {
        Outcome::Success
    } else {
        Outcome::LinkLoss
    })
}

/// `perform_post_lt_adj_req_sequence`: follow the sink's adjust requests
/// while it reports POST_LT_ADJ_REQ_IN_PROGRESS. False if the link lost
/// lock; a timeout or the request limit counts as done, as in Linux.
async fn post_lt_adj_req<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    lt: &mut Training,
) -> Result<bool, Error> {
    let lanes = lt.link.lanes;
    for _ in 0..POST_LT_ADJ_REQ_LIMIT {
        let mut changed = false;
        for _ in 0..POST_LT_ADJ_REQ_TIMEOUT {
            let status = lane_status(aux, lt, 0).await?;
            if status[2] & POST_LT_ADJ_REQ_IN_PROGRESS == 0 {
                return Ok(true);
            }
            if !cr_done(&status, lanes) || !eq_locked(&status, lanes) {
                return Ok(false);
            }
            changed = (0..lanes).any(|l| adjust(&status, l) != (lt.swing, lt.pre));
            if changed {
                decide_lane_settings(lt, &status);
                // dp_set_drive_settings: the PHY, then the sink.
                set_hw_lanes(src, lt, 0)?;
                dpcd_lanes(aux, lt, 0, None).await?;
                break;
            }
            aux.delay_us(1000).await;
        }
        if !changed {
            return Ok(true);
        }
    }
    Ok(true)
}

/// `dp_transition_to_video_idle`: idle pattern, then either 5 ms and a
/// link-loss check (no POST_LT_ADJ_REQ, or TPS4), or the post-training
/// adjust sequence and LANE_COUNT_SET without the grant.
async fn transition_to_video_idle<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    caps: &Caps,
    lt: &mut Training,
    mut status: Outcome,
) -> Result<Outcome, Error> {
    src.video()?;
    if !caps.post_lt_adj_supported() || lt.eq == Tps::Tps4 {
        if status == Outcome::Success {
            aux.delay_us(5000).await;
            status = check_link_loss(aux, lt.link.lanes).await?;
        }
        return Ok(status);
    }
    if status == Outcome::Success && !post_lt_adj_req(aux, src, lt).await? {
        status = Outcome::LqaFail;
    }
    aux.write(LANE_COUNT_SET, &[lt.link.lanes | ENHANCED_FRAMING])
        .await?;
    Ok(status)
}

/// `dp_perform_link_training` on an enabled PHY.
async fn perform<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    caps: &Caps,
    link: DpLink,
    skip_video_pattern: bool,
) -> Result<Outcome, Error> {
    let mut lt = decide_training(aux, caps, link).await;
    // dpcd_exit_training_mode: reset previous training states.
    aux.write(TRAINING_PATTERN_SET, &[0]).await?;
    configure_lttpr(aux, &mut lt).await;
    // dpcd_configure_channel_coding: ANSI 8b/10b (absent before DPCD 1.2).
    write_ignored(aux, MAIN_LINK_CHANNEL_CODING_SET, &[1]).await;
    let mut status = train_8b_10b(aux, src, &mut lt).await?;
    aux.write(TRAINING_PATTERN_SET, &[0]).await?;
    if status == Outcome::Success || !skip_video_pattern {
        status = transition_to_video_idle(aux, src, caps, &mut lt, status).await?;
    }
    Ok(status)
}

/// `dp_enable_link_phy`: the source, then the sink to D0.
pub async fn enable_link_phy<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    link: DpLink,
) -> Result<(), Error> {
    if !matches!(link.lanes, 1 | 2 | 4) || !matches!(link.rate, RBR | HBR | HBR2 | HBR3) {
        return Err(Error::Invalid);
    }
    src.enable(link)?;
    write_ignored(aux, SET_POWER, &[POWER_D0]).await;
    Ok(())
}

/// `dp_disable_link_phy`: the sink to D3 only while one is connected
/// (`link->type != dc_connection_none`), then the source.
pub async fn disable_link_phy<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
) -> Result<(), Error> {
    if aux.connected().await {
        write_ignored(aux, SET_POWER, &[POWER_D3]).await;
    }
    src.disable()
}

/// `perform_link_training_with_retries` for a commit (`enable_link_dp`):
/// `LINK_TRAINING_ATTEMPTS` at `link` itself, no fallback, the delay
/// growing by 50 ms each time. The last failure keeps the PHY on, as Linux
/// does; the caller's link teardown disables it. A transport failure (or a
/// sink that left) disables the source and stops at once.
pub async fn train_with_retries<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    caps: &Caps,
    link: DpLink,
) -> Result<DpLink, Error> {
    let skip_video_pattern = link.rate != RBR;
    let mut delay_ms = RETRY_DELAY_MS;
    let mut last = Outcome::CrFailLane0;
    for attempt in 0..LINK_TRAINING_ATTEMPTS {
        enable_link_phy(aux, src, link).await?;
        let outcome = match perform(aux, src, caps, link, skip_video_pattern).await {
            Ok(outcome) => outcome,
            Err(error) => {
                let _ = disable_link_phy(aux, src).await;
                return Err(error);
            }
        };
        if outcome == Outcome::Success {
            return Ok(link);
        }
        last = outcome;
        if attempt == LINK_TRAINING_ATTEMPTS - 1 {
            break;
        }
        disable_link_phy(aux, src).await?;
        delay_ms += RETRY_DELAY_MS;
        aux.delay_us(delay_ms * 1000).await;
    }
    Err(Error::Training(last.error()))
}

fn reduce_rate(rate: u8) -> u8 {
    match rate {
        HBR3 => HBR2,
        HBR2 => HBR,
        _ => RBR,
    }
}
fn reduce_lanes(lanes: u8) -> u8 {
    match lanes {
        4 => 2,
        _ => 1,
    }
}

/// `decide_fallback_link_setting` for 8b/10b: after a CR failure the rate
/// drops first (then, at RBR, the lanes that failed, from the maximum rate
/// again); after an EQ failure the lanes drop first (then the rate, which
/// also lowers `max` so a later CR fallback cannot climb back). False at the
/// minimum or for an outcome with no fallback.
pub fn decide_fallback(max: &mut DpLink, cur: &mut DpLink, outcome: Outcome) -> bool {
    match outcome {
        Outcome::CrFailLane0 | Outcome::CrFailLane1 | Outcome::CrFailLane23 | Outcome::LqaFail => {
            if cur.rate > RBR {
                cur.rate = reduce_rate(cur.rate);
            } else if cur.lanes > 1 {
                cur.rate = max.rate;
                cur.lanes = match outcome {
                    Outcome::CrFailLane0 => return false,
                    Outcome::CrFailLane1 => 1,
                    Outcome::CrFailLane23 => 2,
                    _ => reduce_lanes(cur.lanes),
                };
            } else {
                return false;
            }
        }
        Outcome::EqFailEq | Outcome::EqFailCrPartial => {
            if cur.lanes > 1 {
                cur.lanes = reduce_lanes(cur.lanes);
            } else if cur.rate > RBR {
                cur.rate = reduce_rate(cur.rate);
                max.rate = cur.rate;
                cur.lanes = max.lanes;
            } else {
                return false;
            }
        }
        Outcome::EqFailCr => {
            if cur.rate > RBR {
                cur.rate = reduce_rate(cur.rate);
                max.rate = cur.rate;
                cur.lanes = max.lanes;
            } else {
                return false;
            }
        }
        Outcome::Success | Outcome::LinkLoss => return false,
    }
    true
}

/// What a capability verification found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// `verified_link_cap`: the highest link that trained, or the fail-safe.
    pub link: DpLink,
    /// The first verification trained cleanly (`fail_count == 0`).
    pub clean: bool,
    pub failures: u32,
}

/// `dp_verify_link_cap`: train down the fallback ladder from `known` until
/// one setting trains; every attempt ends with the link disabled.
async fn verify_once<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    caps: &Caps,
    known: DpLink,
    failures: &mut u32,
) -> Result<Option<DpLink>, Error> {
    // Grant the extended timeout a repeater asks for.
    if let Some(r) = caps.lttpr.filter(|r| r.ext_timeout > 0) {
        write_ignored(
            aux,
            PHY_REPEATER_EXTENDED_WAIT_TIMEOUT,
            &[r.ext_timeout & 0x80],
        )
        .await;
    }
    let (mut max, mut cur) = (known, known);
    loop {
        enable_link_phy(aux, src, cur).await?;
        let status = match perform(aux, src, caps, cur, cur.rate != RBR).await {
            Ok(status) => status,
            Err(error) => {
                let _ = disable_link_phy(aux, src).await;
                return Err(error);
            }
        };
        let mut success = false;
        match status {
            Outcome::Success => {
                success = true;
                aux.delay_us(1000).await;
                let lost = match read_hpd_rx_irq_data(aux, caps.rev()).await {
                    Ok(irq) => parse_link_loss(aux, &irq, cur.lanes).await,
                    Err(_) => false,
                };
                if lost {
                    *failures += 1;
                }
            }
            Outcome::LinkLoss => {
                success = true;
                *failures += 1;
            }
            _ => *failures += 1,
        }
        disable_link_phy(aux, src).await?;
        if success {
            return Ok(Some(cur));
        }
        if !decide_fallback(&mut max, &mut cur, status) {
            return Ok(None);
        }
    }
}

/// `dp_verify_link_cap_with_retries(LINK_TRAINING_MAX_VERIFY_RETRY)`, the
/// destructive verification `verify_link_capability` runs on a newly
/// detected SST sink: the link must be idle (no stream). A sink that left
/// gets the fail-safe link; a transport failure is an error.
pub async fn verify_link_cap<A: Aux + Send, S: Source>(
    aux: &mut A,
    src: &mut S,
    caps: &Caps,
) -> Result<Verified, Error> {
    let known = caps.max_link().ok_or(Error::NoSink)?;
    let mut last = FAIL_SAFE;
    let mut failures = 0;
    for _ in 0..MAX_VERIFY_RETRY {
        if !aux.connected().await {
            return Ok(Verified {
                link: FAIL_SAFE,
                clean: false,
                failures,
            });
        }
        if let Some(link) = verify_once(aux, src, caps, known, &mut failures).await? {
            last = link;
            if failures == 0 {
                return Ok(Verified {
                    link,
                    clean: true,
                    failures,
                });
            }
        }
        aux.delay_us(10_000).await;
    }
    Ok(Verified {
        link: last,
        clean: false,
        failures,
    })
}

/// `dp_link_bandwidth_kbps` for 8b/10b without FEC: 8 data bits per
/// 10-bit symbol on every lane.
pub fn bandwidth_kbps(link: DpLink) -> u64 {
    u64::from(link.rate) * 27_000 * 8 * u64::from(link.lanes)
}
fn required_kbps(pixel_khz: u32, bits_per_pixel: u8) -> u64 {
    u64::from(pixel_khz) * u64::from(bits_per_pixel)
}

/// `dp_validate_mode_timing` against the verified link: 640x480 at 25.175
/// MHz is the DP fail-safe mode and always passes.
pub fn mode_fits(verified: DpLink, h_active: u32, v_active: u32, pixel_khz: u32, bpp: u8) -> bool {
    (pixel_khz == 25_175 && h_active == 640 && v_active == 480)
        || required_kbps(pixel_khz, bpp) <= bandwidth_kbps(verified)
}

/// `decide_dp_link_settings`: the least link (lanes first, then rate, from
/// RBR x1) within the verified link that carries the stream.
pub fn decide_link_settings(verified: DpLink, pixel_khz: u32, bpp: u8) -> Option<DpLink> {
    let need = required_kbps(pixel_khz, bpp);
    if need > bandwidth_kbps(verified) {
        return None;
    }
    let mut cur = FAIL_SAFE;
    while cur.rate <= verified.rate {
        if need <= bandwidth_kbps(cur) {
            return Some(cur);
        }
        if cur.lanes < verified.lanes {
            cur.lanes = if cur.lanes == 1 { 2 } else { 4 };
        } else {
            cur.rate = match cur.rate {
                RBR => HBR,
                HBR => HBR2,
                HBR2 => HBR3,
                _ => return None,
            };
            cur.lanes = 1;
        }
    }
    None
}

/// `union hpd_irq_data` (SST fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrqData {
    pub sink_count: u8,
    pub device_service_irq: u8,
    pub lane01: u8,
    pub lane23: u8,
    pub align: u8,
    pub sink_status: u8,
}
/// `dp_read_hpd_rx_irq_data`: DPCD 0x200..0x205 before DPCD 1.4, the ESI
/// block 0x2002..0x200F from it on.
pub async fn read_hpd_rx_irq_data<A: Aux + Send>(aux: &mut A, rev: u8) -> Result<IrqData, Error> {
    if rev < 0x14 {
        let mut b = [0u8; 6];
        aux.read(SINK_COUNT, &mut b).await?;
        Ok(IrqData {
            sink_count: b[0],
            device_service_irq: b[1],
            lane01: b[2],
            lane23: b[3],
            align: b[4],
            sink_status: b[5],
        })
    } else {
        let mut b = [0u8; 14];
        aux.read(SINK_COUNT_ESI, &mut b).await?;
        Ok(IrqData {
            sink_count: b[0],
            device_service_irq: b[1],
            lane01: b[10],
            lane23: b[11],
            align: b[12],
            sink_status: b[13],
        })
    }
}

/// `dp_parse_link_loss_status`: a trained lane lost CR, EQ or symbol lock
/// (or interlane alignment dropped), and the sink is in D0 (a failed
/// SET_POWER read still counts as lost).
pub async fn parse_link_loss<A: Aux + Send>(aux: &mut A, irq: &IrqData, lanes: u8) -> bool {
    if lanes == 0 {
        return false;
    }
    let status = [irq.lane01, irq.lane23, irq.align, 0, 0, 0];
    let locked = (0..lanes).all(|l| nibble(&status, l) & 0x7 == 0x7);
    if locked && irq.align & INTERLANE_ALIGN_DONE != 0 {
        return false;
    }
    let mut power = [0u8];
    match aux.read(SET_POWER, &mut power).await {
        Ok(()) => power[0] == POWER_D0,
        Err(_) => true,
    }
}

/// What an HPD-RX short pulse (or a periodic link check) found on an SST link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxEvent {
    /// Nothing that needs the link layer.
    None,
    /// An automated-test request, acknowledged and not run.
    AutomatedTest,
    /// The link lost lock while the sink is in D0: `dp_handle_link_loss`.
    LinkLoss(IrqData),
}

/// The SST part of `dp_handle_hpd_rx_irq` for a trained link of `lanes`
/// lanes (0: no link, which `dp_should_allow_hpd_rx_irq` refuses for a
/// non-branch sink). MST sideband bits are left alone.
pub async fn handle_hpd_rx_irq<A: Aux + Send>(
    aux: &mut A,
    rev: u8,
    lanes: u8,
) -> Result<RxEvent, Error> {
    let irq = read_hpd_rx_irq_data(aux, rev).await?;
    if irq.device_service_irq & AUTOMATED_TEST != 0 {
        write_ignored(aux, DEVICE_SERVICE_IRQ_VECTOR, &[AUTOMATED_TEST]).await;
        return Ok(RxEvent::AutomatedTest);
    }
    if lanes == 0 {
        return Ok(RxEvent::None);
    }
    Ok(if parse_link_loss(aux, &irq, lanes).await {
        RxEvent::LinkLoss(irq)
    } else {
        RxEvent::None
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_dp_link_tests.rs"]
mod tests;
