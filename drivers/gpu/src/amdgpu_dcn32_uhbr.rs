//! DCN 3.2 UHBR (128b/132b) link training on the HPO — Navi31/32/33.
//!
//! The link comes up in two halves, as Linux's DCN 3.1/3.2 HPO code does
//! it: the firmware half (`dcn31_hpo_dp_link_enc_enable_dp_output` —
//! transmitter-control ENABLE, which brings up the PHY, routes it to the
//! HPO link encoder and starts the encoder's DPHY and SYMCLK32_LE) and
//! the DC half (`dcn31_hpo_dp_link_enc_enable` — the DPHY register
//! sequence: link-enc clock enable, DPHY reset only when going from
//! disabled to enabled, then DPHY_ENABLE, PRECODER_ENABLE and the lane
//! count). Training itself is Linux's
//! `dp_perform_128b_132b_link_training`, mirrored from the in-tree DCN
//! 4.0.1 owner (`amdgpu_dcn401_uhbr_link.rs`): caps, sink, EQ, CDS,
//! finish. Streams, payload and scanout are separate owners.
//!
//! Differences from the 4.0.1 owner, all grounded in `dcn_3_2_0_offset.h`
//! / `_sh_mask.h`:
//!
//! - The 4.0.1 LINK_CLOCK register (0x369f) does not exist on 3.2 — the
//!   0x3699..0x36bf range is unmapped — so the enable verify watches the
//!   link-enc clock control (0x3697, CLOCK_EN) and STATUS instead, and
//!   there is no PHY lane/mux observation: the firmware owns the PHY.
//! - DC writes the DPHY enable sequence itself (the 4.0.1 owner only
//!   observes it); the writes are idempotent with what the firmware
//!   already set, and the reset is skipped when STATUS already shows the
//!   link enabled.
//! - The DPCD traffic goes over the native AUX engine
//!   ([`Aux`]), as the 3.2 8b/10b training does, not DMUB AUX. The DMUB
//!   half is the shared [`Dmub::command`] with the transmitter-control
//!   request encoding (the DMCUB firmware ABI, identical to the Navi48
//!   engine's bytes, which themselves cite the DCN 3.1 Linux function).
//! - MODE values TPS1 = 0 / TPS2 = 1 / ACTIVE = 2 are adopted from the
//!   in-tree 4.0.1 owner; the `DP2_LINK_*` enum definition is absent from
//!   the reference tree, so this is flagged, not independently verified.
//! - The standalone test-pattern path (`set_link_test_pattern`,
//!   TP_CONFIG / TP_SQ_PULSE / TP_CUSTOM) is out of scope: training
//!   only.
//!
//! The owner is stateless: a training refusal (EQ, CDS or link loss)
//! exits training and returns the error, as Linux does before disabling
//! the PHY; the caller tears the link down with [`UhbrLink::stop`].

use crate::amdgpu_dcn30_dp::Aux;
use crate::amdgpu_dcn30_takeover::Regs;
use crate::amdgpu_dcn_inventory::{Connector, Path};
use crate::amdgpu_dmub::{self as dmub, Dmub};
use crate::amdgpu_navi22_modeset::Error as ModesetError;

/// HPO DP link encoder stride: SYM321 (0x3794) − SYM320 (0x36c0).
const LINK_STRIDE: u64 = 0xD4;
/// Link-enc clock control of encoder 0, at DCN base index 2;
/// `DP_LINK_ENC_CLOCK_EN` is bit 0.
const CLOCK_CONTROL: u64 = 0x3697;
/// DPHY SYM32 registers of encoder 0, at DCN base index 2.
const CONTROL: u64 = 0x36c0;
const STATUS: u64 = 0x36c1;
/// `DP_DPHY_SYM32_CONTROL` fields: DPHY_ENABLE 0, DPHY_RESET 1,
/// PRECODER_ENABLE 2, MODE 4 (mask 0x30), NUM_LANES 8 (mask 0x300).
const CONTROL_ENABLE: u32 = 1;
const CONTROL_RESET: u32 = 1 << 1;
const CONTROL_PRECODER: u32 = 1 << 2;
const CONTROL_MODE_MASK: u32 = 0x30;
const CONTROL_LANES_MASK: u32 = 0x300;
/// `DP_DPHY_SYM32_STATUS__STATUS` (link enabled) is bit 0.
const STATUS_ENABLED: u32 = 1;
/// DP_DPHY_SYM32_CONTROL MODE: 128b/132b TPS1, TPS2 and the active link
/// (adopted from the in-tree DCN 4.0.1 owner; see the module docs).
const MODE_TPS1: u8 = 0;
const MODE_TPS2: u8 = 1;
const MODE_ACTIVE: u8 = 2;
/// DPCD addresses.
const CHANNEL_CODING_SET: u32 = 0x108;
const UHBR_AUX_RD_INTERVAL: u32 = 0x2216;
const UHBR_RATES: u32 = 0x2215;
const LANE_ALIGN: u32 = 0x205;
/// `decide_128b_132b_training_settings`.
const EQ_LOOP_LIMIT: u8 = 20;
const EQ_WAIT_LIMIT_US: u64 = 400_000;
const PATTERN_TIME_US: u64 = 2_500;
const CDS_WAIT_PER_HOP_US: u64 = 20_000;
/// AUX reply timeouts, in us (Linux LINK_AUX_DEFAULT_LTTPR_TIMEOUT_PERIOD
/// / LINK_AUX_DEFAULT_TIMEOUT_PERIOD).
const AUX_TIMEOUT_LTTPR_US: u32 = 3200;
const AUX_TIMEOUT_DEFAULT_US: u32 = 552;
/// LTTPR capability block and mode registers.
const LTTPR_CAPS: u32 = 0xf0000;
const LTTPR_MODE: u32 = 0xf0003;
const LTTPR_TOTAL_COUNT: u32 = 0xf000a;
const LTTPR_MODE_TRANSPARENT: u8 = 0x55;
const LTTPR_MODE_NON_TRANSPARENT: u8 = 0xaa;
/// Lane-status bits in the 0x202 block.
const EQ_INTERLANE_ALIGN_DONE: u8 = 4;
const CDS_INTERLANE_ALIGN_DONE: u8 = 8;
const LT_FAILED: u8 = 0x10;
/// `DMUB_CMD__DIG_TRANSMITTER_CONTROL` (128, 1, 0, 16): the 64-byte
/// mailbox header for transmitter control v1_7.
const TRANSMITTER_CONTROL: [u8; 4] = [128, 1, 0, 16];

/// A DP 128b/132b (UHBR) per-lane rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UhbrRate {
    Uhbr10,
    Uhbr13_5,
    Uhbr20,
}
impl UhbrRate {
    /// Ascending, as Linux's increase_link_rate walks them.
    pub const ALL: [Self; 3] = [Self::Uhbr10, Self::Uhbr13_5, Self::Uhbr20];
    /// DC's link_rate: units of 10 Mbps per lane (LINK_RATE_UHBR10 = 1000).
    pub fn link_rate(self) -> u32 {
        match self {
            Self::Uhbr10 => 1000,
            Self::Uhbr13_5 => 1350,
            Self::Uhbr20 => 2000,
        }
    }
    /// LINK_BW_SET (0x100) for 128b/132b: get_dpcd_link_rate.
    pub fn dpcd_code(self) -> u8 {
        match self {
            Self::Uhbr10 => 0x01,
            Self::Uhbr20 => 0x02,
            Self::Uhbr13_5 => 0x04,
        }
    }
    /// The rate's bit in DP_128B132B_SUPPORTED_LINK_RATES (0x2215) and an
    /// LTTPR's 0xF0007, which share this layout.
    pub fn dpcd_bit(self) -> u8 {
        self.dpcd_code()
    }
}

/// A 128b/132b link: lane count and per-lane rate, and whether it runs
/// MST (its streams' payloads then belong to the MST manager).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrSettings {
    pub lanes: u8,
    pub rate: UhbrRate,
    pub mst: bool,
}

/// A trained 128b/132b link: the HPO link encoder the firmware routed
/// this PHY to, the observed physical lanes, the TX FFE preset in use,
/// and the training loop counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrLinkTrained {
    pub path: Path,
    pub settings: UhbrSettings,
    /// The HPO link encoder the firmware routed this PHY to.
    pub link: u8,
    /// Observed physical lanes, independent of board lane mapping.
    pub physical_lanes: u8,
    /// The TX FFE preset in use: the highest any active lane requested.
    pub preset: u8,
    pub eq_loops: u8,
    /// Repeaters (non-transparent) between source and sink; zero for none.
    pub repeaters: u8,
    /// The encoder's training mode as last set (MODE_*).
    pub mode: u8,
}

/// What training itself can refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrainingError {
    InvalidCaps,
    SinkReadback(u32),
    Equalization,
    ClockDataSwitch,
    LinkLost,
}

/// The UHBR owner's errors. Register and AUX failures arrive as
/// [`ModesetError`] (the takeover `Regs` and native `Aux` both report
/// it); DMUB failures arrive as [`dmub::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    /// A register readback did not match, at this byte address.
    Readback(u64),
    /// A wait expired, at this byte address.
    Timeout(u64),
    Training(TrainingError),
    Firmware(dmub::Error),
    Modeset(ModesetError),
}
impl From<ModesetError> for Error {
    fn from(e: ModesetError) -> Self {
        Error::Modeset(e)
    }
}
impl From<dmub::Error> for Error {
    fn from(e: dmub::Error) -> Self {
        Error::Firmware(e)
    }
}

/// The DMUB half of UHBR: transmitter-control ENABLE, TX FFE presets and
/// DISABLE, plus the waits between training steps.
pub trait UhbrTransport {
    fn enable_uhbr(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> impl core::future::Future<Output = Result<(), dmub::Error>> + Send;
    fn uhbr_ffe(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        preset: u8,
    ) -> impl core::future::Future<Output = Result<(), dmub::Error>> + Send;
    /// DISABLE as SST (the MST link stop goes through the MST owner).
    fn disable_uhbr(
        &mut self,
        path: Path,
    ) -> impl core::future::Future<Output = Result<(), dmub::Error>> + Send;
    fn delay(&mut self, us: u64) -> impl core::future::Future<Output = ()> + Send;
}

impl UhbrTransport for Dmub {
    async fn enable_uhbr(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<(), dmub::Error> {
        // dcn31_hpo_dp_link_enc_enable_dp_output -> transmitter_control_v1_7:
        // ENABLE as DP_MST (digmode 5, even for SST), the 128b/132b symbol
        // clock (link_rate x 1000 / 10 in 10 kHz), the port's HPD, the HPO
        // link encoder's instance.
        if path.connector != Connector::DisplayPort
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || !matches!(settings.lanes, 1 | 2 | 4)
            || link >= 2
        {
            return Err(dmub::Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 1; // TRANSMITTER_CONTROL_ENABLE
        request[6] = 5; // ATOM_TRANSMITTER_DIGMODE_V6_DP_MST
        request[7] = settings.lanes;
        request[8..12].copy_from_slice(&(settings.rate.link_rate() * 100).to_le_bytes());
        request[12] = path.hpd;
        request[15] = link;
        self.command(request).await.map(|_| ())
    }
    async fn uhbr_ffe(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        preset: u8,
    ) -> Result<(), dmub::Error> {
        // dcn31_hpo_dp_link_enc_set_ffe: SET_VOLTAGE_AND_PREEMPASIS as
        // DP_MST with the TX FFE preset in the lane-set byte.
        if path.connector != Connector::DisplayPort
            || path.transmitter >= 4
            || !matches!(settings.lanes, 1 | 2 | 4)
            || preset > 15
        {
            return Err(dmub::Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[5] = 11; // SET_VOLTAGE_AND_PREEMPASIS
        request[6] = preset;
        request[7] = settings.lanes;
        request[8..12].copy_from_slice(&(settings.rate.link_rate() * 100).to_le_bytes());
        request[12] = 1;
        request[15] = 244;
        self.command(request).await.map(|_| ())
    }
    async fn disable_uhbr(&mut self, path: Path) -> Result<(), dmub::Error> {
        // dcn31_hpo_dp_link_enc_disable_output leaves connector_obj_id
        // zero; DISABLE has no clock/lane arguments. The HPO id (244) is
        // the DISABLE resolving the physical transmitter, not the link.
        if path.connector != Connector::DisplayPort
            || path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
        {
            return Err(dmub::Error::Invalid);
        }
        let mut request = [0; 64];
        request[..4].copy_from_slice(&TRANSMITTER_CONTROL);
        request[4] = path.transmitter;
        request[6] = 0; // SST digmode
        request[12] = path.hpd;
        request[14] = 0;
        request[15] = 244;
        self.command(request).await.map(|_| ())
    }
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}

/// Repeaters between the source and the sink, from the LTTPR capability
/// block (dp_retrieve_lttpr_cap / dp_is_lttpr_present). Only the fields
/// training consults are kept: the max link rate (d[1]) and the AUX
/// timeout extension (d[5]) are not used by this owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lttpr {
    revision: u8,
    /// `PHY_REPEATER_CNT` as read, echoed to `TOTAL_LTTPR_CNT`.
    raw_count: u8,
    count: u8,
    max_lanes: u8,
}
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
    fn parse(d: [u8; 10]) -> Option<Self> {
        let count = repeater_count(d[2]);
        (count > 0 && (1..=4).contains(&d[4])).then_some(Self {
            revision: d[0],
            raw_count: d[2],
            count,
            max_lanes: d[4],
        })
    }
}

fn lane_bits(status: [u8; 6], lane: u8) -> u8 {
    (status[usize::from(lane / 2)] >> (4 * (lane % 2))) & 0xf
}
fn uhbr_eq_done(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 2 != 0)
}
fn uhbr_symbol_locked(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 4 != 0)
}
/// Each lane's requested TX_FFE_PRESET_VALUE (all four, as the sink lists
/// them; Linux writes these back to the sink as they are).
fn requested_presets(status: [u8; 6]) -> [u8; 4] {
    core::array::from_fn(|l| status[4 + l / 2] >> (4 * (l % 2)) & 0xf)
}
/// The preset the source transmits: the highest over the active lanes
/// (disallow_per_lane_settings).
fn source_preset(requests: [u8; 4], lanes: u8) -> u8 {
    requests[..usize::from(lanes)]
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
}
/// DP_128B132B_TRAINING_AUX_RD_INTERVAL: (value + 1) units of 2 ms, or of
/// 1 ms with bit 7.
fn uhbr_interval_us(raw: u8) -> u64 {
    (u64::from(raw & 0x7f) + 1) * if raw & 0x80 != 0 { 1000 } else { 2000 }
}

/// The UHBR owner: the DPHY registers at DCN base index 2 and the
/// connector's native AUX engine. The DMUB transport is passed per call.
pub struct UhbrLink<A: Aux> {
    regs: Regs,
    dcn2: u64,
    aux: A,
}

impl<A: Aux> core::fmt::Debug for UhbrLink<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The AUX engine has no Debug bound; name the registers instead.
        f.debug_struct("UhbrLink")
            .field("regs", &self.regs)
            .field("dcn2", &self.dcn2)
            .finish_non_exhaustive()
    }
}

impl<A: Aux + Send> UhbrLink<A> {
    /// Bind the link's DPCD registers and the AUX engine `aux`.
    ///
    /// Consumed only by the kernel-test suite below, which clippy's
    /// lib/test configs do not enable; do not delete — this is the
    /// owner's constructor, wired by the modeset lane that lands the
    /// 3.2 UHBR path.
    #[allow(dead_code)]
    pub(crate) fn new(regs: Regs, dcn2: u64, aux: A) -> Self {
        Self { regs, dcn2, aux }
    }

    fn at(&self, link: u8, reg: u64) -> u64 {
        self.dcn2 + (reg + u64::from(link) * LINK_STRIDE) * 4
    }

    /// DPCD read in 16-byte AUX transactions.
    async fn read<const N: usize>(&mut self, address: u32) -> Result<[u8; N], Error> {
        let mut data = [0; N];
        for (i, piece) in data.chunks_mut(16).enumerate() {
            self.aux
                .read(address + 16 * i as u32, piece)
                .await
                .map_err(Error::from)?;
        }
        Ok(data)
    }

    /// DPCD write in 16-byte AUX transactions.
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        for (i, piece) in data.chunks(16).enumerate() {
            self.aux
                .write(address + 16 * i as u32, piece)
                .await
                .map_err(Error::from)?;
        }
        Ok(())
    }

    /// `dcn31_hpo_dp_link_enc_enable`: the DC DPHY sequence. Idempotent
    /// with what the firmware enable already set; the reset runs only
    /// when STATUS shows the link disabled.
    pub fn link_enable(&mut self, link: u8, lanes: u8) -> Result<(), Error> {
        if link >= 2 || !matches!(lanes, 1 | 2 | 4) {
            return Err(Error::Invalid);
        }
        let enabled = self.regs.read(self.at(link, STATUS))? & STATUS_ENABLED != 0;
        // Enable clocks first.
        self.regs.update(self.at(link, CLOCK_CONTROL), 1, 1)?;
        // Reset DPHY. Only reset if going from disable to enable.
        if !enabled {
            self.regs
                .update(self.at(link, CONTROL), CONTROL_RESET, CONTROL_RESET)?;
            self.regs.update(self.at(link, CONTROL), CONTROL_RESET, 0)?;
        }
        // Configure DPHY settings.
        let lanes_code = match lanes {
            1 => 0,
            2 => 1,
            _ => 3,
        };
        self.regs.update(
            self.at(link, CONTROL),
            CONTROL_ENABLE | CONTROL_PRECODER | CONTROL_LANES_MASK,
            CONTROL_ENABLE | CONTROL_PRECODER | lanes_code << 8,
        )?;
        Ok(())
    }

    /// `dcn31_hpo_dp_link_enc_disable`: DPHY off, clock off last.
    pub fn link_disable(&mut self, link: u8) -> Result<(), Error> {
        if link >= 2 {
            return Err(Error::Invalid);
        }
        self.regs
            .update(self.at(link, CONTROL), CONTROL_ENABLE, 0)?;
        self.regs.update(self.at(link, CLOCK_CONTROL), 1, 0)?;
        Ok(())
    }

    /// Set the encoder's training mode (MODE field, bits 5:4).
    fn set_mode(&mut self, link: u8, mode: u8) -> Result<(), Error> {
        self.regs.update(
            self.at(link, CONTROL),
            CONTROL_MODE_MASK,
            u32::from(mode) << 4,
        )?;
        Ok(())
    }

    /// The running link's firmware-made state, and nothing else awake:
    /// clock on, DPHY enabled with the expected mode and no reset, link
    /// enabled. There is no 3.2 LINK_CLOCK register to watch (see the
    /// module docs).
    fn verify(&mut self, plan: &UhbrLinkTrained) -> Result<(), Error> {
        for (at, mask, value) in [
            (self.at(plan.link, CLOCK_CONTROL), 1, 1),
            (
                self.at(plan.link, CONTROL),
                0x33,
                1 | u32::from(plan.mode) << 4,
            ),
            (self.at(plan.link, STATUS), STATUS_ENABLED, STATUS_ENABLED),
        ] {
            if self.regs.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }

    /// `dp_enable_link_phy` for 128b/132b: the firmware enable, the DC
    /// DPHY sequence, then the encoder state read back.
    async fn enable(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        io.enable_uhbr(plan.path, plan.settings, plan.link).await?;
        self.link_enable(plan.link, plan.settings.lanes)?;
        // The firmware routes the PHY to this encoder; the lane count the
        // firmware reports is the trained lane count, not the board map.
        plan.physical_lanes = plan.settings.lanes;
        plan.mode = ((self.regs.read(self.at(plan.link, CONTROL))? >> 4) & 3) as u8;
        self.verify(plan)
    }

    /// `dpcd_exit_training_mode`: TRAINING_PATTERN_SET cleared, then up
    /// to 10 ms (300 ms per repeater) for the intra-hop AUX reply
    /// indication to clear. Linux carries on regardless.
    async fn exit_training(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &UhbrLinkTrained,
    ) -> Result<(), Error> {
        self.write(0x102, &[0]).await?;
        let polls = if plan.repeaters != 0 {
            u32::from(plan.repeaters) * 300
        } else {
            10
        };
        for _ in 0..polls {
            if self.read::<1>(LANE_ALIGN).await?[0] & 8 == 0 {
                break;
            }
            io.delay(1000).await;
        }
        self.verify(plan)
    }

    /// The sink's and any repeater chain's caps, before the PHY: the sink
    /// codes 128b/132b, lists the rate (or a better one; UHBR13.5 only
    /// where listed) and has the lanes, with no MST owner, and a revision
    /// 1.4 chain carries the rate too. Returns the chain's raw count.
    async fn caps(&mut self, _path: Path, s: UhbrSettings) -> Result<Option<Lttpr>, Error> {
        let mut dpcd = self.read::<16>(0).await?;
        if dpcd[14] & 0x80 != 0 {
            let extended = self.read::<16>(0x2200).await?;
            if extended[0] >= dpcd[0] {
                dpcd = extended;
            }
        }
        if !matches!(dpcd[0], 0x12..=0x14 | 0x20 | 0x21) || !matches!(dpcd[2] & 0x1f, 1 | 2 | 4) {
            return Err(Error::Training(TrainingError::InvalidCaps));
        }
        let best = |bits: u8| {
            UhbrRate::ALL
                .into_iter()
                .rev()
                .find(|r| bits & r.dpcd_bit() != 0)
        };
        let carries = |bits: u8| {
            best(bits).is_some_and(|b| s.rate <= b)
                && (s.rate != UhbrRate::Uhbr13_5 || bits & 4 != 0)
        };
        if dpcd[6] & 2 == 0 || s.lanes > dpcd[2] & 0x1f {
            return Err(Error::Unsupported);
        }
        if !carries(self.read::<1>(UHBR_RATES).await?[0]) {
            return Err(Error::Unsupported);
        }
        // SST: no active MST/up-request owner. MST: the topology manager
        // set MST_EN first (drm_dp_mst_topology_mgr_set_mst).
        let mstm = self.read::<1>(0x111).await?[0];
        if s.mst {
            if mstm & 1 == 0 {
                return Err(Error::Invalid);
            }
        } else if mstm & 7 != 0 {
            return Err(Error::Busy); // active MST/up-request owner
        }
        // retrieve_link_cap's repeater probe under the LTTPR AUX timeout.
        // A failed probe means no repeater chain (the native AUX engine
        // has no error-code granularity to distinguish it).
        self.aux.set_timeout_us(AUX_TIMEOUT_LTTPR_US).await?;
        let caps = (self.read::<10>(LTTPR_CAPS).await).ok();
        let Some(caps) = caps else {
            self.aux.set_timeout_us(AUX_TIMEOUT_DEFAULT_US).await?;
            return Ok(None);
        };
        let Some(r) = Lttpr::parse(caps) else {
            self.aux.set_timeout_us(AUX_TIMEOUT_DEFAULT_US).await?;
            return Ok(None);
        };
        // get_lttpr_max_link_rate: a revision 1.4 chain's 128b/132b rates
        // bound the link like the sink's.
        if s.lanes > r.max_lanes || (caps[0] >= 0x14 && !carries(caps[7])) {
            return Err(Error::Unsupported);
        }
        Ok(Some(r))
    }

    /// With the PHY up: the receiver to D0, the training exit, the
    /// repeater chain's count and modes, 128b/132b channel coding and the
    /// link settings.
    async fn sink(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
        chain: Option<Lttpr>,
    ) -> Result<(), Error> {
        let s = plan.settings;
        self.write(0x600, &[1]).await?;
        io.delay(1000).await;
        if self.read::<1>(0x600).await?[0] & 7 != 1 {
            return Err(Error::Training(TrainingError::SinkReadback(0x600)));
        }
        self.verify(plan)?;
        self.exit_training(io, plan).await?;
        if let Some(r) = chain {
            // The count and transparent mode retrieve_link_cap leaves,
            // then dp_decide_128b_132b_lttpr_mode's non-transparent mode.
            self.write(LTTPR_TOTAL_COUNT, &[r.raw_count]).await?;
            self.write(LTTPR_MODE, &[LTTPR_MODE_TRANSPARENT]).await?;
            self.write(LTTPR_MODE, &[LTTPR_MODE_NON_TRANSPARENT])
                .await?;
        }
        self.write(CHANNEL_CODING_SET, &[2]).await?;
        // dpcd_set_link_settings: 0.5% downspread, lanes without enhanced
        // framing or post-LT adjustment, the 128b/132b rate code.
        self.write(0x107, &[0x10]).await?;
        self.write(0x101, &[s.lanes]).await?;
        self.write(0x100, &[s.rate.dpcd_code()]).await?;
        self.verify(plan)
    }

    async fn status(&mut self, plan: &UhbrLinkTrained) -> Result<[u8; 6], Error> {
        let status = self.read::<6>(0x202).await?;
        self.verify(plan)?;
        Ok(status)
    }

    async fn ffe(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
        preset: u8,
    ) -> Result<(), Error> {
        self.verify(plan)?;
        io.uhbr_ffe(plan.path, plan.settings, preset).await?;
        plan.preset = preset;
        self.verify(plan)
    }

    /// `dp_perform_128b_132b_channel_eq_done_sequence`.
    async fn eq(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        let lanes = plan.settings.lanes;
        let failed = || Error::Training(TrainingError::Equalization);
        self.set_mode(plan.link, MODE_TPS1)?;
        plan.mode = MODE_TPS1;
        self.write(0x102, &[1]).await?;
        let mut interval = uhbr_interval_us(self.read::<1>(UHBR_AUX_RD_INTERVAL).await?[0]);
        let mut status = self.status(plan).await?;
        let mut requests = requested_presets(status);
        self.ffe(io, plan, source_preset(requests, lanes)).await?;
        self.set_mode(plan.link, MODE_TPS2)?;
        plan.mode = MODE_TPS2;
        // TRAINING_PATTERN_SET 2 and the active lanes' requests in one burst.
        let mut burst = [0u8; 5];
        burst[0] = 2;
        burst[1..1 + usize::from(lanes)].copy_from_slice(&requests[..usize::from(lanes)]);
        self.write(0x102, &burst).await?;
        let mut wait = 0;
        let mut loops = 1;
        loop {
            io.delay(interval).await;
            wait += interval;
            status = self.status(plan).await?;
            requests = requested_presets(status);
            interval = uhbr_interval_us(self.read::<1>(UHBR_AUX_RD_INTERVAL).await?[0]);
            plan.eq_loops = loops;
            if uhbr_eq_done(status, lanes) {
                break;
            }
            if loops >= EQ_LOOP_LIMIT || status[2] & LT_FAILED != 0 {
                return Err(failed());
            }
            self.ffe(io, plan, source_preset(requests, lanes)).await?;
            self.write(0x103, &requests).await?;
            loops += 1;
        }
        // EQ interlane alignment, within 400 ms of training altogether.
        loop {
            if status[2] & EQ_INTERLANE_ALIGN_DONE != 0 {
                return Ok(());
            }
            if wait >= EQ_WAIT_LIMIT_US || status[2] & LT_FAILED != 0 {
                return Err(failed());
            }
            io.delay(PATTERN_TIME_US).await;
            wait += PATTERN_TIME_US;
            status = self.status(plan).await?;
        }
    }

    /// `dp_perform_128b_132b_cds_done_sequence`; the hardware keeps TPS2.
    async fn cds(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        self.write(0x102, &[3]).await?;
        let limit = (u64::from(plan.repeaters) + 1) * CDS_WAIT_PER_HOP_US;
        let mut wait = 0;
        loop {
            io.delay(PATTERN_TIME_US).await;
            wait += PATTERN_TIME_US;
            let status = self.status(plan).await?;
            if uhbr_symbol_locked(status, plan.settings.lanes)
                && status[2] & CDS_INTERLANE_ALIGN_DONE != 0
            {
                return Ok(());
            }
            if status[2] & LT_FAILED != 0 || wait >= limit {
                return Err(Error::Training(TrainingError::ClockDataSwitch));
            }
        }
    }

    /// The training exit, the encoder to the active (idle) link, and
    /// dp_check_link_loss_status after 5 ms: every lane's CR done, channel
    /// EQ done and symbol lock, with interlane alignment (0x204 bit 0), as
    /// Linux requires of 128b/132b links too.
    async fn finish(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        self.exit_training(io, plan).await?;
        self.set_mode(plan.link, MODE_ACTIVE)?;
        plan.mode = MODE_ACTIVE;
        io.delay(5000).await;
        let status = self.read::<6>(0x200).await?;
        let lanes = [status[2], status[3], status[4], 0, 0, 0];
        if !(0..plan.settings.lanes).all(|l| lane_bits(lanes, l) & 7 == 7) || status[4] & 1 == 0 {
            return Err(Error::Training(TrainingError::LinkLost));
        }
        self.verify(plan)
    }

    /// Enable the PHY on HPO link encoder `link` at `settings` and train
    /// the sink. A confirmed training refusal exits training and leaves
    /// the encoder on its last pattern for [`UhbrLink::stop`].
    pub async fn train(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<UhbrLinkTrained, Error> {
        if path.connector != Connector::DisplayPort {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || path.aux.is_none_or(|a| a >= 4)
            || !matches!(settings.lanes, 1 | 2 | 4)
            || link >= 2
        {
            return Err(Error::Invalid);
        }
        let chain = self.caps(path, settings).await?;
        let mut plan = UhbrLinkTrained {
            path,
            settings,
            link,
            physical_lanes: 0,
            preset: 0,
            eq_loops: 0,
            repeaters: chain.map_or(0, |r| r.count),
            mode: 0,
        };
        let mut result = async {
            self.enable(io, &mut plan).await?;
            self.sink(io, &mut plan, chain).await?;
            self.eq(io, &mut plan).await?;
            self.cds(io, &mut plan).await?;
            self.finish(io, &mut plan).await
        }
        .await;
        // A refusal the sink confirmed still exits training, as Linux does
        // before disabling the PHY (the encoder stays on its last pattern).
        let refused = matches!(
            result,
            Err(Error::Training(
                TrainingError::Equalization
                    | TrainingError::ClockDataSwitch
                    | TrainingError::LinkLost
            ))
        );
        if refused {
            if let Err(e) = self.exit_training(io, &plan).await {
                result = Err(e);
            }
        }
        result.map(|()| plan)
    }

    /// `disable_link_dp` for 128b/132b: an SST sink to D3 (unless gone),
    /// then the encoder's DPHY and clock off and the firmware DISABLE.
    /// The SYMCLK32_LE route parking belongs to the clock owner
    /// ([`crate::amdgpu_dcn32_dccg::Dccg32::set_symclk32_le`]).
    pub async fn stop(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &UhbrLinkTrained,
        sink: bool,
    ) -> Result<(), Error> {
        // An idle MST branch stays powered for AUX and up requests.
        if sink && !plan.settings.mst {
            self.write(0x600, &[2]).await?;
            self.verify(plan)?;
        }
        self.link_disable(plan.link)?;
        io.disable_uhbr(plan.path).await?;
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
pub(crate) mod tests {
    use super::*;
    use crate::amdgpu_dcn_inventory::Connector;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct FakeAux {
        reads: BTreeMap<u32, Vec<u8>>,
        writes: Vec<(u32, Vec<u8>)>,
    }
    impl FakeAux {
        fn new() -> Self {
            let mut reads = BTreeMap::new();
            // DP 1.4 sink, 4 lanes, 128b/132b, no MST owner.
            reads.insert(
                0,
                alloc::vec![0x14, 0, 0x04, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
            reads.insert(UHBR_RATES, alloc::vec![0x07]);
            reads.insert(0x111, alloc::vec![0x00]);
            reads.insert(UHBR_AUX_RD_INTERVAL, alloc::vec![0x00]);
            reads.insert(LANE_ALIGN, alloc::vec![0x00]);
            // Lane status: EQ done + symbol lock on all lanes, EQ and CDS
            // interlane alignment done, no training failure.
            reads.insert(0x202, alloc::vec![0x66, 0x66, 0x0c, 0, 0, 0]);
            // Link status after training: all lanes CR+EQ+lock, align done.
            reads.insert(0x200, alloc::vec![0, 0, 0x77, 0x77, 0x01, 0]);
            reads.insert(0x600, alloc::vec![0x00]);
            Self {
                reads,
                writes: Vec::new(),
            }
        }
    }
    impl Aux for FakeAux {
        async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), ModesetError> {
            let Some(script) = self.reads.get(&address) else {
                return Err(ModesetError::Aux);
            };
            // A write-through read: the last write to this address wins.
            let value = self
                .writes
                .iter()
                .rev()
                .find(|(a, _)| *a == address)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| script.clone());
            if value.len() < data.len() {
                return Err(ModesetError::Aux);
            }
            data.copy_from_slice(&value[..data.len()]);
            Ok(())
        }
        async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), ModesetError> {
            self.writes.push((address, data.to_vec()));
            Ok(())
        }
    }

    struct FakeTransport {
        enabled: Vec<(Path, UhbrSettings, u8)>,
        ffe: Vec<u8>,
        disabled: Vec<Path>,
    }
    impl FakeTransport {
        fn new() -> Self {
            Self {
                enabled: Vec::new(),
                ffe: Vec::new(),
                disabled: Vec::new(),
            }
        }
    }
    impl UhbrTransport for FakeTransport {
        async fn enable_uhbr(
            &mut self,
            path: Path,
            settings: UhbrSettings,
            link: u8,
        ) -> Result<(), dmub::Error> {
            self.enabled.push((path, settings, link));
            Ok(())
        }
        async fn uhbr_ffe(
            &mut self,
            path: Path,
            _settings: UhbrSettings,
            preset: u8,
        ) -> Result<(), dmub::Error> {
            let _ = path;
            self.ffe.push(preset);
            Ok(())
        }
        async fn disable_uhbr(&mut self, path: Path) -> Result<(), dmub::Error> {
            self.disabled.push(path);
            Ok(())
        }
        async fn delay(&mut self, _us: u64) {}
    }

    fn path() -> Path {
        Path {
            connector: Connector::DisplayPort,
            connector_instance: 1,
            transmitter: 0,
            aux: Some(0),
            hpd: 1,
            device_tag: 0,
            max_speed_mhz: 0,
        }
    }

    fn settings() -> UhbrSettings {
        UhbrSettings {
            lanes: 4,
            rate: UhbrRate::Uhbr10,
            mst: false,
        }
    }

    fn bench() -> (Regs, crate::amdgpu_navi22_modeset_model::Bench) {
        use crate::amdgpu_navi22_modeset_model::Bench;
        let bench = Bench::new();
        let regs = Regs {
            window: crate::amdgpu_reg_window::Window::new(bench.gpu.regs),
            authority: narf_capabilities::Cap::bootstrap(),
        };
        (regs, bench)
    }

    fn dcn32_uhbr_link_enable_resets_only_when_disabled() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::d2;
        let (regs, bench) = bench();
        let mut link = UhbrLink::new(regs, u64::from(d2(0)) * 4, FakeAux::new());
        // STATUS clear: the reset pulse runs.
        if link.link_enable(0, 4).is_err() {
            return TestResult::Fail("DCN32 UHBR link_enable failed");
        }
        let log = bench.log();
        let control = |v: u32| {
            log.iter()
                .any(|w| w.dword == d2(0) + CONTROL as u32 && w.value == v)
        };
        // CLOCK_EN set, RESET pulsed 1 then 0, then ENABLE+PRECODER+lanes 4.
        if !log
            .iter()
            .any(|w| w.dword == d2(0) + CLOCK_CONTROL as u32 && w.value & 1 == 1)
            || !control(CONTROL_RESET)
            || !control(0)
            || !control(CONTROL_ENABLE | CONTROL_PRECODER | 3 << 8)
        {
            return TestResult::Fail("DCN32 UHBR link_enable register sequence wrong");
        }
        // STATUS set: no reset pulse, only the final configure write.
        bench.set(d2(0) + STATUS as u32, 1);
        let before = bench.log().len();
        if link.link_enable(0, 4).is_err() {
            return TestResult::Fail("DCN32 UHBR link_enable on enabled link failed");
        }
        if bench.log()[before..]
            .iter()
            .any(|w| w.dword == d2(0) + CONTROL as u32 && w.value & CONTROL_RESET != 0)
        {
            return TestResult::Fail("DCN32 UHBR link_enable reset an enabled link");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn32-uhbr",
        dcn32_uhbr_link_enable_resets_only_when_disabled
    );

    fn dcn32_uhbr_train_uhbr10_x4() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::d2;
        let (regs, bench) = bench();
        // The model does not synthesize SYM32 STATUS: seed it enabled so
        // the enable verify passes (the reset path is pinned separately).
        bench.set(d2(0) + STATUS as u32, 1);
        let mut link = UhbrLink::new(regs, u64::from(d2(0)) * 4, FakeAux::new());
        let mut io = FakeTransport::new();
        let plan = match narf_scheduler::block_on_spin(link.train(&mut io, path(), settings(), 0)) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("DCN32 UHBR train failed"),
        };
        if plan.link != 0
            || plan.physical_lanes != 4
            || plan.preset != 0
            || plan.eq_loops != 1
            || plan.repeaters != 0
            || plan.mode != MODE_ACTIVE
        {
            return TestResult::Fail("DCN32 UHBR trained plan wrong");
        }
        if io.enabled.len() != 1 || io.ffe != alloc::vec![0] {
            return TestResult::Fail("DCN32 UHBR firmware calls wrong");
        }
        // The encoder ends in ACTIVE mode with DPHY enabled.
        let control = bench.get(d2(0) + CONTROL as u32);
        if control & 0x33 != 1 | u32::from(MODE_ACTIVE) << 4 {
            return TestResult::Fail("DCN32 UHBR encoder not ACTIVE after train");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-uhbr", dcn32_uhbr_train_uhbr10_x4);

    fn dcn32_uhbr_train_refuses_bad_caps() -> TestResult {
        use crate::amdgpu_navi22_modeset_model::d2;
        let (regs, _bench) = bench();
        let mut aux = FakeAux::new();
        // A DP 1.2 sink: no 128b/132b.
        aux.reads.insert(
            0,
            alloc::vec![0x12, 0, 0x04, 0, 0, 0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let mut link = UhbrLink::new(regs, u64::from(d2(0)) * 4, aux);
        let mut io = FakeTransport::new();
        if narf_scheduler::block_on_spin(link.train(&mut io, path(), settings(), 0)).is_ok() {
            return TestResult::Fail("DCN32 UHBR trained a DP 1.2 sink");
        }
        if !io.enabled.is_empty() {
            return TestResult::Fail("DCN32 UHBR enabled the PHY for bad caps");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/dcn32-uhbr", dcn32_uhbr_train_refuses_bad_caps);
}
