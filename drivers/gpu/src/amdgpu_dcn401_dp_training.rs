//! Direct legacy DP SST training: native DC source patterns/drive programming,
//! board-routed DPCD transactions and fresh CR/EQ/link-loss checks. LTTPRs are
//! used as Linux's DCN401 does (always VBIOS-aware): transparent unless the
//! VBIOS asks for non-transparent hop-by-hop training. FEC as Linux keeps it:
//! a FEC-capable DP 1.4 sink trains FEC-ready and has FEC enabled once
//! trained (dp_set_fec_ready/dp_set_fec_enable). No MST, automated rate
//! fallback, stream output or scanout allocation reuse.
use super::*;
use crate::dp_link_training::{LinkRate, TrainingPattern};
pub use dmub::DpDriveSettings;
#[path = "amdgpu_dcn401_dp_frontend.rs"]
mod frontend;
pub use frontend::{DpFrontendReady, DpFrontendRequest, DpVideoRunning};
#[path = "amdgpu_dcn401_dp_link_status.rs"]
mod link_status;
pub use link_status::DpLinkStatus;
#[path = "amdgpu_dcn401_uhbr_link.rs"]
pub(in super::super) mod uhbr;
pub use uhbr::{uhbr_mst_rate, UhbrLinkTrained, UhbrPayload, UhbrSettings, UhbrVideoRunning};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpTrainingError {
    InvalidCaps,
    SinkReadback(u32),
    ClockRecovery,
    Equalization,
    LinkLost,
    /// 128b/132b clock data switch: no CDS interlane alignment or symbol
    /// lock in time, or the sink reported LT_FAILED during it.
    ClockDataSwitch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpLinkTrained {
    pub phy: DpPhyReady,
    pub equalization: TrainingPattern,
    pub drive: DpDriveSettings,
    pub downspread: bool,
    pub cr_attempts: u8,
    pub eq_attempts: u8,
    /// Trained FEC-ready (sink FEC_CAPABLE, DPCD 1.4 or later).
    pub fec: bool,
    controls: [u32; 4],
    /// DPHY_FEC_EN | DPHY_FEC_READY_SHADOW as this owner set them.
    fec_bits: u32,
}
impl DpLinkTrained {
    fn registers(self, l: Layout) -> [(u64, u32); 4] {
        let at = |r| DpStream::Dio(self.phy.path.transmitter).at(l, r);
        [
            (at(0x212e), u32::MAX),
            (at(0x211e), 0x10),
            (at(0x2133), 1),
            (at(0x2129), 0x1113ffff),
        ]
    }
}
pub(in super::super) trait Transport: Firmware {
    fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn drive(
        &mut self,
        path: Path,
        settings: DpPhySettings,
        drive: DpDriveSettings,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn delay(&mut self, us: u64) -> impl Future<Output = ()> + Send;
}
impl Transport for dmub::Dmub {
    async fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        self.aux(instance, action, address, data).await
    }
    async fn drive(
        &mut self,
        path: Path,
        settings: DpPhySettings,
        drive: DpDriveSettings,
    ) -> Result<(), dmub::Error> {
        self.set_dp_drive(path, settings, drive).await
    }
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}
async fn transfer(
    io: &mut impl Transport,
    path: Path,
    action: u8,
    address: u32,
    data: &mut [u8],
) -> Result<(), Error> {
    let aux = path.aux.filter(|&a| a < 4).ok_or(Error::Invalid)?;
    for attempt in 0..7 {
        match io.aux(aux, action, address, data).await {
            Err(dmub::Error::Aux(2 | 8)) if attempt != 6 => io.delay(1000).await,
            result => return result.map_err(Error::Firmware),
        }
    }
    unreachable!()
}
async fn write(io: &mut impl Transport, path: Path, at: u32, data: &mut [u8]) -> Result<(), Error> {
    transfer(io, path, 0x80, at, data).await
}
async fn read<const N: usize>(
    io: &mut impl Transport,
    path: Path,
    at: u32,
) -> Result<[u8; N], Error> {
    let mut data = [0; N];
    transfer(io, path, 0x90, at, &mut data).await?;
    Ok(data)
}
fn invalid_caps() -> Error {
    Error::DpTraining(DpTrainingError::InvalidCaps)
}
fn sink_readback(at: u32) -> Error {
    Error::DpTraining(DpTrainingError::SinkReadback(at))
}
/// LTTPR (DP repeater) AUX reply timeout and the default one, in us
/// (Linux LINK_AUX_DEFAULT_LTTPR_TIMEOUT_PERIOD / LINK_AUX_DEFAULT_TIMEOUT_PERIOD).
pub(in crate::amdgpu_dcn401_otg) const AUX_TIMEOUT_LTTPR_US: u32 = 3200;
pub(in crate::amdgpu_dcn401_otg) const AUX_TIMEOUT_DEFAULT_US: u32 = 552;
const LTTPR_CAPS: u32 = 0xf0000;
const LTTPR_MODE: u32 = 0xf0003;
const LTTPR_TOTAL_COUNT: u32 = 0xf000a;
const LTTPR_MODE_TRANSPARENT: u8 = 0x55;
const LTTPR_MODE_NON_TRANSPARENT: u8 = 0xaa;
/// Per-repeater DPCD block stride and its registers (repeater 1's addresses).
const LTTPR_STRIDE: u32 = 0x50;
const LTTPR_PATTERN_SET: u32 = 0xf0010;
const LTTPR_AUX_RD_INTERVAL: u32 = 0xf0020;
const LTTPR_LANE_STATUS: u32 = 0xf0030;
const LTTPR_ADJUST_REQUEST: u32 = 0xf0033;

/// Repeaters between the source and the sink, from the LTTPR capability
/// block (dp_retrieve_lttpr_cap / dp_is_lttpr_present).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lttpr {
    count: u8,
    raw_count: u8,
    max_rate: u8,
    max_lanes: u8,
    non_transparent: bool,
    /// Each repeater's EQ AUX_RD_INTERVAL (non-transparent only).
    intervals: [u8; 8],
}
impl Lttpr {
    /// None unless the count is valid and the lane count is 1..=4, as Linux
    /// (revision is not checked: some repeaters report a bad one).
    fn parse(caps: [u8; 10], non_transparent: bool) -> Option<Self> {
        let count = match caps[2] {
            0x80 => 1,
            0x40 => 2,
            0x20 => 3,
            0x10 => 4,
            0x08 => 5,
            0x04 => 6,
            0x02 => 7,
            0x01 => 8,
            _ => 0,
        };
        (count > 0 && (1..=4).contains(&caps[4])).then_some(Self {
            count,
            raw_count: caps[2],
            max_rate: caps[1],
            max_lanes: caps[4],
            non_transparent,
            intervals: [0; 8],
        })
    }
}
/// DPCD addresses of one training hop: the sink, or repeater `id` (1 is the
/// one nearest the sink, trained last before it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hop {
    Sink,
    Repeater(u8),
}
impl Hop {
    fn offset(self) -> u32 {
        match self {
            Hop::Sink => 0,
            Hop::Repeater(id) => LTTPR_STRIDE * u32::from(id - 1),
        }
    }
    fn pattern_set(self) -> u32 {
        match self {
            Hop::Sink => 0x102,
            Hop::Repeater(_) => LTTPR_PATTERN_SET + self.offset(),
        }
    }
}
/// dp_translate_training_aux_read_interval.
fn aux_rd_interval_us(interval: u8) -> u64 {
    match interval {
        1 => 4000,
        2 => 8000,
        3 => 12000,
        4 => 16000,
        5 => 32000,
        6 => 64000,
        _ => 400,
    }
}
struct Caps {
    pattern: TrainingPattern,
    cr_us: u64,
    eq_us: u64,
    lttpr: Option<Lttpr>,
}
impl Caps {
    fn parse(
        dpcd: [u8; 16],
        interval: u8,
        settings: DpPhySettings,
        downspread: bool,
        lttpr: Option<Lttpr>,
    ) -> Result<Self, Error> {
        if !matches!(dpcd[0], 0x11..=0x14 | 0x20 | 0x21)
            || !matches!(dpcd[2] & 0x1f, 1 | 2 | 4)
            || LinkRate::from_dpcd_byte(dpcd[1]).is_none()
            || interval & 0x7f > 6
        {
            return Err(invalid_caps());
        }
        // Native passthrough uses enhanced framing. Branches, converters and
        // unsupported source/sink combinations need their own policy/owners.
        if dpcd[2] & 0x80 == 0
            || dpcd[5] & 1 != 0
            || dpcd[6] & 1 == 0
            || settings.lanes > dpcd[2] & 0x1f
            || settings.rate as u8 > dpcd[1]
            || downspread && dpcd[3] & 1 == 0
        {
            return Err(Error::Unsupported);
        }
        let pattern = if dpcd[3] & 0x80 != 0 {
            TrainingPattern::Tps4
        } else if dpcd[2] & 0x40 != 0 {
            TrainingPattern::Tps3
        } else {
            TrainingPattern::Tps2
        };
        if settings.rate == LinkRate::Hbr3 && pattern != TrainingPattern::Tps4 {
            return Err(Error::Unsupported);
        }
        // A repeater carries the link: it bounds rate and lanes too.
        if let Some(r) = lttpr {
            if settings.lanes > r.max_lanes || settings.rate as u8 > r.max_rate {
                return Err(Error::Unsupported);
            }
        }
        // get_cr/eq_training_aux_rd_interval: the base DPCD 0xE byte (its
        // extended-capability bit included) from DPCD 1.2; before that an
        // LTTPR is required to report 0x4 (16 ms).
        let raw = if dpcd[0] >= 0x12 {
            interval
        } else if lttpr.is_some() {
            4
        } else {
            0
        };
        let non_transparent = lttpr.is_some_and(|r| r.non_transparent);
        let mut cr_us = 100;
        if raw != 0 {
            if !non_transparent {
                cr_us = 400;
            }
            if raw & 0x7f != 0 {
                cr_us = u64::from(raw & 0x7f) * 4000;
            }
        }
        Ok(Self {
            pattern,
            cr_us,
            eq_us: aux_rd_interval_us(raw & 0x7f),
            lttpr,
        })
    }
}
fn lane_bits(status: [u8; 6], lane: u8) -> u8 {
    (status[usize::from(lane / 2)] >> (4 * (lane % 2))) & 0xf
}
fn cr_done(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 1 != 0)
}
fn eq_done(status: [u8; 6], lanes: u8) -> bool {
    // No post-LT adjustment grant is issued by this owner.
    (0..lanes).all(|l| lane_bits(status, l) & 7 == 7) && status[2] & 3 == 1
}
/// A repeater hop's EQ: channel EQ and symbol lock on every lane and the
/// interlane alignment bit of its own status register.
fn hop_eq_done(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 7 == 7) && status[2] & 1 == 1
}
fn requested_drive(status: [u8; 6], lanes: u8) -> DpDriveSettings {
    let mut drive = DpDriveSettings::default();
    for l in 0..lanes {
        let request = status[4 + usize::from(l / 2)] >> (4 * (l % 2));
        drive.swing = drive.swing.max(request & 3);
        drive.pre_emphasis = drive.pre_emphasis.max((request >> 2) & 3);
    }
    drive.pre_emphasis = drive.pre_emphasis.min(3 - drive.swing);
    drive
}
fn dpcd_drive(drive: DpDriveSettings) -> u8 {
    drive.swing
        | drive.pre_emphasis << 3
        | if drive.swing == 3 { 4 } else { 0 }
        | if drive.pre_emphasis == 3 { 0x20 } else { 0 }
}
/// DP_FEC_CONFIGURATION.
const FEC_CONFIGURATION: u32 = 0x120;
/// DP_DPHY_CNTL's DPHY_FEC_EN and DPHY_FEC_READY_SHADOW.
const FEC_EN: u32 = 0x10;
const FEC_READY: u32 = 0x20;
async fn sink_config(io: &mut impl Transport, plan: DpLinkTrained) -> Result<(), Error> {
    let config = read::<9>(io, plan.phy.path, 0x100).await?;
    if config[0] != plan.phy.settings.rate as u8
        || config[1] != plan.phy.settings.lanes | 0x80
        || config[2] != 0
        || config[7] != if plan.downspread { 0x10 } else { 0 }
        || config[8] != 1
    {
        return Err(sink_readback(0x100));
    }
    if plan.fec && read::<1>(io, plan.phy.path, FEC_CONFIGURATION).await?[0] & 1 != 1 {
        return Err(sink_readback(FEC_CONFIGURATION));
    }
    Ok(())
}
impl<I: Io> Engine<I> {
    pub(in crate::amdgpu_dcn401_otg) fn dp_training_verify(
        &mut self,
        plan: DpLinkTrained,
    ) -> Result<(), Error> {
        self.dp_training_verify_owned(plan, None, None)
    }
    fn dp_training_verify_owned(
        &mut self,
        plan: DpLinkTrained,
        frontend: Option<u8>,
        timing: Option<u8>,
    ) -> Result<(), Error> {
        self.dp_phy_configuration_owned(plan.phy, frontend, timing)?;
        self.dp_phy_witnesses(plan.phy)?;
        for ((at, mask), expected) in plan.registers(self.layout).into_iter().zip(plan.controls) {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        let at = DpStream::Dio(plan.phy.path.transmitter).at(self.layout, 0x212d);
        if self.read(at)? & (FEC_EN | FEC_READY) != plan.fec_bits {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    fn dp_training_update(
        &mut self,
        plan: &mut DpLinkTrained,
        slot: usize,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.dp_training_verify(*plan)?;
        self.update(plan.registers(self.layout)[slot].0, mask, value)?;
        plan.controls[slot] = (plan.controls[slot] & !mask) | value;
        Ok(())
    }
    fn dp_training_pattern(
        &mut self,
        plan: &mut DpLinkTrained,
        pattern: TrainingPattern,
    ) -> Result<(), Error> {
        let index = match pattern {
            TrainingPattern::Tps1 => 0,
            TrainingPattern::Tps2 => 1,
            TrainingPattern::Tps3 => 2,
            TrainingPattern::Tps4 => 3,
            TrainingPattern::None => return Err(Error::Invalid),
        };
        // Native pattern-select, training-complete, bypass and PRBS ordering.
        self.dp_training_update(plan, 0, u32::MAX, index)?;
        self.dp_training_update(plan, 1, 0x10, 0)?;
        self.update(
            DpStream::Dio(plan.phy.path.transmitter).at(self.layout, 0x212d),
            0x10000,
            0,
        )?;
        self.dp_training_update(plan, 2, 1, 0)?;
        self.dp_training_verify(*plan)
    }
    async fn dp_training_drive(
        &mut self,
        io: &mut impl Transport,
        plan: DpLinkTrained,
    ) -> Result<(), Error> {
        self.dp_training_verify(plan)?;
        io.drive(plan.phy.path, plan.phy.settings, plan.drive)
            .await
            .map_err(Error::Firmware)?;
        // Voltage changes can involve firmware-owned lane handshakes. Wait for
        // the same physical lanes to settle; never write their acknowledgements.
        let mut mask = 0;
        let mut value = 0;
        for l in 0..4 {
            let active = plan.phy.physical_lanes & (1 << l) != 0;
            mask |= (if active { 0x37 } else { 0x3e }) << (l * 8);
            value |= (if active { 4 } else { 2 }) << (l * 8);
        }
        self.wait(
            phy_at(self.layout, plan.phy.path.transmitter, 0x2943),
            mask,
            value,
            100_000,
        )
        .await?;
        self.dp_training_verify(plan)
    }
    async fn dp_training_sink(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
        non_transparent: bool,
    ) -> Result<Caps, Error> {
        let path = plan.phy.path;
        let rev = read::<1>(io, path, 0).await?[0];
        if !matches!(rev, 0x11..=0x14 | 0x20 | 0x21) {
            return Err(invalid_caps());
        }
        self.dp_training_verify(*plan)?;
        write(io, path, 0x600, &mut [1]).await?;
        io.delay(1000).await;
        if read::<1>(io, path, 0x600).await?[0] & 7 != 1 {
            return Err(sink_readback(0x600));
        }
        let mut dpcd = read::<16>(io, path, 0).await?;
        let interval = dpcd[14];
        if dpcd[14] & 0x80 != 0 {
            let extended = read::<16>(io, path, 0x2200).await?;
            if extended[0] >= dpcd[0] {
                dpcd = extended;
            }
        }
        // The sink's own caps refuse before any register write.
        Caps::parse(dpcd, interval, plan.phy.settings, plan.downspread, None)?;
        // SST: no active MST/up-request owner. MST: the topology manager
        // set MST_EN first (drm_dp_mst_topology_mgr_set_mst).
        if plan.phy.settings.mst {
            if dpcd[0] < 0x12 || read::<1>(io, path, 0x111).await?[0] & 1 == 0 {
                return Err(Error::Invalid);
            }
        } else if dpcd[0] >= 0x12 && read::<1>(io, path, 0x111).await?[0] & 7 != 0 {
            return Err(Error::Busy);
        }
        // retrieve_link_cap reads DP_FEC_CAPABILITY from DPCD 1.4 on;
        // dp_should_enable_fec then holds for every FEC-capable sink.
        let fec = dpcd[0] >= 0x14 && read::<1>(io, path, 0x90).await?[0] & 1 != 0;
        self.dp_training_verify(*plan)?;
        // retrieve_link_cap: the LTTPR AUX timeout before reading the repeater
        // capabilities, kept only while one is present. A NACK of the block
        // means no LTTPR; DEFER/timeout/protocol failures are not absence.
        self.aux_timeout(path, AUX_TIMEOUT_LTTPR_US)?;
        let mut lttpr = match read::<10>(io, path, LTTPR_CAPS).await {
            Ok(r) => Lttpr::parse(r, non_transparent),
            Err(Error::Firmware(dmub::Error::Aux(1))) => None,
            Err(e) => return Err(e),
        };
        if lttpr.is_none() {
            self.aux_timeout(path, AUX_TIMEOUT_DEFAULT_US)?;
        }
        if let Some(r) = lttpr.as_mut() {
            // Echo TOTAL_LTTPR_CNT downstream, then dpcd_configure_lttpr_mode:
            // transparent first; non-transparent also reads each repeater's
            // EQ interval.
            write(io, path, LTTPR_TOTAL_COUNT, &mut [r.raw_count]).await?;
            write(io, path, LTTPR_MODE, &mut [LTTPR_MODE_TRANSPARENT]).await?;
            if r.non_transparent {
                write(io, path, LTTPR_MODE, &mut [LTTPR_MODE_NON_TRANSPARENT]).await?;
                for id in (1..=r.count).rev() {
                    let at = LTTPR_AUX_RD_INTERVAL + Hop::Repeater(id).offset();
                    r.intervals[usize::from(id - 1)] = read::<1>(io, path, at).await?[0] & 0x7f;
                }
            }
        }
        let caps = Caps::parse(dpcd, interval, plan.phy.settings, plan.downspread, lttpr)?;
        self.dp_training_verify(*plan)?;
        write(io, path, 0x102, &mut [0]).await?;
        // dp_set_fec_ready before channel coding: the sink, then the source.
        if fec {
            write(io, path, FEC_CONFIGURATION, &mut [1]).await?;
            self.update(
                DpStream::Dio(path.transmitter).at(self.layout, 0x212d),
                FEC_READY,
                FEC_READY,
            )?;
            plan.fec = true;
            plan.fec_bits = FEC_READY;
            self.dp_training_verify(*plan)?;
        }
        write(io, path, 0x108, &mut [1]).await?;
        write(
            io,
            path,
            0x107,
            &mut [if plan.downspread { 0x10 } else { 0 }],
        )
        .await?;
        write(io, path, 0x101, &mut [plan.phy.settings.lanes | 0x80]).await?;
        write(io, path, 0x100, &mut [plan.phy.settings.rate as u8]).await?;
        // Confirm negotiated configuration before entering training. During
        // training, issue only training-related AUX transactions.
        sink_config(io, *plan).await?;
        self.dp_training_verify(*plan)?;
        Ok(caps)
    }
    async fn dp_training_round(
        &mut self,
        io: &mut impl Transport,
        plan: DpLinkTrained,
        pattern: TrainingPattern,
        first: bool,
        delay: u64,
        hop: Hop,
    ) -> Result<[u8; 6], Error> {
        self.dp_training_drive(io, plan).await?;
        let mut data = [dpcd_drive(plan.drive); 5];
        let set = hop.pattern_set();
        if first {
            data[0] = pattern as u8
                | if pattern == TrainingPattern::Tps4 {
                    0
                } else {
                    0x20
                };
            write(
                io,
                plan.phy.path,
                set,
                &mut data[..usize::from(plan.phy.settings.lanes) + 1],
            )
            .await?;
        } else {
            write(
                io,
                plan.phy.path,
                set + 1,
                &mut data[..usize::from(plan.phy.settings.lanes)],
            )
            .await?;
        }
        io.delay(delay).await;
        self.dp_training_verify(plan)?;
        let status = match hop {
            Hop::Sink => read::<6>(io, plan.phy.path, 0x202).await?,
            Hop::Repeater(_) => {
                // dp_get_lane_status_and_lane_adjust: lane status and
                // alignment, then the adjust requests, in the sink's layout.
                let lanes = read::<3>(io, plan.phy.path, LTTPR_LANE_STATUS + hop.offset()).await?;
                let adjust =
                    read::<2>(io, plan.phy.path, LTTPR_ADJUST_REQUEST + hop.offset()).await?;
                [lanes[0], lanes[1], lanes[2], 0, adjust[0], adjust[1]]
            }
        };
        self.dp_training_verify(plan)?;
        Ok(status)
    }
    async fn dp_training_cr(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
        caps: &Caps,
        hop: Hop,
    ) -> Result<(), Error> {
        self.dp_training_pattern(plan, TrainingPattern::Tps1)?;
        let mut same_swing = 0;
        for attempt in 0..100 {
            plan.cr_attempts = attempt + 1;
            let status = self
                .dp_training_round(
                    io,
                    *plan,
                    TrainingPattern::Tps1,
                    attempt == 0,
                    caps.cr_us,
                    hop,
                )
                .await?;
            if cr_done(status, plan.phy.settings.lanes) {
                return Ok(());
            }
            if plan.drive.swing == 3 {
                break;
            }
            let next = requested_drive(status, plan.phy.settings.lanes);
            same_swing = if next.swing == plan.drive.swing {
                same_swing + 1
            } else {
                0
            };
            if same_swing == 5 {
                break;
            }
            plan.drive = next;
        }
        Err(Error::DpTraining(DpTrainingError::ClockRecovery))
    }
    async fn dp_training_eq(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
        caps: &Caps,
        hop: Hop,
    ) -> Result<(), Error> {
        // Repeaters always equalize on TPS4 over 8b/10b, each at its own
        // AUX_RD_INTERVAL (perform_8b_10b_channel_equalization_sequence).
        let (pattern, delay) = match hop {
            Hop::Sink => (caps.pattern, caps.eq_us),
            Hop::Repeater(id) => (
                TrainingPattern::Tps4,
                aux_rd_interval_us(caps.lttpr.map_or(0, |r| r.intervals[usize::from(id - 1)])),
            ),
        };
        self.dp_training_pattern(plan, pattern)?;
        for attempt in 0..6 {
            plan.eq_attempts = attempt + 1;
            let status = self
                .dp_training_round(io, *plan, pattern, attempt == 0, delay, hop)
                .await?;
            if !cr_done(status, plan.phy.settings.lanes) {
                return Err(Error::DpTraining(DpTrainingError::LinkLost));
            }
            let done = match hop {
                Hop::Sink => eq_done(status, plan.phy.settings.lanes),
                Hop::Repeater(_) => hop_eq_done(status, plan.phy.settings.lanes),
            };
            if done {
                return Ok(());
            }
            plan.drive = requested_drive(status, plan.phy.settings.lanes);
        }
        Err(Error::DpTraining(DpTrainingError::Equalization))
    }
    async fn dp_training_idle(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
    ) -> Result<(), Error> {
        self.dp_training_verify(*plan)?;
        write(io, plan.phy.path, 0x102, &mut [0]).await?;
        // Native passthrough: panel, idle BS/VBID/enhanced framing, scrambler
        // BS count, complete, bypass, PRBS. Streams remain disabled throughout.
        let l = self.layout;
        let phy = plan.phy.path.transmitter;
        let at = |r| DpStream::Dio(phy).at(l, r);
        self.update(at(0x2125), u32::MAX, 0)?;
        self.dp_training_update(plan, 3, 0x1103ffff, 0x10002000)?;
        self.update(at(0x2134), 0x3ff00, 0x1ff00)?;
        plan.phy.controls[5] = (plan.phy.controls[5] & !0x3ff00) | 0x1ff00;
        self.dp_training_update(plan, 1, 0x10, 0x10)?;
        self.update(at(0x212d), 0x10000, 0)?;
        self.dp_training_update(plan, 2, 1, 0)?;
        self.dp_training_verify(*plan)
    }
    async fn dp_training_finish(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
    ) -> Result<(), Error> {
        self.dp_training_idle(io, plan).await?;
        io.delay(5000).await;
        self.dp_training_verify(*plan)?;
        sink_config(io, *plan).await?;
        if read::<1>(io, plan.phy.path, 0x600).await?[0] & 7 != 1 {
            return Err(sink_readback(0x600));
        }
        if !eq_done(
            read::<6>(io, plan.phy.path, 0x202).await?,
            plan.phy.settings.lanes,
        ) {
            return Err(Error::DpTraining(DpTrainingError::LinkLost));
        }
        self.dp_training_verify(*plan)
    }
    /// The AUX reply timeout of `path`'s AUX engine (dce_aux_configure_timeout:
    /// AUX_RX_TIMEOUT_LEN in 8/16/32/64-us units by multiplier, capped at 127).
    pub(in crate::amdgpu_dcn401_otg) fn aux_timeout(
        &mut self,
        path: Path,
        us: u32,
    ) -> Result<(), Error> {
        const INCREMENT: u32 = 1016;
        let aux = path.aux.filter(|&a| a < 4).ok_or(Error::Invalid)?;
        let (mul, unit) = if us <= INCREMENT {
            (0, 8)
        } else if us <= 2 * INCREMENT {
            (1, 16)
        } else if us <= 4 * INCREMENT {
            (2, 32)
        } else {
            (3, 64)
        };
        let len = us.div_ceil(unit).min(127);
        let at = self.layout.base + (0x16bd + 0x1c * u64::from(aux)) * 4;
        self.update(at, 0x1_ff00, len << 8 | mul << 15)
    }
    pub(in super::super) async fn train_dp_link(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        downspread: bool,
        non_transparent: bool,
    ) -> Result<DpLinkTrained, Error> {
        if self.status.state != State::DpPhyReady(path.transmitter) || !io.ready() {
            return Err(Error::Busy);
        }
        let phy = self.status.dp_phy_ready.ok_or(Error::Invalid)?;
        if phy.path != path || path.aux.is_none_or(|a| a >= 4) {
            return Err(Error::Invalid);
        }
        self.dp_phy_on(phy)?;
        let mut plan = DpLinkTrained {
            phy,
            equalization: TrainingPattern::None,
            drive: DpDriveSettings::default(),
            downspread,
            cr_attempts: 0,
            eq_attempts: 0,
            fec: false,
            controls: [0; 4],
            fec_bits: 0,
        };
        for (i, (at, mask)) in plan.registers(self.layout).into_iter().enumerate() {
            plan.controls[i] = self.read(at)? & mask;
        }
        self.status.state = State::TrainingDp(path.transmitter);
        let mut result = async {
            let caps = self
                .dp_training_sink(io, &mut plan, non_transparent)
                .await?;
            plan.equalization = caps.pattern;
            // dp_perform_8b_10b_link_training: in non-transparent mode each
            // repeater, farthest from the sink first, is trained and then
            // told training is done (also on failure); the drive restarts at
            // level 0 for the next hop and for the sink.
            if let Some(r) = caps.lttpr.filter(|r| r.non_transparent) {
                for id in (1..=r.count).rev() {
                    let hop = Hop::Repeater(id);
                    let trained = async {
                        self.dp_training_cr(io, &mut plan, &caps, hop).await?;
                        self.dp_training_eq(io, &mut plan, &caps, hop).await
                    }
                    .await;
                    write(io, path, hop.pattern_set(), &mut [0]).await?;
                    trained?;
                    plan.drive = DpDriveSettings::default();
                }
            }
            self.dp_training_cr(io, &mut plan, &caps, Hop::Sink).await?;
            self.dp_training_eq(io, &mut plan, &caps, Hop::Sink).await?;
            self.dp_training_finish(io, &mut plan).await?;
            // dp_set_fec_enable: 1000 LL codes after training (6.173 us at
            // one RBR lane), then FEC on.
            if plan.fec {
                io.delay(7).await;
                self.dp_training_verify(plan)?;
                self.update(
                    DpStream::Dio(path.transmitter).at(self.layout, 0x212d),
                    FEC_EN,
                    FEC_EN,
                )?;
                plan.fec_bits |= FEC_EN;
                self.dp_training_verify(plan)?;
            }
            Ok(())
        }
        .await;
        // A confirmed CR/EQ failure still exits training, as native DC does.
        // Uncertain transport/MMIO failures must not issue speculative cleanup.
        let mut idle = false;
        if matches!(
            result,
            Err(Error::DpTraining(
                DpTrainingError::ClockRecovery
                    | DpTrainingError::Equalization
                    | DpTrainingError::LinkLost
            ))
        ) {
            // A link lost after the finish already ran the idle exit (the only
            // writer of the complete bit); re-verify it instead of replaying.
            let exit = if plan.controls[1] == 0 {
                self.dp_training_idle(io, &mut plan).await
            } else {
                self.dp_training_verify(plan)
            };
            match exit {
                Ok(()) => idle = true,
                Err(e) => result = Err(e),
            }
        }
        match result {
            Ok(()) => {
                self.status.dp_link_trained = Some(plan);
                self.status.state = State::DpLinkTrained(path.transmitter);
                Ok(plan)
            }
            // The sink refused this link and the source is proven back at
            // idle (idle pattern still enabled). As Linux's fallback does, the
            // link is then disabled (sink D3, PHY off) before a lower setting
            // re-enables the PHY: stop_dp_link accepts the retained plan.
            Err(e) if idle => {
                self.status.dp_link_trained = Some(plan);
                self.status.state = State::DpLinkRefused(path.transmitter);
                Err(e)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in super::super) async fn stop_dp_link(
        &mut self,
        io: &mut impl Transport,
        path: Path,
    ) -> Result<(), Error> {
        self.stop_dp_link_with(io, path, true).await
    }
    /// The sink is gone (debounced HPD low): stop without the sink D3 write,
    /// which could only time out. Linux ignores that write's failure.
    pub(in super::super) async fn stop_unplugged_dp_link(
        &mut self,
        io: &mut impl Transport,
        path: Path,
    ) -> Result<(), Error> {
        if self.hpd_sense(path)? {
            return Err(Error::Busy);
        }
        self.stop_dp_link_with(io, path, false).await
    }
    async fn stop_dp_link_with(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        sink: bool,
    ) -> Result<(), Error> {
        let t = path.transmitter;
        if !matches!(self.status.state, State::DpLinkTrained(x) | State::DpLinkRefused(x) if x == t)
            || !io.ready()
        {
            return Err(Error::Busy);
        }
        let plan = self.status.dp_link_trained.ok_or(Error::Invalid)?;
        if plan.phy.path != path {
            return Err(Error::Invalid);
        }
        // An attached display never stops the link it rides, nor the owner
        // while another display streams on it.
        if self.status.mst_owner.is_some()
            || self.displays.siblings.transmitters & bit(path.transmitter) != 0
        {
            return Err(Error::Busy);
        }
        self.dp_training_verify(plan)?;
        self.status.state = State::StoppingDpLink(path.transmitter);
        let result = async {
            if sink && !plan.phy.settings.mst {
                // Keep an idle MST branch powered for AUX/up requests. Our
                // polling manager remains enabled after the last stream stops.
                write(io, path, 0x600, &mut [2]).await?; // native sink D3 before PHY disable
                self.dp_training_verify(plan)?;
            }
            self.dp_phy_stop(io, plan.phy, plan.controls[0], 0x10)
                .await?;
            // dp_set_fec_ready(false) after the PHY: the sink's FEC
            // configuration cleared while it is connected (unchecked, as
            // Linux ignores it); dp_phy_stop cleared the source's.
            if sink && plan.fec {
                let _ = write(io, path, FEC_CONFIGURATION, &mut [0]).await;
            }
            if self.read(plan.registers(self.layout)[3].0)? & 0x1113ffff != plan.controls[3] {
                return Err(Error::Readback(plan.registers(self.layout)[3].0));
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.status.state = State::DpPhyDisabled;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// # Safety
    /// Same retained direct-port and writer/resource obligations as enable_dp_phy.
    /// No fixed-drive retimers, USB-C, eDP or MST; FEC as Linux keeps it. `downspread` matches
    /// the PHY's board/firmware SSC setting; this operation does not change SSC.
    /// `non_transparent` is the VBIOS LTTPR choice. No rate fallback or
    /// scanout. Retain owners after errors/cancellation.
    /// Set the AUX reply timeout of `path`'s AUX engine (us).
    /// # Safety
    /// Exclude concurrent AUX transactions on that engine.
    pub(crate) unsafe fn set_aux_timeout(&mut self, path: Path, us: u32) -> Result<(), Error> {
        self.0.aux_timeout(path, us)
    }
    /// The extended AUX timeout an LTTPR needs (Linux sets it before probing).
    pub const AUX_TIMEOUT_LTTPR_US: u32 = AUX_TIMEOUT_LTTPR_US;
    /// The default AUX timeout without one.
    pub const AUX_TIMEOUT_DEFAULT_US: u32 = AUX_TIMEOUT_DEFAULT_US;
    pub(crate) async unsafe fn train_dp_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
        downspread: bool,
        non_transparent: bool,
    ) -> Result<DpLinkTrained, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0
            .train_dp_link(io, path, downspread, non_transparent)
            .await
    }
    /// # Safety
    /// Same direct-port, writer-exclusion and memory-retention obligations. Only
    /// the matching trained link with no streams may be stopped. SST requests
    /// sink D3; MST keeps D0 for idle branch notifications. Neither grants
    /// analog-power or memory-release proof.
    pub(crate) async unsafe fn stop_dp_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_dp_link(io, path).await
    }
    /// Stop the link of a departed sink: no AUX, refused while HPD is high.
    /// # Safety
    /// As for `stop_dp_link`; the path's HPD block must sense this connector.
    pub(crate) async unsafe fn stop_unplugged_dp_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_unplugged_dp_link(io, path).await
    }
}
