//! Direct legacy DP SST training: native DC source patterns/drive programming,
//! board-routed DPCD transactions and fresh CR/EQ/link-loss checks. No repeaters,
//! MST, FEC, automated rate fallback, stream output or scanout allocation reuse.
use super::*;
use crate::dp_link_training::{LinkRate, TrainingPattern};
pub use dmub::DpDriveSettings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpTrainingError {
    InvalidCaps,
    SinkReadback(u32),
    ClockRecovery,
    Equalization,
    LinkLost,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpLinkTrained {
    pub phy: DpPhyReady,
    pub equalization: TrainingPattern,
    pub drive: DpDriveSettings,
    pub downspread: bool,
    pub cr_attempts: u8,
    pub eq_attempts: u8,
    controls: [u32; 4],
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
struct Caps {
    pattern: TrainingPattern,
    cr_us: u64,
    eq_us: u64,
}
impl Caps {
    fn parse(
        dpcd: [u8; 16],
        interval: u8,
        settings: DpPhySettings,
        downspread: bool,
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
        let interval_us =
            [400, 4000, 8000, 12000, 16000, 32000, 64000][usize::from(interval & 0x7f)];
        Ok(Self {
            pattern,
            // AMD's native CR interval uses the base DPCD 0xE byte, including
            // its extended-capability bit for the 100/400-us default choice.
            cr_us: if dpcd[0] < 0x12 || interval == 0 {
                100
            } else if interval & 0x7f == 0 {
                400
            } else {
                u64::from(interval & 0x7f) * 4000
            },
            eq_us: if dpcd[0] < 0x12 { 400 } else { interval_us },
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
    Ok(())
}
impl<I: Io> Engine<I> {
    fn dp_training_verify(&mut self, plan: DpLinkTrained) -> Result<(), Error> {
        self.dp_phy_configuration(plan.phy)?;
        self.dp_phy_witnesses(plan.phy)?;
        for ((at, mask), expected) in plan.registers(self.layout).into_iter().zip(plan.controls) {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
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
        plan: DpLinkTrained,
    ) -> Result<Caps, Error> {
        let path = plan.phy.path;
        let rev = read::<1>(io, path, 0).await?[0];
        if !matches!(rev, 0x11..=0x14 | 0x20 | 0x21) {
            return Err(invalid_caps());
        }
        self.dp_training_verify(plan)?;
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
        let caps = Caps::parse(dpcd, interval, plan.phy.settings, plan.downspread)?;
        // NACK of the optional repeater capability block means no advertised
        // LTTPR. DEFER/timeout/protocol failures must not be mistaken for absence.
        match read::<8>(io, path, 0xf0000).await {
            Ok(r) if r == [0; 8] || matches!(r[0], 0x14 | 0x20) && r[2] == 0 => {}
            Err(Error::Firmware(dmub::Error::Aux(1))) => {}
            Ok(_) => return Err(Error::Unsupported),
            Err(e) => return Err(e),
        }
        if dpcd[0] >= 0x12 && read::<1>(io, path, 0x111).await?[0] & 7 != 0 {
            return Err(Error::Busy); // active MST/up-request owner
        }
        if dpcd[0] >= 0x14
            && read::<1>(io, path, 0x90).await?[0] & 1 != 0
            && read::<1>(io, path, 0x120).await?[0] & 1 != 0
        {
            return Err(Error::Busy);
        }
        self.dp_training_verify(plan)?;
        write(io, path, 0x102, &mut [0]).await?;
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
        sink_config(io, plan).await?;
        self.dp_training_verify(plan)?;
        Ok(caps)
    }
    async fn dp_training_round(
        &mut self,
        io: &mut impl Transport,
        plan: DpLinkTrained,
        pattern: TrainingPattern,
        first: bool,
        delay: u64,
    ) -> Result<[u8; 6], Error> {
        self.dp_training_drive(io, plan).await?;
        let mut data = [dpcd_drive(plan.drive); 5];
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
                0x102,
                &mut data[..usize::from(plan.phy.settings.lanes) + 1],
            )
            .await?;
        } else {
            write(
                io,
                plan.phy.path,
                0x103,
                &mut data[..usize::from(plan.phy.settings.lanes)],
            )
            .await?;
        }
        io.delay(delay).await;
        self.dp_training_verify(plan)?;
        let status = read::<6>(io, plan.phy.path, 0x202).await?;
        self.dp_training_verify(plan)?;
        Ok(status)
    }
    async fn dp_training_cr(
        &mut self,
        io: &mut impl Transport,
        plan: &mut DpLinkTrained,
        caps: &Caps,
    ) -> Result<(), Error> {
        self.dp_training_pattern(plan, TrainingPattern::Tps1)?;
        let mut same_swing = 0;
        for attempt in 0..100 {
            plan.cr_attempts = attempt + 1;
            let status = self
                .dp_training_round(io, *plan, TrainingPattern::Tps1, attempt == 0, caps.cr_us)
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
    ) -> Result<(), Error> {
        self.dp_training_pattern(plan, caps.pattern)?;
        for attempt in 0..6 {
            plan.eq_attempts = attempt + 1;
            let status = self
                .dp_training_round(io, *plan, caps.pattern, attempt == 0, caps.eq_us)
                .await?;
            if !cr_done(status, plan.phy.settings.lanes) {
                return Err(Error::DpTraining(DpTrainingError::LinkLost));
            }
            if eq_done(status, plan.phy.settings.lanes) {
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
    pub(in super::super) async fn train_dp_link(
        &mut self,
        io: &mut impl Transport,
        path: Path,
        downspread: bool,
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
            controls: [0; 4],
        };
        for (i, (at, mask)) in plan.registers(self.layout).into_iter().enumerate() {
            plan.controls[i] = self.read(at)? & mask;
        }
        self.status.state = State::TrainingDp(path.transmitter);
        let mut result = async {
            let caps = self.dp_training_sink(io, plan).await?;
            plan.equalization = caps.pattern;
            self.dp_training_cr(io, &mut plan, &caps).await?;
            self.dp_training_eq(io, &mut plan, &caps).await?;
            self.dp_training_finish(io, &mut plan).await
        }
        .await;
        // A confirmed CR/EQ failure still exits training, as native DC does.
        // Uncertain transport/MMIO failures must not issue speculative cleanup.
        if matches!(
            result,
            Err(Error::DpTraining(
                DpTrainingError::ClockRecovery
                    | DpTrainingError::Equalization
                    | DpTrainingError::LinkLost
            ))
        ) && plan.controls[1] == 0
        {
            if let Err(e) = self.dp_training_idle(io, &mut plan).await {
                result = Err(e);
            }
        }
        match result {
            Ok(()) => {
                self.status.dp_link_trained = Some(plan);
                self.status.state = State::DpLinkTrained(path.transmitter);
                Ok(plan)
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
        if self.status.state != State::DpLinkTrained(path.transmitter) || !io.ready() {
            return Err(Error::Busy);
        }
        let plan = self.status.dp_link_trained.ok_or(Error::Invalid)?;
        if plan.phy.path != path {
            return Err(Error::Invalid);
        }
        self.dp_training_verify(plan)?;
        self.status.state = State::StoppingDpLink(path.transmitter);
        let result = async {
            write(io, path, 0x600, &mut [2]).await?; // native sink D3 before PHY disable
            self.dp_training_verify(plan)?;
            self.dp_phy_stop(io, plan.phy, plan.controls[0], 0x10)
                .await?;
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
    /// No LTTPR, fixed-drive retimers, USB-C, eDP, MST or FEC. `downspread` matches
    /// the PHY's board/firmware SSC setting; this operation does not change SSC.
    /// No rate fallback or scanout. Retain owners after errors/cancellation.
    pub(crate) async unsafe fn train_dp_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
        downspread: bool,
    ) -> Result<DpLinkTrained, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.train_dp_link(io, path, downspread).await
    }
    /// # Safety
    /// Same direct-port, writer-exclusion and memory-retention obligations. Only
    /// the matching trained link with no streams may be stopped. Sink D3 is an
    /// acknowledged request; no analog-power or memory-release proof is granted.
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
}
