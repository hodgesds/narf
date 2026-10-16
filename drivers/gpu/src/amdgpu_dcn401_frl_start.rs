//! Native HDMI FRL link start, training patterns and FFE, as Linux's
//! enable_link_hdmi_frl drives them on DCN401. The PHY, HDMICHARCLK and
//! the HPO FRL link encoder come up by firmware (hpo_frl_link_enc3_enable_
//! phy_output: DMUB transmitter control ENABLE, digmode 4); Linux never
//! calls the encoder's setup or the DCCG's HDMICHARCLK enable, so this
//! owner observes what the firmware brought up (inferred, not proven on
//! silicon). The SCDC side of training belongs to the DDC owner and the
//! caller; this owner sets the patterns the sink asks for
//! (hpo_frl_link_enc3_set_training_pattern) and switches the encoder to
//! FRL output (hpo_frl_link_enc3_enable_output). Stop is Linux's
//! disable_hpo_frl_link_output through the retirement paths.
use super::*;
use crate::amdgpu_dmub_navi48 as dmub;

/// A started FRL link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlLinkUp {
    pub path: Path,
    pub lanes: u8,
    /// The FRL character clock per lane, kHz.
    pub character_khz: u32,
    /// Observed physical lanes.
    pub physical_lanes: u8,
    /// The training patterns last set (register values, LTP - 1).
    pub patterns: [u8; 4],
    /// Whether the link sends training patterns instead of FRL packets.
    pub training: bool,
    /// Last firmware-acknowledged TxFFE level and de/pre-only flags.
    pub lane_set: u8,
}
pub(in super::super::super) trait FrlFirmware: phy::Firmware {
    fn enable_frl(
        &mut self,
        path: Path,
        lanes: u8,
        character_khz: u32,
    ) -> impl core::future::Future<Output = Result<(), dmub::Error>> + Send;
    fn frl_ffe(
        &mut self,
        path: Path,
        lanes: u8,
        character_khz: u32,
        lane_set: u8,
    ) -> impl core::future::Future<Output = Result<(), dmub::Error>> + Send;
}
impl FrlFirmware for dmub::Dmub {
    async fn enable_frl(
        &mut self,
        path: Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<(), dmub::Error> {
        self.enable_frl(path, lanes, character_khz).await
    }
    async fn frl_ffe(
        &mut self,
        path: Path,
        lanes: u8,
        character_khz: u32,
        lane_set: u8,
    ) -> Result<(), dmub::Error> {
        self.set_frl_ffe(path, lanes, character_khz, lane_set).await
    }
}
fn phy_reg(l: Layout, phy: u8, reg: u64) -> u64 {
    l.base + (reg + u64::from(phy) * 0xd8) * 4
}
/// The RDPCS lane status of `count` active lanes: CLK_RDY without reset,
/// disable or a pending handshake (as for DP), the rest off.
fn active_lanes(value: u32, count: u8) -> Option<u8> {
    let mut lanes = 0u8;
    for lane in 0..4 {
        let byte = (value >> (8 * lane)) & 0x3f;
        if byte & 0x37 == 4 {
            lanes |= 1 << lane;
        } else if byte & 0x3e != 2 {
            return None;
        }
    }
    (lanes.count_ones() == u32::from(count)).then_some(lanes)
}
impl<I: Io> Engine<I> {
    /// This owner's own started FRL link on `path`.
    pub(super) fn own_frl_link(&self, path: Path) -> bool {
        matches!(self.status.state,
            State::FrlLinkTraining(t) | State::FrlLinkActive(t) if t == path.transmitter)
            && self.status.frl_link.is_some_and(|l| l.path == path)
    }
    /// What the firmware's ENABLE brought up, and the training state.
    pub(in crate::amdgpu_dcn401_otg) fn frl_link_witnesses(
        &mut self,
        link: &FrlLinkUp,
    ) -> Result<(), Error> {
        let l = self.layout;
        let phy = link.path.transmitter;
        let lanes = phy_reg(l, phy, 0x2943);
        if active_lanes(self.read(lanes)?, link.lanes) != Some(link.physical_lanes) {
            return Err(Error::Readback(lanes));
        }
        let mut config = u32::from(link.lanes == 4) | u32::from(link.training) << 1;
        for (n, &p) in link.patterns.iter().enumerate() {
            config |= u32::from(p) << (16 + 4 * n);
        }
        for (at, mask, value) in [
            (
                phy_reg(l, phy, 0x2931),
                0x6f0,
                0x600 | u32::from(link.physical_lanes) << 4,
            ),
            (l.base + (0x179a + 3 * u64::from(phy)) * 4, 0x73, 1),
            (self.frl_at(LINK_CONTROL), 0x11, 1),
            (self.frl_at(LINK_CLOCK), 3, 3),
            (l.base + 0x4a * 4, 0x71, 1 | u32::from(phy) << 4),
            (l.base + (0x52 + u64::from(phy)) * 4, 0x31, 0x11),
            (self.frl_at(CONFIG), 0x7777_0007, config),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// Enable the PHY in FRL mode on `lanes` lanes at the character clock,
    /// the HPO FRL stream stopped and no other port routed to the encoder.
    pub(in super::super::super) async fn start_frl_link(
        &mut self,
        io: &mut impl FrlFirmware,
        path: Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<FrlLinkUp, Error> {
        if !io.ready() || !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != Connector::HdmiTypeA {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) || !matches!(lanes, 3 | 4) {
            return Err(Error::Invalid);
        }
        let phy = path.transmitter;
        self.frl_link_stream_stopped()?;
        self.frl_legacy_backend(phy)?;
        if self.frl_link_muxes()?.iter().any(|m| m & 3 == 1) {
            return Err(Error::Busy);
        }
        self.frl_link_off()?;
        for (at, mask) in [
            (phy_reg(self.layout, phy, 0x2943), 0x3c3c_3c3c),
            (phy_reg(self.layout, phy, 0x2931), 0x6f0),
        ] {
            if self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        let mut link = FrlLinkUp {
            path,
            lanes,
            character_khz,
            physical_lanes: 0,
            patterns: [0; 4],
            training: true,
            lane_set: 0,
        };
        self.status.state = State::FrlLinkTraining(phy);
        let result = async {
            io.enable_frl(path, lanes, character_khz)
                .await
                .map_err(Error::Firmware)?;
            let at = phy_reg(self.layout, phy, 0x2943);
            let deadline = narf_time::Deadline::after_us(100_000);
            loop {
                if let Some(mask) = active_lanes(self.read(at)?, lanes) {
                    link.physical_lanes = mask;
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout(at));
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
            }
            self.wait(self.frl_at(LINK_CLOCK), 3, 3, 100_000).await?;
            // The encoder idles in training with every pattern 0 (LTP1).
            let config = self.read(self.frl_at(CONFIG))?;
            if config & 2 == 0 {
                return Err(Error::Readback(self.frl_at(CONFIG)));
            }
            for n in 0..4 {
                link.patterns[n] = (config >> (16 + 4 * n) & 7) as u8;
            }
            self.frl_link_witnesses(&link)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.frl_link = Some(link);
                Ok(link)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    fn frl_training_link(&self, path: Path) -> Result<FrlLinkUp, Error> {
        let link = self.status.frl_link.ok_or(Error::Invalid)?;
        if self.status.state != State::FrlLinkTraining(path.transmitter) {
            return Err(Error::Busy);
        }
        if link.path != path {
            return Err(Error::Invalid);
        }
        Ok(link)
    }
    /// Only this selected display's stable link/video may accept live controls.
    fn frl_control_link(&mut self, path: Path) -> Result<FrlLinkUp, Error> {
        let link = self.status.frl_link.ok_or(Error::Invalid)?;
        if link.path != path {
            return Err(Error::Invalid);
        }
        match self.status.state {
            State::FrlLinkTraining(p) | State::FrlLinkActive(p) if p == path.transmitter => {
                self.frl_link_witnesses(&link)?;
            }
            State::FrlVideoRunning(pipe) | State::ScanoutRunning(pipe) => {
                let v = self.status.frl_video_running.ok_or(Error::Invalid)?;
                if v.request.pipe != pipe || v.link != link {
                    return Err(Error::Invalid);
                }
                if matches!(self.status.state, State::ScanoutRunning(_))
                    && !self
                        .status
                        .scanout
                        .is_some_and(|s| s.pipe == pipe && s.stream == pipe)
                {
                    return Err(Error::Invalid);
                }
                self.frl_video_verify_running(&v)?;
            }
            _ => return Err(Error::Busy),
        }
        Ok(link)
    }
    fn retain_frl_link(&mut self, link: FrlLinkUp) {
        self.status.frl_link = Some(link);
        if let Some(v) = self.status.frl_video_running.as_mut() {
            v.link = link;
        }
    }
    fn finish_frl_control(&mut self, link: FrlLinkUp, state: State) -> Result<(), Error> {
        match self.frl_link_witnesses(&link) {
            Ok(()) => {
                self.retain_frl_link(link);
                if let Some(v) = self.status.frl_video_running {
                    if let Err(e) = self.frl_video_verify_running(&v) {
                        self.status.state = State::Failed(e);
                        return Err(e);
                    }
                }
                self.status.state = state;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Current acknowledged FFE level, after checking the live route.
    pub(in super::super::super) fn frl_current_ffe(&mut self, path: Path) -> Result<u8, Error> {
        Ok(self.frl_control_link(path)?.lane_set & 3)
    }
    /// hpo_frl_link_enc3_set_training_pattern: training on, and each lane
    /// whose value is below 8 (LTP - 1) set; others left as they are.
    pub(in super::super::super) fn frl_training_pattern(
        &mut self,
        path: Path,
        patterns: [u8; 4],
    ) -> Result<(), Error> {
        let mut link = self.frl_control_link(path)?;
        let previous = self.status.state;
        let mut mask = 2;
        let mut value = 2;
        for (n, &p) in patterns.iter().enumerate() {
            if p < 8 {
                mask |= 0xf << (16 + 4 * n);
                value |= u32::from(p) << (16 + 4 * n);
                link.patterns[n] = p;
            }
        }
        link.training = true;
        self.status.state = State::UpdatingFrlLink(path.transmitter);
        if let Err(e) = self.update(self.frl_at(CONFIG), mask, value) {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        // A bare link returns to training; live video/fetch ownership stays.
        let state = if matches!(previous, State::FrlLinkActive(_)) {
            State::FrlLinkTraining(path.transmitter)
        } else {
            previous
        };
        self.finish_frl_control(link, state)
    }
    /// dpcs401_program_eq_setting: the TxFFE level and only-flags. An
    /// interrupted firmware command quarantines the entire retained display.
    pub(in super::super::super) async fn frl_ffe(
        &mut self,
        io: &mut impl FrlFirmware,
        path: Path,
        lane_set: u8,
    ) -> Result<(), Error> {
        if lane_set & !0x63 != 0 {
            return Err(Error::Invalid);
        }
        if !io.ready() {
            return Err(Error::Busy);
        }
        let mut link = self.frl_control_link(path)?;
        let previous = self.status.state;
        self.status.state = State::UpdatingFrlLink(path.transmitter);
        if let Err(e) = io
            .frl_ffe(path, link.lanes, link.character_khz, lane_set)
            .await
        {
            let e = Error::Firmware(e);
            self.status.state = State::Failed(e);
            return Err(e);
        }
        link.lane_set = lane_set;
        self.finish_frl_control(link, previous)
    }
    /// hpo_frl_link_enc3_enable_output: training off, FRL packets and gaps
    /// on the trained link.
    pub(in super::super::super) fn frl_link_output(&mut self, path: Path) -> Result<(), Error> {
        let mut link = self.frl_training_link(path)?;
        self.frl_link_witnesses(&link)?;
        self.status.state = State::UpdatingFrlLink(path.transmitter);
        if let Err(e) = self.update(self.frl_at(CONFIG), 2, 0) {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        link.training = false;
        self.finish_frl_control(link, State::FrlLinkActive(path.transmitter))
    }
    /// disable_hpo_frl_link_output: hpo_frl_link_enc3_disable (training
    /// pattern zero, encoder and clock off, RC compression restored), then
    /// the firmware DISABLE and HDMICHARCLK off.
    pub(in super::super::super) async fn stop_frl_link(
        &mut self,
        io: &mut impl FrlFirmware,
        path: Path,
    ) -> Result<(), Error> {
        if !self.own_frl_link(path) || !io.ready() {
            return Err(Error::Busy);
        }
        self.retire_frl_link(path).await?;
        self.disable_frl(io, path).await?;
        self.status.frl_link = None;
        Ok(())
    }
}
impl Otg {
    /// Enable the PHY of an HDMI port for FRL at `lanes` x the character
    /// clock, leaving the link training.
    /// # Safety
    /// Validated direct HDMI path with an FRL-capable sink; no other agent
    /// programs the PHY, HPO FRL encoders or their clocks.
    pub(crate) async unsafe fn start_frl_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<FrlLinkUp, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.start_frl_link(io, path, lanes, character_khz).await
    }
    /// Set the training patterns the sink requested (LTP - 1 per lane;
    /// 8 and above leave a lane as it is).
    /// # Safety
    /// As for `start_frl_link`.
    pub(crate) unsafe fn frl_training_pattern(
        &mut self,
        path: Path,
        patterns: [u8; 4],
    ) -> Result<(), Error> {
        self.0.frl_training_pattern(path, patterns)
    }
    /// Read the retained FFE level after validating the selected live link.
    pub(crate) fn frl_current_ffe(&mut self, path: Path) -> Result<u8, Error> {
        self.0.frl_current_ffe(path)
    }
    /// Program the transmitter's TxFFE (dpcs401_program_eq_setting's lane
    /// set).
    /// # Safety
    /// As for `start_frl_link`.
    pub(crate) async unsafe fn frl_ffe(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
        lane_set: u8,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.frl_ffe(io, path, lane_set).await
    }
    /// End training: FRL output on the trained link.
    /// # Safety
    /// As for `start_frl_link`.
    pub(crate) unsafe fn frl_link_output(&mut self, path: Path) -> Result<(), Error> {
        self.0.frl_link_output(path)
    }
    /// Stop this owner's FRL link.
    /// # Safety
    /// As for `start_frl_link`; the FRL stream stopped.
    pub(crate) async unsafe fn stop_frl_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_frl_link(io, path).await
    }
}
