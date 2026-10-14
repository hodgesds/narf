//! Native untrained legacy DP SST PHY bring-up. Linux dcn401_link_encoder_setup,
//! enc1_configure_encoder and dcn10_link_encoder_enable_dp_output, via DMUB.
use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use core::future::Future;
pub use dmub::DpPhySettings;
#[path = "amdgpu_dcn401_dp_training.rs"]
pub(super) mod training;
pub use training::{
    DpDriveSettings, DpFrontendReady, DpFrontendRequest, DpLinkStatus, DpLinkTrained,
    DpTrainingError, DpVideoRunning,
};

const LANES_MASK: u32 = 0x3e3e3e3e;
const LANES_OFF: u32 = 0x02020202;
const TX_CLOCKS: u32 = 0x6f0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpPhyReady {
    pub path: Path,
    pub settings: DpPhySettings,
    /// Observed physical lane mask, independent of board lane reversal/mapping.
    pub physical_lanes: u8,
    controls: [u32; 6],
}
impl DpPhyReady {
    fn registers(self, l: Layout) -> [(u64, u32); 6] {
        let at = |r| DpStream::Dio(self.path.transmitter).at(l, r);
        [
            (
                l.base + (0x179a + 3 * u64::from(self.path.transmitter)) * 4,
                0x773,
            ),
            (at(0x20bc), 0x70007f01), // HPD, frontend selection, dual-link
            (at(0x20bb), 0x77),       // mode, clock request, resets
            (at(0x20bd), 1),          // backend enable
            (at(0x2121), u32::MAX),   // native DP_CONFIG is a whole-register write
            (at(0x2134), 0x0103ff11), // scrambler configuration
        ]
    }
}
pub(super) trait Firmware {
    fn ready(&self) -> bool;
    fn enable(
        &mut self,
        path: Path,
        settings: DpPhySettings,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn disable(&mut self, path: Path) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn enable(&mut self, path: Path, settings: DpPhySettings) -> Result<(), dmub::Error> {
        self.enable_dp_sst(path, settings).await
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.disable_dp_sst(path).await
    }
}
fn phy_at(l: Layout, phy: u8, reg: u64) -> u64 {
    l.base + (reg + u64::from(phy) * 0xd8) * 4
}
fn active_lanes(value: u32, count: u8) -> Option<u8> {
    let mut lanes = 0u8;
    for lane in 0..4 {
        let byte = (value >> (8 * lane)) & 0x3f;
        if byte & 0x37 == 4 {
            // CLK_RDY without reset, disable or a pending handshake. DATA_EN
            // is not a training witness; firmware may leave it set or clear.
            lanes |= 1 << lane;
        } else if byte & 0x3e != 2 {
            return None;
        }
    }
    (lanes.count_ones() == u32::from(count)).then_some(lanes)
}
impl<I: Io> Engine<I> {
    fn dp_phy_consumers(&mut self, phy: u8) -> Result<(), Error> {
        self.dp_phy_consumers_owned(phy, None, None)
    }
    fn dp_phy_consumers_owned(
        &mut self,
        phy: u8,
        frontend: Option<u8>,
        timing: Option<u8>,
    ) -> Result<(), Error> {
        let l = self.layout;
        let s = self.displays.siblings;
        if s.transmitters & bit(phy) != 0
            || frontend.is_some_and(|f| s.streams & bit(f) != 0)
            || timing.is_some_and(|p| s.pipes & bit(p) != 0)
        {
            return Err(Error::Busy); // another display's
        }
        let at = |r| DpStream::Dio(phy).at(l, r);
        // The selected backend/PHY and any retained frontend/timing have their
        // own configuration and transition witnesses. All unrelated consumers
        // must be stopped. No inherited active-link adoption.
        for (reg, mask) in l.idle {
            if [
                at(0x20bb),
                at(0x20bd),
                phy_at(l, phy, 0x2943),
                phy_at(l, phy, 0x2931),
            ]
            .contains(&reg)
                || frontend.is_some_and(|f| {
                    [0x2094, 0x2095, 0x209b, 0x2122]
                        .iter()
                        .any(|&r| reg == DpStream::Dio(f).at(l, r))
                })
                || timing.is_some_and(|p| reg == l.otg(p, CONTROL) || reg == l.otg(p, CLOCK))
                || self.sibling_register(reg)
            {
                continue;
            }
            if self.read(reg)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        for (reg, mask) in [(0x2125, 0x11), (0x212d, 0x010101ff)] {
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        if self.read(l.link_clock - 4)? & 0x8888 != 0
            || self.read(l.base + (0x52 + u64::from(phy)) * 4)? & 1 != 0
        {
            return Err(Error::Busy);
        }
        let bank1 = l.link_clock - 0x66 * 4;
        let sources = self.read(bank1 + 0x68 * 4)?;
        let siblings = self.displays.siblings;
        for p in 0..4 {
            // Another display's stream and clock route are its own.
            let other = |mask: u8| mask & 1 << p != 0;
            if frontend != Some(p) && !other(siblings.streams) {
                self.dp_encoder_quiet(DpStream::Dio(p))?;
            }
            self.dp_encoder_quiet(DpStream::Hpo(p))?;
            if (frontend != Some(p)
                && !other(siblings.streams)
                && self.read(l.dio_clock + u64::from(p) * 4)? & 0x10 != 0)
                || self.read(l.otg(p, LOCK))? & 0x101 != 0
                || self.read(l.otg(p, CLOCK))? & 0x10 != 0
            {
                return Err(Error::Busy);
            }
            // Another display's running timing has its own pixel source
            // (its PHY, for TMDS); it never feeds from this PHY.
            if other(siblings.pipes) {
                continue;
            }
            // Prepared, stopped timing may retain clocks only from a live
            // DPREF/DTB DTO. Never start or stop a PHY feeding TMDS timing.
            let pixel = self.read(bank1 + (0x80 + 4 * u64::from(p)) * 4)? & 0x1393;
            let timing = self.read(l.otg(p, CLOCK))? & 0x10103 != 0
                || self.read(l.odm(p, INPUT_CLOCK))? & 7 != 0
                || self.read(l.vtg(p))? & 0x80000000 != 0;
            if (timing || pixel & 0x90 != 0)
                && (pixel & 0x1390 != 0x1090 || !matches!((sources >> (3 * p)) & 7, 4 | 6))
            {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn dp_phy_controls(&mut self, plan: DpPhyReady) -> Result<(), Error> {
        self.dp_phy_untrained(plan.path.transmitter)?;
        self.dp_phy_configuration(plan)
    }
    fn dp_phy_untrained(&mut self, phy: u8) -> Result<(), Error> {
        for (reg, mask) in [(0x211e, 0x10), (0x212e, 3), (0x2133, 1)] {
            if self.read(DpStream::Dio(phy).at(self.layout, reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn dp_phy_configuration(&mut self, plan: DpPhyReady) -> Result<(), Error> {
        self.dp_phy_configuration_owned(plan, None, None)
    }
    fn dp_phy_configuration_owned(
        &mut self,
        plan: DpPhyReady,
        frontend: Option<u8>,
        timing: Option<u8>,
    ) -> Result<(), Error> {
        self.dp_phy_consumers_owned(plan.path.transmitter, frontend, timing)?;
        for ((at, mask), expected) in plan.registers(self.layout).into_iter().zip(plan.controls) {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    fn dp_phy_off(&mut self, phy: u8) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, expected) in [
            (
                DpStream::Dio(phy).at(l, 0x20bb),
                clocks::backend_clock_mask(phy) | 0x60,
                0,
            ),
            (DpStream::Dio(phy).at(l, 0x20bd), 1, 0),
        ] {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        self.dp_phy_lanes_off(phy)
    }
    fn dp_phy_lanes_off(&mut self, phy: u8) -> Result<(), Error> {
        for (at, mask, expected) in [
            (phy_at(self.layout, phy, 0x2943), LANES_MASK, LANES_OFF),
            (phy_at(self.layout, phy, 0x2931), TX_CLOCKS, 0),
        ] {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    fn dp_phy_plan(&mut self, path: Path, settings: DpPhySettings) -> Result<DpPhyReady, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != Connector::DisplayPort {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) || settings.validate().is_err() {
            return Err(Error::Invalid);
        }
        self.dp_phy_consumers(path.transmitter)?;
        self.dp_phy_untrained(path.transmitter)?;
        self.dp_phy_off(path.transmitter)?;
        let mut plan = DpPhyReady {
            path,
            settings,
            physical_lanes: 0,
            controls: [0; 6],
        };
        for (i, (at, mask)) in plan.registers(self.layout).into_iter().enumerate() {
            plan.controls[i] = self.read(at)? & mask;
        }
        if plan.controls[1] & 0x7f01 != 0 || plan.controls[5] & 1 != 0 {
            return Err(Error::Busy);
        }
        Ok(plan)
    }
    async fn dp_phy_start(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut DpPhyReady,
    ) -> Result<(), Error> {
        // Keep each native setup write separate. Revalidate routes and quiet
        // consumers before publishing the firmware command, and after waits.
        let regs = plan.registers(self.layout);
        for (slot, mask, value) in [
            (0, 3, 0),
            (1, 0x70000000, u32::from(plan.path.hpd - 1) << 28),
            (2, 7, 0),
            (2, 0x10, 0x10),
            (3, 1, 1),
            (4, u32::MAX, u32::from(plan.settings.lanes - 1)),
            (5, 0x10, 0x10),
        ] {
            self.dp_phy_controls(*plan)?;
            self.dp_phy_lanes_off(plan.path.transmitter)?;
            self.update(regs[slot].0, mask, value)?;
            plan.controls[slot] = (plan.controls[slot] & !mask) | value;
        }
        self.dp_phy_controls(*plan)?;
        self.dp_phy_lanes_off(plan.path.transmitter)?;
        firmware
            .enable(plan.path, plan.settings)
            .await
            .map_err(Error::Firmware)?;
        let l = self.layout;
        let phy = plan.path.transmitter;
        let lanes = phy_at(l, phy, 0x2943);
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            if let Some(mask) = active_lanes(self.read(lanes)?, plan.settings.lanes) {
                plan.physical_lanes = mask;
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout(lanes));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
        }
        self.wait(
            phy_at(l, phy, 0x2931),
            TX_CLOCKS,
            0x600 | u32::from(plan.physical_lanes) << 4,
            100_000,
        )
        .await?;
        self.wait(
            DpStream::Dio(phy).at(l, 0x20bb),
            clocks::backend_clock_mask(phy),
            0x810,
            100_000,
        )
        .await?;
        self.dp_phy_on(*plan)
    }
    fn dp_phy_on(&mut self, plan: DpPhyReady) -> Result<(), Error> {
        self.dp_phy_controls(plan)?;
        self.dp_phy_witnesses(plan)
    }
    fn dp_phy_witnesses(&mut self, plan: DpPhyReady) -> Result<(), Error> {
        let l = self.layout;
        let phy = plan.path.transmitter;
        let lanes = phy_at(l, phy, 0x2943);
        if active_lanes(self.read(lanes)?, plan.settings.lanes) != Some(plan.physical_lanes) {
            return Err(Error::Readback(lanes));
        }
        for (at, mask, value) in [
            (
                phy_at(l, phy, 0x2931),
                TX_CLOCKS,
                0x600 | u32::from(plan.physical_lanes) << 4,
            ),
            (
                DpStream::Dio(phy).at(l, 0x20bb),
                clocks::backend_clock_mask(phy),
                0x810,
            ),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    pub(super) async fn enable_dp_phy(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
        settings: DpPhySettings,
    ) -> Result<DpPhyReady, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.dp_phy_plan(path, settings)?;
        self.status.state = State::EnablingDpPhy(path.transmitter);
        match self.dp_phy_start(firmware, &mut plan).await {
            Ok(()) => {
                self.status.dp_phy_ready = Some(plan);
                self.status.state = State::DpPhyReady(path.transmitter);
                Ok(plan)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn dp_phy_stop(
        &mut self,
        firmware: &mut impl Firmware,
        mut plan: DpPhyReady,
        pattern: u32,
        complete: u32,
    ) -> Result<(), Error> {
        firmware.disable(plan.path).await.map_err(Error::Firmware)?;
        let l = self.layout;
        let phy = plan.path.transmitter;
        let at = |r| DpStream::Dio(phy).at(l, r);
        self.wait(at(0x20bd), 1, 0, 100_000).await?;
        self.wait(
            at(0x20bb),
            clocks::backend_clock_mask(phy) | 0x67,
            0,
            100_000,
        )
        .await?;
        self.wait(phy_at(l, phy, 0x2943), LANES_MASK, LANES_OFF, 100_000)
            .await?;
        self.wait(phy_at(l, phy, 0x2931), TX_CLOCKS, 0, 100_000)
            .await?;
        plan.controls[2] = 0;
        plan.controls[3] = 0;
        self.dp_phy_configuration(plan)?;
        for (reg, mask, expected) in [
            (0x212e, 3, pattern),
            (0x211e, 0x10, complete),
            (0x2133, 1, 0),
        ] {
            if self.read(at(reg))? & mask != expected {
                return Err(Error::Readback(at(reg)));
            }
        }
        self.dp_phy_off(phy)?;
        // Native disable_output cleanup after the backend stops.
        for (r, mask) in [(0x212e, 3), (0x211e, 0x10), (0x2125, 0x11)] {
            self.update(at(r), mask, 0)?;
        }
        self.dp_phy_controls(plan)?;
        self.dp_phy_off(phy)
    }
    pub(super) async fn disable_dp_phy(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
    ) -> Result<(), Error> {
        if self.status.state != State::DpPhyReady(path.transmitter) || !firmware.ready() {
            return Err(Error::Busy);
        }
        let plan = self.status.dp_phy_ready.ok_or(Error::Invalid)?;
        if plan.path != path {
            return Err(Error::Invalid);
        }
        self.dp_phy_on(plan)?;
        self.status.state = State::DisablingDpPhy(path.transmitter);
        match self.dp_phy_stop(firmware, plan, 0, 0).await {
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
    /// Validated direct external DP SST path, without USB-C/ACPI interlocks or
    /// SSC workarounds; settings supported by board, sink and cable. Retire all
    /// streams and sink/audio/metadata/HDCP/FEC work. Exclude CPU/firmware/FAMS,
    /// display/link/clock/power/reset writers and retain all memory/translations.
    /// Success proves an untrained PHY only; sink power and training are separate.
    pub(crate) async unsafe fn enable_dp_phy(
        &mut self,
        clocks: &mut clocks::ClockManager,
        firmware: &mut dmub::Dmub,
        path: Path,
        settings: DpPhySettings,
    ) -> Result<DpPhyReady, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let (held, layout) = self.0.held();
        clocks
            .pipe_clocks_except(self.0.io.0, &|at| held_by_sibling(held, layout, at))
            .map_err(Error::Clocks)?;
        self.0.enable_dp_phy(firmware, path, settings).await
    }
    /// # Safety
    /// Same direct-port, producer/writer exclusion and retention obligations as
    /// enable_dp_phy. Only the matching still-untrained PHY can be disabled.
    /// Success proves backend/lane/clock stop, not analog power or memory release.
    pub(crate) async unsafe fn disable_dp_phy(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.disable_dp_phy(firmware, path).await
    }
}
