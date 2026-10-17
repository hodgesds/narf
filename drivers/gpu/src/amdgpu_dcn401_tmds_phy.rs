//! Native TMDS transmitter disable after frontend and timing-clock retirement.
//! Park only PHY-fed frontend symclk routes (dccg401_disable_symclk_se), then
//! issue dcn10_link_encoder_disable_output's DMUB command and observe hardware.
use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use core::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmdsDisabled {
    pub path: Path,
    pub parked_frontends: u8,
    pub command_sent: bool,
}
pub(super) trait Firmware {
    fn ready(&self) -> bool;
    fn disable(&mut self, path: Path) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.disable_tmds(path).await
    }
}
struct Plan {
    result: TmdsDisabled,
    links: tmds_timing::Links,
    roots: [u32; 4],
}
fn phy_at(l: Layout, phy: u8, reg: u64) -> u64 {
    l.base + (reg + u64::from(phy) * 0xd8) * 4
}
impl<I: Io> Engine<I> {
    fn tmds_phy_consumers(&mut self, phy: u8) -> Result<(), Error> {
        let l = self.layout;
        // Conservative until per-OTG PHY clock routing has an owner: every
        // timing generator and input clock must be off, including inherited
        // clock requests and late busy/ON acknowledgements.
        for p in 0..4 {
            for (reg, mask) in [
                (l.otg(p, CONTROL), 0x10001),
                (l.otg(p, CLOCK), 0x10113),
                (l.otg(p, LOCK), 0x101),
                (l.odm(p, INPUT_CLOCK), 7),
                (l.odm(p, 0x1aca), 0x80000001),
                (l.vtg(p), 0x80000000),
            ] {
                if self.read(reg)? & mask != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        // No HPO stream root or forced DCIO->PHY clock may use this PLL.
        if self.read(l.link_clock - 4)? & 0x8888 != 0
            || self.read(l.base + (0x52 + u64::from(phy)) * 4)? & 1 != 0
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn tmds_phy_plan(&mut self, path: Path) -> Result<Plan, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != Connector::HdmiTypeA {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) {
            return Err(Error::Invalid);
        }
        let phy = path.transmitter;
        self.tmds_phy_consumers(phy)?;
        let links = self.tmds_timing_links()?;
        let [route, clock, enabled, mux, lanes, tx] = links.registers[usize::from(phy)];
        if route >> 28 != u32::from(path.hpd - 1) {
            return Err(Error::Invalid);
        }
        if mux & 3 != 0 || !matches!(clock & 7, 0 | 3) {
            return Err(Error::Unsupported);
        }
        if enabled != 0 {
            if clock & 0x17 != 0x13 {
                return Err(Error::Busy);
            }
        } else if clock & clocks::backend_clock_mask(phy) != 0 || lanes != 0x02020202 || tx != 0 {
            // Linux skips DISABLE for an inactive DIG. Never replay a PHY
            // command over an inherited, incomplete shutdown.
            return Err(Error::Busy);
        }
        let mut plan = Plan {
            result: TmdsDisabled {
                path,
                parked_frontends: 0,
                command_sent: enabled != 0,
            },
            links,
            roots: [0; 4],
        };
        for p in 0..4 {
            let root = self.read(self.layout.dio_clock + 4 * p)? & 0x710;
            let source = (root >> 8) & 7;
            if root & 0x10 != 0 && source >= 4 {
                return Err(Error::Unsupported);
            }
            if root != 0 && source == u32::from(phy) {
                plan.result.parked_frontends |= 1 << p;
            }
            plan.roots[p as usize] = root;
        }
        Ok(plan)
    }
    fn tmds_phy_unchanged(&mut self, plan: &Plan, disabled: bool) -> Result<(), Error> {
        let phy = plan.result.path.transmitter;
        self.tmds_phy_consumers(phy)?;
        let links = self.tmds_timing_links()?;
        for p in 0..4 {
            let old = plan.links.registers[p];
            let new = links.registers[p];
            if (!disabled || p != usize::from(phy)) && new != old
                || new[0] != old[0]
                || new[3] != old[3]
            {
                return Err(Error::Busy);
            }
            let at = self.layout.dio_clock + 4 * p as u64;
            if self.read(at)? & 0x710 != plan.roots[p] {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    fn tmds_phy_off(&mut self, phy: u8) -> Result<(), Error> {
        let l = self.layout;
        for (reg, mask, value) in [
            (DpStream::Dio(phy).at(l, 0x20bd), 1, 0),
            (
                DpStream::Dio(phy).at(l, 0x20bb),
                clocks::backend_clock_mask(phy) | 0x60,
                0,
            ),
            (phy_at(l, phy, 0x2943), 0x3e3e3e3e, 0x02020202),
            (phy_at(l, phy, 0x2931), 0x6f0, 0),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        let at = DpStream::Dio(phy).at(l, 0x20bb);
        if !matches!(self.read(at)? & 7, 0 | 3) {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    async fn tmds_phy_disable(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut Plan,
    ) -> Result<(), Error> {
        let phy = plan.result.path.transmitter;
        for p in 0..4 {
            if plan.result.parked_frontends & (1 << p) != 0 {
                self.update(self.layout.dio_clock + 4 * p, 0x710, 0)?;
                plan.roots[p as usize] = 0;
            }
        }
        self.tmds_phy_unchanged(plan, false)?;
        if plan.result.command_sent {
            firmware
                .disable(plan.result.path)
                .await
                .map_err(Error::Firmware)?;
            // Transport consumption is not completion. Firmware owns backend
            // and RDPCS controls; observe them, never manufacture off witnesses.
            let l = self.layout;
            self.wait(DpStream::Dio(phy).at(l, 0x20bd), 1, 0, 100_000)
                .await?;
            self.wait(
                DpStream::Dio(phy).at(l, 0x20bb),
                clocks::backend_clock_mask(phy) | 0x60,
                0,
                100_000,
            )
            .await?;
            self.wait(phy_at(l, phy, 0x2943), 0x3e3e3e3e, 0x02020202, 100_000)
                .await?;
            self.wait(phy_at(l, phy, 0x2931), 0x6f0, 0, 100_000).await?;
        }
        self.tmds_phy_unchanged(plan, true)?;
        self.tmds_phy_off(phy)
    }
    pub(super) async fn disable_tmds(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
    ) -> Result<TmdsDisabled, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.tmds_phy_plan(path)?;
        self.status.state = State::DisablingTmds(path.transmitter);
        match self.tmds_phy_disable(firmware, &mut plan).await {
            Ok(()) => {
                self.status.tmds_disabled = Some(plan.result);
                self.status.state = State::TmdsDisabled;
                Ok(plan.result)
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
    /// Path is from this GPU's validated inventory, direct external TMDS HDMI,
    /// without ACPI PHY interlocks or SSC workarounds. Independently handle
    /// sink AVMUTE/SCDC/retimers and audio/metadata/HDCP teardown. Retire all
    /// frontends and timing clocks, exclude CPU/firmware/FAMS and concurrent
    /// display/link/clock/power/reset writers, and retain all allocations and
    /// translations. Success proves backend/lane/TX-clock readback only, not
    /// analog power gating or memory retirement. Retain the owner on failure/cancel.
    pub(crate) async unsafe fn disable_tmds(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: Path,
    ) -> Result<TmdsDisabled, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.disable_tmds(firmware, path).await
    }
}
