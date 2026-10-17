//! Native HPO transmitter DISABLE after digital-link retirement. RDPCS is
//! firmware-owned: software observes lane/TX-clock shutdown, then parks only
//! the selected SYMCLK32_LE route (Linux dccg401_disable_symclk32_le).
use super::*;
use crate::amdgpu_dmub_navi48::{self as dmub, DpSignal};
use core::future::Future;

const PHY_CLOCK: u64 = 0x2931;
const PHY_LANES: u64 = 0x2943;
const LANES_MASK: u32 = 0x3e3e3e3e; // DISABLE, CLK_RDY, DATA_EN, REQ, ACK
const LANES_OFF: u32 = 0x02020202;
const TX_CLOCKS: u32 = 0x6f0; // four lane requests, TX clock request and ON

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpoDpDisabled {
    pub path: Path,
    pub link: u8,
    pub signal: DpSignal,
    pub command_sent: bool,
}
pub(in super::super) trait Firmware {
    fn ready(&self) -> bool;
    fn disable(
        &mut self,
        path: Path,
        signal: DpSignal,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn disable(&mut self, path: Path, signal: DpSignal) -> Result<(), dmub::Error> {
        self.disable_hpo_dp(path, signal).await
    }
}
struct PhyPlan {
    digital: Plan,
    root: u32,
    result: HpoDpDisabled,
}
fn phy_at(layout: Layout, phy: u8, reg: u64) -> u64 {
    layout.base + (reg + u64::from(phy) * 0xd8) * 4
}
impl<I: Io> Engine<I> {
    fn hpo_phy_plan(&mut self, path: Path, signal: DpSignal) -> Result<PhyPlan, Error> {
        if !(1..=4).contains(&path.hpd) {
            return Err(Error::Invalid);
        }
        let digital = self.hpo_link_plan(path)?;
        // Never trust a historical HpoLinkRetired snapshot. This call may also
        // adopt an inherited, already stopped link after the same live checks.
        self.hpo_stopped(&digital)?;
        let root = self.read(self.layout.link_clock)?;
        for i in 0..4 {
            if i != digital.result.link
                && (root >> (i * 4)) & 0xf == u32::from(path.transmitter) | 8
            {
                return Err(Error::Busy);
            }
        }
        self.hpo_legacy_stopped(path.transmitter)?;
        let lanes = self.read(phy_at(self.layout, path.transmitter, PHY_LANES))?;
        let clocks = self.read(phy_at(self.layout, path.transmitter, PHY_CLOCK))?;
        // Do not interrupt an inherited PHY handshake. Reset may stay asserted
        // on disabled lanes; its request bit is not a completion indication.
        if lanes & 0x30303030 != 0 {
            return Err(Error::Busy);
        }
        let command_sent = lanes & LANES_MASK != LANES_OFF || clocks & TX_CLOCKS != 0;
        if command_sent && digital.root_clock != u32::from(path.transmitter) | 8 {
            return Err(Error::Busy);
        }
        Ok(PhyPlan {
            result: HpoDpDisabled {
                path,
                link: digital.result.link,
                signal,
                command_sent,
            },
            digital,
            root,
        })
    }
    fn hpo_legacy_stopped(&mut self, phy: u8) -> Result<(), Error> {
        for (reg, mask) in [
            (0x20bd, 1),
            (0x20bb, clocks::backend_clock_mask(phy) | 0x60),
        ] {
            if self.read(DpStream::Dio(phy).at(self.layout, reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn hpo_phy_off(&mut self, phy: u8) -> Result<(), Error> {
        for (reg, mask, value) in [
            (PHY_LANES, LANES_MASK, LANES_OFF),
            (PHY_CLOCK, TX_CLOCKS, 0),
        ] {
            let addr = phy_at(self.layout, phy, reg);
            if self.read(addr)? & mask != value {
                return Err(Error::Readback(addr));
            }
        }
        self.hpo_legacy_stopped(phy)
    }
    async fn hpo_phy_disable(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut PhyPlan,
    ) -> Result<(), Error> {
        let phy = plan.result.path.transmitter;
        if plan.result.command_sent {
            firmware
                .disable(plan.result.path, plan.result.signal)
                .await
                .map_err(Error::Firmware)?;
            // Inbox consumption is only transport completion. Never write the
            // firmware's lane or clock controls to manufacture shutdown proof.
            self.wait(
                phy_at(self.layout, phy, PHY_LANES),
                LANES_MASK,
                LANES_OFF,
                100_000,
            )
            .await?;
            self.wait(phy_at(self.layout, phy, PHY_CLOCK), TX_CLOCKS, 0, 100_000)
                .await?;
        }
        self.hpo_stopped(&plan.digital)?;
        self.hpo_phy_off(phy)?;
        let root = self.layout.link_clock;
        if self.read(root)? != plan.root {
            return Err(Error::Readback(root));
        }
        let mask = 0xf << (4 * plan.result.link);
        if plan.root & mask != 0 {
            self.update(root, mask, 0)?;
        }
        plan.digital.root_clock = 0;
        if self.read(root)? != plan.root & !mask {
            return Err(Error::Readback(root));
        }
        self.hpo_phy_off(phy)?;
        self.hpo_stopped(&plan.digital)
    }
    pub(in super::super) async fn disable_hpo_dp(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
        signal: DpSignal,
    ) -> Result<HpoDpDisabled, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.hpo_phy_plan(path, signal)?;
        self.status.state = State::DisablingHpoDp(path.transmitter);
        match self.hpo_phy_disable(firmware, &mut plan).await {
            Ok(()) => {
                self.status.hpo_dp_disabled = Some(plan.result);
                self.status.state = State::HpoDpDisabled;
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
    /// Path is from this GPU's validated inventory; signal matches the inherited
    /// link. Direct external DP only, without USB-C/ACPI PHY interlocks or SSC
    /// workarounds. Retire sink/MST bookkeeping, audio/metadata/HDCP producers,
    /// streams and digital link. Exclude CPU/firmware/FAMS and concurrent display,
    /// link, clock, power and reset writers. Retain all memory and translations.
    /// Success proves lane-disable/TX-clock/root-route readback, not analog power
    /// gating or memory retirement. Keep the owner after failure/cancellation.
    pub(crate) async unsafe fn disable_hpo_dp(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: Path,
        signal: DpSignal,
    ) -> Result<HpoDpDisabled, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.disable_hpo_dp(firmware, path, signal).await
    }
}
