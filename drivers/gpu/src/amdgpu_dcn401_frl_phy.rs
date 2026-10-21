//! Native FRL transmitter DISABLE followed by dccg401_disable_hdmicharclk.
//! Firmware owns RDPCS. Only fresh lane/TX-clock readback permits root parking.
use super::super::super::{CLOCK as OTG_CLOCK, CONTROL as OTG_CONTROL};
use super::*;
use crate::amdgpu_dmub_navi48 as dmub;
use core::future::Future;

const LANES_MASK: u32 = 0x3e3e3e3e;
const LANES_OFF: u32 = 0x02020202;
const TX_CLOCKS: u32 = 0x6f0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlDisabled {
    pub path: Path,
    pub command_sent: bool,
}
pub(in super::super::super) trait Firmware {
    fn ready(&self) -> bool;
    fn disable(&mut self, path: Path) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.disable_frl(path).await
    }
}
#[derive(PartialEq, Eq)]
struct Consumers {
    hpo_link: u32,
    hpo_stream: u32,
    dto_sources: u32,
    frontend: [u32; 4],
    pixel: [u32; 4],
}
struct PhyPlan {
    digital: Plan,
    consumers: Consumers,
    result: FrlDisabled,
}
fn phy_at(l: Layout, phy: u8, reg: u64) -> u64 {
    l.base + (reg + u64::from(phy) * 0xd8) * 4
}
impl<I: Io> Engine<I> {
    fn frl_phy_consumers(&mut self, phy: u8) -> Result<Consumers, Error> {
        let l = self.layout;
        let bank1 = l.link_clock - 0x66 * 4;
        let mut c = Consumers {
            hpo_link: self.read(l.link_clock)? & 0xffff,
            hpo_stream: self.read(l.link_clock - 4)? & 0xffff,
            dto_sources: self.read(bank1 + 0x68 * 4)? & 0xfff,
            frontend: [0; 4],
            pixel: [0; 4],
        };
        // Legacy HPO stream roots can consume PHYD32CLK even with video off.
        // Native DCN401 uses DPSTREAMCLK instead; reject inherited enabled SEs.
        if c.hpo_stream & 0x8888 != 0 {
            return Err(Error::Busy);
        }
        for p in 0..4u8 {
            if (c.hpo_link >> (4 * p)) & 15 == u32::from(phy) | 8 {
                return Err(Error::Busy);
            }
            let fe = self.read(l.dio_clock + u64::from(p) * 4)? & 0x710;
            if fe & 0x10 != 0 && (fe >> 8) & 7 == u32::from(phy) {
                return Err(Error::Busy);
            }
            c.frontend[usize::from(p)] = fe;
        }
        // OTGs and their OTG<inst>_PIXEL_RATE_CNTL / DTBCLK_P<inst> are pipe
        // resources: walk the pool's pipes at their hardware instances.
        for p in l.pool.pipes() {
            let inst = u64::from(l.inst(p));
            let pixel = self.read(bank1 + (0x80 + 4 * inst) * 4)? & 0x1393;
            c.pixel[usize::from(p)] = pixel;
            if self.read(l.otg(p, OTG_CLOCK))? & 0x10 != 0
                || self.read(l.otg(p, LOCK))? & 0x101 != 0
                || self.read(l.odm(p, 0x1aca))? & 0x80000001 != 0
            {
                return Err(Error::Busy);
            }
            let timing = self.read(l.otg(p, OTG_CONTROL))? & 0x10001 != 0
                || self.read(l.otg(p, OTG_CLOCK))? & 0x10113 != 0
                || self.read(l.odm(p, INPUT_CLOCK))? & 7 != 0
                || self.read(l.vtg(p))? & 0x80000000 != 0;
            // A live OTG must use an acknowledged DTO fed by DPREFCLK/DTBCLK,
            // not a PHY-fed TMDS pixel clock. Retain its timing/DTO unchanged.
            if (timing || pixel & 0x90 != 0)
                && (pixel & 0x1390 != 0x1090 || !matches!((c.dto_sources >> (3 * inst)) & 7, 4 | 6))
            {
                return Err(Error::Busy);
            }
        }
        Ok(c)
    }
    fn frl_phy_plan(&mut self, path: Path) -> Result<PhyPlan, Error> {
        let digital = self.frl_link_plan(path)?;
        self.frl_link_off()?;
        let consumers = self.frl_phy_consumers(path.transmitter)?;
        let lanes = self.read(phy_at(self.layout, path.transmitter, 0x2943))?;
        let clocks = self.read(phy_at(self.layout, path.transmitter, 0x2931))?;
        if lanes & 0x30303030 != 0 {
            return Err(Error::Busy); // never interrupt a PHY request/ack handshake
        }
        let command_sent = lanes & LANES_MASK != LANES_OFF || clocks & TX_CLOCKS != 0;
        if command_sent
            && (digital.root != 1 | u32::from(path.transmitter) << 4
                || digital.forced_clock != 0x11)
        {
            return Err(Error::Busy);
        }
        Ok(PhyPlan {
            digital,
            consumers,
            result: FrlDisabled { path, command_sent },
        })
    }
    fn frl_phy_unchanged(&mut self, plan: &PhyPlan) -> Result<(), Error> {
        self.frl_link_off()?;
        self.frl_link_unchanged(&plan.digital)?;
        if self.frl_phy_consumers(plan.result.path.transmitter)? != plan.consumers {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn frl_phy_off(&mut self, phy: u8) -> Result<(), Error> {
        for (reg, mask, value) in [(0x2943, LANES_MASK, LANES_OFF), (0x2931, TX_CLOCKS, 0)] {
            let at = phy_at(self.layout, phy, reg);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    async fn frl_phy_disable(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut PhyPlan,
    ) -> Result<(), Error> {
        let phy = plan.result.path.transmitter;
        self.frl_phy_unchanged(plan)?;
        if plan.result.command_sent {
            firmware
                .disable(plan.result.path)
                .await
                .map_err(Error::Firmware)?;
            self.wait(
                phy_at(self.layout, phy, 0x2943),
                LANES_MASK,
                LANES_OFF,
                100_000,
            )
            .await?;
            self.wait(phy_at(self.layout, phy, 0x2931), TX_CLOCKS, 0, 100_000)
                .await?;
        }
        self.frl_phy_unchanged(plan)?;
        self.frl_phy_off(phy)?;
        if plan.digital.root != 0 {
            self.update(self.layout.base + 0x4a * 4, 0x71, 0)?;
            plan.digital.root = 0;
        }
        // Native DCN401 intentionally leaves the forced PHY input clock owned.
        // Do not invent an analog/PLL power-off sequence or a memory reuse proof.
        self.frl_phy_unchanged(plan)?;
        self.frl_phy_off(phy)
    }
    pub(in super::super::super) async fn disable_frl(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
    ) -> Result<FrlDisabled, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.frl_phy_plan(path)?;
        self.status.state = State::DisablingFrl(path.transmitter);
        match self.frl_phy_disable(firmware, &mut plan).await {
            Ok(()) => {
                self.status.frl_disabled = Some(plan.result);
                self.status.state = State::FrlDisabled;
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
    /// Validated direct external HDMI path without ACPI PHY interlocks or SSC
    /// workarounds. Retire FRL frontend/link, sink AVMUTE/SCDC/retimer work and
    /// audio/metadata/HDCP producers. Exclude CPU/firmware/FAMS and concurrent
    /// display/link/clock/power/reset writers. Retain all allocations/translations.
    /// Success proves lane/TX-clock/character-root stop only. Forced input clocks,
    /// timing, analog power and memory remain owned, including after cancellation.
    pub(crate) async unsafe fn disable_frl(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: Path,
    ) -> Result<FrlDisabled, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.disable_frl(firmware, path).await
    }
}
