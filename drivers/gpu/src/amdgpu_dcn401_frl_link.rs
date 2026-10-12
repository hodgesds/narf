//! Native hpo_frl_link_enc3_disable: zero training pattern, link off, clock off,
//! then restore RC compression. PHY firmware and root-clock shutdown are separate.
use super::*;
use crate::amdgpu_dcn_inventory::{Connector, Path};

const LINK_CONTROL: u64 = 0x95b;
const LINK_CLOCK: u64 = 0x95c;
const CONFIG: u64 = 0x965;
const CONFIG2: u64 = 0x966;
const TRAINING: u32 = 0xffff0002;
const RC_DISABLE: u32 = 0x02000000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrlLinkRetired {
    pub path: Path,
    pub lanes: u8,
    /// The digital encoder was enabled, including an inherited training link.
    pub was_enabled: bool,
}
struct Plan {
    result: FrlLinkRetired,
    muxes: [u32; 4],
    root: u32,
    forced_clock: u32,
    stream: [u32; 3],
    backend: [u32; 2],
    config: u32,
    config2: u32,
}
impl<I: Io> Engine<I> {
    fn frl_link_stream_stopped(&mut self) -> Result<[u32; 3], Error> {
        self.frl_packets_stopped()?;
        for (reg, mask) in [(CLOCK, 0x1111), (FIFO, 0x100011), (CONTROL, 0x111)] {
            if self.read(self.frl_at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        let source = self.read(self.frl_at(SOURCE))? & 7;
        if source >= 4 {
            return Err(Error::Unsupported);
        }
        Ok([
            source,
            self.read(self.layout.base + 0x59 * 4)? & 15,
            self.read(self.frl_at(DB))? & 0x1000,
        ])
    }
    fn frl_link_muxes(&mut self) -> Result<[u32; 4], Error> {
        let mut muxes = [0; 4];
        for p in 0..4 {
            muxes[p as usize] = self.read(self.layout.base + (0x179a + p * 3) * 4)? & 0x773;
        }
        Ok(muxes)
    }
    fn frl_legacy_backend(&mut self, phy: u8) -> Result<[u32; 2], Error> {
        let layout = self.layout;
        let at = |r| DpStream::Dio(phy).at(layout, r);
        let clock = self.read(at(0x20bb))?;
        if clock & (clocks::backend_clock_mask(phy) | 0x60) != 0 || self.read(at(0x20bd))? & 1 != 0
        {
            return Err(Error::Busy);
        }
        Ok([clock & 7, self.read(at(0x20bc))? & 0x70007f01])
    }
    fn frl_link_plan(&mut self, path: Path) -> Result<Plan, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) {
            return Err(Error::Invalid);
        }
        if path.connector != Connector::HdmiTypeA {
            return Err(Error::Unsupported);
        }
        let stream = self.frl_link_stream_stopped()?;
        let muxes = self.frl_link_muxes()?;
        // Navi48 has one FRL link encoder, HPO_HDMI instance 0. Neither the
        // input OTG nor the connector index identifies its physical transmitter.
        if muxes[usize::from(path.transmitter)] & 0x73 != 1 {
            return Err(Error::Unsupported);
        }
        if muxes.iter().filter(|m| **m & 0x73 == 1).count() != 1 {
            return Err(Error::Busy);
        }
        let backend = self.frl_legacy_backend(path.transmitter)?;
        let control = self.read(self.frl_at(LINK_CONTROL))? & 0x11;
        let clock = self.read(self.frl_at(LINK_CLOCK))? & 3;
        if control & 0x10 != 0 || !matches!((control, clock), (0, 0) | (1, 3)) {
            return Err(Error::Busy);
        }
        let root = self.read(self.layout.base + 0x4a * 4)? & 0x71;
        if (control != 0 || root & 1 != 0) && root != 1 | u32::from(path.transmitter) << 4 {
            return Err(Error::Invalid);
        }
        let forced_clock =
            self.read(self.layout.base + (0x52 + u64::from(path.transmitter)) * 4)? & 0x31;
        if (control != 0 || root & 1 != 0) && forced_clock != 0x11 {
            // Native enable_hdmicharclk also forces PHYD18CLK back through DCIO.
            return Err(Error::Busy);
        }
        let config = self.read(self.frl_at(CONFIG))? & 0xffff0007;
        let config2 = self.read(self.frl_at(CONFIG2))? & 0x1f1ff1ff;
        if config & 0x88880004 != 0 {
            return Err(Error::Unsupported); // reserved patterns or scrambler bypass
        }
        if config2 & 0x11000000 != 0 {
            return Err(Error::Busy); // independent jitter calibration/reset
        }
        if control == 0 && (config & TRAINING != 2 || config2 & RC_DISABLE != 0) {
            // Never wake/replay over an inherited partial disable. Native
            // completion has zero training patterns and restored compression.
            return Err(Error::Busy);
        }
        Ok(Plan {
            result: FrlLinkRetired {
                path,
                lanes: if config & 1 == 0 { 3 } else { 4 },
                was_enabled: control != 0,
            },
            muxes,
            root,
            forced_clock,
            stream,
            backend,
            config,
            config2,
        })
    }
    fn frl_link_unchanged(&mut self, plan: &Plan) -> Result<(), Error> {
        let phy = plan.result.path.transmitter;
        if self.frl_link_muxes()? != plan.muxes
            || self.frl_link_stream_stopped()? != plan.stream
            || self.frl_legacy_backend(phy)? != plan.backend
        {
            return Err(Error::Busy);
        }
        for (reg, mask, value) in [
            (self.layout.base + 0x4a * 4, 0x71, plan.root),
            (
                self.layout.base + (0x52 + u64::from(phy)) * 4,
                0x31,
                plan.forced_clock,
            ),
            (self.frl_at(CONFIG), 0xffff0007, plan.config),
            (self.frl_at(CONFIG2), 0x1f1ff1ff, plan.config2),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        Ok(())
    }
    fn frl_link_off(&mut self) -> Result<(), Error> {
        for (reg, mask) in [(LINK_CONTROL, 0x11), (LINK_CLOCK, 3)] {
            let at = self.frl_at(reg);
            if self.read(at)? & mask != 0 {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    async fn frl_link_disable(&mut self, plan: &mut Plan) -> Result<(), Error> {
        if plan.result.was_enabled {
            self.update(self.frl_at(CONFIG), TRAINING, 2)?;
            plan.config = (plan.config & !TRAINING) | 2;
            self.frl_link_unchanged(plan)?;
            self.update(self.frl_at(LINK_CONTROL), 1, 0)?;
            let control = self.frl_at(LINK_CONTROL);
            if self.read(control)? & 0x11 != 0 {
                return Err(Error::Readback(control));
            }
            self.frl_link_unchanged(plan)?;
            self.update(self.frl_at(LINK_CLOCK), 1, 0)?;
            self.wait(self.frl_at(LINK_CLOCK), 3, 0, 1000).await?;
            self.frl_link_off()?;
            self.frl_link_unchanged(plan)?;
            self.update(self.frl_at(CONFIG2), RC_DISABLE, 0)?;
            plan.config2 &= !RC_DISABLE;
        }
        self.frl_link_off()?;
        self.frl_link_unchanged(plan)
    }
    pub(in super::super) async fn retire_frl_link(
        &mut self,
        path: Path,
    ) -> Result<FrlLinkRetired, Error> {
        let mut plan = self.frl_link_plan(path)?;
        self.status.state = State::RetiringFrlLink(path.transmitter);
        match self.frl_link_disable(&mut plan).await {
            Ok(()) => {
                self.status.frl_link_retired = Some(plan.result);
                self.status.state = State::FrlLinkRetired;
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
    /// Path is from this GPU's validated inventory. Retire the FRL frontend,
    /// sink/SCDC/retimer work and audio/metadata/HDCP producers. Exclude CPU,
    /// firmware/FAMS and concurrent display/link/clock/power/reset writers.
    /// Retain all allocations and translations. This retires only the digital
    /// link; PHY output, forced PHY input clocks and root clocks remain owned.
    /// Keep the owner on failure/cancellation until independent reset.
    pub(crate) async unsafe fn retire_frl_link(
        &mut self,
        path: Path,
    ) -> Result<FrlLinkRetired, Error> {
        self.0.retire_frl_link(path).await
    }
}
