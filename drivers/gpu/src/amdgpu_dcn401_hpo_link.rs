//! DCN401 HPO digital-link retirement, before the separate firmware PHY disable.
//! Linux dcn31_hpo_dp_link_encoder.c: empty SAT with ACT, disable DPHY, clock last.
use super::*;
use crate::amdgpu_dcn_inventory::{Connector, Path};

const CLOCK: u64 = 0x369f;
const CONTROL: u64 = 0x36b4;
const STATUS: u64 = 0x36b5;
const SAT_UPDATE: u64 = 0x36b8;
const SAT: u64 = 0x36bf;
const SAT_STATUS: u64 = 0x36c5;
const ROW: u32 = 0x7f07;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpoLinkRetired {
    pub path: Path,
    /// Resolved from this transmitter's PHY mux, never its connector/OTG index.
    pub link: u8,
    /// All stream encoders routed to this link, including unallocated streams.
    pub streams: u8,
    pub removed_slots: u16,
}
struct Plan {
    result: HpoLinkRetired,
    muxes: [u32; 4],
    streams: [u32; 4],
    root_clock: u32,
    active: bool,
}
impl<I: Io> Engine<I> {
    fn hpo_routes(&mut self) -> Result<([u32; 4], [u32; 4]), Error> {
        let mut muxes = [0; 4];
        let mut streams = [0; 4];
        for p in 0..4usize {
            muxes[p] = self.read(self.layout.base + (0x179a + p as u64 * 3) * 4)? & 0x773;
            streams[p] = self.read(self.layout.mpc_base + (0xe56 + p as u64) * 4)? & 7;
        }
        Ok((muxes, streams))
    }
    fn hpo_streams_stopped(&mut self, streams: u8) -> Result<(), Error> {
        for p in 0..4 {
            if streams & (1 << p) == 0 {
                continue;
            }
            let s = DpStream::Hpo(p);
            self.dp_encoder_quiet(s)?;
            // Blanking alone is not retirement: the stream encoder and every
            // clock-on witness must be down before its link can be stopped.
            for (reg, mask) in [(0x3623, 0x11111), (0x365d, 0x111)] {
                if self.read(s.at(self.layout, reg))? & mask != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    fn hpo_link_plan(&mut self, path: Path) -> Result<Plan, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.transmitter >= 4 {
            return Err(Error::Invalid);
        }
        if path.connector != Connector::DisplayPort {
            return Err(Error::Unsupported);
        }
        let (muxes, streams) = self.hpo_routes()?;
        let mux = muxes[usize::from(path.transmitter)];
        let link = ((mux >> 8) & 7) as u8;
        if mux & 3 != 2 || link >= 4 {
            return Err(Error::Unsupported);
        }
        // A cloned/shared PHY route must not be silently stopped with one port.
        if muxes
            .iter()
            .filter(|m| **m & 0x703 == ((u32::from(link) << 8) | 2))
            .count()
            != 1
        {
            return Err(Error::Busy);
        }
        let mask = streams.iter().enumerate().fold(0, |bits, (i, s)| {
            bits | if *s == u32::from(link) { 1 << i } else { 0 }
        });
        self.hpo_streams_stopped(mask)?;
        let l = self.layout;
        let at = |r| DpStream::Hpo(link).at(l, r);
        let control = self.read(at(CONTROL))?;
        let status = self.read(at(STATUS))?;
        let clock = self.read(at(CLOCK))? & 0x11;
        if (control | status) & 2 != 0 || status & 0x131000 != 0 {
            return Err(Error::Busy);
        }
        if self.read(at(0x36cb))? & 1 != 0 {
            return Err(Error::Unsupported);
        }
        let active = (control | status) & 1 != 0;
        if active && (control & 1 == 0 || status & 1 == 0 || clock != 0x11) {
            return Err(Error::Busy);
        }
        if active && (control & 0x30 != 0x20 || status & 0x30 != 0x20) {
            return Err(Error::Unsupported);
        }
        if !active && clock != 0 {
            return Err(Error::Busy);
        }
        let root_clock = (self.read(l.link_clock)? >> (4 * link)) & 0xf;
        if (active || root_clock & 8 != 0) && root_clock != (u32::from(path.transmitter) | 8) {
            return Err(Error::Invalid);
        }
        let mut slots = 0;
        for row in 0..6 {
            let staged = self.read(at(SAT + row))? & ROW;
            let current = self.read(at(SAT_STATUS + row))? & ROW;
            if staged != current {
                return Err(Error::Busy);
            }
            if staged & 0x7f00 != 0 {
                let source = staged & 7;
                if source >= 4 || streams[source as usize] != u32::from(link) {
                    return Err(Error::Unsupported);
                }
                slots += ((staged >> 8) & 0x7f) as u16;
            }
        }
        if !active && slots != 0 {
            return Err(Error::Busy);
        }
        Ok(Plan {
            result: HpoLinkRetired {
                path,
                link,
                streams: mask,
                removed_slots: slots,
            },
            muxes,
            streams,
            root_clock,
            active,
        })
    }
    fn hpo_unchanged(&mut self, plan: &Plan) -> Result<(), Error> {
        let (muxes, streams) = self.hpo_routes()?;
        if muxes != plan.muxes
            || streams != plan.streams
            || (self.read(self.layout.link_clock)? >> (4 * plan.result.link)) & 0xf
                != plan.root_clock
        {
            return Err(Error::Readback(self.layout.link_clock));
        }
        self.hpo_streams_stopped(plan.result.streams)
    }
    fn hpo_sat_empty(&mut self, link: u8) -> Result<bool, Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(link).at(l, r);
        if self.read(at(STATUS))? & 0x131002 != 0 {
            return Ok(false);
        }
        for row in 0..6 {
            if (self.read(at(SAT + row))? | self.read(at(SAT_STATUS + row))?) & 0x7f00 != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn hpo_link_disable(&mut self, plan: &Plan) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| DpStream::Hpo(plan.result.link).at(l, r);
        if plan.result.removed_slots != 0 {
            for row in 0..6 {
                self.update(at(SAT + row), ROW, 0)?;
            }
            // ACT trigger is self-clearing; do not require a persistent request
            // bit. Positive completion comes from the actual allocation rows.
            self.access(|io| {
                let old = checked(io.read(at(SAT_UPDATE)))?;
                io.write(at(SAT_UPDATE), (old & !3) | 1);
                Ok(())
            })?;
            let deadline = narf_time::Deadline::after_ms(20);
            while !self.hpo_sat_empty(plan.result.link)? {
                if deadline.expired() {
                    return Err(Error::Timeout(at(SAT_STATUS)));
                }
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
            }
        }
        self.hpo_unchanged(plan)?;
        if plan.active {
            self.update(at(CONTROL), 1, 0)?;
            self.wait(at(STATUS), 0x1f1003, 0, 100_000).await?;
            self.hpo_unchanged(plan)?;
            self.update(at(CLOCK), 1, 0)?;
            self.wait(at(CLOCK), 0x11, 0, 1000).await?;
        }
        for (reg, bits) in [(CONTROL, 3), (STATUS, 0x1f1003), (CLOCK, 0x11)] {
            if self.read(at(reg))? & bits != 0 {
                return Err(Error::Readback(at(reg)));
            }
        }
        if !self.hpo_sat_empty(plan.result.link)? {
            return Err(Error::Readback(at(SAT_STATUS)));
        }
        self.hpo_unchanged(plan)
    }
    pub(super) async fn retire_hpo_link(&mut self, path: Path) -> Result<HpoLinkRetired, Error> {
        let plan = self.hpo_link_plan(path)?;
        self.status.state = State::RetiringHpoLink(plan.result.link);
        match self.hpo_link_disable(&plan).await {
            Ok(()) => {
                self.status.hpo_link_retired = Some(plan.result);
                self.status.state = State::HpoLinkRetired;
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
    /// Path is from this GPU's validated board inventory. Stop sink/MST payload
    /// bookkeeping, audio/metadata/HDCP producers and all associated streams;
    /// exclude CPU/firmware/FAMS and concurrent display/link/clock/power writers.
    /// Retain allocations and translations. This only retires the digital link;
    /// PHY output, PHY clocks and sink state still require separate shutdown.
    pub(crate) async unsafe fn retire_hpo_link(
        &mut self,
        path: Path,
    ) -> Result<HpoLinkRetired, Error> {
        self.0.retire_hpo_link(path).await
    }
}
