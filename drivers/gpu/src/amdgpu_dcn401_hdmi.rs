//! Native TMDS HDMI stream retirement. Linux enc3_stream_encoder_stop_hdmi_info_packets,
//! enc1_reset_hdmi_stream_attribute and reset_dio_stream_encoder ordering.
//! Keep the backend/PHY clocks: an active TMDS OTG can still consume symclk.
use super::*;

const CLOCK: u64 = 0x2094;
const ENABLE: u64 = 0x2095;
const FIFO: u64 = 0x209b;
const CONTROL: u64 = 0x209e;
const PACKETS: u64 = 0x20a5;
const PACKETS_HIGH: u64 = 0x20a6;
const PACKET_PENDING: u64 = 0x20b0;
const DB: u64 = 0x20b1;
const ROUTE: u64 = 0x20bc;
const ROUTE_MASK: u32 = 0x70007f01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiTmdsRetired {
    pub stream: u8,
    /// Backends disconnected from this frontend; their clocks remain owned.
    pub detached_backends: u8,
}
struct Plan {
    result: HdmiTmdsRetired,
    source: u32,
    routes: [u32; 4],
    backends: [(u32, u32, u32); 4],
}
impl<I: Io> Engine<I> {
    fn hdmi_at(&self, stream: u8, reg: u64) -> u64 {
        self.layout.base + (reg + u64::from(stream) * 0x124) * 4
    }
    fn hdmi_quiet(&mut self, stream: u8) -> Result<(), Error> {
        if self.read(self.hdmi_at(stream, CLOCK))? & 7 != 3 {
            return Err(Error::Unsupported);
        }
        // Audio must already be powered down by its owner. Do not access
        // potentially gated AFMT/VPG memory, or consume their completion bits.
        for (reg, mask) in [
            (CLOCK, 0x5020), // AFMT clocks and frontend reset
            (FIFO, 0x100002),
            (0x2091, 0x1010),     // dynamic metadata enable/pending
            (0x209d, 1),          // HDMI metadata
            (CONTROL, 0x400),     // Dolby Vision
            (0x20a7, 0x3fffffff), // immediate generic send/pending, packets 0..14
            (0x2122, 0x10001),    // independent DP video enable/status
        ] {
            if self.read(self.hdmi_at(stream, reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    pub(super) fn hdmi_packets_stopped(&mut self, s: u8) -> Result<(), Error> {
        for (reg, mask) in [
            (PACKETS, u32::MAX),
            (PACKETS_HIGH, u32::MAX),
            (0x20a9, u32::MAX),
            (0x20aa, u32::MAX),
            (0x20ab, u32::MAX),
            (0x20ac, u32::MAX),
            (0x20ad, u32::MAX),
            (0x20ae, u32::MAX),
            (0x20af, u32::MAX),
            (PACKET_PENDING, 0x7fffffff),
            (DB, 0x8101),
        ] {
            let at = self.hdmi_at(s, reg);
            if self.read(at)? & mask != 0 {
                return Err(Error::Readback(at));
            }
        }
        self.hdmi_quiet(s)
    }
    fn hdmi_plan(&mut self, stream: u8) -> Result<Plan, Error> {
        if stream >= 4 {
            return Err(Error::Invalid);
        }
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        let clock = self.read(self.hdmi_at(stream, CLOCK))?;
        if clock & 7 != 3 {
            return Err(Error::Unsupported);
        }
        self.hdmi_quiet(stream)?;
        if self.read(self.hdmi_at(stream, DB))? & 0x8101 != 0
            || self.read(self.hdmi_at(stream, PACKET_PENDING))? & 0x7fff0000 != 0
        {
            return Err(Error::Busy);
        }
        let enabled = self.read(self.hdmi_at(stream, ENABLE))? & 1 != 0;
        let fifo = self.read(self.hdmi_at(stream, FIFO))? & 1 != 0;
        if fifo && !enabled || enabled && clock & 0x10 == 0 {
            return Err(Error::Busy);
        }
        let mut plan = Plan {
            result: HdmiTmdsRetired {
                stream,
                detached_backends: 0,
            },
            source: self.read(self.hdmi_at(stream, 0x2093))? & 0x107177,
            routes: [0; 4],
            backends: [(0, 0, 0); 4],
        };
        if plan.source & 7 >= 4 || plan.source & 0x100000 != 0 {
            return Err(Error::Unsupported);
        }
        for b in 0..4 {
            let route = self.read(self.hdmi_at(b, ROUTE))? & ROUTE_MASK;
            plan.routes[usize::from(b)] = route;
            if route & (0x100 << stream) == 0 {
                continue;
            }
            // HDMI is single-link and must not share this backend with another
            // frontend, a dual-link encoder or an HPO PHY route.
            let mux = self.read(self.layout.base + (0x179a + 3 * u64::from(b)) * 4)? & 0x773;
            let be_clock =
                self.read(self.hdmi_at(b, 0x20bb))? & (clocks::backend_clock_mask(b) | 0x67);
            let be_enable = self.read(self.hdmi_at(b, 0x20bd))? & 1;
            if route & 0x7f01 != 0x100 << stream || mux & 3 != 0 || be_clock & 7 != 3 {
                return Err(Error::Unsupported);
            }
            if be_clock & 0x60 != 0 {
                return Err(Error::Busy);
            }
            plan.backends[usize::from(b)] = (be_clock, be_enable, mux);
            plan.result.detached_backends |= 1 << b;
        }
        Ok(plan)
    }
    fn hdmi_routes(&mut self, plan: &Plan, detached: bool) -> Result<(), Error> {
        let s = plan.result.stream;
        let source = self.hdmi_at(s, 0x2093);
        if self.read(source)? & 0x107177 != plan.source {
            return Err(Error::Readback(source));
        }
        for b in 0..4 {
            let at = self.hdmi_at(b, ROUTE);
            let expected =
                plan.routes[usize::from(b)] & if detached { !(0x100 << s) } else { u32::MAX };
            if self.read(at)? & ROUTE_MASK != expected {
                return Err(Error::Readback(at));
            }
            if plan.result.detached_backends & (1 << b) != 0 {
                let (clock, enable, mux) = plan.backends[usize::from(b)];
                for (reg, mask, value) in [
                    (
                        self.hdmi_at(b, 0x20bb),
                        clocks::backend_clock_mask(b) | 0x67,
                        clock,
                    ),
                    (self.hdmi_at(b, 0x20bd), 1, enable),
                    (
                        self.layout.base + (0x179a + 3 * u64::from(b)) * 4,
                        0x773,
                        mux,
                    ),
                ] {
                    if self.read(reg)? & mask != value {
                        return Err(Error::Readback(reg));
                    }
                }
            }
        }
        Ok(())
    }
    async fn hdmi_retire_inner(&mut self, plan: &Plan) -> Result<(), Error> {
        let s = plan.result.stream;
        // Native stop sequence clears all generic scheduling fields, including
        // line references/update-lock overrides. Preserve status in CONTROL10.
        for reg in [
            PACKETS,
            0x20a9,
            0x20aa,
            0x20ab,
            0x20ac,
            PACKETS_HIGH,
            0x20ad,
            0x20ae,
            0x20af,
        ] {
            self.update(self.hdmi_at(s, reg), u32::MAX, 0)?;
        }
        self.update(self.hdmi_at(s, PACKET_PENDING), 0xffff, 0)?;
        self.wait(self.hdmi_at(s, PACKET_PENDING), 0x7fff0000, 0, 150_000)
            .await?;
        self.wait(self.hdmi_at(s, DB), 0x8101, 0, 150_000).await?;
        self.hdmi_packets_stopped(s)?;
        self.hdmi_routes(plan, false)?;
        self.update(self.hdmi_at(s, CONTROL), 0x1000017, 0x11)?;
        self.wait(self.hdmi_at(s, DB), 0x8101, 0, 150_000).await?;
        self.hdmi_packets_stopped(s)?;
        self.hdmi_routes(plan, false)?;
        self.update(self.hdmi_at(s, FIFO), 1, 0)?;
        self.update(self.hdmi_at(s, ENABLE), 1, 0)?;
        self.update(self.hdmi_at(s, CLOCK), 0x10, 0)?;
        self.wait(self.hdmi_at(s, CLOCK), 0x2c10, 0, 1000).await?;
        self.hdmi_packets_stopped(s)?;
        self.hdmi_routes(plan, false)?;
        self.update(self.hdmi_at(s, FIFO), 0x300, 0)?;
        for b in 0..4 {
            if plan.result.detached_backends & (1 << b) != 0 {
                self.update(self.hdmi_at(b, ROUTE), 0x100 << s, 0)?;
            }
        }
        for (reg, mask, value) in [
            (CLOCK, 0x2c37, 3),
            (ENABLE, 1, 0),
            (FIFO, 0x100303, 0),
            (CONTROL, 0x1000017, 0x11),
            (DB, 0x8101, 0),
            (PACKETS, u32::MAX, 0),
            (PACKETS_HIGH, u32::MAX, 0),
            (PACKET_PENDING, 0x7fffffff, 0),
        ] {
            let at = self.hdmi_at(s, reg);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        self.hdmi_packets_stopped(s)?;
        self.hdmi_routes(plan, true)
    }
    pub(super) async fn retire_hdmi_tmds_encoder(
        &mut self,
        stream: u8,
    ) -> Result<HdmiTmdsRetired, Error> {
        let plan = self.hdmi_plan(stream)?;
        self.status.state = State::RetiringHdmiTmds(stream);
        match self.hdmi_retire_inner(&plan).await {
            Ok(()) => {
                self.status.hdmi_tmds_retired = Some(plan.result);
                self.status.state = State::HdmiTmdsRetired;
                Ok(plan.result)
            }
            Err(error) => {
                self.status.state = State::Failed(error);
                Err(error)
            }
        }
    }
}
impl Otg {
    /// Stop generic packets and retire one native TMDS HDMI frontend.
    /// # Safety
    /// Independently mute/blank the sink as required by its quirks, reset SCDC
    /// and external retimers, stop audio/metadata/HDCP producers, and exclude
    /// CPU/firmware/FAMS and concurrent display/link/clock/power writers. Retain
    /// all memory and translations on success, failure or cancellation. Backend,
    /// PHY and OTG clocks remain owned; this does not prove link/memory retirement.
    pub async unsafe fn retire_hdmi_tmds_encoder(
        &mut self,
        stream: u8,
    ) -> Result<HdmiTmdsRetired, Error> {
        self.0.retire_hdmi_tmds_encoder(stream).await
    }
}
