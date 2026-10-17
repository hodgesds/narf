//! Break the TMDS OTG/symclk dependency without disabling a live transmitter.
//! Native optc401_disable_crtc followed by optc1_enable_optc_clock(false).
use super::*;

const INPUT_GLOBAL: u64 = 0x1aca;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TmdsTimingRetired {
    pub pipe: u8,
    /// Live TMDS transmitters whose clocks/output remain retained.
    pub retained_transmitters: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Links {
    pub(super) registers: [[u32; 6]; 4],
    active: u8,
}
impl<I: Io> Engine<I> {
    fn tmds_retained_register(&self, at: u64) -> bool {
        (0..4).any(|p| {
            [0x20bb, 0x20bd]
                .iter()
                .any(|&r| at == DpStream::Dio(p).at(self.layout, r))
                || [0x2931, 0x2943]
                    .iter()
                    .any(|&r| at == self.layout.base + (r + u64::from(p) * 0xd8) * 4)
        })
    }
    pub(super) fn tmds_timing_links(&mut self) -> Result<Links, Error> {
        let l = self.layout;
        for (at, mask) in l.idle {
            let timing = (0..4).any(|p| at == l.otg(p, CONTROL) || at == l.otg(p, CLOCK));
            if !timing && !self.tmds_retained_register(at) && self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        let mut links = Links {
            registers: [[0; 6]; 4],
            active: 0,
        };
        for p in 0..4 {
            let dio = |r| DpStream::Dio(p).at(l, r);
            // Stop independent audio/metadata, too. No gated VPG/AFMT reads.
            for (r, mask) in [(0x2094, 0x7c30), (0x2091, 0x1010), (0x209d, 1)] {
                if self.read(dio(r))? & mask != 0 {
                    return Err(Error::Busy);
                }
            }
            if self.read(dio(0x2094))? & 7 == 3 {
                self.hdmi_packets_stopped(p)?;
            }
            let route = self.read(dio(0x20bc))? & 0x70007f01;
            let clock = self.read(dio(0x20bb))? & (clocks::backend_clock_mask(p) | 0x67);
            let enabled = self.read(dio(0x20bd))? & 1;
            let mux = self.read(l.base + (0x179a + 3 * u64::from(p)) * 4)? & 0x773;
            let lanes = self.read(l.base + (0x2943 + 0xd8 * u64::from(p)) * 4)? & 0x3e3e3e3e;
            let phy_clock = self.read(l.base + (0x2931 + 0xd8 * u64::from(p)) * 4)? & 0x6f0;
            // Every frontend must already be detached. Pending resets or PHY
            // handshakes cannot be interpreted as stable retained clocks.
            if route & 0x7f01 != 0 || clock & 0x60 != 0 || lanes & 0x30303030 != 0 {
                return Err(Error::Busy);
            }
            let active = enabled != 0
                || clock & clocks::backend_clock_mask(p) != 0
                || lanes & 0x3c3c3c3c != 0
                || phy_clock != 0;
            if active {
                if clock & 7 != 3 || mux & 3 != 0 {
                    return Err(Error::Unsupported);
                }
                links.active |= 1 << p;
            }
            links.registers[usize::from(p)] = [route, clock, enabled, mux, lanes, phy_clock];
        }
        Ok(links)
    }
    fn tmds_timing_unlocked(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        if self.read(l.otg(pipe, LOCK))? & 0x101 != 0
            || self.read(l.otg(pipe, CLOCK))? & 0x10 != 0
            || self.read(l.odm(pipe, INPUT_GLOBAL))? & 0x80000001 != 0
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn tmds_timing_unchanged(&mut self, pipe: u8, before: Links) -> Result<(), Error> {
        self.tmds_timing_unlocked(pipe)?;
        if self.tmds_timing_links()? != before {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn tmds_timing_stopped(&mut self, pipe: u8, gated: bool) -> Result<(), Error> {
        let l = self.layout;
        for (reg, mask, value) in [
            (l.otg(pipe, CONTROL), 0x10001, 0),
            (l.vtg(pipe), 0x80000000, 0),
            (l.odm(pipe, SOURCE), 0xffff0003, 0xffff0000),
            (l.odm(pipe, MEMORY), 0xffff, 0),
            (l.odm(pipe, INPUT_GLOBAL), 0x400, 0),
            (l.otg(pipe, CLOCK), if gated { 0x10113 } else { 0x10010 }, 0),
            (l.odm(pipe, INPUT_CLOCK), if gated { 7 } else { 0 }, 0),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        Ok(())
    }
    async fn tmds_timing_disable(&mut self, pipe: u8, links: Links) -> Result<(), Error> {
        let l = self.layout;
        self.disable(pipe).await?;
        self.tmds_timing_unchanged(pipe, links)?;
        let input = l.odm(pipe, INPUT_GLOBAL);
        if self.read(input)? & 0x400 != 0 {
            // Native W1C command, not a retained bit to compare with readback.
            self.access(|io| {
                let value = checked(io.read(input))?;
                io.write(input, value | 0x1000);
                Ok(())
            })?;
            self.wait(input, 0x400, 0, 1000).await?;
        }
        self.tmds_timing_unchanged(pipe, links)?;
        self.tmds_timing_stopped(pipe, false)?;
        // Keep the PHY available through both gate requests and acknowledgements.
        self.update(l.otg(pipe, CLOCK), 3, 0)?;
        self.update(l.odm(pipe, INPUT_CLOCK), 3, 0)?;
        self.wait(l.otg(pipe, CLOCK), 0x10113, 0, 1000).await?;
        self.wait(l.odm(pipe, INPUT_CLOCK), 7, 0, 1000).await?;
        self.tmds_timing_unchanged(pipe, links)?;
        self.tmds_timing_stopped(pipe, true)
    }
    pub(super) async fn retire_tmds_timing(
        &mut self,
        pipe: u8,
    ) -> Result<TmdsTimingRetired, Error> {
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        if !(self.status.state.reusable() || self.status.state == State::RunningBlank(pipe)) {
            return Err(Error::Busy);
        }
        self.tmds_timing_unlocked(pipe)?;
        let links = self.tmds_timing_links()?;
        self.status.state = State::RetiringTmdsTiming(pipe);
        match self.tmds_timing_disable(pipe, links).await {
            Ok(()) => {
                let result = TmdsTimingRetired {
                    pipe,
                    retained_transmitters: links.active,
                };
                self.status.pipes[usize::from(pipe)] = None;
                self.status.blanks[usize::from(pipe)] = None;
                self.status.running_blank = None;
                self.status.retired |= 1 << pipe;
                self.status.tmds_timing_retired = Some(result);
                self.status.state = State::TmdsTimingRetired;
                Ok(result)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Stop one timing generator and its input/OTG clocks with TMDS PHYs retained.
    /// # Safety
    /// Retire all frontends and independent audio/metadata/HDCP producers first.
    /// Exclude CPU/firmware/FAMS and concurrent display/link/clock/power writers;
    /// retain every scanout allocation and translation. This does not retire
    /// PHYs, other timing generators, HUBP fetches or memory. Future PHY shutdown
    /// must independently check all timing and clock users, never this snapshot.
    pub async unsafe fn retire_tmds_timing(
        &mut self,
        pipe: u8,
    ) -> Result<TmdsTimingRetired, Error> {
        self.0.retire_tmds_timing(pipe).await
    }
}
