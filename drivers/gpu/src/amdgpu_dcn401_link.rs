//! Native legacy DP SST disable via DMUB's transmitter-control v1.7 command.
//! Linux dcn10_link_encoder_disable_output orders PHY disable before training
//! cleanup; legacy SST frontends must stay enabled until the backend stops.
use super::*;
use crate::{amdgpu_dcn_inventory as inventory, amdgpu_dmub_navi48 as dmub};
use core::future::Future;

const BE_CLOCK: u64 = 0x20bb;
const BE_ROUTE: u64 = 0x20bc;
const BE_ENABLE: u64 = 0x20bd;
const LINK: u64 = 0x211e;
const PANEL: u64 = 0x2125;
const TRAINING: u64 = 0x212e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpSstDisabled {
    pub path: inventory::Path,
    pub frontend: u8,
    pub command_sent: bool,
}

pub(super) trait Firmware {
    fn ready(&self) -> bool;
    fn disable(
        &mut self,
        path: inventory::Path,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn disable(&mut self, path: inventory::Path) -> Result<(), dmub::Error> {
        self.disable_dp_sst(path).await
    }
}
struct Plan {
    result: DpSstDisabled,
    route: u32,
    frontend: [u32; 3],
}
impl<I: Io> Engine<I> {
    fn sst_other_links_quiet(&mut self) -> Result<(), Error> {
        // HPO and FRL have independent physical muxes. Until those mappings
        // have their own owner, never infer that their PHY is unrelated.
        for p in 0..4 {
            for (reg, mask) in [(0x369f, 0x11), (0x36b4, 3), (0x36b5, 0x1f1003)] {
                if self.read(DpStream::Hpo(p).at(self.layout, reg))? & mask != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        for (reg, mask) in clocks::FRL_IDLE {
            if self.read(self.layout.mpc_base + reg * 4)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    fn sst_frontend(&mut self, p: u8) -> Result<[u32; 3], Error> {
        let l = self.layout;
        let at = |reg| DpStream::Dio(p).at(l, reg);
        self.dp_encoder_quiet(DpStream::Dio(p))?;
        let clock = self.read(at(0x2094))? & 0x37;
        let enable = self.read(at(0x2095))? & 1;
        let reset = self.read(at(0x2123))? & 6;
        if clock & 7 != 0 {
            return Err(Error::Unsupported);
        }
        if clock & 0x20 != 0 || !matches!(reset, 0 | 6) {
            return Err(Error::Busy);
        }
        Ok([clock, enable, reset])
    }
    fn sst_plan(&mut self, path: inventory::Path) -> Result<Plan, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != inventory::Connector::DisplayPort {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4 || !(1..=4).contains(&path.hpd) {
            return Err(Error::Invalid);
        }
        self.sst_other_links_quiet()?;
        let l = self.layout;
        let at = |reg| DpStream::Dio(path.transmitter).at(l, reg);
        let route = self.read(at(BE_ROUTE))? & 0x70007f01;
        let select = (route >> 8) & 0x7f;
        if route & 1 != 0 || select & !0xf != 0 || select.count_ones() != 1 {
            return Err(Error::Unsupported);
        }
        if route >> 28 != u32::from(path.hpd - 1) {
            return Err(Error::Invalid);
        }
        let frontend = select.trailing_zeros() as u8;
        let fe = self.sst_frontend(frontend)?;
        let clock = self.read(at(BE_CLOCK))?;
        let enabled = self.read(at(BE_ENABLE))? & 1 != 0;
        if clock & 7 != 0 {
            return Err(Error::Unsupported);
        }
        // FEC teardown and reset/HDCP transitions require separate owners.
        if clock & 0x60 != 0 || self.read(at(0x212d))? & 0x70 != 0 {
            return Err(Error::Busy);
        }
        if (enabled && (clock & 0x10 == 0 || fe[0] != 0x10 || fe[1] != 1))
            || (!enabled && clock & clocks::backend_clock_mask(path.transmitter) != 0)
        {
            return Err(Error::Busy);
        }
        Ok(Plan {
            result: DpSstDisabled {
                path,
                frontend,
                command_sent: enabled,
            },
            route,
            frontend: fe,
        })
    }
    fn sst_unchanged(&mut self, plan: &Plan) -> Result<(), Error> {
        self.sst_other_links_quiet()?;
        let at = DpStream::Dio(plan.result.path.transmitter).at(self.layout, BE_ROUTE);
        if self.read(at)? & 0x70007f01 != plan.route
            || self.sst_frontend(plan.result.frontend)? != plan.frontend
        {
            return Err(Error::Readback(at));
        }
        Ok(())
    }
    async fn sst_disable(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &Plan,
    ) -> Result<(), Error> {
        let l = self.layout;
        let at = |reg| DpStream::Dio(plan.result.path.transmitter).at(l, reg);
        let clock_mask = clocks::backend_clock_mask(plan.result.path.transmitter) | 0x67;
        if plan.result.command_sent {
            firmware
                .disable(plan.result.path)
                .await
                .map_err(Error::Firmware)?;
            // A consumed inbox slot is not hardware completion. Do not directly
            // gate BE clocks to manufacture the witness firmware must provide.
            self.wait(at(BE_ENABLE), 1, 0, 100_000).await?;
            self.wait(at(BE_CLOCK), clock_mask, 0, 100_000).await?;
            self.sst_unchanged(plan)?;
            self.update(at(TRAINING), 3, 0)?;
            self.update(at(LINK), 0x10, 0)?;
            self.update(at(PANEL), 0x11, 0)?;
        }
        // Disabled-on-entry links need no firmware command or cleanup writes.
        // Recheck every witness after the final write/capability invocation.
        for (reg, mask) in [(BE_ENABLE, 1), (BE_CLOCK, clock_mask), (0x212d, 0x70)] {
            if self.read(at(reg))? & mask != 0 {
                return Err(Error::Readback(at(reg)));
            }
        }
        if plan.result.command_sent {
            for (reg, mask) in [(TRAINING, 3), (LINK, 0x10), (PANEL, 0x11)] {
                if self.read(at(reg))? & mask != 0 {
                    return Err(Error::Readback(at(reg)));
                }
            }
        }
        self.sst_unchanged(plan)
    }
    pub(super) async fn disable_dp_sst(
        &mut self,
        firmware: &mut impl Firmware,
        path: inventory::Path,
    ) -> Result<DpSstDisabled, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let plan = self.sst_plan(path)?;
        self.status.state = State::DisablingDpSst(path.transmitter);
        match self.sst_disable(firmware, &plan).await {
            Ok(()) => {
                self.status.dp_sst_disabled = Some(plan.result);
                self.status.state = State::DpSstDisabled;
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
    /// Path belongs to this board's validated inventory. Use only direct,
    /// external DP SST without USB-C/ACPI PHY interlocks or SSC workarounds.
    /// Independently stop sink/audio/metadata/HDCP/FEC producers; exclude
    /// firmware/FAMS and concurrent display/clock/power/reset writers. Keep all
    /// scanout allocations and translations, even after success or cancellation.
    pub(crate) async unsafe fn disable_dp_sst(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: inventory::Path,
    ) -> Result<DpSstDisabled, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.disable_dp_sst(firmware, path).await
    }
}
