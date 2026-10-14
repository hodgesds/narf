//! Native DOMAIN0–3 power lifecycle for disconnected HUBPs. Linux references:
//! dcn401_enable_plane_sequence, dcn401_plane_atomic_power_down,
//! dcn32_hubp_pg_control, hubp2_clk_cntl and hubp2_set_blank_regs.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HubpPower {
    pub pipe: u8,
    /// On means blank, drained and fetch-clock-disabled, ready for later setup.
    /// Off means the native PGFSM acknowledged power gating.
    pub powered: bool,
}

impl<I: Io> Engine<I> {
    fn hubp_transactions_stopped(&mut self, pipe: u8, staged: bool) -> Result<(), Error> {
        let l = self.layout;
        self.auxiliary_fetchers_stopped(pipe)?;
        for (r, mask) in [
            (HUBP_CONTROL, 4), // SOFT_RESET, not TTU_DISABLE
            (HUBP_CLOCK, 1),
            (CURSOR, 1),
            (FLIP, if staged { 0x201 } else { 0x301 }),
            (FLIP2, 0x100),
        ] {
            if self.read(l.hubp(pipe, r))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    pub(super) fn hubp_power_tree_stopped(&mut self) -> Result<(), Error> {
        self.hubp_tree_stopped(None)
    }
    // Only a caller retaining the selected staged address may tolerate its
    // pending flip. Blank/drain/clock/lock and unrelated pipes stay strict.
    pub(super) fn hubp_tree_stopped(&mut self, staged: Option<u8>) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask) in l.idle {
            if !self.sibling_register(at) && self.read(at)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // Other displays' pipes run; fetchers_stopped checks their fetch.
        let kept = self.displays.siblings.pipes;
        for p in (0..4).filter(|p| kept & 1 << p == 0) {
            if self.read(l.otg(p, LOCK))? & 0x101 != 0
                || self.read(l.otg(p, CLOCK))? & 0x10 != 0
                || self.read(l.otg(p, GSL))? & 0x8000000f != 0
                || self.read(l.mpcc(p, UPDATE_LOCK))? & 0x70 != 0
            {
                return Err(Error::Busy);
            }
            for at in [
                l.out_mux(p),
                l.mpcc(p, TOP),
                l.mpcc(p, BOTTOM),
                l.mpcc(p, OPP_ID),
                l.mpcc(p, UPDATE_LOCK),
            ] {
                if self.read(at)? & 0xf != 0xf {
                    return Err(Error::Busy);
                }
            }
            let status = self.read(l.mpcc(p, MPC_STATUS))?;
            if status & 2 != 0 || status & 5 == 0 {
                return Err(Error::Busy);
            }
            if self.hubp_powered(p)? {
                self.hubp_transactions_stopped(p, staged == Some(p))?;
            }
        }
        self.fetchers_stopped()
    }
    async fn change_hubp_power(&mut self, request: HubpPower) -> Result<(), Error> {
        let l = self.layout;
        let p = request.pipe;
        let ip_request = l.base + 0xa0 * 4;
        let original_request = self.read(ip_request)? & 1;
        if original_request == 0 {
            self.update(ip_request, 1, 1)?;
        }
        // Native REG_SET(..., 0, DOMAIN_POWER_GATE, ...) also clears FORCEON.
        // Do not access the HUBP while its power state is unknown or off.
        self.update(
            l.pg(p, false),
            u32::MAX,
            if request.powered { 0 } else { 0x100 },
        )?;
        self.wait(
            l.pg(p, true),
            0xc0000000,
            if request.powered { 0 } else { 0x80000000 },
            1000,
        )
        .await?;
        if self.hubp_powered(p)? != request.powered {
            return Err(Error::Busy);
        }
        if original_request == 0 {
            self.update(ip_request, 1, 0)?;
        }
        if request.powered {
            // No surfaces, timing or MPC routes have been enabled. Reject
            // unexpected auxiliary activity before enabling the fetch clock.
            self.hubp_transactions_stopped(p, false)?;
            self.update(l.hubp(p, HUBP_CLOCK), 1, 1)?;
            self.wait(l.hubp(p, HUBP_CONTROL), 2, 2, 100_000).await?;
            self.update(l.hubp(p, HUBP_CONTROL), 0x1001, 1)?;
            self.update(l.hubp(p, MALL), 0x1f, 8)?;
            self.update(l.hubp(p, FLIP2), 0x100, 0)?;
            self.wait(l.hubp(p, HUBP_CONTROL), 0x1007, 3, 100_000)
                .await?;
            self.update(l.hubp(p, HUBP_CLOCK), 1, 0)?;
        }
        // Fresh evidence, including every unrelated domain and consumer.
        // Acknowledged power-off is not permission to reuse any backing memory.
        self.hubp_power_tree_stopped()?;
        if self.hubp_powered(p)? != request.powered
            || self.read(ip_request)? & 1 != original_request
        {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub(in super::super) async fn set_hubp_power(
        &mut self,
        pipe: u8,
        powered: bool,
    ) -> Result<HubpPower, Error> {
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        self.hubp_power_tree_stopped()?;
        let request = HubpPower { pipe, powered };
        if self.hubp_powered(pipe)? != powered {
            self.status.state = State::ChangingHubpPower(pipe);
            self.status.planes_retired = None;
            self.status.hubp_power[usize::from(pipe)] = None;
            self.status.surfaces[usize::from(pipe)] = None;
            self.status.memory[usize::from(pipe)] = None;
            self.status.dpps[usize::from(pipe)] = None;
            self.status.mpcs[usize::from(pipe)] = None;
            self.status.requestor = None;
            self.status.deadlines = None;
            if let Err(e) = self.change_hubp_power(request).await {
                self.status.state = State::Failed(e);
                return Err(e);
            }
        }
        self.status.hubp_power[usize::from(pipe)] = Some(request);
        self.status.state = State::HubpPowerChanged;
        Ok(request)
    }
}

impl Otg {
    /// Change one disconnected HUBP's power, leaving an enabled domain blank,
    /// drained and fetch-clock-disabled. All timing/outputs must be stopped
    /// and all MPC routes disconnected. Does not configure or enable scanout.
    /// # Safety
    /// Stop CPU scanout writers and exclude firmware/FAMS and concurrent
    /// display, auxiliary fetcher, clock and power writers. Retain every
    /// allocation and translation, including inherited resources, on success,
    /// error and cancellation. Power-off alone never permits memory reuse.
    /// Retain this owner after cancellation; do not replay uncertain changes.
    pub async unsafe fn set_hubp_power(
        &mut self,
        pipe: u8,
        powered: bool,
    ) -> Result<HubpPower, Error> {
        self.0.set_hubp_power(pipe, powered).await
    }
}
