//! Partial beacon replacement retains an uncertain native template owner.
use super::*;
impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn ap_update_beacon(
        &mut self,
        authority: Arc<ApControlAuthority>,
        head: Option<alloc::vec::Vec<u8>>,
        tail: Option<alloc::vec::Vec<u8>>,
        probe: Option<alloc::vec::Vec<u8>>,
    ) -> Result<(), Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        let mut config = owner.plan.config.clone();
        if let Some(head) = head {
            config.beacon_head = head;
        }
        if let Some(tail) = tail {
            config.beacon_tail = tail;
        }
        if let Some(probe) = probe {
            config.probe_resp = (!probe.is_empty()).then_some(probe);
        }
        let policy = self.backend.regulatory_domain()?;
        let mut plan = Plan::prepare(owner.info, config, &policy)?;
        // The START role is fixed for this BSS (no AP<->GO retargeting).
        plan.network = owner.plan.network;
        plan.vif = owner.plan.vif;
        let plan = Arc::new(plan);
        if plan.permission != owner.plan.permission
            || plan.rates != owner.plan.rates
            || plan.basic_rates != owner.plan.basic_rates
            || plan.rate != owner.plan.rate
            || plan.five_ghz != owner.plan.five_ghz
        {
            return Err(Error::Bounds);
        }
        // Beacon slot-time changes require a separate native timing update;
        // this initial replacement preserves the installed MAC timing owner.
        if (plan.config.beacon_head[35] ^ owner.plan.config.beacon_head[35]) & 4 != 0 {
            return Err(Error::Bounds);
        }
        let record = ap_wire::beacon_on(plan.vif, &plan.beacon, plan.tim_offset, None, plan.rate)?;
        self.begin_ap_peer_request(authority.clone())?;
        self.ap_owner.as_mut().unwrap().pending_plan = Some(plan.clone());
        let result = async {
            self.ap_drain_packets().await?;
            self.ap_exchange(&authority, Command::Unified { id: 2 }, &record)
                .await?;
            self.ap_owner.as_mut().unwrap().plan = plan;
            self.ap_owner.as_mut().unwrap().pending_plan = None;
            self.finish_ap_peer_request(&authority)
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
}
