// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-supported SET_BEACON replaces native vendor IE templates. Native
//! standard beacon/TIM/rate/security parameters remain the original BSS.
use super::{
    ap::Session,
    ap_native::{self, Guard},
    ap_plan::{same_rates, Plan},
};
use crate::cyw43439::{fullmac::Fullmac, runtime::Error, station::Station};
use alloc::vec::Vec;
use narf_wireless::ap_control::ApEmissionAuthority;

impl Session {
    pub(crate) async fn beacon<R: Fullmac>(
        &mut self,
        station: &mut Station<R>,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
        probe: Option<Vec<u8>>,
        source: ApEmissionAuthority,
    ) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Failed);
        }
        let mut config = self.plan.config.clone();
        if let Some(head) = head {
            config.beacon_head = head;
        }
        if let Some(tail) = tail {
            config.beacon_tail = tail;
        }
        let clear_probe = probe.as_ref().is_some_and(Vec::is_empty);
        if let Some(probe) = probe {
            config.probe_resp = (!probe.is_empty()).then_some(probe);
        }
        let mut next = Plan::new(config, self.plan.settings.clone(), self.plan.own)?;
        if clear_probe {
            next.probe_vendor.clear();
        }
        if next.capability != self.plan.capability
            || next.rsne != self.plan.rsne
            || !same_rates(&next.rates, &self.plan.rates)
        {
            return Err(Error::Unsupported);
        }
        let original = self.command_capture(source, None)?;
        let operation = self.operation()?;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        // Retain both candidates before native publication. Cancellation
        // cannot erase knowledge of a possibly installed template prefix.
        self.pending_template = Some((next.beacon_vendor.clone(), next.probe_vendor.clone()));
        let guard = Guard::Program(&original);
        ap_native::vendor(
            &mut station.runtime,
            &guard,
            &self.plan.beacon_vendor,
            &next.beacon_vendor,
            1,
        )
        .await?;
        ap_native::vendor(
            &mut station.runtime,
            &guard,
            &self.plan.probe_vendor,
            &next.probe_vendor,
            2,
        )
        .await?;
        ap_native::verify(&mut station.runtime, &original, &next, self.scope).await?;
        if !self.prefix(&mut station.runtime)? {
            return Err(Error::Busy);
        }
        original.current().map_err(|_| Error::Authority)?;
        self.plan = next;
        self.pending_template = None;
        self.busy = false;
        operation.finish();
        Ok(())
    }
}
