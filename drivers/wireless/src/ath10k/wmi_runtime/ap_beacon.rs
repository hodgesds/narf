// SPDX-License-Identifier: GPL-2.0-or-later
//! Atomic validation and native firmware-owned AP template replacement.
use super::{ap::Session, ap_wire, Error, Hif, HostMemory, HttMemory, Radio};
use alloc::vec::Vec;
use narf_wireless::ap_control::ApEmissionAuthority;

pub(in crate::ath10k) type BeaconPieces = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) async fn ap_set_beacon(
        &mut self,
        pieces: BeaconPieces,
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        validate()?;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() {
            return Err(Error::Failed);
        }
        let ap = self.ap.as_ref().unwrap();
        let mut config = ap.plan.config.clone();
        let (head, tail, probe) = pieces;
        if head.is_none() && tail.is_none() && probe.is_none() {
            return Err(Error::Malformed);
        }
        if let Some(head) = head {
            config.beacon_head = head;
        }
        if let Some(tail) = tail {
            config.beacon_tail = tail;
        }
        if let Some(probe) = probe {
            config.probe_resp = Some(probe);
        }
        let next = ap_wire::Plan::new_role(
            ap.plan.vdev,
            ap.plan.role,
            config,
            ap.plan.settings.clone(),
            ap.own.mac,
            self.ap_uapsd(),
        )?;
        if next.rsn != ap.plan.rsn
            || next.rates != ap.plan.rates
            || next.basic != ap.plan.basic
            || next.qos != ap.plan.qos
            || next.wmm.map(|wmm| wmm.uapsd) != ap.plan.wmm.map(|wmm| wmm.uapsd)
        {
            return Err(Error::Unsupported);
        }
        let wmm = next.wmm;
        let parameters = ap_wire::parameters(&next)?;
        let templates = ap_wire::templates(&next)?;
        let max = self.htt.wmi.htc.wmi_max_payload();
        if templates.iter().any(|command| command.len() > max) {
            return Err(Error::Unsupported);
        }

        let ap = self.ap.as_mut().unwrap();
        // A real RF/template transition closes old copies before any native
        // wait. Unsupported later pieces cannot publish a partial prefix.
        Session::advance(&ap.epoch)?;
        Session::advance(&ap.data_epoch)?;
        let capture = ap.capture(false, true)?.for_control_wait();
        let current = || {
            validate()?;
            if !source.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        ap.busy = true;
        self.ap_quiet(&current).await?;
        for command in parameters {
            self.ap_command(&command, &current).await?;
        }
        if let Some(wmm) = wmm {
            self.ap_command(&super::wmm::command(self.wire.dialect, wmm)?, &current)
                .await?;
        }
        for command in &templates {
            self.ap_command(command, &current).await?;
        }
        self.ap_barrier(&current).await?;
        self.ap_prefix(&current).await?;
        let ap = self.ap.as_mut().unwrap();
        current()?;
        Session::advance(&ap.epoch)?;
        ap.plan = next;
        ap.template_source = Some(source);
        ap.busy = false;
        // The real ECHO proves command processing. It is deliberately not an
        // air ACK or a per-template beacon TX/DMA completion.
        Ok(())
    }
}
