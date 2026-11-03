// SPDX-License-Identifier: GPL-2.0-or-later
//! One retained scan-backed station ROC. STARTED is not foreign-channel proof.
use super::*;
use crate::ath10k::regulatory::Permission;
use alloc::boxed::Box;
use narf_wireless::{
    ap_control::{RadioEmissionAuthority, RadioEventAuthority, RadioInterfaceIdentity},
    reg::RegulatoryDomain,
};

#[path = "offchannel_action.rs"]
mod action;
#[path = "offchannel_receive.rs"]
mod receive;
pub(in crate::ath10k) use receive::{Captured, Subscriptions};
pub(in crate::ath10k) const MAX_DURATION: u32 = 500;
#[derive(Clone, Debug)]
pub(in crate::ath10k) struct Owner {
    pub emission: RadioEmissionAuthority,
    pub event: RadioEventAuthority,
    pub identity: RadioInterfaceIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath10k) struct Receipt {
    pub cookie: u64,
    pub frequency: u16,
    pub duration: u32,
}
#[derive(Debug)]
pub(super) struct Completed {
    pub cookie: u64,
    pub status: bool,
    pub emission: RadioEmissionAuthority,
}
#[derive(Debug)]
pub(super) struct Work {
    /// The vdev the ROC scan runs on (`mac.c::ath10k_remain_on_channel`
    /// uses the requesting interface's `arvif->vdev_id`).
    pub vdev: u8,
    pub owner: Owner,
    pub receipt: Receipt,
    plan: active_scan::Plan,
    caps: wmi_boot::Capabilities,
    started: bool,
    foreign: bool,
    home: bool,
    terminal: bool,
    stop_sent: bool,
    duration: Option<narf_time::Deadline>,
    acquisition: narf_time::Deadline,
    public: bool,
    cancelled: bool,
    action: Option<action::Action>,
    capture_epoch: Option<u64>,
    wait_ms: Option<u32>,
}
impl Work {
    fn response_deadline(&self) -> Option<narf_time::Deadline> {
        let grant = self.duration?;
        Some(
            self.action
                .as_ref()
                .and_then(action::Action::response_until)
                .map_or(grant, |tail| tail.min(grant)),
        )
    }
    fn check(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        if !self.owner.emission.current() {
            return Err(Error::Failed);
        }
        self.plan.validate(&self.caps, domain)
    }
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn roc_failed(&self) -> bool {
        self.failed
    }
    pub(in crate::ath10k) fn validate_roc_request(
        &self,
        receipt: Receipt,
        domain: &RegulatoryDomain,
    ) -> Result<(), Error> {
        if self.failed
            || self.ready.is_none()
            || self.scan_pending.is_some()
            || self.roc.is_some()
            || self.management_completed.is_some()
            || receipt.cookie == 0
            || !(1..=MAX_DURATION).contains(&receipt.duration)
            || !self.channels.contains(&receipt.frequency)
        {
            return Err(Error::Unsupported);
        }
        receive_permission(domain, &[receipt.frequency])?;
        if self
            .station
            .data
            .as_ref()
            .is_some_and(|data| !data.roc_quiescent())
        {
            return Err(Error::Unsupported);
        }
        let binding = self.scan_binding()?;
        if let Some(binding) = &binding {
            binding.check(domain)?;
        }
        self.check_scan_binding(binding.as_ref())
    }
    pub(in crate::ath10k) fn roc_owner(&self) -> Option<Owner> {
        self.roc.as_ref().map(|w| w.owner.clone())
    }
    pub(in crate::ath10k) fn roc_receipt(&self) -> Option<Receipt> {
        self.roc.as_ref().map(|w| w.receipt)
    }
    pub(in crate::ath10k) fn roc_current(&self, domain: &RegulatoryDomain) -> Result<bool, Error> {
        let Some(w) = &self.roc else { return Ok(false) };
        w.check(domain)?;
        self.check_scan_binding(w.plan.station.as_ref())?;
        Ok(!self.failed
            && w.started
            && w.foreign
            && !w.terminal
            && !w.cancelled
            && w.duration.as_ref().is_some_and(|d| !d.expired()))
    }
    pub(in crate::ath10k) fn roc_cancel(&mut self, cookie: u64) -> Result<(), Error> {
        let w = self.roc.as_mut().ok_or(Error::Unsupported)?;
        if cookie == 0 || cookie != w.receipt.cookie || !w.public {
            return Err(Error::Unsupported);
        }
        w.cancelled = true;
        Ok(())
    }
    pub(in crate::ath10k) fn roc_active(&self) -> bool {
        self.roc.is_some()
    }

    /// Reserve retained ownership before setup can publish any scan command.
    /// A dropped acquire leaves failed+scan_pending for mandatory STOP cleanup.
    pub(in crate::ath10k) async fn begin_roc(
        &mut self,
        owner: Owner,
        receipt: Receipt,
        public: bool,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        let vdev = self.primary.id();
        self.begin_roc_on(vdev, owner, receipt, public, current)
            .await
    }
    /// ROC on an owned vdev: the managed role's, or the P2P_DEVICE vdev
    /// for discovery (`mac.c::ath10k_remain_on_channel`, `arvif->vdev_id`).
    pub(in crate::ath10k) async fn begin_roc_on(
        &mut self,
        vdev: u8,
        owner: Owner,
        receipt: Receipt,
        public: bool,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        if !self.roc_vdev_owned(vdev) {
            return Err(Error::Unsupported);
        }
        if self.failed
            || self.ready.is_none()
            || self.scan_pending.is_some()
            || self.roc.is_some()
            || receipt.cookie == 0
            || !(1..=MAX_DURATION).contains(&receipt.duration)
            || !self.channels.contains(&receipt.frequency)
        {
            return Err(Error::Unsupported);
        }
        self.validate_roc_request(receipt, &current()?)?;
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?.clone();
        let domain = current()?;
        receive_permission(&domain, &[receipt.frequency])?;
        let mut plan = if self
            .hinted_permission(&domain, receipt.frequency, None, false)
            .is_ok()
        {
            let mut plan =
                self.prepare_active_scan(&[receipt.frequency], &[Vec::new()], &domain)?;
            // Enable only a policy-qualified TX row; the scan itself remains
            // strictly passive. An action request supplies separate authority.
            plan.ssids.clear();
            plan
        } else if self.station.peer.is_some() {
            self.prepare_associated_passive_scan(&[receipt.frequency], &domain)?
        } else {
            let restore = self.scan_restore(None)?;
            active_scan::Plan {
                channels: alloc::vec![receipt.frequency],
                ssids: Vec::new(),
                extra_ies: Vec::new(),
                permissions: Vec::new(),
                setup: restore.clone(),
                restore,
                station: None,
                p2p_device: None,
            }
        };
        plan.extra_ies.clear();
        plan.validate(&caps, &domain)?;
        if !owner.emission.current() {
            return Err(Error::Failed);
        }
        self.check_scan_binding(plan.station.as_ref())?;
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= 4095)
            .ok_or(Error::Exhausted)?;
        let command = self
            .wire
            .roc(vdev, sequence, receipt.frequency, receipt.duration)?;
        // Invalidate every copied RX batch before changing physical RF. The
        // shared epoch already fences native40->20; no pre-ROC PPDU or host
        // callback may cross this additional channel-ownership boundary.
        self.coexistence_epoch
            .fetch_update(
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
                |epoch| epoch.checked_add(1),
            )
            .map_err(|_| Error::Exhausted)?;
        if let Some(data) = &mut self.station.data {
            data.retire_roc_receive();
        }
        self.close_roc_capture()?;
        self.sequence = sequence;
        self.scan_pending = Some(sequence);
        self.scan_terminal = None;
        let home = plan.station.is_none();
        self.roc = Some(Box::new(Work {
            vdev,
            owner,
            receipt,
            plan,
            caps,
            started: false,
            foreign: false,
            home,
            terminal: false,
            stop_sent: false,
            duration: None,
            acquisition: narf_time::Deadline::after_ms(1500),
            public,
            cancelled: false,
            action: None,
            capture_epoch: None,
            wait_ms: None,
        }));
        self.failed = true;
        let setup = self.roc.as_ref().ok_or(Error::Failed)?.plan.setup.clone();
        for packet in setup
            .iter()
            .map(Vec::as_slice)
            .chain(core::iter::once(command.as_slice()))
        {
            let emission = self
                .roc
                .as_ref()
                .ok_or(Error::Failed)?
                .owner
                .emission
                .clone();
            let caps = self.roc.as_ref().ok_or(Error::Failed)?.caps.clone();
            let plan = &self.roc.as_ref().ok_or(Error::Failed)?.plan;
            // Do not borrow Radio across its mutable command future.
            let permissions = plan.permissions.clone();
            let station = plan.station.clone();
            let frequency = receipt.frequency;
            self.send_scan_command(packet, &|| {
                if !emission.current() {
                    return Err(Error::Failed);
                }
                let domain = current()?;
                receive_permission(&domain, &[frequency])?;
                if let Some(s) = &station {
                    s.check(&domain)?;
                }
                for p in &permissions {
                    p.check(&domain)?;
                    let fresh = Permission::occupied_width_with_hint(
                        &caps,
                        &domain,
                        p.frequency,
                        None,
                        false,
                        p.hint.clone(),
                    )?;
                    if fresh.half_dbm < p.half_dbm {
                        return Err(Error::Unsupported);
                    }
                }
                Ok(())
            })
            .await?;
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        for _ in 0..65536 {
            self.roc.as_ref().ok_or(Error::Failed)?.check(&current()?)?;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.roc_progress().await?;
            let w = self.roc.as_ref().ok_or(Error::Failed)?;
            if w.terminal {
                return Err(Error::Firmware(1));
            }
            if w.started && w.foreign {
                self.check_scan_binding(w.plan.station.as_ref())?;
                self.failed = false;
                return Ok(());
            }
            narf_scheduler::yield_now().await;
        }
        Err(Error::Timeout)
    }

    pub(super) fn observe_roc(&mut self, event: &htt::Event) -> Result<(), Error> {
        let Some(w) = &mut self.roc else {
            return Ok(());
        };
        let htt::Event::Wmi(bytes) = event else {
            return Ok(());
        };
        if wire::word(bytes, 0)? & 0xffffff != self.wire.scan_event {
            return Ok(());
        }
        let event = self.wire.scan_event(&bytes[4..])?;
        if event.sequence != 0xa000 | u32::from(self.scan_pending.ok_or(Error::Failed)?)
            || event.request != 0xa001
            || event.vdev != u32::from(w.vdev)
        {
            return Ok(());
        }
        let mut close = false;
        let mut open = false;
        match event.kind {
            1 if !w.terminal => w.started = true,
            8 if w.started && !w.terminal && event.frequency == u32::from(w.receipt.frequency) => {
                // A repeated event cannot extend the originally granted tail.
                if !w.foreign && w.duration.is_none() {
                    w.duration = Some(narf_time::Deadline::after_ms(u64::from(w.receipt.duration)));
                }
                open = !w.foreign;
                w.foreign = true;
                if w.plan.station.is_some() {
                    w.home = false;
                }
            }
            8 if w.started && w.foreign => {
                close = true;
                w.foreign = false;
            }
            4 => {
                close = w.foreign || w.capture_epoch.is_some();
                w.foreign = false;
                if w.plan
                    .station
                    .as_ref()
                    .is_some_and(|p| event.frequency == u32::from(p.permission.frequency))
                {
                    w.home = true;
                }
            }
            256 => {
                close = true;
                w.foreign = false;
            }
            2 if w.started || w.stop_sent => {
                close = true;
                w.foreign = false;
                w.terminal = true;
                self.scan_terminal = self.scan_pending;
            }
            64 => {
                close = true;
                w.foreign = false;
                w.terminal = true;
                self.scan_terminal = self.scan_pending;
            }
            _ => {}
        }
        if close {
            self.close_roc_capture()?;
        }
        if open {
            self.open_roc_capture()?;
        }
        Ok(())
    }
    // ROC may run before any BSS peer exists. Keep management/HTT receipts
    // on their usual native path; DATA observed offchannel is discarded.
    async fn roc_progress(&mut self) -> Result<bool, Error> {
        let event = self.htt.poll().await?;
        let idle = matches!(event, htt::Event::Idle);
        self.observe_roc(&event)?;
        match event {
            // A P2P client slot's RX (by peer/vdev) is parked for it; only
            // the polling owner's offchannel DATA is discarded.
            rx @ (htt::Event::Rx(_) | htt::Event::InOrder(_, _)) => {
                let _ = self.route_sibling(rx);
            }
            other => {
                let other = self.station_event(other)?;
                let _ = self.route_sibling(other);
            }
        }
        self.observe_roc_action_completion()?;
        Ok(idle)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn expire_roc_for_test(&mut self) -> Result<(), Error> {
        let work = self.roc.as_mut().ok_or(Error::Failed)?;
        if work.duration.is_none() {
            return Err(Error::Failed);
        }
        work.duration = Some(narf_time::Deadline::after_cycles(0));
        self.close_roc_capture()
    }

    /// Host expiry/cancel is a STOP request. Only the matching native terminal
    /// and the complete original-home restore retire this interval.
    pub(in crate::ath10k) async fn service_roc(
        &mut self,
        force: bool,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
        cleanup: impl Fn() -> Result<(), Error>,
    ) -> Result<Option<(Owner, Receipt)>, Error> {
        let Some(w) = &self.roc else { return Ok(None) };
        let healthy = !force
            && !self.failed
            && self.roc_action_current()
            && current().is_ok_and(|domain| w.check(&domain).is_ok());
        let stop = !healthy
            || w.cancelled
            || w.terminal
            || w.duration.is_some() && !w.foreign
            || !w.public
                && w.action
                    .as_ref()
                    .and_then(action::Action::response_until)
                    .is_some_and(|d| d.expired())
            || w.duration
                .as_ref()
                .is_some_and(narf_time::Deadline::expired)
            || w.acquisition.expired() && w.duration.is_none();
        if !stop {
            self.roc_progress().await?;
            self.retire_roc_action(&cleanup).await?;
            return Ok(None);
        }
        self.close_roc_capture()?;
        self.failed = true;
        let sequence = self.scan_pending.ok_or(Error::Failed)?;
        if !self.roc.as_ref().ok_or(Error::Failed)?.terminal
            && !self.roc.as_ref().ok_or(Error::Failed)?.stop_sent
        {
            self.roc.as_mut().ok_or(Error::Failed)?.stop_sent = true;
            let stop = self.wire.stop_scan(sequence)?;
            self.send_scan_command(&stop, &cleanup).await?;
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        for _ in 0..65536 {
            cleanup()?;
            if self.roc.as_ref().is_some_and(|w| w.terminal && w.home) {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.roc_progress().await?;
            narf_scheduler::yield_now().await;
        }
        if !self.roc.as_ref().is_some_and(|w| w.terminal && w.home) {
            return Err(Error::Timeout);
        }
        // A scan COMPLETE cannot retire a still-firmware-owned frame or
        // temporary destination peer. Drain its exact TX terminal first.
        let deadline = narf_time::Deadline::after_ms(1500);
        for _ in 0..65536 {
            cleanup()?;
            self.retire_roc_action(&cleanup).await?;
            if self.roc_action_retired() {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            self.roc_progress().await?;
            narf_scheduler::yield_now().await;
        }
        if !self.roc_action_retired() {
            return Err(Error::Timeout);
        }
        let owner = self.roc.as_ref().ok_or(Error::Failed)?.owner.clone();
        let still_healthy = healthy
            && owner.emission.current()
            && self
                .roc
                .as_ref()
                .ok_or(Error::Failed)?
                .check(&current()?)
                .is_ok();
        if !still_healthy {
            self.scan_pending = None;
            self.roc = None;
            if self.station.peer.is_some() {
                self.disconnect_after_failed_scan().await?;
            }
            return Ok(None);
        }
        let plan = self.roc.as_ref().ok_or(Error::Failed)?.plan.clone();
        let caps = self.roc.as_ref().ok_or(Error::Failed)?.caps.clone();
        for packet in &plan.restore {
            self.send_scan_command(packet, &|| {
                cleanup()?;
                if !owner.emission.current() {
                    return Err(Error::Failed);
                }
                plan.validate(&caps, &current()?)
            })
            .await?;
        }
        let w = self.roc.as_ref().ok_or(Error::Failed)?;
        w.check(&current()?)?;
        self.check_scan_binding(w.plan.station.as_ref())?;
        let notice = w.public.then_some((owner, w.receipt));
        self.management_completed = self.completed_private_action()?;
        self.roc = None;
        self.scan_pending = None;
        self.failed = false;
        Ok(notice)
    }
}
