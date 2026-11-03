// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact action descriptor and temporary DA-peer ownership inside one ROC.
use super::*;
use crate::ath10k::htt_runtime::tx::{Kind, Parameters};
use narf_wireless::MgmtTxRequest;

#[derive(Debug)]
pub(super) struct Action {
    cookie: u64,
    emission: RadioEmissionAuthority,
    /// The ROC vdev the temporary peer and descriptor were created on.
    vdev: u8,
    destination: [u8; 6],
    temporary: bool,
    ids: [u64; 32],
    delete_sent: bool,
    delete_ack: bool,
    token: Option<ManagementToken>,
    status: Option<bool>,
    retired: bool,
    response_until: Option<narf_time::Deadline>,
}
impl Action {
    pub(super) fn response_until(&self) -> Option<narf_time::Deadline> {
        self.response_until
    }
}
fn validate(frame: &[u8], own: [u8; 6]) -> Result<[u8; 6], Error> {
    if !(26..=2304).contains(&frame.len())
        || frame[0] != 0xd0
        || frame[1] != 0
        || frame[22] & 15 != 0
        || frame[10..16] != own
        || frame[4..10] == [0; 6]
        || frame[24] != 4
        || !(frame[16..22] == frame[4..10] || frame[16..22] == [255; 6])
    {
        return Err(Error::Unsupported);
    }
    // Only non-robust Public Action is exported here. Initial SME, PMF and
    // rekey keep their existing exact BSS/key owner and cannot use this API.
    Ok(frame[4..10].try_into().unwrap())
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn offchannel_action_supported(&self) -> bool {
        self.htt.wmi.caps.as_ref().is_some_and(|caps| {
            matches!(
                management::path(self.wire.dialect, self.features, caps),
                Ok(management::Path::Htt | management::Path::Reference)
            )
        })
    }
    pub(in crate::ath10k) fn validate_roc_action(
        &self,
        cookie: u64,
        request: &MgmtTxRequest,
        emission: &RadioEmissionAuthority,
        domain: &RegulatoryDomain,
    ) -> Result<(), Error> {
        if !emission.current()
            || cookie == 0
            || !request.offchannel_ok
            || !self.offchannel_action_supported()
            || !self.roc_current(domain)?
        {
            return Err(Error::Unsupported);
        }
        if request.duration != 0 && !(10..=MAX_DURATION).contains(&request.duration) {
            return Err(Error::Unsupported);
        }
        let w = self.roc.as_ref().ok_or(Error::Failed)?;
        if request.frequency_mhz != u32::from(w.receipt.frequency)
            || w.public && request.duration != 0
            || w.action.is_some()
            || request.no_cck && w.receipt.frequency < 3000
        {
            return Err(Error::Unsupported);
        }
        let permission = self.hinted_permission(domain, w.receipt.frequency, None, false)?;
        if !w.plan.permissions.contains(&permission) {
            return Err(Error::Unsupported);
        }
        validate(&request.frame, self.vdev_address(w.vdev)?).map(|_| ())
    }
    pub(in crate::ath10k) fn validate_private_frame(
        &self,
        cookie: u64,
        request: &MgmtTxRequest,
        domain: &RegulatoryDomain,
    ) -> Result<(), Error> {
        if cookie == 0
            || !request.offchannel_ok
            || !self.offchannel_action_supported()
            || request.duration != 0 && !(10..=MAX_DURATION).contains(&request.duration)
        {
            return Err(Error::Unsupported);
        }
        let frequency = u16::try_from(request.frequency_mhz).map_err(|_| Error::Unsupported)?;
        self.validate_roc_request(
            Receipt {
                cookie,
                frequency,
                duration: MAX_DURATION,
            },
            domain,
        )?;
        if request.no_cck && frequency < 3000 {
            return Err(Error::Unsupported);
        }
        self.hinted_permission(domain, frequency, None, false)?;
        validate(&request.frame, self.ready.ok_or(Error::Failed)?.mac).map(|_| ())
    }
    /// A FRAME outside any ROC gets its own bounded ROC on `vdev` (the
    /// managed role's or the P2P_DEVICE vdev; mac80211 `ieee80211_mgmt_tx`
    /// starts an offchannel ROC on the sending interface).
    pub(in crate::ath10k) async fn begin_private_frame(
        &mut self,
        vdev: u8,
        owner: Owner,
        cookie: u64,
        request: &MgmtTxRequest,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        self.validate_private_frame(cookie, request, &current()?)?;
        let frequency = u16::try_from(request.frequency_mhz).map_err(|_| Error::Unsupported)?;
        // Native setup/peer/TX has a finite500ms budget. The response tail
        // begins only at its actual terminal and is clipped to this original
        // grant; no host timer extends or fabricates foreign-channel time.
        self.begin_roc_on(
            vdev,
            owner,
            Receipt {
                cookie,
                frequency,
                duration: MAX_DURATION,
            },
            false,
            &current,
        )
        .await?;
        self.roc.as_mut().ok_or(Error::Failed)?.wait_ms = Some(if request.duration == 0 {
            10
        } else {
            request.duration
        });
        Ok(())
    }
    pub(in crate::ath10k) async fn begin_roc_action(
        &mut self,
        cookie: u64,
        request: &MgmtTxRequest,
        emission: RadioEmissionAuthority,
        current: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<(), Error> {
        self.validate_roc_action(cookie, request, &emission, &current()?)?;
        if !emission.current()
            || cookie == 0
            || !request.offchannel_ok
            || !self.offchannel_action_supported()
            || !self.roc_current(&current()?)?
        {
            return Err(Error::Unsupported);
        }
        let w = self.roc.as_ref().ok_or(Error::Failed)?;
        if request.frequency_mhz != u32::from(w.receipt.frequency)
            || w.public && request.duration != 0
            || w.action.is_some()
            || request.no_cck && w.receipt.frequency < 3000
        {
            return Err(Error::Unsupported);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let permission = self.hinted_permission(&current()?, w.receipt.frequency, None, false)?;
        // Never upgrade a receive-only ROC by silently changing its inventory.
        if !w.plan.permissions.contains(&permission) {
            return Err(Error::Unsupported);
        }
        // Peer, MGMT_TX and HTT descriptors all name the ROC's own vdev,
        // whose address the frame must carry (`ath10k_mac_tx_wmi_mgmt`).
        let vdev = w.vdev;
        let destination = validate(&request.frame, self.vdev_address(vdev)?)?;
        let path = management::path(self.wire.dialect, self.features, caps)?;
        let existing = vdev == self.primary.id()
            && self
                .peer
                .as_ref()
                .is_some_and(|p| p.bssid == destination && p.mapped().is_some());
        let temporary = !existing && !self.htt.offchannel_frequency_field();
        let sync_delete = self.wire.sync_delete_required(caps);
        // The native protocol has unversioned peer/delete records. Drain the
        // ordered old receive stream before creating this new DA owner.
        let deadline = narf_time::Deadline::after_ms(1500);
        let mut idle = false;
        for _ in 0..4096 {
            if !emission.current() || !self.roc_current(&current()?)? || deadline.expired() {
                return Err(Error::Timeout);
            }
            if self.roc_progress().await? {
                idle = true;
                break;
            }
            narf_scheduler::yield_now().await;
        }
        if !idle {
            return Err(Error::Timeout);
        }
        self.roc.as_mut().ok_or(Error::Failed)?.action = Some(Action {
            cookie,
            emission: emission.clone(),
            vdev,
            destination,
            temporary,
            ids: [0; 32],
            delete_sent: false,
            delete_ack: !sync_delete,
            token: None,
            status: None,
            retired: false,
            response_until: None,
        });
        if temporary {
            // WMI_PEER_TYPE_DEFAULT, not the associated BSS peer type. Native
            // multicast DA peers are legitimate offchannel firmware records.
            let create = self.wire.offchannel_peer(vdev, destination)?;
            let roc_emission = self
                .roc
                .as_ref()
                .ok_or(Error::Failed)?
                .owner
                .emission
                .clone();
            self.send_scan_command(&create, &|| {
                if !emission.current() || !roc_emission.current() {
                    return Err(Error::Failed);
                }
                permission.check(&current()?)
            })
            .await?;
            let deadline = narf_time::Deadline::after_ms(1500);
            for _ in 0..65536 {
                if !self.roc_current(&current()?)? {
                    return Err(Error::Timeout);
                }
                if self.roc_action()?.ids.iter().any(|b| *b != 0) {
                    break;
                }
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                self.roc_progress().await?;
                narf_scheduler::yield_now().await;
            }
            if self.roc_action()?.ids.iter().all(|b| *b == 0) {
                return Err(Error::Timeout);
            }
        }
        if !self.roc_current(&current()?)? {
            return Err(Error::Timeout);
        }
        let frequency = self.roc.as_ref().ok_or(Error::Failed)?.receipt.frequency;
        let (token, command) = match path {
            management::Path::Htt => {
                let (id, command) = self.htt.prepare_offchannel(
                    Parameters {
                        kind: Kind::Management,
                        vdev,
                        tid: 17,
                        hardware_crypto: false,
                    },
                    &request.frame,
                    frequency,
                )?;
                (ManagementToken::Htt(id), command)
            }
            management::Path::Reference => {
                let (id, address) = self
                    .htt
                    .wmi
                    .htc
                    .transport
                    .prepare_wmi_management(&request.frame)?;
                (
                    ManagementToken::Wmi(id),
                    management::reference(vdev, id, address, &request.frame)?,
                )
            }
            management::Path::Inline(_) => return Err(Error::Unsupported),
        };
        // Store the actual DMA ID before its first potentially suspended
        // publication; dropping FRAME never loses this terminal owner.
        self.roc
            .as_mut()
            .ok_or(Error::Failed)?
            .action
            .as_mut()
            .ok_or(Error::Failed)?
            .token = Some(token);
        let roc_emission = self
            .roc
            .as_ref()
            .ok_or(Error::Failed)?
            .owner
            .emission
            .clone();
        let tail = self
            .roc
            .as_ref()
            .ok_or(Error::Failed)?
            .duration
            .ok_or(Error::Failed)?;
        let validate = || {
            if tail.expired() {
                return Err(Error::Timeout);
            }
            if !emission.current() || !roc_emission.current() {
                return Err(Error::Failed);
            }
            permission.check(&current()?)
        };
        match token {
            ManagementToken::Htt(_) => {
                checked_policy(
                    async {
                        self.htt
                            .submit_prepared(&command)
                            .await
                            .map_err(Error::from)
                    },
                    &validate,
                )
                .await?
            }
            ManagementToken::Wmi(_) => self.send_scan_command(&command, &validate).await?,
            ManagementToken::Inline => return Err(Error::Unsupported),
        }
        validate()
    }
    fn roc_action(&self) -> Result<&Action, Error> {
        self.roc
            .as_ref()
            .and_then(|w| w.action.as_ref())
            .ok_or(Error::Failed)
    }
    pub(in crate::ath10k::wmi_runtime) fn observe_roc_peer(
        &mut self,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        let Some(a) = self.roc.as_mut().and_then(|w| w.action.as_mut()) else {
            return Ok(false);
        };
        if !a.temporary {
            return Ok(false);
        }
        if !matches!(bytes.first(), Some(3 | 4)) {
            return Ok(false);
        }
        if bytes.len() != if bytes[0] == 3 { 12 } else { 4 } {
            return Err(Error::Malformed);
        }
        let id = u16::from_le_bytes([bytes[2], bytes[3]]);
        if id >= 2048 {
            return Err(Error::Malformed);
        }
        let word = &mut a.ids[usize::from(id) / 64];
        let bit = 1u64 << (id % 64);
        if bytes[0] == 3 {
            // HTT PEER_MAP byte 1 is the vdev the peer was created on.
            if bytes[1] != a.vdev || bytes[4..10] != a.destination {
                if *word & bit != 0 {
                    return Err(Error::Malformed);
                }
                return Ok(false);
            }
            if self.peer.as_ref().is_some_and(|p| p.owns(id)) || a.delete_sent {
                return Err(Error::Malformed);
            }
            *word |= bit;
            return Ok(true);
        }
        if *word & bit == 0 {
            return Ok(false);
        }
        if !a.delete_sent {
            return Err(Error::Failed);
        }
        *word &= !bit;
        Ok(true)
    }
    pub(super) fn observe_roc_action_completion(&mut self) -> Result<(), Error> {
        let Some(a) = self.roc.as_ref().and_then(|w| w.action.as_ref()) else {
            return Ok(());
        };
        if a.status.is_some() {
            return Ok(());
        }
        let status = match a.token {
            Some(ManagementToken::Htt(id)) => {
                self.htt.take_tx_receipt_for(id).map(|r| r.status == 0)
            }
            Some(ManagementToken::Wmi(id)) => self
                .management_done
                .iter()
                .position(|r| r.id == id)
                .and_then(|at| self.management_done.remove(at))
                .map(|r| r.status == 0),
            _ => None,
        };
        if let Some(status) = status {
            let wait = self.roc.as_ref().ok_or(Error::Failed)?.wait_ms;
            let a = self
                .roc
                .as_mut()
                .and_then(|w| w.action.as_mut())
                .ok_or(Error::Failed)?;
            a.status = Some(status && a.destination[0] & 1 == 0);
            a.response_until = wait.map(|ms| narf_time::Deadline::after_ms(u64::from(ms)));
            if wait.is_some() {
                self.close_roc_capture()?;
                self.open_roc_capture()?;
            }
        }
        Ok(())
    }
    pub(super) fn roc_action_current(&self) -> bool {
        self.roc
            .as_ref()
            .and_then(|w| w.action.as_ref())
            .is_none_or(|a| a.emission.current())
    }
    pub(super) fn roc_action_retired(&self) -> bool {
        self.roc
            .as_ref()
            .and_then(|w| w.action.as_ref())
            .is_none_or(|a| a.retired)
    }
    pub(super) async fn retire_roc_action(
        &mut self,
        cleanup: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some(a) = self.roc.as_ref().and_then(|w| w.action.as_ref()) else {
            return Ok(());
        };
        if a.retired || a.status.is_none() && a.token.is_some() {
            return Ok(());
        }
        // Keep a private FRAME's separate DA peer through its response
        // window. Deleting it immediately could stall RX behind a native
        // credit/delete wait. TX already has its terminal, but peer/native
        // resources retire only after that finite window and scan terminal.
        if a.temporary
            && self
                .roc
                .as_ref()
                .is_some_and(|w| !w.public && !w.terminal && !w.stop_sent)
        {
            return Ok(());
        }
        if !a.temporary {
            self.roc
                .as_mut()
                .and_then(|w| w.action.as_mut())
                .ok_or(Error::Failed)?
                .retired = true;
            return Ok(());
        }
        if !a.delete_sent {
            // When no descriptor was published, MAP still proves the exact
            // created peer before DELETE. Uncertain creation is retained.
            if a.ids.iter().all(|b| *b == 0) {
                return Err(Error::Failed);
            }
            let (vdev, destination) = (a.vdev, a.destination);
            let deadline = narf_time::Deadline::after_ms(1500);
            let mut idle = false;
            for _ in 0..4096 {
                cleanup()?;
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                if self.roc_progress().await? {
                    idle = true;
                    break;
                }
                narf_scheduler::yield_now().await;
            }
            if !idle {
                return Err(Error::Timeout);
            }
            self.roc
                .as_mut()
                .and_then(|w| w.action.as_mut())
                .ok_or(Error::Failed)?
                .delete_sent = true;
            let command = self.wire.delete_offchannel_peer(vdev, destination)?;
            self.send_scan_command(&command, cleanup).await?;
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        for _ in 0..65536 {
            cleanup()?;
            let a = self.roc_action()?;
            if a.ids.iter().all(|b| *b == 0) && a.delete_ack {
                self.roc
                    .as_mut()
                    .and_then(|w| w.action.as_mut())
                    .ok_or(Error::Failed)?
                    .retired = true;
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.htt.poll().await?;
            if let htt::Event::Wmi(bytes) = &event {
                if Some(wire::word(bytes, 0)? & 0xffffff) == self.wire.delete_event_id()
                    && self
                        .wire
                        .delete_response(&bytes[4..], self.roc_action()?.destination)?
                {
                    self.roc
                        .as_mut()
                        .and_then(|w| w.action.as_mut())
                        .ok_or(Error::Failed)?
                        .delete_ack = true;
                }
            }
            let _ = self.station_event(event)?;
            self.observe_roc_action_completion()?;
            narf_scheduler::yield_now().await;
        }
        Err(Error::Timeout)
    }
    pub(super) fn completed_private_action(&self) -> Result<Option<Completed>, Error> {
        let w = self.roc.as_ref().ok_or(Error::Failed)?;
        if w.public {
            return Ok(None);
        }
        let a = w.action.as_ref().ok_or(Error::Failed)?;
        if !a.retired || !a.emission.current() {
            return Err(Error::Failed);
        }
        Ok(Some(Completed {
            cookie: a.cookie,
            status: a.status.ok_or(Error::Failed)?,
            emission: a.emission.clone(),
        }))
    }
    pub(in crate::ath10k) fn take_roc_action_status(
        &mut self,
        cookie: u64,
    ) -> Result<Option<bool>, Error> {
        if let Some(done) = &self.management_completed {
            if done.cookie != cookie || !done.emission.current() {
                return Err(Error::Failed);
            }
            return Ok(self.management_completed.take().map(|done| done.status));
        }
        if self.roc.as_ref().is_some_and(|w| !w.public) {
            return Ok(None);
        }
        let a = self.roc_action()?;
        if a.cookie != cookie {
            return Err(Error::Unsupported);
        }
        if !a.retired {
            return Ok(None);
        }
        let status = a.status.ok_or(Error::Failed)?;
        self.roc.as_mut().ok_or(Error::Failed)?.action = None;
        Ok(Some(status))
    }
}
