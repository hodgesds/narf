// SPDX-License-Identifier: GPL-2.0-or-later
//! MSI-backed host-vote maintenance before any station association.
use super::*;

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// The retained Device pump calls this under its normal publication and
    /// Radio locks. There is no RF/key/scan command here. Unknown native input
    /// remains owned by the existing queue and prevents an idle declaration.
    pub(in crate::ath10k) fn poll_passive_host_idle(&mut self) -> Result<(), Error> {
        if !self.htt.wmi.htc.transport.runtime_idle_supported() {
            return Ok(());
        }
        let eligible = !self.failed
            && self.ready.is_some()
            && self.peer.is_none()
            && self.data.is_none()
            && self.scan_pending.is_none()
            && self.scan_dwell.is_none()
            && self.roc.is_none()
            && self.pending.is_empty()
            && self.management_done.is_empty()
            && self.management_received.is_empty()
            && self.management_completed.is_none()
            && self.coexistence.is_none();
        self.htt.wmi.htc.transport.runtime_idle(eligible);
        if !eligible {
            return Ok(());
        }
        self.htt
            .wmi
            .htc
            .transport
            .check_current()
            .map_err(crate::ath10k::control::Error::from)
            .map_err(htt::Error::from)?;
        self.failed = true;
        for _ in 0..64 {
            let event = self.htt.poll_now()?;
            if self.htt.take_idle_deferred() {
                // A CPU/timer/IRQ observation deferred BAR access. It is not
                // a genuine native Idle receipt, nor station/event authority.
                self.failed = false;
                return Ok(());
            }
            match event {
                htt::Event::Progress => {}
                htt::Event::Idle => {
                    self.failed = false;
                    return Ok(());
                }
                event => {
                    // Do not discard a peer/management/TX/RX event or let an
                    // unknown event become a fabricated empty prefix. Normal
                    // protocol owners can consume this exact retained event.
                    self.htt.wmi.htc.transport.runtime_idle(false);
                    self.queue(event)?;
                    self.failed = false;
                    return Ok(());
                }
            }
        }
        // Sustained credit-only input is bounded work, not a fresh quiet
        // prefix. Continue on the next real worker poll with host wake held.
        self.htt.wmi.htc.transport.runtime_idle(false);
        self.failed = false;
        Ok(())
    }
}
