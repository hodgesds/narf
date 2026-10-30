// SPDX-License-Identifier: GPL-2.0-or-later
//! Cooperative WMI for an outer retained scan owner. Credits/sequence live in
//! Session, and CE3 occupancy/bounce DMA live in HIF. Dropping a public waiter
//! cannot discard either receipt or reopen/reuse an outstanding source slot.
use super::*;

impl<T: Hif> Session<T> {
    fn retained_wmi_ready(&mut self) -> Result<bool, Error> {
        self.transport.check_current()?;
        if !self.started || self.failed {
            return Err(Error::Failed);
        }
        let pipe = self.endpoints[self.wmi as usize].pipe;
        self.failed = true;
        let ready = super::super::firmware_source::invoke(
            self.transport.current_sources().as_ref(),
            || self.transport.source_ready(pipe),
        )
        .map_err(|_| Error::Transport(BmiError::DeviceGone))??;
        self.failed = false;
        Ok(ready)
    }

    /// Consume only native wire/credit progress. Keep WMI/HTT payloads in
    /// Session's existing queue for their one ordinary protocol owner.
    fn retained_wmi_progress(&mut self) -> Result<(), Error> {
        self.transport.check_current()?;
        if self.failed {
            return Err(Error::Failed);
        }
        self.failed = true;
        let wire = match self.pending_wire.pop_front() {
            Some(wire) => Some(wire),
            None => super::super::firmware_source::invoke(
                self.transport.current_sources().as_ref(),
                || self.transport.poll_now(),
            )
            .map_err(|_| Error::Transport(BmiError::DeviceGone))??,
        };
        if let Some((pipe, bytes)) = wire {
            self.accept(pipe, &bytes)?;
        }
        self.failed = false;
        Ok(())
    }

    fn begin_retained_wmi(&mut self, payload: &[u8]) -> Result<bool, Error> {
        if !self.retained_wmi_ready()? {
            return Ok(false);
        }
        if payload.is_empty()
            || payload.len() > usize::from(self.endpoints[self.wmi as usize].maximum)
        {
            return Err(Error::Malformed);
        }
        let credits = (payload.len() + 8).div_ceil(usize::from(self.credit_size)) as u16;
        let endpoint = &mut self.endpoints[self.wmi as usize];
        if endpoint.credits < credits {
            return Ok(false);
        }
        let mut frame = owned(&[0; 8])?;
        frame
            .try_reserve_exact(payload.len())
            .map_err(|_| Error::NoMemory)?;
        frame[0] = self.wmi;
        frame[1] = 1;
        frame[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        frame[5] = endpoint.sequence;
        frame.extend_from_slice(payload);
        endpoint.credits -= credits;
        endpoint.sequence = endpoint.sequence.wrapping_add(1);
        let pipe = endpoint.pipe;
        self.failed = true;
        super::super::firmware_source::invoke(self.transport.current_sources().as_ref(), || {
            self.transport.begin_send(pipe, &frame)
        })
        .map_err(|_| Error::Transport(BmiError::DeviceGone))??;
        self.failed = false;
        Ok(true)
    }

    /// Caller keeps Radio's scan ID/failed state retained across every await.
    /// This is a publication + exact CE-source receipt, never a firmware ACK.
    /// Cancellation while waiting for credits or CE completion leaves the
    /// Session usable only by that outer owner's quiescing continuation.
    pub(in crate::ath10k) async fn send_wmi_retained(
        &mut self,
        payload: &[u8],
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        while !self.begin_retained_wmi(payload)? {
            if deadline.expired() {
                return Err(Error::Transport(BmiError::Timeout));
            }
            self.retained_wmi_progress()?;
            narf_scheduler::yield_now().await;
        }
        self.wait_wmi_source().await?;
        Ok(())
    }

    /// A cancelled restore may already have its firmware scan terminal, but
    /// its last command's source bounce remains owned until this CE receipt.
    pub(in crate::ath10k) async fn wait_wmi_source(&mut self) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        while !self.retained_wmi_ready()? {
            if deadline.expired() {
                return Err(Error::Transport(BmiError::Timeout));
            }
            self.retained_wmi_progress()?;
            narf_scheduler::yield_now().await;
        }
        Ok(())
    }
}
