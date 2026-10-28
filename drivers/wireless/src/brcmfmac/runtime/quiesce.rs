// SPDX-License-Identifier: GPL-2.0-or-later
//! D3 mailbox handshake and the DMA-stop proof that makes published msgbuf
//! memory reclaimable.
//!
//! Linux v7.2 `pcie.c::brcmf_pcie_pm_enter_D3` sets the bus down, sends
//! `BRCMF_H2D_HOST_D3_INFORM` and waits `BRCMF_PCIE_MBDATA_TIMEOUT` (2 s) for
//! `BRCMF_D2H_DEV_D3_ACK`; on timeout it returns the bus to UP.
//! `brcmf_pcie_pm_leave_D3` checks `INTMASK` for a still-powered dongle,
//! sends `BRCMF_H2D_HOST_D0_INFORM` and re-enables the mailbox and
//! host-ready; otherwise it re-probes (firmware was lost).
//! `brcmf_pcie_reset`/`brcmf_pcie_remove` release the IRQ and only then the
//! scratch and ring buffers.
//!
//! The reclaim proof is stricter than Linux, which frees rings after
//! `release_irq` without any device-side evidence: the firmware must have
//! acknowledged D3 (it stops its DMA engines before acking), every D2H
//! completion published before the ack is consumed, BME is cleared with a
//! verified readback, and non-posted BAR reads issued after BME clear (whose
//! completions cannot pass earlier device posted writes) must still observe
//! unchanged D2H write indices and a present function. Only that complete
//! proof marks the owner reclaimable; any timeout, fault or change keeps all
//! published memory retained forever.
use super::*;
use mailbox::{H2D_HOST_D0_INFORM, H2D_HOST_D3_INFORM};

/// `BRCMF_PCIE_MBDATA_TIMEOUT`.
const MBDATA_TIMEOUT_MS: u64 = 2000;
/// `brcmf_pcie_send_mb_data` pending-word wait: 100 x 10 ms.
const MB_PENDING_TRIES: usize = 100;

/// Outcome of a confirmed stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopProof {
    /// D2H completions consumed between the D3 ack and BME clear.
    pub drained: usize,
    /// D2H write indices observed by the post-BME flush reads.
    pub indices: [u16; 3],
}

impl<B: Bus> Runtime<B> {
    /// Whether a confirmed stop proved all published DMA reclaimable.
    pub fn is_reclaimable(&self) -> bool {
        self.reclaimable
    }
    /// Whether the bus is in the Linux `BRCMFMAC_PCIE_STATE_DOWN` state.
    pub fn is_down(&self) -> bool {
        self.down
    }
    async fn send_mb_data(&mut self, value: u32) -> Result<(), Error> {
        for _ in 0..MB_PENDING_TRIES {
            match self.try_send_mb_data(value) {
                Err(Error::Busy) => {
                    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(10_000_000)).await
                }
                other => return other,
            }
        }
        Err(Error::Timeout)
    }
    /// `brcmf_pcie_pm_enter_D3`. Requires an idle control path: a pending
    /// IOCTL would otherwise lose its completion across the down state.
    pub async fn enter_d3(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.down || self.pending.is_some() || self.mailbox.is_none() {
            return Err(Error::Busy);
        }
        // brcmf_bus_change_state(BRCMF_BUS_DOWN): no further H2D posts.
        self.down = true;
        if let Some(mailbox) = self.mailbox.as_mut() {
            mailbox.d3_acked = false;
            mailbox.awaiting = true;
        }
        let result = self.await_d3_ack().await;
        if let Some(mailbox) = self.mailbox.as_mut() {
            mailbox.awaiting = false;
        }
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                if !self.failed {
                    // Timeout: Linux returns the bus to UP and fails suspend.
                    self.down = false;
                    let _ = self.intr_enable();
                }
                Err(error)
            }
        }
    }
    async fn await_d3_ack(&mut self) -> Result<(), Error> {
        self.send_mb_data(H2D_HOST_D3_INFORM).await?;
        let deadline = narf_time::Deadline::after_ms(MBDATA_TIMEOUT_MS);
        loop {
            // A vector or the fallback poll services MAILBOXINT/FN0 here.
            if let Err(error) = self.service_mailbox() {
                self.fail();
                return Err(error);
            }
            if self.mailbox.is_some_and(|m| m.d3_acked) {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }
    /// `brcmf_pcie_pm_leave_D3` hot path. `Err(Failed)` means the dongle
    /// lost power or firmware (`INTMASK` reads zero): Linux re-probes, and
    /// this owner becomes terminal so a transport reset must rebuild it.
    pub async fn leave_d3(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let Some(mailbox) = self.mailbox else {
            return Err(Error::Protocol);
        };
        if !self.down {
            return Err(Error::Busy);
        }
        let alive = match self.read_reg(mailbox.reg.intmask) {
            Ok(value) => value != 0,
            Err(_) => false,
        };
        if !alive || self.send_mb_data(H2D_HOST_D0_INFORM).await.is_err() {
            self.fail();
            return Err(Error::Failed);
        }
        self.down = false;
        self.intr_enable()?;
        let db1 = self.hostrdy_db1;
        self.bus.host_ready(db1)?;
        Ok(())
    }
    /// Consume completions published before the D3 ack without posting
    /// replacement buffers (the bus is down).
    fn drain_completions(&mut self) -> Result<usize, Error> {
        let mut total = 0;
        loop {
            let processed = self.service_rings()?;
            total += processed;
            if processed == 0 {
                return Ok(total);
            }
        }
    }
    pub(super) fn completion_indices(&mut self) -> Result<[u16; 3], Error> {
        let mut indices = [0; 3];
        for (slot, ring_id) in (2..5).enumerate() {
            let address = self.resources.as_ref().unwrap().rings[ring_id].wptr;
            indices[slot] = read16(&mut self.bus, address)?;
        }
        Ok(indices)
    }
    /// Confirmed device stop: D3 handshake, completion drain, IRQ release,
    /// verified BME clear and post-clear flush reads. On success all
    /// published memory is reclaimable and is released by `Drop`/teardown.
    pub async fn quiesce(&mut self) -> Result<StopProof, Error> {
        if self.reclaimable {
            return Err(Error::Busy);
        }
        self.enter_d3().await?;
        let result = self.prove_stopped();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn prove_stopped(&mut self) -> Result<StopProof, Error> {
        let drained = self.drain_completions()?;
        let before = self.completion_indices()?;
        let reads: [u16; 3] =
            core::array::from_fn(|slot| self.resources.as_ref().unwrap().rings[slot + 2].read);
        if before != reads {
            return Err(Error::Protocol);
        }
        self.stop_interrupts();
        self.bus.park_dma()?;
        if self.bus.dma_enabled()? {
            return Err(Error::Access);
        }
        // Non-posted reads after BME clear: their completions order behind
        // every posted write the function issued before the clear.
        let after = self.completion_indices()?;
        let mailbox = self.mailbox.ok_or(Error::Protocol)?;
        self.read_reg(mailbox.reg.mailboxint)?;
        if after != before {
            return Err(Error::Protocol);
        }
        self.reclaimable = true;
        Ok(StopProof {
            drained,
            indices: after,
        })
    }
}
