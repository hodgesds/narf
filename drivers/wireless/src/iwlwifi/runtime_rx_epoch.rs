//! Single-RFH MLD BAID retirement. Firmware echoes an opaque host cookie,
//! type and BAID after that queue's prefix (Linux mld/{agg,rx}.c,rx.h).
use super::super::scan_api;
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Clone)]
pub(in crate::iwlwifi) struct Publication {
    generation: Arc<AtomicU64>,
    open: Arc<AtomicBool>,
    epoch: u64,
}
impl Publication {
    pub(in crate::iwlwifi) fn current(&self) -> bool {
        self.open.load(Ordering::Acquire) && self.generation.load(Ordering::Acquire) == self.epoch
    }
    pub(in crate::iwlwifi) fn same_epoch(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && Arc::ptr_eq(&self.generation, &other.generation)
            && Arc::ptr_eq(&self.open, &other.open)
    }
}

#[derive(Default)]
pub(super) struct State {
    cookie: u32,
    pending: Option<(u32, Option<u8>)>,
    generation: Arc<AtomicU64>,
    open: Arc<AtomicBool>,
    proved: Option<u64>,
}
impl State {
    pub(super) fn deny(&mut self) {
        self.open.store(false, Ordering::Release);
        self.proved = None;
    }
    pub(super) fn reset_after_dma_stop(&mut self) {
        self.pending = None;
        self.deny();
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn model() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(true)),
            ..Self::default()
        }
    }
    pub(super) fn capture(&self) -> Option<u64> {
        self.open
            .load(Ordering::Acquire)
            .then(|| self.generation.load(Ordering::Acquire))
    }
    fn reserve(&mut self, baid: Option<u8>) -> Result<u32, &'static str> {
        if baid.is_some_and(|id| id >= 32) || self.pending.is_some() {
            return Err("RX BAID epoch is invalid/already uncertain");
        }
        self.cookie = self
            .cookie
            .checked_add(1)
            .ok_or("RX BAID cookie exhausted")?;
        self.pending = Some((self.cookie, baid));
        Ok(self.cookie)
    }
}
impl Hardware {
    pub(in crate::iwlwifi) fn receive_capture_epoch(&self) -> Option<u64> {
        self.rx_epoch.capture()
    }
    pub(in crate::iwlwifi) fn receive_publication(&self) -> Option<Publication> {
        self.rx_epoch.capture().map(|epoch| Publication {
            generation: self.rx_epoch.generation.clone(),
            open: self.rx_epoch.open.clone(),
            epoch,
        })
    }
    pub(in crate::iwlwifi) fn close_receive_epoch(&mut self) -> Result<u64, &'static str> {
        self.rx_epoch.open.store(false, Ordering::Release);
        self.rx_epoch.proved = None;
        self.rx_epoch
            .generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map(|prior| prior + 1)
            .map_err(|_| "Intel receive generation exhausted")
    }
    pub(in crate::iwlwifi) fn commit_receive_epoch(
        &mut self,
        epoch: u64,
    ) -> Result<(), &'static str> {
        let fence = self.source_fence()?;
        fence.invoke(|| self.commit_receive_epoch_current(epoch))
    }
    fn commit_receive_epoch_current(&mut self, epoch: u64) -> Result<(), &'static str> {
        if self.failed
            || self.rx_epoch.pending.is_some()
            || self.rx_epoch.generation.load(Ordering::Acquire) != epoch
            || self.rx_epoch.proved != Some(epoch)
        {
            return Err("Intel receive generation lacks native prefix proof");
        }
        self.rx_epoch.proved = None;
        self.rx_epoch.open.store(true, Ordering::Release);
        Ok(())
    }
    /// MLD EMPTY (type0) is an ordered single-RFH prefix proof, not a
    /// temporarily empty descriptor ring or a key-command acknowledgement.
    pub(in crate::iwlwifi) async fn synchronize_receive_epoch(
        &mut self,
    ) -> Result<Vec<Packet>, &'static str> {
        if self.rx_epoch.open.load(Ordering::Acquire) {
            return Err("Intel receive epoch was not closed before native sync");
        }
        let prefix = self.synchronize_rx(None).await?;
        self.rx_epoch.proved = Some(self.rx_epoch.generation.load(Ordering::Acquire));
        Ok(prefix)
    }
    /// Only a matching native marker permits host BAID/window reuse. Return
    /// bounded original management packets for the Connection's existing
    /// peer/PHY/PMF checks; discard old data without committing its PN.
    pub(in crate::iwlwifi) async fn synchronize_rx_baid(
        &mut self,
        baid: u8,
    ) -> Result<Vec<Packet>, &'static str> {
        self.synchronize_rx(Some(baid)).await
    }
    async fn synchronize_rx(&mut self, baid: Option<u8>) -> Result<Vec<Packet>, &'static str> {
        if self.failed
            || self.format == rx_rfh::CompletionFormat::Qu
            || !matches!(self.version(5, 2).map(|v| v.0), None | Some(1 | 99))
        {
            return Err("unsupported/failed native MLD RX epoch contract");
        }
        let cookie = self.rx_epoch.reserve(baid)?;
        let result = self.rx_baid_marker(baid, cookie).await;
        match result {
            Ok(prefix) => {
                self.rx_epoch.pending = None;
                Ok(prefix)
            }
            Err(e) => {
                self.fail();
                Err(e)
            }
        }
    }
    async fn rx_baid_marker(
        &mut self,
        baid: Option<u8>,
        cookie: u32,
    ) -> Result<Vec<Packet>, &'static str> {
        let mut body = vec![0; if baid.is_some() { 24 } else { 20 }];
        boot_context::put32(&mut body, 4, 1); // single owned RFH queue0
        let count = if baid.is_some() { 12 } else { 8 };
        boot_context::put32(&mut body, 8, count);
        body[12] = u8::from(baid.is_some()); // EMPTY0 / DEL_BA1
        boot_context::put32(&mut body, 16, cookie);
        if let Some(id) = baid {
            boot_context::put32(&mut body, 20, u32::from(id));
        }
        let receipt = self.command_with_header_version(5, 2, &body, 0).await?;
        if !receipt.payload.is_empty() {
            return Err("MLD RX BAID epoch ACK extent");
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        let mut management = Vec::new();
        for _ in 0..4096 {
            let activity = self.activity();
            self.poll()?;
            for _ in 0..256 {
                let Some(index) = self.notifications.iter().position(|p| {
                    p.header.group_id == 0 && matches!(p.header.cmd, 0xc1..=0xc3)
                        || p.header.group_id == 5 && p.header.cmd == 0xff
                }) else {
                    break;
                };
                let packet = self.notifications.remove(index).unwrap();
                if packet.header.group_id == 5 {
                    let b = &packet.payload;
                    if b.len() != count as usize + 4
                        || b[..8] != [count as u8, 0, 0, 0, u8::from(baid.is_some()), 0, 0, 0]
                    {
                        return Err("MLD RX BAID marker geometry/type");
                    }
                    if u32::from_le_bytes(b[8..12].try_into().unwrap()) != cookie {
                        continue;
                    }
                    if baid.is_some_and(|id| b[12..16] != u32::from(id).to_le_bytes()) {
                        return Err("MLD RX BAID marker identity");
                    }
                    return Ok(management);
                }
                if packet.header.cmd == 0xc1
                    && scan_api::mpdu(&packet.payload)
                        .is_some_and(|m| m.frame.first().is_some_and(|fc| fc & 12 == 0))
                {
                    if management.len() == 32 {
                        return Err("MLD RX epoch management prefix bound");
                    }
                    management.push(packet);
                }
            }
            if deadline.expired() {
                return Err("MLD RX BAID marker timeout");
            }
            activity.await;
        }
        Err("MLD RX BAID marker progress bound")
    }
}
