// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent native BE allocations and one immutable descriptor batch.
use super::*;
pub(super) struct Pending {
    id: u64,
    slot: usize,
    length: usize,
    next: u16,
    consumed: bool,
    started: u64,
    pub(super) report_sequence: u8,
    pub(super) report: Option<bool>,
}
impl Core {
    pub(in crate::rtw88) fn aggregation(
        &mut self,
        cfg: Option<format::Aggregation>,
    ) -> Result<(), Error> {
        if !self.ready() || cfg.is_some_and(|c| !c.valid()) {
            return Err(Error::State);
        }
        self.aggregation = cfg;
        Ok(())
    }
    pub(in crate::rtw88) fn submit_batch(
        &mut self,
        port: &mut impl Port,
        frames: &[Vec<u8>],
    ) -> Result<Vec<u64>, Error> {
        if !self.ready() {
            return Err(Error::Busy);
        }
        let cfg = self.aggregation.ok_or(Error::State)?;
        if !port.originator_ba_allowed() || !cfg.admits(self.data_profile, frames) {
            return Err(Error::Access);
        }
        port.transmit_allowed()?;
        let count = frames.len();
        if usize::from(self.reports) + count > 64 {
            let index = port.index(0x3b4)?;
            if !self.rx_idle
                || index & 0xfff != u32::from(self.rx)
                || index >> 16 & 0xfff != u32::from(self.rx)
            {
                return Err(Error::Busy);
            }
            self.reports = 0;
        }
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(count)
            .map_err(|_| Error::Memory)?;
        let mut ids = Vec::new();
        ids.try_reserve_exact(count).map_err(|_| Error::Memory)?;
        self.batch_pending
            .try_reserve(count)
            .map_err(|_| Error::Memory)?;
        for (slot, frame) in frames.iter().enumerate() {
            if frame.len() < 26 || frame[0] != 0x88 || frame[24..26] != [0, 0] {
                return Err(Error::Packet);
            }
            let sequence = (self.reports + slot as u8) << 2;
            let (mut descriptor, queue) = format::transmit_profile(
                frame,
                self.own,
                self.mac_id,
                Some(sequence),
                self.data_profile,
            )?;
            if queue != Queue::Data {
                return Err(Error::Packet);
            }
            let word2 = u32::from_le_bytes(descriptor[8..12].try_into().unwrap())
                | (1 << 12)
                | u32::from(cfg.density) << 20;
            let word3 = u32::from_le_bytes(descriptor[12..16].try_into().unwrap()) | 3 << 17;
            descriptor[8..12].copy_from_slice(&word2.to_le_bytes());
            descriptor[12..16].copy_from_slice(&word3.to_le_bytes());
            super::super::protection::descriptor(
                &mut descriptor,
                frame.len(),
                port.rts_threshold(),
            );
            let memory = self.batch_buffers.get(slot).ok_or(Error::State)?;
            let bd = format::buffer_descriptor(memory.dma_addr().raw(), frame.len())?;
            let id = self.next_id.checked_add(slot as u64).ok_or(Error::State)?;
            let next = (usize::from(self.tx_host[1]) + slot + 1) % Queue::Data.depth();
            prepared.push((descriptor, bd, next as u16, sequence));
            ids.push(id);
        }
        let next_id = self.next_id.checked_add(count as u64).ok_or(Error::State)?;
        let result = (|| {
            for (slot, (frame, (descriptor, bd, next, sequence))) in
                frames.iter().zip(&prepared).enumerate()
            {
                let memory = &self.batch_buffers[slot];
                port.memory(|| {
                    copy_to(memory, 0, descriptor)?;
                    copy_to(memory, format::TX_DESC, frame)
                })?;
                // Seal identity and immutable bytes before the first visible
                // BD. A later failure pins every possibly visible allocation.
                self.batch_pending.push_back(Pending {
                    id: ids[slot],
                    slot,
                    length: frame.len(),
                    next: *next,
                    consumed: false,
                    started: port.now_us(),
                    report_sequence: *sequence,
                    report: None,
                });
                self.batch_published = true;
                let ring_slot = (usize::from(self.tx_host[1]) + slot) % Queue::Data.depth();
                port.transmit_allowed()?;
                port.tx_descriptor(Queue::Data, ring_slot, bd)?;
            }
            let next = prepared.last().ok_or(Error::Packet)?.2;
            port.transmit_allowed()?;
            barrier();
            port.publish(Queue::Data.index(), next)?;
            self.tx_host[1] = next;
            self.next_id = next_id;
            self.reports += count as u8;
            self.rx_idle = false;
            Ok(ids)
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    pub(super) fn complete_batch(
        &mut self,
        port: &mut impl Port,
    ) -> Result<Option<Receipt>, Error> {
        if self.batch_pending.is_empty() {
            return Ok(None);
        }
        let index = port.index(Queue::Data.index())?;
        let host = (index & 0xfff) as u16;
        let device = (index >> 16 & 0xfff) as u16;
        let depth = Queue::Data.depth();
        if host != self.tx_host[1] || usize::from(device) >= depth {
            return Err(Error::Packet);
        }
        let available =
            (usize::from(self.tx_host[1]) + depth - usize::from(self.tx_device[1])) % depth;
        let advanced = (usize::from(device) + depth - usize::from(self.tx_device[1])) % depth;
        if advanced > available {
            return Err(Error::Packet);
        }
        for p in &mut self.batch_pending {
            if !p.consumed {
                let distance =
                    (usize::from(p.next) + depth - usize::from(self.tx_device[1])) % depth;
                if distance != 0 && distance <= advanced {
                    p.consumed = true;
                }
            }
            if port.now_us().saturating_sub(p.started) >= 1_000_000 {
                return Err(Error::Timeout);
            }
            if p.report == Some(false) {
                return Err(Error::Packet);
            }
        }
        self.tx_device[1] = device;
        let p = self.batch_pending.front().ok_or(Error::State)?;
        if !p.consumed || p.report != Some(true) {
            return Ok(None);
        }
        let memory = self.batch_buffers.get(p.slot).ok_or(Error::State)?;
        let bytes = port.memory(|| copy_from(memory, format::TX_DESC, p.length))?;
        let receipt = Receipt {
            id: p.id,
            bytes,
            radio_acknowledged: true,
        };
        self.batch_pending.pop_front();
        Ok(Some(receipt))
    }
}
