// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 per-physical-RFH replay and native deaggregation state.
//! Physical queue identity comes from DMA copy ownership, never RX bytes.
use super::{super::frame_api::Replay, data::Prepared};
use alloc::vec::Vec;

#[derive(Default)]
pub(super) struct Queue {
    pub replay: Replay,
    pub aggregate: super::amsdu::Receiver,
}
impl Prepared {
    pub(super) fn receiver(
        &mut self,
        queue: u8,
    ) -> Option<(&mut Replay, &mut super::amsdu::Receiver)> {
        if queue == 0 {
            Some((&mut self.replay, &mut self.aggregate))
        } else {
            self.extra_rx
                .get_mut(usize::from(queue) - 1)
                .map(|rx| (&mut rx.replay, &mut rx.aggregate))
        }
    }
    pub(super) fn each_receiver(
        &mut self,
        mut operation: impl FnMut(&mut Replay, &mut super::amsdu::Receiver),
    ) {
        operation(&mut self.replay, &mut self.aggregate);
        for rx in &mut self.extra_rx {
            operation(&mut rx.replay, &mut rx.aggregate);
        }
    }
    pub(super) fn pop_aggregate(&mut self, now: u64) -> Option<Vec<u8>> {
        self.aggregate.pop(now).or_else(|| {
            self.extra_rx
                .iter_mut()
                .find_map(|rx| rx.aggregate.pop(now))
        })
    }
    /// History spans the whole radio. A safely reused PTK cannot start
    /// below any committed queue/TID floor, even after new RSS steering.
    pub(super) fn pairwise_floors(&self) -> [u64; 17] {
        let mut floors = self.replay.pairwise;
        for rx in &self.extra_rx {
            for (floor, pn) in floors.iter_mut().zip(rx.replay.pairwise) {
                *floor = (*floor).max(pn);
            }
        }
        floors
    }
}

pub(super) fn receivers(queues: u8) -> Result<Vec<Queue>, &'static str> {
    if !(1..=3).contains(&queues) {
        return Err("MVM native RFH queue count outside retained profile");
    }
    let mut receivers = Vec::new();
    for _ in 1..queues {
        receivers.push(Queue::default());
    }
    Ok(receivers)
}

impl super::Owner {
    pub(super) fn close_gen2_receive_epoch(&mut self) -> Result<(), &'static str> {
        if self.hardware.receive_queue_count() > 1 {
            let epoch = self.hardware.close_receive_epoch()?;
            let data = self
                .power
                .prepared
                .as_mut()
                .and_then(|p| p.mlme.data.as_mut())
                .ok_or("MVM multi-RFH epoch lacks data owner")?;
            data.receive_epoch = Some(epoch);
        }
        Ok(())
    }
    pub(super) fn commit_gen2_receive_epoch(&mut self) -> Result<(), &'static str> {
        if self.hardware.receive_queue_count() > 1 {
            let epoch = self
                .power
                .prepared
                .as_ref()
                .and_then(|p| p.mlme.data.as_ref())
                .and_then(|d| d.receive_epoch)
                .ok_or("MVM multi-RFH receive epoch absent")?;
            self.hardware.commit_receive_epoch(epoch)?;
        }
        Ok(())
    }
}
