// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Sc bounded plaintext A-MSDU construction. Native key insertion
//! and the sole protected TX packet-number owner remain in firmware.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::iwlwifi) enum Batch {
    Unsuited,
    Busy,
    Sent,
}
impl Connection {
    pub(in crate::iwlwifi) fn amsdu_feedback(&mut self, packet: &super::super::runtime::Packet) {
        if packet.receive_queue != 0 || (packet.header.group_id, packet.header.cmd) != (5, 0xf7) {
            return;
        }
        if let Some(version) = self.tlc_notification_version {
            self.tx_amsdu.observe(version, &packet.payload);
        }
    }
    pub(in crate::iwlwifi) fn can_batch(&self, category: usize) -> bool {
        self.authorized
            && !self.power_pending
            && self.phy.mode != 0
            && self.qos.is_some()
            && category < 4
            && self.amsdu_memory.is_some()
            && self.tx_amsdu.permits(super::super::qos::TIDS[category])
    }
    pub(in crate::iwlwifi) fn amsdu_memory_pending(&self) -> bool {
        self.phy.mode != 0
            && self.qos.is_some()
            && self.tx_amsdu.active()
            && !self.amsdu_memory_attempted
    }
    pub(in crate::iwlwifi) async fn prepare_amsdu_memory(
        &mut self,
        hw: &mut Hardware,
    ) -> Result<(), &'static str> {
        if !self.amsdu_memory_pending() {
            return Ok(());
        }
        self.amsdu_memory_attempted = true;
        self.amsdu_memory = hw.station_shared_memory().await?;
        Ok(())
    }
    pub(in crate::iwlwifi) fn try_enqueue_batch(
        &mut self,
        hw: &mut Hardware,
        first: &[u8],
        second: &[u8],
        category: usize,
    ) -> Result<Batch, &'static str> {
        if !self.can_batch(category) {
            return Ok(Batch::Unsuited);
        }
        let tid = super::super::qos::TIDS[category];
        let qos = self.qos.as_ref().unwrap();
        if qos.admitted(category) != Some(category)
            || qos.classify(first) != Some(category)
            || qos.classify(second) != Some(category)
        {
            return Ok(Batch::Unsuited);
        }
        let Some(ceiling) = self.tx_amsdu.payload_ceiling(
            self.amsdu_memory.as_ref().unwrap(),
            hw.station_lmac(self.beacon.channel),
            tid,
            self.he.is_some(),
        ) else {
            return Ok(Batch::Unsuited);
        };
        let Ok(body) = narf_wireless::amsdu::encode(
            &[first, second],
            self.local,
            narf_wireless::amsdu::Limit::Ht3839,
        ) else {
            return Ok(Batch::Unsuited);
        };
        if body.len() > ceiling {
            return Ok(Batch::Unsuited);
        }
        let queue = self.data_queues[category].ok_or("Sc A-MSDU lost admitted native queue")?;
        if !hw.transmit_space(queue)? {
            return Ok(Batch::Busy);
        }
        let Some(mut frame) = frame_api::transmit_qos(
            self.local,
            self.beacon.bssid,
            self.sequence,
            first,
            self.security.is_some(),
            tid,
        ) else {
            return Ok(Batch::Unsuited);
        };
        frame.truncate(26);
        frame[24] |= 0x80;
        frame.extend_from_slice(&body);
        // The existing transport derives MAC-size and the native AMSDU/PAD
        // exclusion from this actual QoS header. No pre-encryption or host
        // PTK/PN synthesis is involved. Current source/policy is invoked at
        // the actual descriptor/doorbell publication inside enqueue.
        hw.enqueue_transmit_assisted(queue, &frame, 26, None, 1 << 14)?;
        self.sequence = self.sequence.wrapping_add(1);
        Ok(Batch::Sent)
    }
}
