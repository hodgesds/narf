// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained TLC_MNG_UPDATE_NTFY_API_S_VER_3 per-TID aggregate limits.
//! Linux mvm/rs-fw.c::iwl_mvm_tlc_update_notif. These firmware facts do not
//! select a signed TX A-MSDU emitter or grant queue/key/controlled-port access.
use super::{Owner, Phase};
use alloc::vec::Vec;
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::reg::RegulatoryDomain;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Limits {
    size: u16,
    tids: u8,
}
impl Limits {
    pub(super) fn get(&self, tid: u8) -> Option<u16> {
        (tid < 8 && self.tids & (1 << tid) != 0 && self.size != 0).then_some(self.size)
    }
    pub(super) fn observe(&mut self, bytes: &[u8]) {
        // The retained API77 AP is station0. An unrelated station's report
        // cannot change its limits; malformed matching input suppresses use
        // until a fresh complete report, instead of retaining a larger size.
        if bytes.first().is_some_and(|sta| *sta != 0) {
            return;
        }
        if bytes.len() != 20 || bytes[1..4] != [0; 3] {
            *self = Self::default();
            return;
        }
        let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if flags & !3 != 0 {
            *self = Self::default();
            return;
        }
        if flags & 2 == 0 {
            return;
        } // RATE-only notification.
        let size = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let mask = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if size < 2000 {
            *self = Self::default();
        } else {
            // Every admitted HT peer supports3839; retaining that smaller
            // limit avoids inferring an unnegotiated 7935/11454 profile.
            self.size = size.min(3839) as u16;
            self.tids = mask as u8;
        }
    }
}

impl Owner {
    fn tx_amsdu_ceiling(&self, tid: u8) -> Option<usize> {
        if self.power.phy.features & super::power::feature::TX_AMSDU == 0
            || !self.power.phy.negotiated.is_some_and(|p| p.ht)
        {
            return None;
        }
        let power = self.power.prepared.as_ref()?;
        if power.emission.features() & super::power::feature::TX_AMSDU == 0 {
            return None;
        }
        let data = power.mlme.data.as_ref()?;
        let firmware = data.tx_amsdu.get(tid)?;
        let cdb = super::super::parse_ucode(&self.firmware)
            .ok()?
            .api
            .has_capability(40);
        let lmac = u8::from(data.status.channel > 14 && cdb);
        let fifo = self
            .power
            .shared_memory
            .as_ref()?
            .edca_payload_ceiling(lmac, tid)?;
        // TLC max_mpdu_len is3839: reserve QoS MAC26, CCMP16 and FCS4
        // even for Open traffic, so the complete on-air MPDU stays bounded.
        Some(usize::from(firmware).min(fifo as usize).min(3839 - 46))
    }
    pub(in crate::iwlwifi) fn station_can_amsdu_batch(&self, tid: u8) -> bool {
        self.phase == Phase::DataPrepared
            && self.tx_amsdu_ceiling(tid).is_some_and(|limit| limit >= 44)
    }
    pub(in crate::iwlwifi) async fn transmit_amsdu_batch_using(
        &mut self,
        packets: &[(Vec<u8>, u32)],
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if packets.is_empty() || packets.len() > 8 {
            return Err("MVM A-MSDU batch bound");
        }
        let mut at = 0;
        while at < packets.len() {
            let tid = self.data_tid(&packets[at].0);
            let count = packets[at..]
                .iter()
                .take_while(|(bytes, assist)| *assist == 0 && self.data_tid(bytes) == tid)
                .count();
            let mut count = count.min(8);
            let mut aggregate = None;
            if let Some(ceiling) = self.tx_amsdu_ceiling(tid) {
                while count >= 2 {
                    let frames: Vec<_> = packets[at..at + count]
                        .iter()
                        .map(|(bytes, _)| bytes.as_slice())
                        .collect();
                    if let Ok(body) = narf_wireless::amsdu::encode(
                        &frames,
                        self.mac.unwrap(),
                        narf_wireless::amsdu::Limit::Ht3839,
                    ) {
                        if body.len() <= ceiling {
                            aggregate = Some(body);
                            break;
                        }
                    }
                    count -= 1;
                }
            }
            if let Some(body) = aggregate {
                self.transmit_amsdu_body(&body, tid, &mut policy).await?;
                at += count;
            } else {
                // A caller checksum request retains the existing single-MSDU
                // offload; control/tunnel frames never enter an A-MSDU.
                self.transmit_data_assisted(&packets[at].0, packets[at].1, &mut policy)
                    .await?;
                at += 1;
            }
        }
        Ok(())
    }
    async fn transmit_amsdu_body(
        &mut self,
        body: &[u8],
        tid: u8,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let status = self.data_ready(&policy()?)?;
        if status.protected && !self.security.ready() {
            return Err("MVM A-MSDU controlled port is not authorized");
        }
        if self
            .tx_amsdu_ceiling(tid)
            .is_none_or(|ceiling| body.len() > ceiling)
        {
            return Err("MVM A-MSDU lacks current TLC/FIFO/program admission");
        }
        let local = self.mac.ok_or("MVM A-MSDU MAC absent")?;
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let queue = if tid == 0 {
            status.queue
        } else {
            data.tid_queues[usize::from(tid)].ok_or("MVM A-MSDU TID queue absent")?
        };
        let sequence = if tid == 0 {
            &mut data.sequence
        } else {
            &mut data.tid_sequences[usize::from(tid)]
        };
        let mut frame =
            super::super::frame_api::management(0x88, local, status.bssid, *sequence, &[]);
        frame[1] = 1 | if status.protected { 0x40 } else { 0 };
        frame.extend_from_slice(&[0x80 | tid, 0]);
        frame.extend_from_slice(body);
        *sequence = sequence.wrapping_add(1) & 4095;
        self.phase = Phase::TransmittingData;
        let result = async {
            self.fresh_data_policy(policy).await?;
            if tid == 0 && self.ba_qualified() {
                self.enable_ba_tx(policy).await?;
            }
            {
                let power = self.power.prepared.as_ref().unwrap();
                let mut future =
                    pin!(self
                        .hardware
                        .transmit_assisted(queue, &frame, 26, None, 1 << 14));
                poll_fn(|cx| {
                    if let Err(error) = policy().and_then(|domain| power.check_applied(&domain)) {
                        return Poll::Ready(Err(error));
                    }
                    future.as_mut().poll(cx)
                })
                .await?;
            }
            self.check_link_power(&policy()?)?;
            if !self.hardware.idle_tx_binding(queue, 0, tid) {
                return Err("MVM A-MSDU completion left native DMA outstanding");
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(())
            }
            Err(error) => self.data_failed(error),
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_mvm_tlc_amsdu_limits_are_station_tid_and_native_extent_bound() -> TestResult {
        let mut limits = Limits::default();
        let mut report = [
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe, 0, 0, 0x21, 0, 0, 0,
        ];
        limits.observe(&report);
        if limits.get(0) != Some(3839)
            || limits.get(5) != Some(3839)
            || limits.get(1).is_some()
            || limits.get(8).is_some()
        {
            return TestResult::Fail("TLC per-TID size/mask decoded incorrectly");
        }
        report[0] = 1;
        report[12..16].fill(0);
        limits.observe(&report);
        if limits.get(0) != Some(3839) {
            return TestResult::Fail("foreign station changed aggregate limits");
        }
        report[0] = 0;
        report[4] = 1;
        limits.observe(&report);
        if limits.get(0) != Some(3839) {
            return TestResult::Fail("RATE-only notification erased aggregate state");
        }
        report[4] = 2;
        report[12..16].copy_from_slice(&1999u32.to_le_bytes());
        limits.observe(&report);
        if limits.get(0).is_some() {
            return TestResult::Fail("below-minimum TLC size enabled aggregation");
        }
        report[12..16].copy_from_slice(&7935u32.to_le_bytes());
        limits.observe(&report);
        if limits.get(0) != Some(3839) {
            return TestResult::Fail("TLC limit widened past the retained HT profile");
        }
        limits.observe(&report[..19]);
        if limits.get(0).is_some() {
            return TestResult::Fail("malformed matching report retained stale limits");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2/tx_amsdu",
        smoke_mvm_tlc_amsdu_limits_are_station_tid_and_native_extent_bound
    );
}
