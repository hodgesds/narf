// SPDX-License-Identifier: GPL-2.0-or-later
//! Native recipient BA control receipts. Linux mt7921_mcu_uni_rx_ba calls
//! mt76_connac_mcu_sta_ba: WTBL_SET/WTBL_BA first, then STA_REC_BA.
use super::{ba, scan::NativeRx, station::Command, Backend, Error, Session};
use alloc::vec;

impl<B: Backend> Session<B> {
    /// Process only this AP's exact, unfragmented native action/BAR profile.
    pub(super) fn receive_ba_control(
        &mut self,
        native: &NativeRx<'_>,
        own: [u8; 6],
        peer: [u8; 6],
    ) -> bool {
        if self.tx_ba.receive(native) {
            return true;
        }
        if self.ht20_profile.is_none() || native.ccmp.is_some() || native.wcid != 1 {
            return false;
        }
        let frame = native.frame;
        if frame.len() == 20
            && frame[0] == 0x84
            && frame[1] & 0xc7 == 0
            && frame[4..10] == own
            && frame[10..16] == peer
        {
            let control = u16::from_le_bytes([frame[16], frame[17]]);
            let sequence = u16::from_le_bytes([frame[18], frame[19]]);
            if control & 0x0ffe == 4 && sequence & 15 == 0 {
                self.rx_ba.bar((control >> 12) as u8, sequence >> 4);
            }
            return true;
        }
        let Some(header) = frame.get(..26) else {
            return false;
        };
        if header[0] != 0xd0
            || header[1] & 0xc7 != 0
            || header[22] & 15 != 0
            || header[4..10] != own
            || header[10..16] != peer
            || header[16..22] != peer
            || header[24] != 3
        {
            return false;
        }
        if header[25] == 0 && frame.len() == 33 {
            if ba::Request::parse(frame)
                .is_some_and(|r| self.rx_ba.reserve(r, self.backend.now_ns()))
            {
                return true;
            }
            if self.control_pending.len() < 4 {
                let mut response = vec![0; 33];
                response[0] = 0xd0;
                response[4..10].copy_from_slice(&peer);
                response[10..16].copy_from_slice(&own);
                response[16..22].copy_from_slice(&peer);
                response[24..29].copy_from_slice(&[3, 1, frame[26], 37, 0]);
                response[29] = frame[27] & 0x3e;
                self.control_pending.push_back(response);
            }
            return true;
        }
        if header[25] == 2 && frame.len() == 30 {
            let parameters = u16::from_le_bytes([frame[26], frame[27]]);
            if parameters & 0x0fff == 0x0800 && frame[28..30] != [0, 0] {
                self.rx_ba.stop((parameters >> 12) as u8, false);
                self.clear_aggregate_receive();
            }
            return true;
        }
        false
    }

    /// Called under the station's retained running control owner. Success is
    /// not published until both exact firmware receipts and management TX end.
    pub(super) async fn service_receive_ba(
        &mut self,
        own: [u8; 6],
        peer: [u8; 6],
    ) -> Result<(), Error> {
        if self.rx_ba.tick(self.backend.now_ns()) {
            self.clear_aggregate_receive();
        }
        for _ in 0..12 {
            let Some(work) = self.rx_ba.next() else {
                break;
            };
            let (tid, epoch) = match work {
                ba::Work::Start(t, e) | ba::Work::Repeat(t, e) | ba::Work::Stop(t, e, _) => (t, e),
            };
            let Some(request) = self.rx_ba.request(tid, epoch) else {
                continue;
            };
            match work {
                ba::Work::Start(..) => {
                    self.exchange_station(Command::Unified { id: 3 }, &request.wtbl(peer, true))
                        .await?;
                    self.exchange_station(Command::Unified { id: 3 }, &request.station(true))
                        .await?;
                    self.send_management(&request.response(own, peer), 1)
                        .await?;
                    self.check_station_tx()?;
                    if !self.rx_ba.activate(tid, epoch, self.backend.now_ns()) {
                        return Err(Error::Busy);
                    }
                }
                ba::Work::Repeat(..) => {
                    if self.rx_ba.active(tid) {
                        self.send_management(&request.response(own, peer), 1)
                            .await?;
                        self.rx_ba
                            .response_complete(tid, epoch, self.backend.now_ns());
                    }
                }
                ba::Work::Stop(_, _, notify) => {
                    // Receive/WTBL retirement is non-RF cleanup, including
                    // after policy loss. Current device authority still applies.
                    self.exchange(Command::Unified { id: 3 }, &request.wtbl(peer, false))
                        .await?;
                    self.exchange(Command::Unified { id: 3 }, &request.station(false))
                        .await?;
                    self.rx_ba.finish_stop(tid, epoch);
                    if notify {
                        self.send_management(&request.delba(own, peer), 1).await?;
                    }
                }
            }
            self.check_station_tx()?;
        }
        Ok(())
    }

    /// Close delivery before the first wait and retain each native BA record
    /// until both terminal disable receipts. Key/WCID reuse follows this fence.
    pub(super) async fn retire_receive_ba(&mut self, peer: [u8; 6]) -> Result<(), Error> {
        self.rx_ba.fence();
        self.clear_aggregate_receive();
        for (tid, epoch, request) in self.rx_ba.records() {
            self.exchange(Command::Unified { id: 3 }, &request.wtbl(peer, false))
                .await?;
            self.exchange(Command::Unified { id: 3 }, &request.station(false))
                .await?;
            self.rx_ba.finish_stop(tid, epoch);
        }
        Ok(())
    }
}
