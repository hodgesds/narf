//! One fresh-peer BE originator agreement; Linux mac80211/agg-tx.c and
//! mt76_connac_mcu.c::mt76_connac_mcu_{wtbl,sta}_ba_tlv.
use super::{scan::NativeRx, Error};
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Fresh,
    Requested,
    Offered,
    Configuring,
    Active,
    Stopping,
    Fallback,
}
#[derive(Debug)]
pub(super) struct Owner {
    phase: Phase,
    next_dialog: u16,
    dialog: u8,
    own: [u8; 6],
    peer: [u8; 6],
    channel: u8,
    window: u16,
    timeout: u16,
    activity: u64,
    published: bool,
    remote: bool,
    notify: bool,
    /// The response's A-MSDU-in-A-MPDU bit (mac80211 `tid_tx->amsdu`).
    amsdu: bool,
}
impl Default for Owner {
    fn default() -> Self {
        Self {
            phase: Phase::Fresh,
            next_dialog: 1,
            dialog: 0,
            own: [0; 6],
            peer: [0; 6],
            channel: 0,
            window: 0,
            timeout: 0,
            activity: 0,
            published: false,
            remote: false,
            notify: false,
            amsdu: false,
        }
    }
}
impl Owner {
    pub fn begin_connection(&mut self) -> bool {
        if self.published || self.remote {
            return false;
        }
        self.phase = Phase::Fresh;
        self.dialog = 0;
        self.window = 0;
        self.timeout = 0;
        self.notify = false;
        self.amsdu = false;
        true
    }
    pub fn start(&mut self, own: [u8; 6], peer: [u8; 6], channel: u8) -> Result<bool, Error> {
        if self.phase != Phase::Fresh || self.published {
            return Err(Error::Busy);
        }
        // Do not reuse a dialog while an old native RX can still name it.
        // Optional BA exhaustion preserves this fresh peer's non-BA path.
        if self.next_dialog > 255 {
            self.fallback();
            return Ok(false);
        }
        self.dialog = self.next_dialog as u8;
        self.next_dialog += 1;
        self.own = own;
        self.peer = peer;
        self.channel = channel;
        self.phase = Phase::Requested;
        self.remote = true;
        Ok(true)
    }
    pub fn offered(&self) -> bool {
        self.phase == Phase::Offered
    }
    pub fn abandoned(&self) -> bool {
        self.phase == Phase::Fallback
    }
    pub fn active(&self) -> bool {
        self.phase == Phase::Active
    }
    pub fn published(&self) -> bool {
        self.published
    }
    /// Whether the active agreement permits A-MSDU inside the A-MPDU.
    pub fn amsdu(&self) -> bool {
        self.amsdu
    }
    pub fn remote(&self) -> bool {
        self.remote
    }
    pub fn capacity(&self) -> usize {
        usize::from(self.window).min(crate::mt7921::packet_tx::PIPELINE)
    }
    pub fn request(&self) -> Vec<u8> {
        let mut frame = self.action(33, 0);
        frame[26] = self.dialog;
        // Source HT compatibility window64; no TX A-MSDU. This request's
        // fresh TID0 SSN0 is distinct from the native operational SN field.
        // ieee80211_send_addba_request: AMSDU | immediate policy | TID0 | 64.
        frame[27..29].copy_from_slice(&0x1003u16.to_le_bytes());
        frame
    }
    fn action(&self, length: usize, action: u8) -> Vec<u8> {
        let mut frame = vec![0; length];
        frame[0] = 0xd0;
        frame[4..10].copy_from_slice(&self.peer);
        frame[10..16].copy_from_slice(&self.own);
        frame[16..22].copy_from_slice(&self.peer);
        frame[24..26].copy_from_slice(&[3, action]);
        frame
    }
    pub fn delba(&self) -> Vec<u8> {
        let mut frame = self.action(30, 2);
        frame[26..30].copy_from_slice(&[0, 8, 39, 0]); // TID0, originator; QSTA_TIMEOUT.
        frame
    }
    pub fn receive(&mut self, native: &NativeRx<'_>) -> bool {
        let frame = native.frame;
        if native.wcid != 1
            || native.channel != self.channel
            || native.ccmp.is_some()
            || native.ampdu
            || native.amsdu != 0
            || frame.len() < 26
            || frame[0] != 0xd0
            || frame[1] & 0xc7 != 0
            || frame[22] & 15 != 0
            || frame[4..10] != self.own
            || frame[10..16] != self.peer
            || frame[16..22] != self.peer
            || frame[24] != 3
        {
            return false;
        }
        if frame[25] == 1 && frame.len() == 33 {
            if self.phase != Phase::Requested || frame[26] != self.dialog {
                return true;
            }
            let parameters = u16::from_le_bytes([frame[29], frame[30]]);
            if parameters >> 2 & 15 != 0 {
                return true;
            }
            let window = parameters >> 6;
            if frame[27..29] != [0, 0] {
                self.remote = false;
                self.phase = Phase::Fallback;
                return true;
            }
            if parameters & 2 != 2 || !(1..=64).contains(&window) {
                self.phase = Phase::Fallback;
                return true;
            }
            // agg-tx.c ieee80211_process_addba_resp keeps the responder's
            // A-MSDU bit; mt7921_mcu_uni_tx_ba clears wcid->amsdu without it.
            self.amsdu = parameters & 1 != 0;
            self.window = window;
            self.timeout = u16::from_le_bytes([frame[31], frame[32]]);
            self.phase = Phase::Offered;
            return true;
        }
        if frame[25] == 2 && frame.len() == 30 && frame[26..28] == [0, 0] && frame[28..30] != [0, 0]
        {
            // The recipient initiates this DELBA; an originator DELBA belongs
            // to the independent recipient RX BA owner instead.
            self.remote = false;
            if self.published {
                self.stop(false);
            } else if self.phase != Phase::Fresh {
                self.phase = Phase::Fallback;
            }
            return true;
        }
        false
    }
    pub fn configuring(&mut self) {
        self.phase = Phase::Configuring;
        self.published = true;
    }
    pub fn activate(&mut self, now: u64) -> Result<(), Error> {
        if self.phase != Phase::Configuring || !self.published {
            return Err(Error::Busy);
        }
        self.phase = Phase::Active;
        self.activity = now;
        Ok(())
    }
    pub fn touch(&mut self, now: u64) {
        if self.active() {
            self.activity = now;
        }
    }
    fn expired(&self, now: u64) -> bool {
        self.active()
            && self.timeout != 0
            && now.saturating_sub(self.activity) >= u64::from(self.timeout) * 1_024_000
    }
    pub fn pending(&self, now: u64) -> bool {
        self.phase == Phase::Stopping || self.expired(now)
    }
    pub fn tick(&mut self, now: u64) {
        if self.expired(now) {
            self.stop(true);
        }
    }
    pub fn stop(&mut self, notify: bool) {
        self.phase = Phase::Stopping;
        self.notify = notify;
    }
    pub fn notify(&self) -> bool {
        self.notify
    }
    pub fn abandon(&mut self) {
        self.phase = Phase::Fallback;
    }
    pub fn fallback(&mut self) {
        self.phase = Phase::Fallback;
        self.published = false;
        self.remote = false;
        self.notify = false;
    }
    pub fn fence(&mut self) {
        if self.published || self.remote {
            self.stop(false);
        } else {
            self.phase = Phase::Fallback;
        }
    }
    pub fn reset_after_quiescence(&mut self) {
        self.published = false;
        self.remote = false;
        self.fallback();
    }
    pub fn wtbl(&self, enable: bool) -> Vec<u8> {
        let mut out = vec![0; 48];
        out[..20].copy_from_slice(&[0, 1, 1, 0, 1, 0, 0, 0, 13, 0, 40, 0, 1, 2, 1, 0, 0, 0, 0, 0]);
        out[20..26].copy_from_slice(&[8, 0, 28, 0, 0, 1]);
        // mac80211's TX_OPERATIONAL callback has native SN0; no guessed
        // midstream hardware sequence or CONNAC1 window-index programming.
        out[30] = u8::from(enable);
        if enable {
            out[32..34].copy_from_slice(&self.window.to_le_bytes());
        }
        out
    }
    pub fn station(&self, enable: bool) -> Vec<u8> {
        let mut out = vec![0; 20];
        out[..14].copy_from_slice(&[0, 1, 1, 0, 1, 0, 0, 0, 6, 0, 12, 0, 0, 1]);
        // mt76_connac_mcu_sta_ba_tlv: ba->amsdu = params->amsdu.
        out[14] = u8::from(enable && self.amsdu);
        out[15] = u8::from(enable);
        if enable {
            out[18..20].copy_from_slice(&self.window.to_le_bytes());
        }
        out
    }
}
