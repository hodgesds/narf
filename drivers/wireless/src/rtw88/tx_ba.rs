// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual peer/TID originator dialogs over one serialized native control owner.
use super::{
    firmware_transport::{Error, Io},
    station,
};
use alloc::{vec, vec::Vec};

fn header(own: [u8; 6], ap: [u8; 6]) -> Vec<u8> {
    let mut b = vec![0xd0, 0, 0, 0];
    b.extend_from_slice(&ap);
    b.extend_from_slice(&own);
    b.extend_from_slice(&ap);
    b.extend_from_slice(&[0, 0, 3]);
    b
}
fn action(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
    b.len() >= 26
        && b[..2] == [0xd0, 0]
        && b[4..10] == own
        && b[10..16] == ap
        && b[16..22] == ap
        && b[22] & 15 == 0
        && b[24] == 3
}
pub(super) fn peer_delba(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<u8> {
    if b.len() != 30 || !action(b, own, ap) || b[25] != 2 {
        return None;
    }
    let parameter = u16::from_le_bytes([b[26], b[27]]);
    // Recipient-initiated, all reserved bits zero. This retires only that TID.
    let tid = (parameter >> 12) as u8;
    (parameter & 0x0fff == 0 && tid < 8).then_some(tid)
}
fn delba(own: [u8; 6], ap: [u8; 6], tid: u8) -> Vec<u8> {
    let mut b = header(own, ap);
    b.push(2);
    b.extend_from_slice(&(0x0800 | u16::from(tid) << 12).to_le_bytes());
    b.extend_from_slice(&[39, 0]);
    b
}
struct Control {
    bytes: Vec<u8>,
    sent: bool,
    delivered: bool,
    request: bool,
    cancelled: bool,
    ssn: u16,
    window: u8,
    started: u64,
    response: Option<(u8, u16)>,
}
fn same_control(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && if a.len() == 20 {
            a == b
        } else {
            a.len() >= 24 && a[..22] == b[..22] && a[24..] == b[24..]
        }
}
pub(super) struct Originator {
    tid: u8,
    tried: bool,
    dialog: u8,
    control: Option<Control>,
    active: Option<(u8, u16, u64)>,
    teardown: bool,
    /// The ADDBA request carries the A-MSDU-supported bit
    /// (`agg-tx.c::ieee80211_send_addba_request`); set only while the 5GHz
    /// TX A-MSDU producer is admissible.
    request_amsdu: bool,
    /// The peer's ADDBA response cleared A-MSDU permission: like
    /// `IEEE80211_TXQ_NO_AMSDU`, this TID stops aggregating MSDUs for the
    /// rest of the association.
    no_amsdu: bool,
}
impl Originator {
    #[cfg(feature = "kernel-test")]
    pub(super) fn new() -> Self {
        Self::for_tid(0)
    }
    fn for_tid(tid: u8) -> Self {
        Self {
            tid,
            tried: false,
            dialog: 0,
            control: None,
            active: None,
            teardown: false,
            request_amsdu: false,
            no_amsdu: false,
        }
    }
    /// `tx.c::ieee80211_amsdu_aggregate`'s `IEEE80211_TXQ_NO_AMSDU` test.
    pub(super) fn amsdu_allowed(&self) -> bool {
        !self.no_amsdu
    }
    pub(super) fn active(&self) -> Option<u8> {
        self.active.map(|a| a.0)
    }
    pub(super) fn waiting(&self) -> bool {
        self.control.is_some()
    }
    pub(super) fn settled(&self) -> bool {
        self.tried && self.control.is_none()
    }
    pub(super) fn can_begin(&self) -> bool {
        !self.tried && self.control.is_none() && self.active.is_none()
    }
    pub(super) fn begin(
        &mut self,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
        window: u8,
        now: u64,
    ) -> Result<(), station::Error> {
        if !self.can_begin() || ssn > 4095 || !(1..=64).contains(&window) {
            return Err(station::Error::State);
        }
        self.dialog = self.dialog.checked_add(1).ok_or(station::Error::State)?;
        self.tried = true;
        let mut b = header(own, ap);
        b.extend_from_slice(&[0, self.dialog]);
        // A-MSDU support is requested only while the 5GHz producer may run.
        b.extend_from_slice(
            &(u16::from(self.request_amsdu)
                | 2
                | u16::from(self.tid) << 2
                | u16::from(window) << 6)
                .to_le_bytes(),
        );
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&(ssn << 4).to_le_bytes());
        self.control = Some(Control {
            bytes: b,
            sent: false,
            delivered: false,
            request: true,
            cancelled: false,
            ssn,
            window,
            started: now,
            response: None,
        });
        Ok(())
    }
    pub(super) fn next(&self) -> Option<Vec<u8>> {
        self.control
            .as_ref()
            .filter(|c| !c.sent)
            .map(|c| c.bytes.clone())
    }
    pub(super) fn submitted(&mut self, b: &[u8]) -> Result<(), station::Error> {
        let c = self.control.as_mut().ok_or(station::Error::State)?;
        if c.sent || !same_control(b, &c.bytes) {
            return Err(station::Error::State);
        }
        c.sent = true;
        Ok(())
    }
    pub(super) fn delivered(&mut self, b: &[u8]) -> Result<(), station::Error> {
        let c = self.control.as_mut().ok_or(station::Error::State)?;
        if !c.sent || c.delivered || !same_control(b, &c.bytes) {
            return Err(station::Error::State);
        }
        c.delivered = true;
        Ok(())
    }
    pub(super) fn response(&mut self, b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
        if b.len() != 33 || !action(b, own, ap) || b[25] != 1 {
            return false;
        }
        let Some(c) = self
            .control
            .as_mut()
            .filter(|c| c.request && c.sent && !c.cancelled)
        else {
            return true;
        };
        if b[26] != self.dialog {
            return true;
        }
        let p = u16::from_le_bytes([b[29], b[30]]);
        let window = p >> 6;
        // `ieee80211_process_addba_resp`: a response for this TID without
        // A-MSDU permission sets NO_AMSDU whether or not it is accepted.
        if p & 1 == 0 && (p >> 2) & 15 == u16::from(self.tid) {
            self.no_amsdu = true;
        }
        if b[27..29] != [0, 0]
            || p & 2 == 0
            || (p >> 2) & 15 != u16::from(self.tid)
            || window == 0
            || window > u16::from(c.window)
        {
            c.cancelled = true;
            return true;
        }
        let response = (window as u8, u16::from_le_bytes([b[31], b[32]]));
        if c.response.is_some_and(|old| old != response) {
            c.cancelled = true;
        } else {
            c.response = Some(response);
        }
        true
    }
    /// Local host eligibility retires before any native cleanup waits. A sent
    /// request must still drain its real ownership/CCX; unsent work is dropped.
    pub(super) fn retire(&mut self) {
        self.active = None;
        if let Some(c) = &mut self.control {
            if c.sent {
                c.cancelled = true;
            } else {
                self.control = None;
            }
        }
    }
    pub(super) fn stop(&mut self, own: [u8; 6], ap: [u8; 6], now: u64) {
        let was_active = self.active.is_some();
        self.retire();
        if was_active {
            self.queue_delba(own, ap, now);
        }
    }
    pub(super) fn after_key(&mut self) {
        self.active = None;
        // Security replies cannot own the native control slot until prior
        // requests drained. Keep a queued local DELBA, then use a fresh token.
        self.tried = self.dialog == u8::MAX;
    }
    pub(super) fn terminal(&mut self) {
        self.active = None;
        self.control = None;
        self.tried = true;
        self.teardown = false;
    }
    pub(super) fn note_tx(&mut self, now: u64) {
        if let Some(a) = &mut self.active {
            a.2 = now;
        }
    }
    pub(super) fn tick(&mut self, now: u64, own: [u8; 6], ap: [u8; 6]) {
        let expired = self.active.is_some_and(|(_, timeout, last)| {
            timeout != 0
                && now.saturating_sub(last).saturating_mul(1000) >= u64::from(timeout) * 1024
        });
        if expired {
            self.active = None;
            self.queue_delba(own, ap, now);
        }
        if let Some(c) = &mut self.control {
            if c.request && now.saturating_sub(c.started) >= 1000 {
                c.cancelled = true;
            }
        }
    }
    fn queue_delba(&mut self, own: [u8; 6], ap: [u8; 6], now: u64) {
        self.teardown = true;
        if self.control.as_ref().is_some_and(|c| !c.sent && !c.request) {
            self.control = None;
        }
        if self.control.is_none() {
            self.control = Some(Control {
                bytes: delba(own, ap, self.tid),
                sent: false,
                delivered: false,
                request: false,
                cancelled: false,
                ssn: 0,
                window: 0,
                started: now,
                response: None,
            });
            self.teardown = false;
        }
    }
    pub(super) fn queue_bar(
        &mut self,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
        now: u64,
    ) -> Result<(), station::Error> {
        if ssn > 4095 || self.active.is_none() || self.control.is_some() {
            return Err(station::Error::State);
        }
        let mut b = vec![0x84, 0, 0, 0];
        b.extend_from_slice(&ap);
        b.extend_from_slice(&own);
        b.extend_from_slice(&(4 | u16::from(self.tid) << 12).to_le_bytes());
        b.extend_from_slice(&(ssn << 4).to_le_bytes());
        self.control = Some(Control {
            bytes: b,
            sent: false,
            delivered: false,
            request: false,
            cancelled: false,
            ssn,
            window: 0,
            started: now,
            response: None,
        });
        Ok(())
    }
    /// Caller proves current sources, exact current next SSN, native RX idle
    /// and MAC FIFO empty. CCX alone never creates the peer agreement.
    pub(super) fn idle(
        &mut self,
        now: u64,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
    ) -> Result<bool, station::Error> {
        let Some(c) = self.control.as_ref() else {
            return Ok(false);
        };
        if !c.delivered {
            return Ok(false);
        }
        if !c.request {
            let bar = c.bytes.len() == 20;
            self.control = None;
            if bar && self.teardown {
                self.queue_delba(own, ap, now);
            } else {
                self.teardown = false;
            }
            return Ok(false);
        }
        if c.cancelled {
            self.control = None;
            self.queue_delba(own, ap, now);
            return Ok(false);
        }
        let Some((window, timeout)) = c.response else {
            return Ok(false);
        };
        if c.ssn != ssn {
            return Err(station::Error::State);
        }
        self.active = Some((window, timeout, now));
        self.control = None;
        Ok(true)
    }
}
/// Independent logical agreements share the same real management DMA slot.
/// Dialog tokens are globally nonwrapping, so a response with a wrong TID can
/// never be mistaken for a different simultaneously pending agreement.
pub(super) struct Originators {
    tids: [Originator; 8],
    wanted: u8,
    dialog: u8,
    cursor: usize,
}
impl Originators {
    pub(super) fn new() -> Self {
        Self {
            tids: core::array::from_fn(|tid| Originator::for_tid(tid as u8)),
            wanted: 1,
            dialog: 0,
            cursor: 0,
        }
    }
    pub(super) fn want(&mut self, tid: u8, allowed: u8) {
        if tid < 6 && allowed & (1 << tid) != 0 {
            self.wanted |= 1 << tid;
        }
    }
    pub(super) fn active(&self, tid: u8) -> Option<u8> {
        self.tids.get(usize::from(tid)).and_then(Originator::active)
    }
    /// Later ADDBA requests carry the A-MSDU-supported bit (5GHz producer).
    pub(super) fn request_amsdu(&mut self, on: bool) {
        for t in &mut self.tids {
            t.request_amsdu = on;
        }
    }
    pub(super) fn amsdu_allowed(&self, tid: u8) -> bool {
        self.tids
            .get(usize::from(tid))
            .is_some_and(Originator::amsdu_allowed)
    }
    pub(super) fn any_active(&self) -> bool {
        self.tids.iter().any(|t| t.active().is_some())
    }
    pub(super) fn waiting(&self) -> bool {
        self.tids.iter().any(Originator::waiting)
    }
    pub(super) fn settled(&self) -> bool {
        self.tids
            .iter()
            .enumerate()
            .all(|(i, t)| self.wanted & (1 << i) == 0 || t.settled())
    }
    pub(super) fn can_begin(&self, tid: u8) -> bool {
        self.dialog != u8::MAX
            && self.wanted & (1 << tid) != 0
            && !self.waiting()
            && self.tids[usize::from(tid)].can_begin()
    }
    pub(super) fn begin(
        &mut self,
        tid: u8,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
        window: u8,
        now: u64,
    ) -> Result<(), station::Error> {
        if tid >= 6 || !self.can_begin(tid) {
            return Err(station::Error::State);
        }
        let token = self.dialog.checked_add(1).ok_or(station::Error::State)?;
        let t = &mut self.tids[usize::from(tid)];
        t.dialog = token - 1;
        t.begin(own, ap, ssn, window, now)?;
        self.dialog = token;
        Ok(())
    }
    pub(super) fn idle(
        &mut self,
        tid: u8,
        now: u64,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
    ) -> Result<bool, station::Error> {
        self.tids[usize::from(tid)].idle(now, own, ap, ssn)
    }
    pub(super) fn next(&self) -> Option<Vec<u8>> {
        (0..8).find_map(|offset| self.tids[(self.cursor + offset) % 8].next())
    }
    fn control(&mut self, bytes: &[u8], delivered: bool) -> Result<(), station::Error> {
        let i = self
            .tids
            .iter()
            .position(|t| {
                t.control
                    .as_ref()
                    .is_some_and(|c| same_control(bytes, &c.bytes))
            })
            .ok_or(station::Error::State)?;
        if delivered {
            self.tids[i].delivered(bytes)
        } else {
            self.tids[i].submitted(bytes)?;
            self.cursor = (i + 1) % 8;
            Ok(())
        }
    }
    pub(super) fn submitted(&mut self, b: &[u8]) -> Result<(), station::Error> {
        self.control(b, false)
    }
    pub(super) fn delivered(&mut self, b: &[u8]) -> Result<(), station::Error> {
        self.control(b, true)
    }
    pub(super) fn response(&mut self, b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
        if b.len() != 33 || !action(b, own, ap) || b[25] != 1 {
            return false;
        }
        if let Some(t) = self
            .tids
            .iter_mut()
            .find(|t| t.dialog == b[26] && t.control.as_ref().is_some_and(|c| c.request && c.sent))
        {
            t.response(b, own, ap);
        }
        true
    }
    pub(super) fn retire_tid(&mut self, tid: u8) {
        if let Some(t) = self.tids.get_mut(usize::from(tid)) {
            t.retire();
        }
    }
    pub(super) fn stop(&mut self, own: [u8; 6], ap: [u8; 6], now: u64) {
        for t in &mut self.tids {
            t.stop(own, ap, now);
        }
    }
    pub(super) fn after_key(&mut self) {
        for t in &mut self.tids {
            t.after_key();
            if self.dialog == u8::MAX {
                t.tried = true;
            }
        }
    }
    pub(super) fn terminal(&mut self) {
        for t in &mut self.tids {
            t.terminal();
        }
    }
    pub(super) fn tick(&mut self, now: u64, own: [u8; 6], ap: [u8; 6]) {
        for t in &mut self.tids {
            t.tick(now, own, ap);
        }
    }
    pub(super) fn note_tx(&mut self, tid: u8, now: u64) {
        self.tids[usize::from(tid)].note_tx(now);
    }
    pub(super) fn queue_bar(
        &mut self,
        tid: u8,
        own: [u8; 6],
        ap: [u8; 6],
        ssn: u16,
        now: u64,
    ) -> Result<(), station::Error> {
        self.tids[usize::from(tid)].queue_bar(own, ap, ssn, now)
    }
}
/// Source16-bit prioq counters, not a PCI-consumption or radio-ACK inference.
pub(super) async fn fifo_empty(io: &mut impl Io, c21: bool) -> Result<bool, Error> {
    fifo_empty_tids(io, c21, 1).await
}
pub(super) async fn fifo_empty_tids(io: &mut impl Io, c21: bool, tids: u8) -> Result<bool, Error> {
    let map = io.read16(0x10c).await?;
    if map != 0xc5a0 {
        return Err(Error::Prerequisite);
    }
    let mut empty = true;
    let shifts: &[u8] = if tids & !1 == 0 {
        &[8, 12]
    } else {
        &[6, 8, 10, 12]
    };
    for &shift in shifts {
        let reg = [0x23c, 0x234, 0x238, 0x230][usize::from((map >> shift) & 3)];
        let reserved = io.read16(reg).await?;
        let expected = if c21 {
            if reg == 0x23c {
                14
            } else {
                16
            }
        } else {
            64
        };
        let available = io.read16(reg + 2).await?;
        if reserved != expected || available > reserved || io.read16(reg).await? != reserved {
            return Err(Error::Prerequisite);
        }
        empty &= available == reserved;
    }
    Ok(empty)
}
pub(super) async fn program(io: &mut impl Io) -> Result<(), Error> {
    io.station_allowed()?;
    // Exact controls used by source rtw_coex_limited_tx. Fixed-rate fallback
    // remains disabled; this static program is separately measured by T.
    io.write16(0x42a, 0x0808).await?;
    io.write8(0x455, 0x20).await?;
    readback(io).await
}
pub(super) async fn readback(io: &mut impl Io) -> Result<(), Error> {
    io.station_profile_readback()?;
    if io.read16(0x42a).await? != 0x0808
        || io.read8(0x455).await? != 0x20
        || io.read16(0x4ce).await? != 0x0801
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
fn smoke_rtw88_tx_ba_literal_dialog_ssn_receipts_and_cancel() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let own = [2, 1, 2, 3, 4, 5];
    let ap = [2, 0, 0, 0, 0, 1];
    let mut tx = Originator::new();
    if tx.begin(own, ap, 4095, 64, 0).is_err() {
        return TestResult::Fail("actual SSN4095 request");
    }
    let Some(mut request) = tx.next() else {
        return TestResult::Fail("request missing");
    };
    if request[24..] != [3, 0, 1, 2, 16, 0, 0, 0xf0, 0xff] || tx.active().is_some() {
        return TestResult::Fail("literal request flags/window/SSN");
    }
    request[22..24].copy_from_slice(&0x1250u16.to_le_bytes());
    if tx.delivered(&request).is_ok() || tx.submitted(&request).is_err() {
        return TestResult::Fail("selection/receipt invented native submission");
    }
    let mut response = vec![0xd0, 0, 0, 0];
    response.extend_from_slice(&own);
    response.extend_from_slice(&ap);
    response.extend_from_slice(&ap);
    response.extend_from_slice(&[0, 0, 3, 1, 1, 0, 0, 2, 4, 1, 0]);
    if !tx.response(&response, own, ap)
        || tx.idle(0, own, ap, 4095) != Ok(false)
        || tx.delivered(&request).is_err()
        || tx.idle(0, own, ap, 4095) != Ok(true)
        || tx.active() != Some(16)
    {
        return TestResult::Fail("peer response/actual CCX/current SSN activation");
    }
    if tx.queue_bar(own, ap, 0, 1).is_err() {
        return TestResult::Fail("actual next SN BAR wrap");
    }
    let Some(bar) = tx.next() else {
        return TestResult::Fail("native BAR absent");
    };
    if bar.len() != 20 || bar[16..20] != [4, 0, 0, 0] || tx.submitted(&bar).is_err() {
        return TestResult::Fail("literal BAR20 source encoding");
    }
    tx.stop(own, ap, 1);
    if tx.active().is_some()
        || tx.next().is_some()
        || tx.delivered(&bar).is_err()
        || tx.idle(1, own, ap, 0) != Ok(false)
    {
        return TestResult::Fail("sent BAR cancellation lost retained receipt or host eligibility");
    }
    let Some(delba) = tx.next() else {
        return TestResult::Fail("DELBA after held BAR absent");
    };
    if delba[24..] != [3, 2, 0, 8, 39, 0] {
        return TestResult::Fail("literal originator DELBA direction");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtw88/tx_ba",
    smoke_rtw88_tx_ba_literal_dialog_ssn_receipts_and_cancel
);
