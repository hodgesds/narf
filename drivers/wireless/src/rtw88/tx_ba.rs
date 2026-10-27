// SPDX-License-Identifier: GPL-2.0-or-later
//! One actual peer's BE/TID0 originator dialog. No peer response is inferred.
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
pub(super) fn peer_delba(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> bool {
    b.len() == 30 && action(b, own, ap) && b[25] == 2 && b[26..28] == [0, 0]
}
fn delba(own: [u8; 6], ap: [u8; 6]) -> Vec<u8> {
    let mut b = header(own, ap);
    b.extend_from_slice(&[2, 0, 8, 39, 0]);
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
    tried: bool,
    dialog: u8,
    control: Option<Control>,
    active: Option<(u8, u16, u64)>,
    teardown: bool,
}
impl Originator {
    pub(super) fn new() -> Self {
        Self {
            tried: false,
            dialog: 0,
            control: None,
            active: None,
            teardown: false,
        }
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
        // No TX A-MSDU producer is advertised by this dialog.
        b.extend_from_slice(&(2 | u16::from(window) << 6).to_le_bytes());
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
        if b[27..29] != [0, 0]
            || p & 2 == 0
            || p & 0x3c != 0
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
                bytes: delba(own, ap),
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
        b.extend_from_slice(&[4, 0]);
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
/// Source16-bit prioq counters, not a PCI-consumption or radio-ACK inference.
pub(super) fn fifo_empty(io: &mut impl Io, c21: bool) -> Result<bool, Error> {
    let map = io.read16(0x10c)?;
    if map != 0xc5a0 {
        return Err(Error::Prerequisite);
    }
    let mut empty = true;
    for shift in [8, 12] {
        let reg = [0x23c, 0x234, 0x238, 0x230][usize::from((map >> shift) & 3)];
        let reserved = io.read16(reg)?;
        let expected = if c21 {
            if reg == 0x23c {
                14
            } else {
                16
            }
        } else {
            64
        };
        let available = io.read16(reg + 2)?;
        if reserved != expected || available > reserved || io.read16(reg)? != reserved {
            return Err(Error::Prerequisite);
        }
        empty &= available == reserved;
    }
    Ok(empty)
}
pub(super) fn program(io: &mut impl Io) -> Result<(), Error> {
    io.station_allowed()?;
    // Exact controls used by source rtw_coex_limited_tx. Fixed-rate fallback
    // remains disabled; this static program is separately measured by T.
    io.write16(0x42a, 0x0808)?;
    io.write8(0x455, 0x20)?;
    readback(io)
}
pub(super) fn readback(io: &mut impl Io) -> Result<(), Error> {
    io.station_profile_readback()?;
    if io.read16(0x42a)? != 0x0808 || io.read8(0x455)? != 0x20 || io.read16(0x4ce)? != 0x0801 {
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
