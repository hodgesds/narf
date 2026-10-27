// SPDX-License-Identifier: GPL-2.0-or-later
//! Host recipient BA. Linux rtw88 RX_START/STOP are no-ops; no H2C ACK exists.
use super::{packet_core::Frame, station::Error};
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_wireless::{reorder::Reorder, station_security::RawFrame};

pub(super) fn readback(
    io: &mut impl super::firmware_transport::Io,
    c21: bool,
) -> Result<(), super::firmware_transport::Error> {
    use super::firmware_transport::Error;
    let rcr = io.read32(0x608)?;
    let required = (1 << 31) | (1 << 28) | (1 << 26) | (1 << 10);
    let forbidden = (1 << 30) | (1 << 29) | (1 << 27) | (1 << 25);
    if rcr & required != required
        || rcr & forbidden != 0
        // C21 mac.c starts at0fff, but its later original MAC table writes
        // both6a2/6a3=ff. This checks the retained post-table native owner.
        || io.read16(0x6a2)? != 0xffff
        || io.read16(0x4ce)? != 0x0801
        || !c21 && (io.read8(0x426)? & 32 != 0 || io.read8(0x66e)? != 5)
    {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    tid: u8,
    dialog: u8,
    window: u8,
    timeout: u16,
    ssn: u16,
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
pub(super) fn request(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<Request> {
    if b.len() != 33 || !action(b, own, ap) || b[25] != 0 {
        return None;
    }
    let p = u16::from_le_bytes([b[27], b[28]]);
    let seq = u16::from_le_bytes([b[31], b[32]]);
    let tid = ((p >> 2) & 15) as u8;
    let w = p >> 6;
    // rtw88's maintained RX ABI does not label aggregate membership. Require
    // the peer's A-MSDU permission, so a whole original is legal either as a
    // standalone MPDU or within its BA aggregate. Otherwise retain decline.
    if p & 3 != 3 || tid >= 8 || w > 64 || seq & 15 != 0 {
        return None;
    }
    Some(Request {
        tid,
        dialog: b[26],
        window: if w == 0 { 64 } else { w as u8 },
        timeout: u16::from_le_bytes([b[29], b[30]]),
        ssn: seq >> 4,
    })
}
pub(super) fn delba(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<u8> {
    if b.len() != 30 || !action(b, own, ap) || b[25] != 2 {
        return None;
    }
    let p = u16::from_le_bytes([b[26], b[27]]);
    // Peer is the originator for our RX session. Recipient DELBA is TX-only.
    (p & 0x7ff == 0 && p & 0x800 != 0 && p >> 12 < 8).then_some((p >> 12) as u8)
}
pub(super) fn bar(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<(u8, u16)> {
    if b.len() != 20 || b[..2] != [0x84, 0] || b[4..10] != own || b[10..16] != ap {
        return None;
    }
    let p = u16::from_le_bytes([b[16], b[17]]);
    let s = u16::from_le_bytes([b[18], b[19]]);
    (p & 0xfff == 4 && p >> 12 < 8 && s & 15 == 0).then_some(((p >> 12) as u8, s >> 4))
}
pub(super) fn data(b: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<(u8, u16)> {
    if b.len() < 26
        || b[0] != 0x88
        || b[1] & 0x87 != 2
        || b[4..10] != own
        || b[10..16] != ap
        || b[16] & 1 != 0
        || b[16..22] == [0; 6]
        || b[22] & 15 != 0
        || b[25] != 0
        || b[24] & 0x10 != 0
        || !matches!(b[24] & 0x60, 0 | 0x60)
        || b[24] & 15 >= 8
    {
        return None;
    }
    Some((b[24] & 15, u16::from_le_bytes([b[22], b[23]]) >> 4))
}
struct Session {
    request: Request,
    reorder: Reorder<Frame>,
    last: u64,
    started: bool,
    epoch: u64,
    prefix: VecDeque<(u64, u16, Frame)>,
}
struct Control {
    bytes: Vec<u8>,
    activate: Option<Session>,
    sent: bool,
    delivered: bool,
}
pub(super) struct Table {
    sessions: [Option<Session>; 8],
    controls: VecDeque<Control>,
}
fn header(own: [u8; 6], ap: [u8; 6]) -> Vec<u8> {
    let mut b = vec![0xd0, 0, 0, 0];
    b.extend_from_slice(&ap);
    b.extend_from_slice(&own);
    b.extend_from_slice(&ap);
    b.extend_from_slice(&[0, 0, 3]);
    b
}
fn clock(now: u64) -> u64 {
    now.saturating_mul(1_000_000)
}
impl Table {
    pub(super) fn new() -> Self {
        Self {
            sessions: core::array::from_fn(|_| None),
            controls: VecDeque::new(),
        }
    }
    pub(super) fn active(&self, tid: u8) -> bool {
        self.sessions
            .get(usize::from(tid))
            .is_some_and(Option::is_some)
    }
    pub(super) fn negotiating(&self, tid: u8) -> bool {
        self.controls
            .iter()
            .any(|c| c.bytes.len() == 33 && (c.bytes[29] >> 2) & 15 == tid)
    }
    pub(super) fn clear(&mut self) {
        self.sessions = core::array::from_fn(|_| None);
        self.controls.clear();
    }
    pub(super) fn retire(&mut self, tid: u8) {
        if let Some(s) = self.sessions.get_mut(usize::from(tid)) {
            *s = None;
        }
        self.controls.retain_mut(|c| {
            if c.bytes.len() == 33 && (c.bytes[29] >> 2) & 15 == tid {
                if !c.sent {
                    return false;
                }
                // Keep real native ownership/CCX drainage, never activation.
                c.activate = None;
            }
            true
        });
    }
    pub(super) fn propose(
        &mut self,
        mut r: Request,
        maximum: u8,
        own: [u8; 6],
        ap: [u8; 6],
        now: u64,
        epoch: u64,
    ) -> Result<bool, Error> {
        if self.controls.len() >= 8 {
            return Ok(false);
        }
        if self.negotiating(r.tid) {
            return Ok(false);
        }
        r.window = r.window.min(maximum);
        let prior = self.sessions[usize::from(r.tid)].as_ref();
        if prior.is_some_and(|s| s.request.dialog == r.dialog && s.request != r) {
            return Ok(false);
        }
        let duplicate = prior.is_some_and(|s| s.request == r);
        let mut reorder = Reorder::new(r.window, 100_000_000).map_err(|_| Error::State)?;
        let mut prefix = VecDeque::new();
        prefix
            .try_reserve(usize::from(r.window))
            .map_err(|_| Error::State)?;
        // An actual on-air ADDBA contains an SSN; this is not offload auto_seq.
        let _ = reorder
            .advance(r.ssn, clock(now))
            .map_err(|_| Error::State)?;
        if !duplicate {
            self.retire(r.tid);
        }
        let mut bytes = header(own, ap);
        bytes.extend_from_slice(&[1, r.dialog, 0, 0]);
        // Both chips support original A-MSDU inside A-MPDU. Never deaggregate
        // before the existing whole-original authentication and PN commit.
        bytes.extend_from_slice(
            &(3 | u16::from(r.tid) << 2 | u16::from(r.window) << 6).to_le_bytes(),
        );
        bytes.extend_from_slice(&r.timeout.to_le_bytes());
        self.controls.push_back(Control {
            bytes,
            activate: (!duplicate).then_some(Session {
                request: r,
                reorder,
                last: now,
                started: false,
                epoch,
                prefix,
            }),
            sent: false,
            delivered: false,
        });
        Ok(true)
    }
    pub(super) fn next(&self) -> Option<Vec<u8>> {
        let c = self.controls.front()?;
        if c.sent {
            return None;
        }
        Some(c.bytes.clone())
    }
    pub(super) fn submitted(&mut self, b: &[u8]) -> Result<(), Error> {
        let c = self.controls.front_mut().ok_or(Error::State)?;
        if c.sent
            || b.len() != c.bytes.len()
            || b[..22] != c.bytes[..22]
            || b[24..] != c.bytes[24..]
        {
            return Err(Error::State);
        }
        c.sent = true;
        Ok(())
    }
    pub(super) fn delivered(&mut self, b: &[u8]) -> Result<(), Error> {
        let c = self.controls.front_mut().ok_or(Error::State)?;
        // Sequence is assigned by the actual shared management transmitter.
        if !c.sent
            || c.delivered
            || b.len() != c.bytes.len()
            || b[..22] != c.bytes[..22]
            || b[24..] != c.bytes[24..]
        {
            return Err(Error::State);
        }
        c.delivered = true;
        Ok(())
    }
    pub(super) fn stage_pending(
        &mut self,
        frame: Frame,
        own: [u8; 6],
        ap: [u8; 6],
        epoch: u64,
        now: u64,
    ) -> Result<Option<Frame>, Error> {
        let Some((tid, seq)) = data(frame.bytes(), own, ap) else {
            return Ok(Some(frame));
        };
        if self.active(tid) {
            // An identical retry queues only another native response; the
            // already committed original agreement still owns this capture.
            return Ok(Some(frame));
        }
        if !self.negotiating(tid) {
            return Ok(Some(frame));
        }
        if let Some(s) = self.controls.iter_mut().filter(|c| c.sent).find_map(|c| {
            c.activate
                .as_mut()
                .filter(|s| s.request.tid == tid && s.epoch == epoch)
        }) {
            // Only a genuinely published, still-current exact proposal may
            // stage originals. Never give pre-proposal/closed capture a grant.
            if s.prefix.len() < usize::from(s.request.window) {
                s.prefix.push_back((now, seq, frame));
            }
        }
        Ok(None)
    }
    pub(super) fn idle(&mut self, now: u64, epoch: u64) -> Result<Vec<Frame>, Error> {
        let mut out = Vec::new();
        if self.controls.front().is_some_and(|c| c.delivered) {
            if let Some(mut s) = self.controls.pop_front().and_then(|c| c.activate) {
                if s.epoch != epoch {
                    return Ok(out);
                }
                while let Some((arrived, seq, frame)) = s.prefix.pop_front() {
                    // Preserve the capture age; the active path performs the
                    // same pre-SSN and original ordering before any crypto.
                    let distance =
                        seq.wrapping_sub(s.reorder.head().unwrap_or(s.request.ssn)) & 4095;
                    if !s.started && distance > 2048 {
                        out.push(frame);
                        continue;
                    }
                    if !s.started && distance == 2048 {
                        continue;
                    }
                    s.started = true;
                    out.extend(
                        s.reorder
                            .push(seq, clock(arrived), frame)
                            .map_err(|_| Error::State)?,
                    );
                }
                s.last = now;
                let tid = usize::from(s.request.tid);
                self.sessions[tid] = Some(s);
            }
        }
        Ok(out)
    }
    pub(super) fn push(
        &mut self,
        tid: u8,
        seq: u16,
        now: u64,
        frame: Frame,
    ) -> Result<Vec<Frame>, Error> {
        let s = self.sessions[usize::from(tid)]
            .as_mut()
            .ok_or(Error::State)?;
        s.last = now;
        if !s.started {
            let distance = seq.wrapping_sub(s.reorder.head().unwrap_or(s.request.ssn)) & 4095;
            // Linux mac80211 permits a pre-SSN original before this BA stream
            // starts. It still passes the real key/PN owner; it cannot change
            // the explicit negotiated head. Half-range ambiguity is dropped.
            if distance > 2048 {
                return Ok(vec![frame]);
            }
            if distance == 2048 {
                return Ok(Vec::new());
            }
            s.started = true;
        }
        s.reorder
            .push(seq, clock(now), frame)
            .map_err(|_| Error::State)
    }
    pub(super) fn advance(&mut self, tid: u8, ssn: u16, now: u64) -> Result<Vec<Frame>, Error> {
        let Some(s) = self.sessions[usize::from(tid)].as_mut() else {
            return Ok(Vec::new());
        };
        s.last = now;
        s.reorder.advance(ssn, clock(now)).map_err(|_| Error::State)
    }
    pub(super) fn expire(
        &mut self,
        now: u64,
        own: [u8; 6],
        ap: [u8; 6],
    ) -> Result<Vec<Frame>, Error> {
        let mut out = Vec::new();
        for tid in 0..8 {
            let Some(s) = self.sessions[tid].as_mut() else {
                continue;
            };
            if s.request.timeout != 0
                && now.saturating_sub(s.last).saturating_mul(1000)
                    >= u64::from(s.request.timeout) * 1024
            {
                self.retire(tid as u8);
                if self.controls.len() >= 8 {
                    return Err(Error::State);
                }
                let mut bytes = header(own, ap);
                bytes.push(2);
                bytes.extend_from_slice(&((tid as u16) << 12).to_le_bytes());
                bytes.extend_from_slice(&39u16.to_le_bytes());
                self.controls.push_back(Control {
                    bytes,
                    activate: None,
                    sent: false,
                    delivered: false,
                });
            } else {
                out.extend(s.reorder.expire(clock(now)).map_err(|_| Error::State)?);
            }
        }
        Ok(out)
    }
    pub(super) fn captured(&self, frame: &Frame, own: [u8; 6], ap: [u8; 6]) -> bool {
        data(frame.bytes(), own, ap).is_some_and(|(tid, _)| self.active(tid))
    }
}
impl Request {
    pub(super) fn tid(self) -> u8 {
        self.tid
    }
}

#[cfg(feature = "kernel-test")]
fn smoke_rtw88_rx_ba_literal_request_bar_delba_bounds() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let own = [2, 4, 6, 8, 10, 12];
    let ap = [2, 0, 0, 0, 0, 1];
    let mut req = vec![
        0xd0, 0, 0, 0, 2, 4, 6, 8, 10, 12, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 3, 0, 9, 0x1f,
        0x10, 5, 0, 0xf0, 0xff,
    ];
    let expected = Request {
        tid: 7,
        dialog: 9,
        window: 64,
        timeout: 5,
        ssn: 4095,
    };
    if request(&req, own, ap) != Some(expected) {
        return TestResult::Fail("literal TID7/SSN4095 request");
    }
    req[28] = 0;
    req[27] = 3;
    if request(&req, own, ap).is_none_or(|r| r.window != 64) {
        return TestResult::Fail("ADDBA default zero window");
    }
    for (at, value) in [
        (1, 4),
        (10, 4),
        (22, 1),
        (25, 1),
        (27, 1),
        (28, 17),
        (31, 1),
    ] {
        let mut bad = req.clone();
        bad[at] = value;
        if request(&bad, own, ap).is_some() {
            return TestResult::Fail("malformed ADDBA request admitted");
        }
    }
    for n in 0..33 {
        if request(&req[..n], own, ap).is_some() {
            return TestResult::Fail("truncated ADDBA");
        }
    }
    let b = [
        0x84, 0, 0, 0, 2, 4, 6, 8, 10, 12, 2, 0, 0, 0, 0, 1, 4, 0x70, 0xf0, 0xff,
    ];
    if bar(&b, own, ap) != Some((7, 4095)) || !super::packet_format::native_bar(&b) {
        return TestResult::Fail("literal compressed BAR20");
    }
    for (at, value) in [
        (0, 0x94),
        (1, 0x40),
        (4, 4),
        (10, 4),
        (16, 5),
        (17, 0x80),
        (18, 1),
    ] {
        let mut bad = b;
        bad[at] = value;
        if bar(&bad, own, ap).is_some() {
            return TestResult::Fail("foreign/reserved BAR advanced");
        }
    }
    let mut d = vec![
        0xd0, 0, 0, 0, 2, 4, 6, 8, 10, 12, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 3, 2, 0, 0x78,
        39, 0,
    ];
    if delba(&d, own, ap) != Some(7) {
        return TestResult::Fail("literal peer originator DELBA");
    }
    d[27] = 0x70;
    if delba(&d, own, ap).is_some() {
        return TestResult::Fail("peer recipient DELBA retired RX");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "drivers/wireless/rtw88/rx_ba",
    smoke_rtw88_rx_ba_literal_request_bar_delba_bounds
);
