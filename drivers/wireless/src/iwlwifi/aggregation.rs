//! MLD TX A-MPDU completion and host RX Block Ack reordering.
//! TX session setup/retries are firmware-owned (Linux TX_AMPDU_SETUP_IN_HW).
//! RX accepts immediate BA with up to 64 MPDUs and no A-MSDU inside A-MPDU.

use super::{
    boot_context::{put16, put32},
    data_queue::DataQueue,
    scan_api,
};
use alloc::vec::Vec;

pub const MAX_WINDOW: u16 = 64;
pub const MAX_TIDS: usize = 8;

/// Validate all entries before reclaiming any DMA, including duplicates and
/// station/TID ownership. Counts use checked arithmetic before slicing.
pub fn complete_tx_ba(queues: &mut [DataQueue], body: &[u8]) -> Result<(), &'static str> {
    if body.len() < 32 || body[4] != 0 {
        return Err("invalid compressed BA header/station");
    }
    let count = u16::from_le_bytes(body[28..30].try_into().unwrap()) as usize;
    // Linux treats the trailing union as TFD entries; RA/TID information is
    // firmware debug data, not an appended array with a host-owned layout.
    if count > queues.len() || body.len() < 32 + count * 8 {
        return Err("invalid compressed BA length/count");
    }
    let mut updates = Vec::with_capacity(count);
    for entry in body[32..32 + count * 8].chunks_exact(8) {
        let id = u16::from_le_bytes(entry[..2].try_into().unwrap());
        let ssn = u16::from_le_bytes(entry[2..4].try_into().unwrap());
        let index = queues
            .iter()
            .position(|q| q.id() == Some(id))
            .ok_or("BA for unknown TX queue")?;
        if updates.iter().any(|&(old, _)| old == index) {
            return Err("duplicate queue in compressed BA");
        }
        queues[index].validate_ba(body[4], entry[5], ssn)?;
        updates.push((index, ssn));
    }
    for (index, ssn) in updates {
        queues[index].reclaim(ssn)?;
    }
    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    Add {
        token: u8,
        tid: u8,
        window: u16,
        ssn: u16,
        timeout: u16,
        immediate: bool,
    },
    Delete {
        tid: u8,
        originator: bool,
    },
}
pub fn action(bytes: &[u8]) -> Option<Action> {
    if bytes.first() != Some(&3) {
        return None;
    }
    match *bytes.get(1)? {
        0 if bytes.len() == 9 => {
            let params = u16::from_le_bytes(bytes[3..5].try_into().ok()?);
            let seq = u16::from_le_bytes(bytes[7..9].try_into().ok()?);
            if seq & 15 != 0 {
                return None;
            }
            let requested = params >> 6;
            Some(Action::Add {
                token: bytes[2],
                tid: ((params >> 2) & 15) as u8,
                window: if requested == 0 {
                    MAX_WINDOW
                } else {
                    requested.min(MAX_WINDOW)
                },
                ssn: seq >> 4,
                timeout: u16::from_le_bytes(bytes[5..7].try_into().ok()?),
                immediate: params & 2 != 0,
            })
        }
        2 if bytes.len() == 6 => {
            let params = u16::from_le_bytes(bytes[2..4].try_into().ok()?);
            Some(Action::Delete {
                tid: (params >> 12) as u8,
                originator: params & (1 << 11) != 0,
            })
        }
        _ => None, // Firmware consumes responses for its own TX sessions.
    }
}

pub fn add_response(token: u8, tid: u8, window: u16, timeout: u16, status: u16) -> [u8; 9] {
    let mut body = [3, 1, token, 0, 0, 0, 0, 0, 0];
    put16(&mut body, 3, status);
    // Clear A-MSDU support and require immediate BA.
    put16(&mut body, 5, (window << 6) | ((tid as u16) << 2) | 2);
    put16(&mut body, 7, timeout);
    body
}
pub fn delete(tid: u8) -> [u8; 6] {
    let mut body = [3, 2, 0, 0, 39, 0]; // receiver teardown: timeout
    put16(&mut body, 2, (tid as u16) << 12);
    body
}
pub fn allocate(tid: u8, ssn: u16, window: u16) -> [u8; 16] {
    let mut body = [0; 16];
    put32(&mut body, 4, 1); // station 0
    body[8] = tid;
    put16(&mut body, 12, ssn);
    put16(&mut body, 14, window);
    body
}
pub fn remove(tid: u8) -> [u8; 16] {
    let mut body = [0; 16];
    put32(&mut body, 0, 2);
    put32(&mut body, 4, 1);
    put32(&mut body, 8, tid as u32);
    body
}

fn delta(a: u16, b: u16) -> u16 {
    a.wrapping_sub(b) & 0xfff
}

#[derive(Debug)]
pub struct Window {
    pub baid: u8,
    pub tid: u8,
    pub token: u8,
    pub timeout: u16,
    pub size: u16,
    pub start: u16,
    head: u16,
    slots: Vec<Option<Vec<u8>>>,
    last_rx: u64,
    hole_since: Option<u64>,
}
impl Window {
    pub fn new(
        baid: u8,
        tid: u8,
        token: u8,
        ssn: u16,
        size: u16,
        timeout: u16,
        now: u64,
    ) -> Result<Self, &'static str> {
        if baid >= 32 || tid >= MAX_TIDS as u8 || ssn >= 4096 || !(1..=MAX_WINDOW).contains(&size) {
            return Err("invalid RX BA session");
        }
        Ok(Self {
            baid,
            tid,
            token,
            timeout,
            size,
            start: ssn,
            head: ssn,
            // Index by the 12-bit sequence modulo 64, not modulo a possibly
            // non-power-of-two negotiated size (which aliases across wrap).
            slots: (0..MAX_WINDOW).map(|_| None).collect(),
            last_rx: now,
            hole_since: None,
        })
    }

    pub fn discard(&mut self) {
        self.slots.iter_mut().for_each(|entry| *entry = None);
        self.hole_since = None;
    }

    pub fn expired(&self, now: u64) -> bool {
        self.timeout != 0
            && now.wrapping_sub(self.last_rx)
                >= narf_time::wall::ns_to_cycles(u64::from(self.timeout) * 1_024_000)
    }

    fn advance(&mut self, end: u16, output: &mut Vec<Vec<u8>>) {
        let distance = delta(end, self.head);
        if distance >= 2048 {
            return;
        }
        for _ in 0..distance {
            if let Some(frame) = self.slots[self.head as usize % MAX_WINDOW as usize].take() {
                output.push(frame);
            }
            self.head = (self.head + 1) & 0xfff;
        }
    }
    fn contiguous(&mut self, output: &mut Vec<Vec<u8>>) {
        for _ in 0..self.size {
            if self.slots[self.head as usize % MAX_WINDOW as usize].is_none() {
                break;
            }
            self.advance((self.head + 1) & 0xfff, output);
        }
    }
    fn update_hole(&mut self, now: u64, previous_head: u16) {
        if self.slots.iter().all(Option::is_none) {
            self.hole_since = None;
        } else if self.hole_since.is_none() || previous_head != self.head {
            self.hole_since = Some(now);
        }
    }

    pub fn push(&mut self, bytes: &[u8], now: u64) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        let Some(mpdu) = scan_api::mpdu(bytes) else {
            return output;
        };
        let frame = mpdu.frame;
        if frame.len() < 26
            || frame[0] != 0x88
            || frame[1] & 7 != 2
            || frame[4] & 1 != 0
            || frame[24] & 15 != self.tid
            || mpdu.amsdu
            || mpdu.reorder >> 31 != 0
            || ((mpdu.reorder >> 24) & 127) != self.baid as u32
        {
            return output;
        }
        let sn = u16::from_le_bytes(frame[22..24].try_into().unwrap()) >> 4;
        if sn != ((mpdu.reorder >> 12) & 4095) as u16 || delta(sn, self.head) >= 2048 {
            return output;
        }
        let old_head = self.head;
        if delta(sn, self.head) >= self.size {
            self.advance(sn.wrapping_sub(self.size - 1) & 4095, &mut output);
        }
        let slot = &mut self.slots[sn as usize % MAX_WINDOW as usize];
        if slot.is_some() {
            return output;
        }
        *slot = Some(bytes.to_vec());
        self.last_rx = now;
        self.advance((mpdu.reorder & 4095) as u16, &mut output);
        self.contiguous(&mut output);
        self.update_hole(now, old_head);
        output
    }

    pub fn release(&mut self, nssn: u16, now: u64) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        if nssn >= 4096 {
            return output;
        }
        let old = self.head;
        self.advance(nssn, &mut output);
        self.contiguous(&mut output);
        self.update_hole(now, old);
        output
    }

    /// Lost MPDUs cannot stall the data path indefinitely. Release the first
    /// buffered sequence and its contiguous successors after 100ms.
    pub fn tick(&mut self, now: u64) -> Vec<Vec<u8>> {
        if self.hole_since.is_some_and(|since| {
            now.wrapping_sub(since) >= narf_time::wall::ns_to_cycles(100_000_000)
        }) {
            for offset in 0..self.size {
                let sn = (self.head + offset) & 4095;
                if self.slots[sn as usize % MAX_WINDOW as usize].is_some() {
                    return self.release(sn, now);
                }
            }
        }
        Vec::new()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "aggregation_tests.rs"]
mod tests;
