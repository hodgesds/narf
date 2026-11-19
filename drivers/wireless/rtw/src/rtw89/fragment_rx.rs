// SPDX-License-Identifier: GPL-2.0-or-later
//! Open-link plaintext defragmentation only; the native station supplies every
//! current peer/source/header/CRC fact. Secure links use their original Security
//! cache instead, so plaintext cannot gain a cryptographic/controlled port proof.
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroizing;
const SLOTS: usize = 4;
struct Entry {
    header: Vec<u8>,
    body: Zeroizing<Vec<u8>>,
    first: u64,
    last: u8,
}
pub(super) struct Plain {
    slots: [Option<Entry>; SLOTS],
    next: usize,
}
impl Default for Plain {
    fn default() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            next: 0,
        }
    }
}
pub(super) fn fragmented(frame: &[u8]) -> bool {
    frame.len() >= 24 && (frame[1] & 4 != 0 || frame[22] & 15 != 0)
}
impl Plain {
    pub(super) fn boxed() -> Box<Self> {
        Box::default()
    }
    pub(super) fn pending(&mut self, now: u64) -> bool {
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|e| now < e.first || now - e.first > 2000)
            {
                *slot = None;
            }
        }
        self.slots.iter().any(Option::is_some)
    }
    pub(super) fn push(
        &mut self,
        bytes: &[u8],
        own: [u8; 6],
        peer: [u8; 6],
        now: u64,
    ) -> Option<Vec<u8>> {
        self.pending(now);
        if !fragmented(bytes)
            || bytes[0] & 3 != 0
            || bytes[1] & 0xf0 != 0
            || bytes[4..10] != own
            || bytes[10..16] != peer
        {
            return None;
        }
        let length = match bytes[0] {
            0x00 | 0x10 | 0x50 | 0xa0 | 0xb0 | 0xc0 | 0xd0
                if bytes[1] & 3 == 0 && bytes[16..22] == peer =>
            {
                24
            }
            8 if bytes[1] & 3 == 2 && bytes[16] & 1 == 0 && bytes[16..22] != [0; 6] => 24,
            0x88 if bytes[1] & 3 == 2
                && bytes.len() >= 26
                && bytes[24] & 0xf8 == 0
                && bytes[25] == 0
                && bytes[16] & 1 == 0
                && bytes[16..22] != [0; 6] =>
            {
                26
            }
            _ => return None,
        };
        if bytes.len() <= length || bytes.len() > 4096 {
            return None;
        }
        let number = bytes[22] & 15;
        let more = bytes[1] & 4 != 0;
        if number == 15 && more {
            return None;
        }
        if number == 0 {
            self.slots[self.next] = Some(Entry {
                header: bytes[..length].to_vec(),
                body: Zeroizing::new(bytes[length..].to_vec()),
                first: now,
                last: 0,
            });
            self.next = (self.next + 1) % SLOTS;
            return None;
        }
        let at = self.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|e| {
                e.last + 1 == number
                    && e.header[0] == bytes[0]
                    && e.header[1] & !0x0c == bytes[1] & !0x0c
                    && e.header[4..22] == bytes[4..22]
                    && e.header[22] & 0xf0 == bytes[22] & 0xf0
                    && e.header[23] == bytes[23]
                    && e.header.len() == length
                    && (length == 24 || e.header[24..26] == bytes[24..26])
            })
        })?;
        let entry = self.slots[at].as_mut()?;
        if entry.header.len() + entry.body.len() + bytes.len() - length > 4096 {
            self.slots[at] = None;
            return None;
        }
        entry.body.try_reserve(bytes.len() - length).ok()?;
        entry.body.extend_from_slice(&bytes[length..]);
        entry.last = number;
        if more {
            return None;
        }
        let mut entry = self.slots[at].take()?;
        entry.header[1] &= !4;
        entry.header[22] &= !15;
        entry.header.extend_from_slice(&entry.body);
        Some(entry.header)
    }
}
