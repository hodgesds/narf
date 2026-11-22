// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Actual ar9285_hw_pa_cal(false) program and source unchanged-offset skips.
use super::{modify, Error, Io};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Update {
    /// Actual factory high-power TXGAIN needs no PA calibration.
    Disabled,
    /// The prior factual offset remains authoritative; no new receipt.
    Skipped(u8),
    Measured(u8),
}
pub(in crate::ath9k) struct Pa {
    previous: Option<u8>,
    maximum_skip: u8,
    remaining: u8,
}
impl Pa {
    /// `initial` comes only from this retained initial Report: None means
    /// the actual factory high-power branch, never an erased/default profile.
    pub fn new(initial: Option<u8>) -> Result<Self, Error> {
        if initial.is_some_and(|value| value > 127) {
            return Err(Error::Descriptor);
        }
        Ok(Self {
            previous: initial,
            maximum_skip: 1,
            remaining: 0,
        })
    }
    pub fn long(&mut self, io: &impl Io) -> Result<Update, Error> {
        let Some(previous) = self.previous else {
            return Ok(Update::Disabled);
        };
        if self.remaining != 0 {
            self.remaining -= 1;
            return Ok(Update::Skipped(self.remaining));
        }
        // Caller retains the current full-program P source, actual awake
        // MAC/TX/RX quiescence and mapped packet/key/BA generation throughout.
        let offset = run(io)?;
        if offset == previous {
            self.maximum_skip = (self.maximum_skip * 2).min(8);
            self.remaining = self.maximum_skip;
        } else {
            self.maximum_skip = 1;
            self.remaining = 0;
            self.previous = Some(offset);
        }
        Ok(Update::Measured(offset))
    }
}
fn field(io: &impl Io, reg: u64, mask: u32, shift: u32, value: u32) -> Result<(), Error> {
    modify(io, reg, mask, (value << shift) & mask).map(|_| ())
}
fn run(io: &impl Io) -> Result<u8, Error> {
    let addresses = [0x786c, 0x7854, 0x7820, 0x7824, 0x7868, 0x783c, 0x7838];
    let mut saved = [0; 7];
    for (register, value) in addresses.into_iter().zip(&mut saved) {
        *value = io.read(register)?;
    }
    modify(io, 0x7834, 1, 0)?;
    modify(io, 0x9808, 0, 1 << 27)?;
    for (reg, mask, shift, value) in [
        (0x786c, 0x800000, 23, 1),
        (0x7854, 0x20, 5, 1),
        (0x7854, 0x80, 7, 1),
        (0x7854, 0x100, 8, 1),
        (0x7824, 0x1000, 12, 0),
        (0x7838, 2, 1, 0),
        (0x7820, 0x800, 11, 0),
        (0x7820, 0x2000000, 25, 0),
        (0x7820, 0x1000000, 24, 0),
        (0x7820, 0x800000, 23, 0),
        (0x783c, 0x1c000, 14, 7),
        (0x7838, 0xe0000000, 29, 0),
    ] {
        field(io, reg, mask, shift, value)?;
    }
    let ccomp = io.read(0x7834)? >> 11 & 15;
    field(io, 0x7834, 0x7800, 11, 15)?;
    io.write(0x7868, 0xca0358a0)?;
    if io.read(0x7868)? != 0xca0358a0 {
        return Err(Error::Descriptor);
    }
    io.delay_us(30);
    field(io, 0x7834, 0x3f00000, 20, 0)?;
    field(io, 0x7828, 0x2000000, 25, 0)?;
    for index in (1..=6).rev() {
        let bit = 1 << (19 + index);
        modify(io, 0x7834, 0, bit)?;
        io.delay_us(1);
        let spare = io.read(0x7840)? & 1;
        modify(io, 0x7834, bit, spare << (19 + index))?;
    }
    field(io, 0x7828, 0x2000000, 25, 1)?;
    io.delay_us(1);
    let spare = io.read(0x7840)? & 1;
    field(io, 0x7828, 0x2000000, 25, spare)?;
    let high = io.read(0x7834)? >> 20 & 63;
    let low = io.read(0x7828)? >> 25 & 1;
    let offset = ((high << 1) | low) as u8;
    field(io, 0x7834, 0x3f00000, 20, u32::from(offset >> 1))?;
    field(io, 0x7828, 0x2000000, 25, u32::from(offset & 1))?;
    modify(io, 0x7834, 0, 1)?;
    modify(io, 0x9808, 1 << 27, 0)?;
    for (register, value) in addresses.into_iter().zip(saved) {
        io.write(register, value)?;
        if io.read(register)? != value {
            return Err(Error::Descriptor);
        }
    }
    field(io, 0x7834, 0x7800, 11, ccomp)?;
    if (io.read(0x7834)? >> 20 & 63) as u8 != offset >> 1
        || (io.read(0x7828)? >> 25 & 1) as u8 != offset & 1
        || io.read(0x9808)? & (1 << 27) != 0
    {
        return Err(Error::Descriptor);
    }
    Ok(offset)
}
