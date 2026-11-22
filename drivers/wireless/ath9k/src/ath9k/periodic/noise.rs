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
//! calib.c AR9285 single-chain control/extension NF history and actual load.
use super::{modify, Error, Io};
#[derive(Clone, Copy)]
pub(in crate::ath9k) struct History {
    samples: [i16; 5],
    cursor: usize,
    invalid: u8,
    applied: i16,
}
fn sanitize(raw: i16) -> Result<i16, Error> {
    if raw == 0 {
        return Err(Error::Descriptor);
    }
    Ok(if raw < -127 { -118 } else { raw.min(-108) })
}
fn decode(value: u32, shift: u32) -> Result<i16, Error> {
    sanitize((((value >> shift) & 511) as i16) << 7 >> 7)
}
impl History {
    pub fn new(seed: i16) -> Result<Self, Error> {
        let seed = sanitize(seed)?;
        Ok(Self {
            samples: [seed; 5],
            cursor: 0,
            invalid: 5,
            applied: seed,
        })
    }
    fn push(&mut self, raw: i16) -> Result<i16, Error> {
        let raw = sanitize(raw)?;
        self.samples[self.cursor] = raw;
        self.cursor = (self.cursor + 1) % 5;
        if self.invalid != 0 {
            self.invalid -= 1;
            self.applied = raw;
        } else {
            let mut sorted = self.samples;
            sorted.sort_unstable();
            self.applied = sorted[2];
        }
        Ok(self.applied)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Receipt {
    /// Native signed nine-bit measurements before source sanitization.
    pub raw: [i16; 2],
    /// Actual hardware load completed for these source-filtered values.
    pub loaded: [i16; 2],
    pub wide: bool,
}
#[derive(Clone, Copy)]
enum Phase {
    Idle,
    Measuring(u64),
    Loading(u64, Receipt),
}
pub(in crate::ath9k) struct Noise {
    history: [History; 2],
    wide: bool,
    phase: Phase,
}
impl Noise {
    /// Seed only from the actual initial Report/WideReport under the same
    /// current retained calibration/geometry; no nominal history is inferred.
    pub fn new(control: i16, extension: Option<i16>) -> Result<Self, Error> {
        Ok(Self {
            history: [
                History::new(control)?,
                History::new(extension.unwrap_or(control))?,
            ],
            wide: extension.is_some(),
            phase: Phase::Idle,
        })
    }
    pub fn start(&mut self, io: &impl Io) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Idle)
            || io.read(0x9860)? & 2 != 0
            || io.read(0x9920)? & 0x10000 != 0
        {
            return Err(Error::State);
        }
        // start_nfcal(update=false): keep measured hardware minCCA separate
        // until getnf/history/load has supplied a fresh actual load receipt.
        modify(io, 0x9860, 0, 0x8000 | 0x20000)?;
        modify(io, 0x9860, 0, 2)?;
        self.phase = Phase::Measuring(io.now_us());
        Ok(())
    }
    pub fn poll(&mut self, io: &impl Io) -> Result<Option<Receipt>, Error> {
        let (began, loading) = match self.phase {
            Phase::Idle => return Err(Error::State),
            Phase::Measuring(began) => (began, None),
            Phase::Loading(began, receipt) => (began, Some(receipt)),
        };
        let now = io.now_us();
        if now < began {
            return Err(Error::State);
        }
        if io.read(0x9860)? & 2 != 0 {
            if now - began >= 222_000 {
                return Err(Error::Timeout);
            }
            return Ok(None);
        }
        if let Some(receipt) = loading {
            // Only the observed completed NF-load edge permits restoring
            // maxCCA=-50. A timed-out load never makes the receiver deaf by
            // replacing an in-progress median with an invented success.
            for reg in self.registers() {
                modify(io, reg, 511, ((-50i32 as u32) << 1) & 511)?;
            }
            self.phase = Phase::Idle;
            return Ok(Some(receipt));
        }
        let control = io.read(0x9864)?;
        let extension = if self.wide { io.read(0x99bc)? } else { control };
        let raw_control = (((control >> 20) & 511) as i16) << 7 >> 7;
        let raw_extension = if self.wide {
            (((extension >> 16) & 511) as i16) << 7 >> 7
        } else {
            raw_control
        };
        let loaded = [
            self.history[0].push(decode(control, 20)?)?,
            self.history[1].push(if self.wide {
                decode(extension, 16)?
            } else {
                decode(control, 20)?
            })?,
        ];
        let receipt = Receipt {
            raw: [raw_control, raw_extension],
            loaded,
            wide: self.wide,
        };
        // loadnf: explicit software median, stop/no-update modes cleared,
        // actual hardware load edge; every native write must read back.
        for (reg, value) in self.registers().zip(loaded) {
            modify(io, reg, 511, ((i32::from(value) as u32) << 1) & 511)?;
        }
        modify(io, 0x9860, 0x8000 | 0x20000, 0)?;
        modify(io, 0x9860, 0, 2)?;
        self.phase = Phase::Loading(now, receipt);
        Ok(None)
    }
    fn registers(&self) -> impl Iterator<Item = u64> {
        [0x9864, 0x99bc]
            .into_iter()
            .take(if self.wide { 2 } else { 1 })
    }
}
