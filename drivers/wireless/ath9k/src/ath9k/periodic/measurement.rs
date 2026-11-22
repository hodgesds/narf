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
//! ar9002_calib.c single-sample (PER_MAX_LOG_COUNT10) source arithmetic.
//! ADC gain/DC are HT40-only; IQ applies to both source widths.
use super::{modify, Error, Io};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Mode {
    AdcGain,
    AdcDc,
    Iq,
}
impl Mode {
    pub(super) fn register(self) -> u32 {
        match self {
            Self::AdcGain => 1,
            Self::AdcDc => 2,
            Self::Iq => 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Correction {
    /// Actual enabled IQ correction bits11..0, not an initial Report rewrite.
    pub iq: u32,
    /// Actual complete gain/DC correction register; absent for20MHz.
    pub adc: Option<u32>,
}
impl Correction {
    pub fn read(io: &impl Io, wide: bool) -> Result<Self, Error> {
        let iq = io.read(0x9920)?;
        if iq & 0x10000 != 0 || iq & 0x800 == 0 {
            return Err(Error::State);
        }
        let adc = if wide {
            let value = io.read(0x99b4)?;
            if value & 0xc0000000 != 0xc0000000 {
                return Err(Error::State);
            }
            Some(value)
        } else {
            None
        };
        Ok(Self {
            iq: iq & 0xfff,
            adc,
        })
    }
    pub fn readback(self, io: &impl Io) -> Result<(), Error> {
        if io.read(0x9920)? & 0x10fff != self.iq
            || self.adc.is_some_and(|value| io.read(0x99b4) != Ok(value))
        {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Step {
    Waiting,
    /// Source30-second timeout cleared DO_CAL; no fresh correction is minted.
    Retry(Mode),
    Complete(Mode, Correction),
}
pub(in crate::ath9k) struct Sampler {
    mode: Mode,
    began: u64,
    wide: bool,
    finished: bool,
}
impl Sampler {
    pub fn expired(&self, now: u64) -> Result<bool, Error> {
        if now < self.began {
            return Err(Error::State);
        }
        Ok(now - self.began >= 30_000_000)
    }
    /// Caller owns the actual quiet MAC/rings for this start, current dynamic
    /// qualification and unchanged full-span/channel/power/chain receipt.
    /// While hardware measures, a separately sealed native live owner may
    /// resume RX/TX under the unchanged prior coefficients and this exact
    /// bounded mode. Collection/writes require actual quiescence again.
    pub fn begin(io: &impl Io, mode: Mode, wide: bool) -> Result<Self, Error> {
        if mode != Mode::Iq && !wide
            || io.read(0x9920)? & 0x10000 != 0
            || io.read(0x9860)? & 2 != 0
            || io.read(0x981c)? & 1 == 0
        {
            return Err(Error::State);
        }
        modify(io, 0x9920, 0xf000, 10 << 12)?;
        io.write(0x99f0, mode.register())?;
        if io.read(0x99f0)? != mode.register() {
            return Err(Error::Descriptor);
        }
        // Observe an actual running hardware operation. An ignored write
        // plus old measurement data cannot become a new calibration receipt.
        modify(io, 0x9920, 0, 0x10000)?;
        Ok(Self {
            mode,
            began: io.now_us(),
            wide,
            finished: false,
        })
    }
    pub fn poll(&mut self, io: &impl Io) -> Result<Step, Error> {
        if self.finished {
            return Err(Error::State);
        }
        let now = io.now_us();
        if now < self.began || io.read(0x99f0)? != self.mode.register() {
            return Err(Error::State);
        }
        let running = io.read(0x9920)? & 0x10000 != 0;
        if now - self.began >= 30_000_000 {
            // The distinct P contract never accepts an unobserved late
            // completion as an in-budget fresh measurement. Retain the
            // previous coefficients and retry the exact source mode.
            if running {
                modify(io, 0x9920, 0x10000, 0)?;
            }
            self.finished = true;
            return Ok(Step::Retry(self.mode));
        }
        if running {
            return Ok(Step::Waiting);
        }
        let data = [
            io.read(0x9c10)?,
            io.read(0x9c14)?,
            io.read(0x9c18)?,
            io.read(0x9c1c)?,
        ];
        match self.mode {
            Mode::Iq => {
                let (i, q) = iq(data[0], data[1], data[2])?;
                modify(io, 0x9920, 0x7ff, (i << 5) | (q as u32 & 31) | 0x800)?;
            }
            Mode::AdcGain => {
                let value = adc_gain(io.read(0x99b4)?, data)?;
                io.write(0x99b4, value)?;
                if io.read(0x99b4)? != value {
                    return Err(Error::Descriptor);
                }
            }
            Mode::AdcDc => {
                let value = adc_dc(io.read(0x99b4)?, data);
                io.write(0x99b4, value)?;
                if io.read(0x99b4)? != value {
                    return Err(Error::Descriptor);
                }
            }
        }
        // During the HT40 list, ADC Gain can finish before ADC DC. Capture
        // the factual register without claiming both enable bits are fresh.
        let correction = Correction {
            iq: io.read(0x9920)? & 0xfff,
            adc: if self.wide {
                Some(io.read(0x99b4)?)
            } else {
                None
            },
        };
        correction.readback(io)?;
        self.finished = true;
        Ok(Step::Complete(self.mode, correction))
    }
}
fn iq(i_power: u32, q_power: u32, correlation: u32) -> Result<(u32, i32), Error> {
    let i_denominator = (i_power / 2 + q_power / 2) / 128;
    let q_denominator = q_power / 64;
    if q_power == 0 || i_denominator == 0 || q_denominator == 0 {
        // Keep the old immutable receipt, never mint a fabricated coefficient.
        return Err(Error::Descriptor);
    }
    let negative = correlation > 0x80000000;
    let magnitude = if negative {
        correlation.wrapping_neg()
    } else {
        correlation
    };
    let coefficient = (magnitude / i_denominator) & 63;
    let i = if negative {
        coefficient
    } else {
        64 - coefficient
    } & 63;
    let q = (i_power / q_denominator).wrapping_sub(64) as i32;
    Ok((i, q.clamp(-16, 15)))
}
fn adc_gain(old: u32, data: [u32; 4]) -> Result<u32, Error> {
    if data[0] == 0 || data[3] == 0 {
        return Err(Error::Descriptor);
    }
    let i = (data[1].wrapping_mul(32) / data[0]) & 63;
    let q = (data[2].wrapping_mul(32) / data[3]) & 63;
    Ok((old & 0xfffff000) | q | (i << 6) | 0x40000000)
}
fn adc_dc(old: u32, data: [u32; 4]) -> u32 {
    // Source u32 I subtraction and signed Q division/truncation. One sample
    // at log10 means1<<15 samples; never reinterpret as rounded signed I.
    let i = (data[1].wrapping_sub(data[0]).wrapping_mul(2) / 32768) & 511;
    let q = (data[2] as i32)
        .wrapping_sub(data[3] as i32)
        .wrapping_mul(2)
        / 32768;
    (old & 0xc0000fff) | ((q as u32 & 511) << 12) | (i << 21) | 0x80000000
}
