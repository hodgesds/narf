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
//! Retained AR9285 initial PCIe/AGC/CLC/PA/noise-floor/IQ calibration.
//! Linux ar9002_{hw,calib,phy}.c and calib.c are the reference. Packet DMA,
//! MAC receive, all TX queues and interrupts remain disabled throughout.
use super::{
    identity::{BringUpError, RegisterIo, Registers},
    EEPROM_4K_BYTES,
};
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

pub(super) trait Io: RegisterIo {
    fn now_us(&self) -> u64;
    async fn settle(&mut self, microseconds: u64);
}
impl Io for Registers {
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1000
    }
    async fn settle(&mut self, microseconds: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            microseconds.saturating_mul(1000),
        ))
        .await;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Running,
    Ready,
    Failed,
}
struct Attempt<'a> {
    state: &'a mut State,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        // Diagnostic/ownership state only: cancellation never attempts MMIO
        // cleanup or claims the partially configured radio can be reused.
        if *self.state == State::Running {
            *self.state = State::Failed;
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub country: [u8; 2],
    pub frequency_mhz: u16,
    pub max_power_half_dbm: u8,
    pub pa_offset: Option<u8>,
    pub iq_i: u8,
    pub iq_q: i8,
    pub measured_noise_dbm: i16,
    pub noise_dbm: i16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Permission {
    country: [u8; 2],
    ceiling: u8,
}
impl Permission {
    pub(super) fn from_domain(domain: &RegulatoryDomain) -> Result<Self, BringUpError> {
        // The first one-shot profile is channel1/full-rate/20MHz. The entire
        // occupied span must be covered; every overlapping limit constrains it.
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(BringUpError::Policy);
        }
        let mut covered = false;
        let mut ceiling = 20i8;
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.max_bandwidth_mhz < 20
                || rule.flags.intersects(RegFlags::DFS | RegFlags::INDOOR_ONLY)
                || rule.max_power_dbm < 0
            {
                return Err(BringUpError::Policy);
            }
            ceiling = ceiling.min(rule.max_power_dbm);
            covered |= rule.freq_start_mhz <= 2402 && rule.freq_end_mhz >= 2422;
        }
        if !covered {
            return Err(BringUpError::Policy);
        }
        Ok(Self {
            country: domain.country_code,
            ceiling: (ceiling as u8) * 2,
        })
    }
}

#[derive(Debug)]
pub(super) struct Calibration {
    state: State,
    report: Option<Report>,
}
impl Default for Calibration {
    fn default() -> Self {
        Self {
            state: State::New,
            report: None,
        }
    }
}
impl Calibration {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn report(&self) -> Option<Report> {
        self.report
    }
    /// # Safety
    /// Exclusive identified AR9285 after full reference INI/modal/detector
    /// preparation. PCI BME off, no published packet DMA, MAC/TX/IRQ parked.
    /// Owner and exact factory image survive cancellation; a new attempt
    /// requires an independently proved complete reset, not a new struct.
    pub(super) async unsafe fn run(
        &mut self,
        io: &mut impl Io,
        image: &[u8; EEPROM_4K_BYTES],
        permission: Permission,
        xe2: bool,
    ) -> Result<Report, BringUpError> {
        if self.state != State::New {
            return Err(BringUpError::BadState);
        }
        if read(io, 0x981c)? & 1 != 0
            || read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
            || read(io, 0x9860)? & 3 != 0
            || read(io, 0x9920)? & 0x10000 != 0
        {
            return Err(BringUpError::BadState);
        }
        self.state = State::Running;
        let attempt = Attempt {
            state: &mut self.state,
        };
        // Caller supplied the signed domain; factory CTL, antenna and all
        // per-rate target limits are intersected before PHY activation.
        super::phy::program_live_power(io, image, permission.ceiling)?;
        pcie(io, xe2).await?;
        let delay = read(io, 0x9914)? & 0x3fff;
        write(io, 0x981c, 1)?;
        io.settle(u64::from(delay / 10 + 100)).await;
        leakage(io, xe2).await?;
        let pa_offset = if image[31] == 1 {
            None
        } else {
            Some(pa(io).await?)
        };
        let (measured_noise_dbm, noise_dbm) = noise(io).await?;
        let (iq_i, iq_q) = iq(io).await?;
        if read(io, 8)? & 4 != 0
            || read(io, 0x840)? & 0x3ff != 0
            || read(io, 0x24)? & 1 != 0
            || read(io, 0x981c)? & 1 != 1
            || read(io, 0x8048)? & 0x02000020 != 0x02000020
        {
            return Err(BringUpError::BadState);
        }
        let report = Report {
            country: permission.country,
            frequency_mhz: 2412,
            max_power_half_dbm: permission.ceiling,
            pa_offset,
            iq_i,
            iq_q,
            measured_noise_dbm,
            noise_dbm,
        };
        self.report = Some(report);
        *attempt.state = State::Ready;
        Ok(report)
    }
}
fn read(io: &mut impl RegisterIo, register: u64) -> Result<u32, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let value = io.read32(register);
    if value == u32::MAX {
        Err(BringUpError::DeviceGone)
    } else {
        Ok(value)
    }
}
fn measurement(io: &mut impl RegisterIo, register: u64) -> Result<u32, BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let value = io.read32(register);
    if value == u32::MAX {
        // A full-width IQ correlation of -1 is legitimate. Check immutable
        // silicon identity instead of confusing that data value with removal.
        let revision = read(io, 0x4020)?;
        if revision & 0xff != 0xff || (revision & 0xfffc0000) >> 12 != 0xc0 {
            return Err(BringUpError::DeviceGone);
        }
    }
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(value)
}
fn write(io: &mut impl RegisterIo, register: u64, value: u32) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, value);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
fn modify(
    io: &mut impl RegisterIo,
    register: u64,
    clear: u32,
    set: u32,
) -> Result<(), BringUpError> {
    let value = read(io, register)?;
    write(io, register, (value & !clear) | set)
}
fn field(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    shift: u32,
    value: u32,
) -> Result<(), BringUpError> {
    modify(io, register, mask, (value << shift) & mask)
}
async fn wait(
    io: &mut impl Io,
    register: u64,
    mask: u32,
    timeout: u64,
) -> Result<(), BringUpError> {
    let start = io.now_us();
    loop {
        if read(io, register)? & mask == 0 {
            return Ok(());
        }
        if io.now_us().saturating_sub(start) >= timeout {
            return Err(BringUpError::Timeout);
        }
        io.settle(10).await;
    }
}
async fn pcie(io: &mut impl Io, xe2: bool) -> Result<(), BringUpError> {
    // ar9280PciePhy_clkreq_always_on_L1_9280, selected by AR9285 Linux.
    for value in [
        0x9248fd00, 0x24924924, 0xa8000019, 0x13160820, 0xe5980560, 0xc01dcffd, 0x1aaabe41,
        0xbe105554, 0x00043007,
    ] {
        write(io, 0x4040, value)?;
    }
    write(io, 0x4044, 0)?;
    io.settle(1000).await;
    write(
        io,
        0x4004,
        (0x004a050b & !0x4000) | 0xc0 | if xe2 { 1 << 23 } else { 0 },
    )?;
    modify(io, 0x4014, 0, 1 << 19)
}
async fn carrier_leakage(io: &mut impl Io) -> Result<(), BringUpError> {
    modify(io, 0xa358, 0, 2)?;
    // Initial full-rate HT20 geometry, even when peer rates stay legacy.
    modify(io, 0xa358, 0, 1)?;
    modify(io, 0x9804, 0, 4)?;
    modify(io, 0x9860, 0x10000, 0)?;
    modify(io, 0xa258, 0x400000, 0)?;
    modify(io, 0x9860, 0, 1)?;
    wait(io, 0x9860, 1, 100000).await?;
    modify(io, 0x9804, 4, 0)?;
    modify(io, 0xa358, 1, 0)?;
    modify(io, 0xa358, 2, 0)?;
    modify(io, 0x982c, 0x8000, 0)?;
    modify(io, 0x9860, 0, 0x10000)?;
    modify(io, 0xa258, 0, 0x400000)?;
    modify(io, 0x9860, 0, 1)?;
    wait(io, 0x9860, 1, 100000).await?;
    modify(io, 0x982c, 0, 0x8000)?;
    modify(io, 0xa358, 2, 0)?;
    modify(io, 0x9860, 0x10000, 0)
}
async fn leakage(io: &mut impl Io, xe2: bool) -> Result<(), BringUpError> {
    carrier_leakage(io).await?;
    let maximum = (read(io, 0xa274)? & 0x7e000) >> 13;
    let mut gains = 0u32;
    for index in 0..=maximum {
        let gain = (read(io, 0xa300 + u64::from(index) * 4)? & 0x1e) >> 1;
        gains |= 1 << gain;
    }
    let mut zeros = 0;
    for index in 0..gains.count_ones() {
        let value = read(io, 0xa35c + u64::from(index) * 4)?;
        zeros += u32::from(value & 0x7ff0000 == 0);
        zeros += u32::from((value & 0xffd0) >> 5 == 0);
    }
    if zeros > 1 {
        let original = read(io, 0x7830)?;
        write(
            io,
            0x7830,
            (original & 0xfffff8ff) | if xe2 { 0x500 } else { 0x400 },
        )?;
        carrier_leakage(io).await?;
        write(io, 0x7830, original)?;
    }
    Ok(())
}
async fn pa(io: &mut impl Io) -> Result<u8, BringUpError> {
    let addresses = [0x786c, 0x7854, 0x7820, 0x7824, 0x7868, 0x783c, 0x7838];
    let mut saved = [0u32; 7];
    for (index, &register) in addresses.iter().enumerate() {
        saved[index] = read(io, register)?;
    }
    modify(io, 0x7834, 1, 0)?;
    modify(io, 0x9808, 0, 1 << 27)?;
    for (register, mask, shift, value) in [
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
        field(io, register, mask, shift, value)?;
    }
    let ccomp = (read(io, 0x7834)? & 0x7800) >> 11;
    field(io, 0x7834, 0x7800, 11, 15)?;
    write(io, 0x7868, 0xca0358a0)?;
    io.settle(30).await;
    field(io, 0x7834, 0x3f00000, 20, 0)?;
    field(io, 0x7828, 0x2000000, 25, 0)?;
    for index in (1..=6).rev() {
        modify(io, 0x7834, 0, 1 << (19 + index))?;
        io.settle(1).await;
        let value = read(io, 0x7834)? & !(1 << (19 + index));
        let spare = read(io, 0x7840)? & 1;
        write(io, 0x7834, value | (spare << (19 + index)))?;
    }
    field(io, 0x7828, 0x2000000, 25, 1)?;
    io.settle(1).await;
    let low = read(io, 0x7840)? & 1;
    field(io, 0x7828, 0x2000000, 25, low)?;
    let high = (read(io, 0x7834)? & 0x3f00000) >> 20;
    let low = (read(io, 0x7828)? & 0x2000000) >> 25;
    let offset = (high << 1) | low;
    field(io, 0x7834, 0x3f00000, 20, offset >> 1)?;
    field(io, 0x7828, 0x2000000, 25, offset & 1)?;
    modify(io, 0x7834, 0, 1)?;
    modify(io, 0x9808, 1 << 27, 0)?;
    for (register, value) in addresses.into_iter().zip(saved) {
        write(io, register, value)?;
    }
    field(io, 0x7834, 0x7800, 11, ccomp)?;
    Ok(offset as u8)
}
async fn noise(io: &mut impl Io) -> Result<(i16, i16), BringUpError> {
    // First load uses AR9285's native nominal floor; a completed hardware
    // measurement is still required before this owner can report Ready.
    let initial = read(io, 0x9860)?;
    modify(io, 0x9864, 0x1ff, ((-118i32 as u32) << 1) & 0x1ff)?;
    if initial & 2 != 0 {
        modify(io, 0x9860, 2, 0)?;
    }
    modify(io, 0x9860, 0x8000, 0)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222000).await?;
    modify(io, 0x9864, 0x1ff, ((-50i32 as u32) << 1) & 0x1ff)?;
    modify(io, 0x9860, 0, 0x8000)?;
    modify(io, 0x9860, 0x20000, 0)?;
    modify(io, 0x9860, 0, 2)?;
    wait(io, 0x9860, 2, 222000).await?;
    let raw = ((read(io, 0x9864)? >> 20) & 0x1ff) as i16;
    let raw = (raw << 7) >> 7;
    if raw == 0 {
        return Err(BringUpError::BadCalibration);
    }
    let applied = if raw < -127 { -118 } else { raw.min(-108) };
    Ok((raw, applied))
}
fn iq_coefficients(power_i: u32, power_q: u32, correlation: u32) -> Result<(u8, i8), BringUpError> {
    let i_denominator = (power_i / 2 + power_q / 2) / 128;
    let q_denominator = power_q / 64;
    if power_q == 0 || i_denominator == 0 || q_denominator == 0 {
        return Err(BringUpError::BadCalibration);
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
    };
    let q = (power_i / q_denominator).wrapping_sub(64) as i32;
    Ok(((i & 63) as u8, q.clamp(-16, 15) as i8))
}
async fn iq(io: &mut impl Io) -> Result<(u8, i8), BringUpError> {
    field(io, 0x9920, 0xf000, 12, 10)?;
    write(io, 0x99f0, 0)?;
    modify(io, 0x9920, 0, 0x10000)?;
    wait(io, 0x9920, 0x10000, 30000000).await?;
    let i = measurement(io, 0x9c10)?;
    let q = measurement(io, 0x9c14)?;
    let correlation = measurement(io, 0x9c18)?;
    let (i, q) = iq_coefficients(i, q, correlation)?;
    field(io, 0x9920, 0x7e0, 5, u32::from(i))?;
    field(io, 0x9920, 31, 0, q as u32)?;
    modify(io, 0x9920, 0, 0x800)?;
    Ok((i, q))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "calibration/tests.rs"]
mod tests;
