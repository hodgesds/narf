// SPDX-License-Identifier: GPL-2.0-or-later
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
//! `hw.c::{ath9k_set_power_network_sleep,ath9k_hw_set_power_awake}` for
//! AR9462 AUTOSLEEP + live MCI, using the retained N46S/PCI raw adapter.
use super::super::mci::{AR_BTCOEX_CTRL, AR_BTCOEX_CTRL_MCI_MODE_EN};
use crate::ath9k::{packet::Error, ps::hardware::Raw};

fn write(io: &impl Raw, register: u64, value: u32) -> Result<(), Error> {
    io.write(register, value)?;
    if io.read(register)? != value {
        return Err(Error::Descriptor);
    }
    Ok(())
}
fn modify(io: &impl Raw, register: u64, clear: u32, set: u32) -> Result<(), Error> {
    write(io, register, (io.read(register)? & !clear) | set)
}

pub(in crate::ath9k) fn network_sleep(io: &impl Raw, wa: u32) -> Result<(), Error> {
    if io.read(0x7044)? & 15 != 2
        || io.read(0x840)? & 0x3ff != 0
        || io.read(8)? & 0xc != 0xc
        || io.read(0x8048)? & 0x02000020 != 0
        || io.read(0x24)? & 1 == 0
        || io.read(0x8240)? & 0x31 != 0x31
        || io.read(0xac)? & 0x67000000 != 0x67000000
        || io.read(0x403c)? & 0x82 != 0x82
        || io.read(AR_BTCOEX_CTRL)? & AR_BTCOEX_CTRL_MCI_MODE_EN == 0
    {
        return Err(Error::State);
    }
    for queue in 0..10 {
        if io.read(0xa00 + queue * 4)? & 3 != 0 {
            return Err(Error::Busy);
        }
    }
    // AUTOSLEEP keeps the real receive FIFOs available for beacon/TIM wake.
    // Unlike AR9285 no-AUTOSLEEP, it does not set RX_ABORT/RX_DIS.
    modify(io, 0x8004, 0, 0x40000)?;
    modify(io, 0x183c, 0x23e, 0)?; // reg_mci.h::RX_HW_MSG_MASK.
    modify(io, 0x704c, 1, 0)?;
    io.delay(30);
    write(io, 0x4004, wa & !0x4000)?;
    io.wait(0x7044, 15, 4, 2000)
}

struct MciIo<'a, P> {
    io: &'a P,
    error: Option<Error>,
}
impl<P: Raw> crate::ath9k::identity::RegisterIo for MciIo<'_, P> {
    fn authorized(&self) -> bool {
        self.error.is_none()
    }
    fn read32(&mut self, register: u64) -> u32 {
        if self.error.is_some() {
            return u32::MAX;
        }
        self.io.read(register).unwrap_or_else(|error| {
            self.error = Some(error);
            u32::MAX
        })
    }
    fn write32(&mut self, register: u64, value: u32) {
        if self.error.is_none() {
            if let Err(error) = self.io.write(register, value) {
                self.error = Some(error);
            }
        }
    }
    fn delay_us(&mut self, us: u64) {
        self.io.delay(us);
    }
}
pub(in crate::ath9k) fn awake(io: &impl Raw, wa: u32) -> Result<(), Error> {
    // Source WA restore precedes RTC status/ForceWake and the MCI LNA
    // workaround. SHUTDOWN cannot preserve a live station or its DMA/keys.
    write(io, 0x4004, wa)?;
    io.delay(10);
    if !matches!(io.read(0x7044)? & 15, 2 | 4) {
        return Err(Error::State);
    }
    modify(io, 0x704c, 0, 1)?;
    io.delay(50);
    io.wait(0x7044, 15, 2, 2000)?;
    let mut mci = MciIo { io, error: None };
    let result = super::super::mci::set_power_awake(&mut mci);
    if let Some(error) = mci.error {
        return Err(error);
    }
    result.map_err(|_| Error::Descriptor)?;
    modify(io, 0x8004, 0x40000, 0)
}
