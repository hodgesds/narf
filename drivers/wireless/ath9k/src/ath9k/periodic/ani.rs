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
//! AR9285 ANI: ani.c, ar5008_phy.c and common hw.c source operations.
//! The retained current P/native owner encloses every operation. A plan
//! does not become a live receive-sensitivity receipt until actual quiet
//! hardware writes/readbacks complete. AR9285 has no MRC-CCK hardware.
use super::{modify, Error, Io};

// Only ANI-owned fields: other channel/spur/NF fields survive every update.
const FIELDS: [(u64, u32); 7] = [
    (0x9868, 0x7ffe001f),
    (0x986c, 0x0fffff01),
    (0x99c0, 0x0fffffff),
    (0x9858, 0x0003f000),
    (0x9840, 0x00000fc0),
    (0x9924, 0x000000fe),
    (0x99bc, 0x0000fe00),
];
// Source logical levels; defaults label the actual INI, which must not be
// replaced by a computed default. In particular, default spur INI values can
// differ from the formula used when an actual level transition occurs.
const OFDM: [(u8, u8, bool); 10] = [
    (0, 0, true),
    (1, 1, true),
    (2, 2, true),
    (3, 2, true),
    (4, 3, true),
    (5, 4, true),
    (6, 5, true),
    (7, 6, true),
    (7, 7, true),
    (7, 8, false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Settings([u32; 7]);
impl Settings {
    pub fn read(io: &impl Io) -> Result<Self, Error> {
        let mut words = [0; 7];
        for (word, &(register, mask)) in words.iter_mut().zip(&FIELDS) {
            *word = io.read(register)? & mask;
        }
        Ok(Self(words))
    }
    pub fn readback(self, io: &impl Io) -> Result<(), Error> {
        if Self::read(io)? != self {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
    fn write(self, io: &impl Io) -> Result<(), Error> {
        for (&word, &(register, mask)) in self.0.iter().zip(&FIELDS) {
            modify(io, register, mask, word)?;
        }
        self.readback(io)
    }
    fn firstep(&mut self, level: u8) {
        let value = u32::from(level) * 2;
        self.0[3] = value << 12;
        self.0[4] = value << 6;
    }
    fn spur(&mut self, level: u8) {
        let value = (u32::from(level) + 1) * 2;
        self.0[5] = value << 1;
        self.0[6] = (value - 1) << 9;
    }
    fn weak(&mut self, on: bool, ini: Self) {
        if on {
            self.0[..3].copy_from_slice(&ini.0[..3]);
            self.0[1] |= 1;
        } else {
            // Source off thresholds127, counts31/63 and USE_SELF_CORR_LOW0.
            self.0[0] = (127 << 17) | (127 << 24) | 31;
            self.0[1] = (127 << 14) | (127 << 21) | (63 << 8);
            self.0[2] = 127 | (127 << 7) | (127 << 14) | (127 << 21);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Levels {
    ofdm: u8,
    cck: u8,
    spur: u8,
    firstep: u8,
    weak: bool,
    ofdm_turn: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Plan {
    serial: u64,
    levels: Levels,
    settings: Settings,
}

/// Source fixed-point beacon RSSI, updated only for an actually admitted
/// current-peer beacon with a valid native (non-subframe) signal sample.
pub(in crate::ath9k) struct Rssi(Option<i32>);
impl Rssi {
    pub fn new() -> Self {
        Self(None)
    }
    pub fn beacon(&mut self, native: i8) {
        if native >= -20 {
            let sample = i32::from(native) * 128;
            self.0 = Some(self.0.map_or(sample, |old| (old * 9 + sample) / 10));
        }
    }
    pub fn value(&self) -> Option<u8> {
        self.0.map(|value| ((value + 64) / 128).max(0) as u8)
    }
}

pub(in crate::ath9k) struct Ani {
    ini: Settings,
    current: Settings,
    levels: Levels,
    listen_ms: u64,
    serial: u64,
    ofdm_errors: u32,
    cck_errors: u32,
    /// Actual source MIB observations; not synthetic success counters.
    mib: [u64; 5],
    wide: bool,
}
impl Ani {
    pub fn reset_counters(&mut self, io: &impl Io) -> Result<(), Error> {
        self.restart(io)
    }
    /// Current actual INI/PHY receipt is required; this does not replay INI
    /// or silently assume that default level numbers encode register values.
    pub fn begin(io: &impl Io, wide: bool) -> Result<Self, Error> {
        let ini = Settings::read(io)?;
        if ini.0[1] & 1 == 0 {
            return Err(Error::State);
        }
        let mut owner = Self {
            ini,
            current: ini,
            levels: Levels {
                ofdm: 3,
                cck: 2,
                spur: 3,
                firstep: 2,
                weak: true,
                ofdm_turn: true,
            },
            listen_ms: 0,
            serial: 0,
            ofdm_errors: 0,
            cck_errors: 0,
            mib: [0; 5],
            wide,
        };
        // Enable source MIB counters and OFDM/CCK timing-error masks.
        io.write(0x8124, 0)?;
        io.write(0x8128, 0)?;
        io.write(0x40, 0)?;
        if io.read(0x40)? & 15 != 0 {
            return Err(Error::Descriptor);
        }
        owner.restart(io)?;
        owner.cycles(io)?;
        Ok(owner)
    }
    fn mib(&mut self, io: &impl Io) -> Result<(), Error> {
        for (total, register) in self
            .mib
            .iter_mut()
            .zip([0x8088, 0x808c, 0x8090, 0x8094, 0x8098])
        {
            *total = total.saturating_add(u64::from(io.read(register)?));
        }
        Ok(())
    }
    fn restart(&mut self, io: &impl Io) -> Result<(), Error> {
        io.write(0x812c, 0)?;
        io.write(0x8134, 0)?;
        io.write(0x8130, 0x00020000)?;
        io.write(0x8138, 0x02000000)?;
        if io.read(0x8130)? != 0x00020000 || io.read(0x8138)? != 0x02000000 {
            return Err(Error::Descriptor);
        }
        self.mib(io)?;
        self.listen_ms = 0;
        self.ofdm_errors = 0;
        self.cck_errors = 0;
        Ok(())
    }
    fn cycles(&self, io: &impl Io) -> Result<[u32; 4], Error> {
        // Actual source snapshot freezes first, reads all counters, clears
        // while frozen and unfreezes. The sole owner serializes survey use.
        io.write(0x40, 2)?;
        if io.read(0x40)? & 15 != 2 {
            return Err(Error::Descriptor);
        }
        let registers = [0x80f8, 0x80f4, 0x80f0, 0x80ec];
        let mut values = [0; 4];
        for (value, register) in values.iter_mut().zip(registers) {
            *value = io.read(register)?;
        }
        for register in registers {
            io.write(register, 0)?;
            if io.read(register)? != 0 {
                return Err(Error::Descriptor);
            }
        }
        io.write(0x40, 0)?;
        if io.read(0x40)? & 15 != 0 {
            return Err(Error::Descriptor);
        }
        Ok(values)
    }
    /// A counter observation confers no permission to mutate coefficients.
    /// Plan application needs a separately retained actual quiet native epoch.
    pub fn observe(&mut self, io: &impl Io, rssi: u8) -> Result<Option<Plan>, Error> {
        self.current.readback(io)?;
        let [cycles, _, rx, tx] = self.cycles(io)?;
        let listen = i64::from(cycles) - i64::from(rx) - i64::from(tx);
        let listen = listen / if self.wide { 88_000 } else { 44_000 };
        if listen <= 0 {
            self.restart(io)?;
            return Ok(None);
        }
        self.listen_ms = self.listen_ms.saturating_add(listen as u64);
        self.mib(io)?;
        let ofdm = io.read(0x812c)?;
        let cck = io.read(0x8134)?;
        if ofdm > 0xffffff || cck > 0xffffff || ofdm < self.ofdm_errors || cck < self.cck_errors {
            return Err(Error::Descriptor);
        }
        self.ofdm_errors = ofdm;
        self.cck_errors = cck;
        if self.listen_ms <= 300 {
            return Ok(None);
        }
        let ofdm_rate = u64::from(ofdm) * 1000 / self.listen_ms;
        let cck_rate = u64::from(cck) * 1000 / self.listen_ms;
        let mut plan = Plan {
            serial: self.serial,
            levels: self.levels,
            settings: self.current,
        };
        // AR9285 takes the OLD thresholds: OFDM500/200, CCK200/100.
        if cck_rate < 100 && ofdm_rate < 200 {
            if plan.levels.ofdm > 0 && (plan.levels.ofdm_turn || plan.levels.cck == 0) {
                let level = plan.levels.ofdm - 1;
                self.ofdm(&mut plan, level, rssi);
            } else if plan.levels.cck > 0 {
                let level = plan.levels.cck - 1;
                Self::cck(&mut plan, level, rssi);
            }
            plan.levels.ofdm_turn = !plan.levels.ofdm_turn;
        } else if ofdm_rate > 500 {
            let level = (plan.levels.ofdm + 1).min(9);
            self.ofdm(&mut plan, level, rssi);
            plan.levels.ofdm_turn = false;
        } else if cck_rate > 200 {
            let level = (plan.levels.cck + 1).min(8);
            Self::cck(&mut plan, level, rssi);
            plan.levels.ofdm_turn = true;
        } else {
            return Ok(None);
        }
        Ok(Some(plan))
    }
    fn ofdm(&self, plan: &mut Plan, level: u8, rssi: u8) {
        plan.levels.ofdm = level;
        let (spur, firstep, weak) = OFDM[usize::from(level)];
        if plan.levels.spur != spur {
            plan.settings.spur(spur);
            plan.levels.spur = spur;
        }
        if plan.levels.firstep != firstep && firstep >= plan.levels.cck {
            plan.settings.firstep(firstep);
            plan.levels.firstep = firstep;
        }
        let weak = if rssi <= 40 {
            true
        } else if level >= 8 {
            false
        } else {
            weak
        };
        if plan.levels.weak != weak {
            plan.settings.weak(weak, self.ini);
            plan.levels.weak = weak;
        }
    }
    fn cck(plan: &mut Plan, level: u8, rssi: u8) {
        let level = if rssi <= 7 { level.min(6) } else { level };
        plan.levels.cck = level;
        if plan.levels.firstep != level && level >= OFDM[usize::from(plan.levels.ofdm)].1 {
            plan.settings.firstep(level);
            plan.levels.firstep = level;
        }
    }
    pub fn apply(&mut self, io: &impl Io, plan: Plan) -> Result<Settings, Error> {
        if plan.serial != self.serial {
            return Err(Error::State);
        }
        self.current.readback(io)?;
        plan.settings.write(io)?;
        self.restart(io)?;
        let serial = self.serial.checked_add(1).ok_or(Error::State)?;
        self.levels = plan.levels;
        self.current = plan.settings;
        self.serial = serial;
        Ok(self.current)
    }
}
