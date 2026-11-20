// SPDX-License-Identifier: ISC
//! AR9003 ANI: Linux ani.c, ar9003_phy.c1062..1450 and ath/hw.c.
//! The fresh P record covers the complete native program. A/S/D records
//! retain their existing meanings; this owner never composes S or D.
use crate::ath9k::{
    packet::Error,
    periodic::{BeaconRssi, Io},
};
#[path = "ani/qualification.rs"]
mod qualification;
pub use qualification::Request;
pub(in crate::ath9k) use qualification::{Base, Grant};

// Only source ANI-owned fields. In particular MC_GAIN/LNA-diversity and
// source NF/spur/channel fields are not antenna or ANI semantic aliases.
const FIELDS: [(u64, u32); 8] = [
    (0x9824, 0x7ffe001f),
    (0x9828, 0x0fffff01),
    (0x982c, 0x0fffffff),
    (0x9e10, 0x0003f000),
    (0x9820, 0x00000fc0),
    (0x9810, 0x000000fe),
    (0x9830, 0x0000fe00),
    (0x9fd0, 3),
];
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
pub(in crate::ath9k) struct Settings(pub(super) [u32; 8]);
impl Settings {
    pub(in crate::ath9k) fn read(io: &impl Io, device: u16) -> Result<Self, Error> {
        let mut words = [0; 8];
        for (index, (word, (r, mask))) in words.iter_mut().zip(FIELDS).enumerate() {
            *word = if index == 7 && device != 0x0034 {
                u32::MAX
            } else {
                io.read(r)? & mask
            };
        }
        Ok(Self(words))
    }
    pub(in crate::ath9k) fn readback(self, io: &impl Io) -> Result<(), Error> {
        for (word, (r, mask)) in self.0.into_iter().zip(FIELDS) {
            if word != u32::MAX && io.read(r)? & mask != word {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
    fn write(self, io: &impl Io, previous: Self) -> Result<(), Error> {
        // Source OFDM order: spur, firstep, weak detection; CCK only
        // changes firstep and (on multichain9462) MRC. Unchanged fields,
        // including skipped9462/9565 weak thresholds, are not rewritten.
        for index in [5, 6, 3, 4, 1, 0, 2, 7] {
            let word = self.0[index];
            let old = previous.0[index];
            let (r, mask) = FIELDS[index];
            if word == old || word == u32::MAX {
                continue;
            }
            // USE_SELF_CORR_LOW is committed after all weak thresholds.
            let mask = if index == 1 { mask & !1 } else { mask };
            if (word ^ old) & mask == 0 {
                continue;
            }
            let value = (io.read(r)? & !mask) | (word & mask);
            io.write(r, value)?;
            if io.read(r)? != value {
                return Err(Error::Descriptor);
            }
        }
        if self.0[1] & 1 != previous.0[1] & 1 {
            let value = (io.read(0x9828)? & !1) | (self.0[1] & 1);
            io.write(0x9828, value)?;
            if io.read(0x9828)? != value {
                return Err(Error::Descriptor);
            }
        }
        self.readback(io)
    }
    fn firstep(&mut self, level: u8, ini: Self) {
        // firstep_table[level] - firstep_table[2] == 2*level-4.
        let delta = i32::from(level) * 2 - 4;
        self.0[3] = (((ini.0[3] >> 12) as i32 + delta).clamp(0, 20) as u32) << 12;
        self.0[4] = (((ini.0[4] >> 6) as i32 + delta).clamp(0, 20) as u32) << 6;
    }
    fn spur(&mut self, level: u8, ini: Self) {
        let delta = i32::from(level) * 2 - 6;
        self.0[5] = (((ini.0[5] >> 1) as i32 + delta).clamp(0, 22) as u32) << 1;
        self.0[6] = (((ini.0[6] >> 9) as i32 + delta).clamp(0, 22) as u32) << 9;
    }
    fn weak(&mut self, on: bool, ini: Self, device: u16) {
        // ar9003_hw_ani_control skips threshold writes on9462/9565.
        if device == 0x0032 {
            if on {
                self.0[..3].copy_from_slice(&ini.0[..3]);
            } else {
                self.0[0] = (127 << 17) | (127 << 24) | 31;
                self.0[1] = (127 << 14) | (127 << 21) | (63 << 8);
                self.0[2] = 127 | (127 << 7) | (127 << 14) | (127 << 21);
            }
        }
        self.0[1] = (self.0[1] & !1) | u32::from(on);
    }
}
#[derive(Clone, Copy)]
struct Levels {
    ofdm: u8,
    cck: u8,
    spur: u8,
    firstep: u8,
    weak: bool,
    mrc: bool,
    ofdm_turn: bool,
}
pub(in crate::ath9k) struct Owner {
    ini: Settings,
    current: Settings,
    levels: Levels,
    device: u16,
    rx_chainmask: u8,
    listen_ms: u64,
    ofdm_errors: u32,
    cck_errors: u32,
    mib: [u64; 5],
    rssi: BeaconRssi,
    next_ms: u64,
}
impl Owner {
    pub(in crate::ath9k) fn begin(
        io: &impl Io,
        device: u16,
        rx_chainmask: u8,
        ini: Settings,
    ) -> Result<Self, Error> {
        if !matches!(device, 0x0032 | 0x0034 | 0x0036) || ini.0[1] & 1 == 0 {
            return Err(Error::State);
        }
        if ini.0[3] >> 12 > 20 || ini.0[4] >> 6 > 20 || ini.0[5] >> 1 > 22 || ini.0[6] >> 9 > 22 {
            return Err(Error::Descriptor);
        }
        ini.readback(io)?;
        let mut owner = Self {
            ini,
            current: ini,
            device,
            rx_chainmask,
            levels: Levels {
                ofdm: 3,
                cck: 2,
                spur: 3,
                firstep: 2,
                weak: true,
                mrc: true,
                ofdm_turn: true,
            },
            listen_ms: 0,
            ofdm_errors: 0,
            cck_errors: 0,
            mib: [0; 5],
            rssi: BeaconRssi::new(),
            next_ms: io.now_us() / 1000 + 1000,
        };
        owner.mib(io)?;
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
    pub(in crate::ath9k) fn settings(&self) -> Settings {
        self.current
    }
    pub(in crate::ath9k) fn beacon(&mut self, rssi: i8) {
        self.rssi.beacon(rssi);
    }
    pub(in crate::ath9k) fn epoch(&mut self) {
        self.rssi = BeaconRssi::new();
    }
    fn mib(&mut self, io: &impl Io) -> Result<(), Error> {
        for (total, r) in self
            .mib
            .iter_mut()
            .zip([0x8088, 0x808c, 0x8090, 0x8094, 0x8098])
        {
            *total = total.saturating_add(u64::from(io.read(r)?));
        }
        Ok(())
    }
    fn restart(&mut self, io: &impl Io) -> Result<(), Error> {
        for (r, v) in [
            (0x812c, 0),
            (0x8134, 0),
            (0x8130, 0x20000),
            (0x8138, 0x2000000),
        ] {
            io.write(r, v)?;
        }
        if io.read(0x8130)? != 0x20000 || io.read(0x8138)? != 0x2000000 {
            return Err(Error::Descriptor);
        }
        self.mib(io)?;
        self.listen_ms = 0;
        self.ofdm_errors = 0;
        self.cck_errors = 0;
        Ok(())
    }
    fn cycles(&self, io: &impl Io) -> Result<[u32; 4], Error> {
        io.write(0x40, 2)?;
        if io.read(0x40)? & 15 != 2 {
            return Err(Error::Descriptor);
        }
        let mut values = [0; 4];
        for (value, r) in values.iter_mut().zip([0x80f8, 0x80f4, 0x80f0, 0x80ec]) {
            *value = io.read(r)?;
        }
        // Source clear order CCCNT,RFCNT,RCCNT,TFCNT, while frozen.
        for r in [0x80f8, 0x80f0, 0x80f4, 0x80ec] {
            io.write(r, 0)?;
            if io.read(r)? != 0 {
                return Err(Error::Descriptor);
            }
        }
        io.write(0x40, 0)?;
        if io.read(0x40)? & 15 != 0 {
            return Err(Error::Descriptor);
        }
        Ok(values)
    }
    fn ofdm(&self, l: &mut Levels, s: &mut Settings, level: u8, rssi: u8) {
        l.ofdm = level;
        let (spur, step, weak) = OFDM[usize::from(level)];
        if l.spur != spur {
            s.spur(spur, self.ini);
            l.spur = spur;
        }
        if l.firstep != step && step >= l.cck {
            s.firstep(step, self.ini);
            l.firstep = step;
        }
        // AR9003 does not take the old >=8 weak-detector override.
        let weak = weak || rssi <= 40;
        if l.weak != weak {
            s.weak(weak, self.ini, self.device);
            l.weak = weak;
        }
    }
    fn cck(&self, l: &mut Levels, s: &mut Settings, level: u8, rssi: u8) {
        let level = if rssi <= 7 { level.min(6) } else { level };
        l.cck = level;
        if l.firstep != level && level >= OFDM[usize::from(l.ofdm)].1 {
            s.firstep(level, self.ini);
            l.firstep = level;
        }
        let mrc = level < 4;
        if self.device == 0x0034 && self.rx_chainmask != 1 && l.mrc != mrc {
            s.0[7] = if mrc { 3 } else { 0 };
            l.mrc = mrc;
        }
    }
    pub(in crate::ath9k) fn service(&mut self, io: &impl Io) -> Result<(), Error> {
        self.current.readback(io)?;
        let now = io.now_us() / 1000;
        if now < self.next_ms {
            return Ok(());
        }
        self.next_ms = now.checked_add(1000).ok_or(Error::State)?;
        let [cycles, _, rx, tx] = self.cycles(io)?;
        // Native full-rate20MHz uses source OFDM2g/Fast5g clock44.
        let listen = (i64::from(cycles) - i64::from(rx) - i64::from(tx)) / 44_000;
        if listen <= 0 {
            return self.restart(io);
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
            return Ok(());
        }
        let ofdm_rate = u64::from(ofdm) * 1000 / self.listen_ms;
        let cck_rate = u64::from(cck) * 1000 / self.listen_ms;
        let mut l = self.levels;
        let mut s = self.current;
        let rssi = self.rssi.value().unwrap_or(0);
        // At >=INI OFDM level the dynamic low threshold is900; below it
        // the source uses high1000/low400. Initial post-reset is>=INI.
        let (high, low) = if l.ofdm >= 3 {
            (3500, 900)
        } else {
            (1000, 400)
        };
        if cck_rate < 300 && ofdm_rate < low {
            if l.ofdm > 0 && (l.ofdm_turn || l.cck == 0) {
                let n = l.ofdm - 1;
                self.ofdm(&mut l, &mut s, n, rssi);
            } else if l.cck > 0 {
                let n = l.cck - 1;
                self.cck(&mut l, &mut s, n, rssi);
            }
            l.ofdm_turn = !l.ofdm_turn;
        } else if ofdm_rate > high {
            if l.ofdm < 9 {
                let n = l.ofdm + 1;
                self.ofdm(&mut l, &mut s, n, rssi);
            }
            l.ofdm_turn = false;
        } else if cck_rate > 600 {
            if l.cck < 8 {
                let n = l.cck + 1;
                self.cck(&mut l, &mut s, n, rssi);
            }
            l.ofdm_turn = true;
        } else {
            return Ok(());
        }
        s.write(io, self.current)?;
        self.restart(io)?;
        self.current = s;
        self.levels = l;
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "ani/tests.rs"]
mod tests;
