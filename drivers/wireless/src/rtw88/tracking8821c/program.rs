// SPDX-License-Identifier: GPL-2.0-or-later
use super::super::{dma_stop, packet_format::DataProfile, station_control::Admission};
use super::*;
const OFDM_N: [u8; 30] = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7, 8, 8, 9,
];
const OFDM_P: [u8; 30] = [
    0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 9,
];
const CCK_N: [u8; 30] = [
    0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9,
];
const CCK_P: [u8; 30] = [
    0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 9, 9, 9,
];

pub(super) fn bind(h: &mut narf_crypto::sha256::Sha256) {
    h.update(b"intersect current original H/R/T/RTS signed ceiling before all W operations");
    for table in [OFDM_N, OFDM_P, CCK_N, CCK_P] {
        h.update(&table);
    }
    for word in [
        2000u32,
        29,
        15,
        10,
        36,
        8,
        300,
        20_000,
        1000,
        10,
        13,
        0xc94,
        0x7e,
        0xc1c,
        0xffe00000,
        0x42,
        0x30000,
        0xfc00,
        0x284,
        1 << 18,
        1 << 17,
        0x522,
        255,
        0x1bf0,
        0x100ff,
        0xabcde,
    ] {
        h.update(&word.to_le_bytes());
    }
}

/// Linux's AGC split, narrowed across every programmed native TX/response
/// rate because the hardware offset is global. This never infers RF dBm.
fn select(g: &Grant, delta: i8) -> Result<Program, Error> {
    let limits = g.base.tracking_factory_limits().ok_or(Error::State)?;
    let legacy = g.base.c21_indices().ok_or(Error::State)?;
    let mcs = g.base.ht_grant().ok_or(Error::State)?.tracking_indices();
    let mut upper = 15i16;
    let mut lower = -15i16;
    for (i, index) in legacy.into_iter().chain(mcs).enumerate() {
        let maximum = limits[if i < 4 {
            0
        } else if i < 12 {
            1
        } else {
            2
        }];
        if index > maximum {
            return Err(Error::Prerequisite);
        }
        upper = upper.min(i16::from(maximum - index));
        lower = lower.max(-i16::from(index));
    }
    let delta = i16::from(delta);
    let agc = delta.clamp(lower, upper);
    let swing = (i16::from(g.initial) + delta - agc).clamp(0, (i16::from(g.initial) + 10).min(36));
    let p = Program {
        agc: agc as i8,
        swing: swing as u8,
    };
    if !g.permits(p) {
        return Err(Error::Prerequisite);
    }
    Ok(p)
}
fn read(io: &mut impl Io, r: u16) -> Result<u32, Error> {
    match io.read32(r)? {
        u32::MAX => Err(Error::Gone),
        v => Ok(v),
    }
}
fn mask(io: &mut impl Io, r: u16, bits: u32, value: u32) -> Result<(), Error> {
    let old = read(io, r)?;
    io.write32(r, (old & !bits) | (value << bits.trailing_zeros()))
}
fn rf_read(io: &mut impl Io, r: u8) -> Result<u32, Error> {
    Ok(read(io, 0x2800 + u16::from(r) * 4)? & 0xfffff)
}
struct Attempt {
    admission: Admission,
    armed: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.armed {
            self.admission.close();
        }
    }
}

pub(in crate::rtw88) struct Tracker {
    grant: Arc<Grant>,
    next: u64,
    triggered: Option<u64>,
    ewma: u64,
    thermal_k: u8,
    last_delta: Option<i8>,
    rate: Option<u8>,
    iqk_changed: bool,
}
impl Tracker {
    pub(in crate::rtw88) fn new(grant: Arc<Grant>) -> Self {
        Self {
            thermal_k: grant.thermal,
            grant,
            next: 0,
            triggered: None,
            ewma: 0,
            last_delta: None,
            rate: None,
            iqk_changed: false,
        }
    }
    pub(in crate::rtw88) fn c2h(&mut self, body: &[u8]) {
        if body.len() >= 9 && body[0] == 0x0c && body[3] == 0 && body[2] & 0x7f < 20 {
            self.rate = Some(body[2] & 0x7f);
        }
    }
    pub(in crate::rtw88) fn grant(&self) -> Arc<Grant> {
        self.grant.clone()
    }
    /// Return true after an actual program/calibration commit; normal quiet
    /// deferral retains the pending sample and never allocates DATA/PN.
    pub(in crate::rtw88) async fn tick(
        &mut self,
        io: &mut impl Io,
        a: &Admission,
        now: u64,
        profile: DataProfile,
    ) -> Result<bool, Error> {
        let g = self.grant.clone();
        // Revoke is checked before the timer or ordinary DM/Q/C/F downgrade.
        if g.authority(|| Ok(())).is_err() {
            return self.restore(io, a).await;
        }
        if now < self.next {
            return Ok(false);
        }
        if self.triggered.is_none() {
            a.run(|| {
                g.authority(|| {
                    let old = rf_read(io, 0x42)?;
                    io.write32(0xc90, 0x42 << 20 | (old & !0x30000) | 0x30000)
                })
            })?;
            io.delay_us(13).await;
            a.check()?;
            self.triggered = Some(now);
            self.next = now.saturating_add(2000);
            return Ok(false);
        }
        if now.saturating_sub(self.triggered.ok_or(Error::State)?) < 2000 {
            return Ok(false);
        }
        let raw = a.run(|| g.authority(|| Ok(((rf_read(io, 0x42)? >> 10) & 63) as u8)))?;
        if g.temperature(raw).is_err() {
            return self.restore(io, a).await;
        }
        let ewma = if self.ewma == 0 {
            u64::from(raw) << 10
        } else {
            (self.ewma * 3 + (u64::from(raw) << 10)) >> 2
        };
        let avg = (ewma >> 10) as u8;
        let distance = usize::from(avg.abs_diff(g.thermal).min(29));
        // Fallback uses a real native C2H RA report; no guessed C22/default
        // rate grants the C21 table selection.
        let rate = if profile.fallback {
            match self.rate {
                Some(r) => r,
                None => return Ok(false),
            }
        } else {
            profile.rate()
        };
        let cck = rate <= 3;
        let table = if avg > g.thermal {
            if cck {
                CCK_P
            } else {
                OFDM_P
            }
        } else if cck {
            CCK_N
        } else {
            OFDM_N
        };
        let mut delta = table[distance] as i8;
        if avg <= g.thermal {
            delta = -delta;
        }
        let iqk = avg.abs_diff(self.thermal_k) >= 8;
        // Source initially programs even delta0; later unchanged delta still
        // checks periodic IQK. No sample is consumed on a quiet deferral.
        if self.last_delta == Some(delta) && !iqk {
            self.ewma = ewma;
            self.triggered = None;
            self.next = now.saturating_add(2000);
            return Ok(false);
        }
        let p = match select(&g, delta) {
            Ok(p) => p,
            Err(_) => return self.restore(io, a).await,
        };
        let entered = a.run(|| io.station_power_tracking_begin(&g, false))?;
        if !entered {
            return Ok(false);
        }
        let mut attempt = Attempt {
            admission: a.clone(),
            armed: true,
        };
        a.retire_receive()?;
        Self::park(io, &g, a).await?;
        a.run(|| {
            g.authority(|| {
                mask(io, 0xc94, 0x7e, u32::from(p.agc as u8 & 63))?;
                mask(
                    io,
                    0xc1c,
                    0xffe00000,
                    u32::from(SCALE[usize::from(p.swing)]),
                )?;
                Grant::read_program(p, &mut |r| read(io, r))
            })
        })?;
        if iqk {
            Self::iqk(io, &g, a).await?;
            self.iqk_changed = true;
        }
        a.run(|| g.authority(|| io.station_power_tracking_finish(Some(p))))?;
        a.retire_receive()?;
        attempt.armed = false;
        self.ewma = ewma;
        self.last_delta = Some(delta);
        if iqk {
            self.thermal_k = avg;
        }
        self.triggered = None;
        self.next = now.saturating_add(2000);
        Ok(true)
    }
    async fn park(io: &mut impl Io, g: &Grant, a: &Admission) -> Result<(), Error> {
        a.run(|| {
            g.authority(|| {
                if read(io, dma_stop::RXPKT_NUM)? & dma_stop::RW_RELEASE != 0
                    || io.read8(0x522)? != 0
                {
                    return Err(Error::Prerequisite);
                }
                io.write8(0x522, 255)?;
                let rx = read(io, dma_stop::RXPKT_NUM)?;
                io.write32(dma_stop::RXPKT_NUM, rx | dma_stop::RW_RELEASE)
            })
        })?;
        for _ in 0..1000 {
            let idle = a.run(|| {
                g.authority(|| Ok(read(io, dma_stop::RXPKT_NUM)? & dma_stop::RXDMA_IDLE != 0))
            })?;
            if idle {
                if !a.run(|| g.authority(|| io.station_power_tracking_quiet()))? {
                    return Err(Error::Prerequisite);
                }
                return Ok(());
            }
            io.delay_us(10).await;
        }
        Err(Error::Timeout)
    }
    async fn iqk(io: &mut impl Io, g: &Grant, a: &Admission) -> Result<(), Error> {
        // A stale completion cannot acknowledge this new command.
        a.run(|| {
            g.authority(|| {
                if rf_read(io, 8)? != 0 {
                    return Err(Error::Prerequisite);
                }
                io.station_power_tracking_iqk()
            })
        })?;
        let mut consumed = false;
        for _ in 0..1000 {
            if a.run(|| g.authority(|| io.poll_h2c()))? {
                consumed = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !consumed {
            return Err(Error::Timeout);
        }
        let mut applied = false;
        for _ in 0..300 {
            if a.run(|| g.authority(|| Ok(rf_read(io, 8)? == 0xabcde)))? {
                applied = true;
                break;
            }
            io.delay_us(20_000).await;
        }
        if !applied {
            return Err(Error::Timeout);
        }
        a.run(|| {
            g.authority(|| {
                if read(io, 0x1bf0)? & 0x100ff == 0 {
                    Ok(())
                } else {
                    Err(Error::Prerequisite)
                }
            })
        })?;
        // Reset the actual source completion only after its failure/reload
        // bits were checked. Any cancelled/failed IQK remains terminal.
        a.run(|| g.authority(|| io.write32(0xc90, 8 << 20)))?;
        io.delay_us(13).await;
        a.run(|| {
            g.authority(|| {
                if rf_read(io, 8)? == 0 {
                    Ok(())
                } else {
                    Err(Error::Prerequisite)
                }
            })
        })
    }
    async fn restore(&mut self, io: &mut impl Io, a: &Admission) -> Result<bool, Error> {
        // Firmware owns the periodic-IQK coefficient image. No source receipt
        // proves that simply clearing power offsets restores startup IQK.
        if self.iqk_changed {
            return Err(Error::Prerequisite);
        }
        let g = self.grant.clone();
        if !a.run(|| io.station_power_tracking_begin(&g, true))? {
            return Ok(false);
        }
        let mut attempt = Attempt {
            admission: a.clone(),
            armed: true,
        };
        a.retire_receive()?;
        // Original measured static gate, never the revoked W, authorizes
        // restoration. No command has been sent in this continuation.
        let base = g.base.clone();
        a.run(|| {
            base.invoke_base(|| {
                io.write8(0x522, 255)?;
                let rx = read(io, dma_stop::RXPKT_NUM)?;
                io.write32(dma_stop::RXPKT_NUM, rx | dma_stop::RW_RELEASE)
            })
        })?;
        let mut idle = false;
        for _ in 0..1000 {
            if a.run(|| {
                base.invoke_base(|| Ok(read(io, dma_stop::RXPKT_NUM)? & dma_stop::RXDMA_IDLE != 0))
            })? {
                idle = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !idle || !a.run(|| base.invoke_base(|| io.station_power_tracking_quiet()))? {
            return Err(Error::Timeout);
        }
        a.run(|| {
            base.invoke_base(|| {
                mask(io, 0xc94, 0x7e, 0)?;
                mask(
                    io,
                    0xc1c,
                    0xffe00000,
                    u32::from(SCALE[usize::from(g.initial)]),
                )?;
                io.station_power_tracking_finish(None)
            })
        })?;
        a.retire_receive()?;
        attempt.armed = false;
        Ok(true)
    }
}
