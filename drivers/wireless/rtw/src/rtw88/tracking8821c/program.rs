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

/// The MCS indices the AGC split narrows across: the bound N2xB HT40
/// record's one-stream MCS0..7 at BW40 when a 40MHz association is bound
/// (the indices `ht40::write_power` commits to 0x1d0c for C21), else the
/// HT grant's HT20 tracking indices. Pure over its inputs so the rule is
/// unit-testable without a Gate.
pub(in crate::rtw88) fn mcs_indices(
    ht40: Option<&crate::rtw88::ht40::Record>,
    ht: &[u8; 8],
) -> [u8; 8] {
    match ht40 {
        Some(r) => r.indices[..8].try_into().expect("HT40 one-stream MCS0..7"),
        None => *ht,
    }
}

/// Linux's AGC split, narrowed across every programmed native TX/response
/// rate because the hardware offset is global. This never infers RF dBm.
fn select(g: &Grant, delta: i8) -> Result<Program, Error> {
    let limits = g.base.tracking_factory_limits().ok_or(Error::State)?;
    let legacy = g.base.c21_indices().ok_or(Error::State)?;
    let ht = g.base.ht_grant().ok_or(Error::State)?;
    let mcs = mcs_indices(g.base.ht40_record().as_ref(), &ht.tracking_indices());
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
async fn read(io: &mut impl Io, r: u16) -> Result<u32, Error> {
    match io.read32(r).await? {
        u32::MAX => Err(Error::Gone),
        v => Ok(v),
    }
}
async fn mask(io: &mut impl Io, r: u16, bits: u32, value: u32) -> Result<(), Error> {
    let old = read(io, r).await?;
    io.write32(r, (old & !bits) | (value << bits.trailing_zeros()))
        .await
}
async fn rf_read(io: &mut impl Io, r: u8) -> Result<u32, Error> {
    Ok(read(io, 0x2800 + u16::from(r) * 4).await? & 0xfffff)
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
            crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
                crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                    let old = rf_read(io, 0x42).await?;
                    io.write32(0xc90, 0x42 << 20 | (old & !0x30000) | 0x30000)
                        .await
                })
                .await
            })
            .await?;
            io.delay_us(13).await;
            a.check()?;
            self.triggered = Some(now);
            self.next = now.saturating_add(2000);
            return Ok(false);
        }
        if now.saturating_sub(self.triggered.ok_or(Error::State)?) < 2000 {
            return Ok(false);
        }
        let raw =
            crate::rtw88::firmware_transport::enclosed(|op| a.run(|| g.authority(op)), async {
                Ok(((rf_read(io, 0x42).await? >> 10) & 63) as u8)
            })
            .await?;
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
        let entered = crate::rtw88::firmware_transport::enclosed(
            |op| a.run(op),
            io.station_power_tracking_begin(&g, false),
        )
        .await?;
        if !entered {
            return Ok(false);
        }
        let mut attempt = Attempt {
            admission: a.clone(),
            armed: true,
        };
        a.retire_receive()?;
        Self::park(io, &g, a).await?;
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                mask(io, 0xc94, 0x7e, u32::from(p.agc as u8 & 63)).await?;
                mask(
                    io,
                    0xc1c,
                    0xffe00000,
                    u32::from(SCALE[usize::from(p.swing)]),
                )
                .await?;
                Grant::read_program(p, &mut super::super::firmware_transport::RadioRead32(io)).await
            })
            .await
        })
        .await?;
        if iqk {
            Self::iqk(io, &g, a).await?;
            self.iqk_changed = true;
        }
        crate::rtw88::firmware_transport::enclosed(
            |op| a.run(|| g.authority(op)),
            io.station_power_tracking_finish(Some(p)),
        )
        .await?;
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
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                if read(io, dma_stop::RXPKT_NUM).await? & dma_stop::RW_RELEASE != 0
                    || io.read8(0x522).await? != 0
                {
                    return Err(Error::Prerequisite);
                }
                io.write8(0x522, 255).await?;
                let rx = read(io, dma_stop::RXPKT_NUM).await?;
                io.write32(dma_stop::RXPKT_NUM, rx | dma_stop::RW_RELEASE)
                    .await
            })
            .await
        })
        .await?;
        for _ in 0..1000 {
            let idle = crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
                crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                    Ok(read(io, dma_stop::RXPKT_NUM).await? & dma_stop::RXDMA_IDLE != 0)
                })
                .await
            })
            .await?;
            if idle {
                if !crate::rtw88::firmware_transport::enclosed(
                    |op| a.run(|| g.authority(op)),
                    io.station_power_tracking_quiet(),
                )
                .await?
                {
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
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                if rf_read(io, 8).await? != 0 {
                    return Err(Error::Prerequisite);
                }
                io.station_power_tracking_iqk().await
            })
            .await
        })
        .await?;
        let mut consumed = false;
        for _ in 0..1000 {
            if crate::rtw88::firmware_transport::enclosed(
                |op| a.run(|| g.authority(op)),
                io.poll_h2c(),
            )
            .await?
            {
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
            if crate::rtw88::firmware_transport::enclosed(|op| a.run(|| g.authority(op)), async {
                Ok(rf_read(io, 8).await? == 0xabcde)
            })
            .await?
            {
                applied = true;
                break;
            }
            io.delay_us(20_000).await;
        }
        if !applied {
            return Err(Error::Timeout);
        }
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                if read(io, 0x1bf0).await? & 0x100ff == 0 {
                    Ok(())
                } else {
                    Err(Error::Prerequisite)
                }
            })
            .await
        })
        .await?;
        // Reset the actual source completion only after its failure/reload
        // bits were checked. Any cancelled/failed IQK remains terminal.
        crate::rtw88::firmware_transport::enclosed(
            |op| a.run(|| g.authority(op)),
            io.write32(0xc90, 8 << 20),
        )
        .await?;
        io.delay_us(13).await;
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| g.authority(op), async {
                if rf_read(io, 8).await? == 0 {
                    Ok(())
                } else {
                    Err(Error::Prerequisite)
                }
            })
            .await
        })
        .await
    }
    async fn restore(&mut self, io: &mut impl Io, a: &Admission) -> Result<bool, Error> {
        // Firmware owns the periodic-IQK coefficient image. No source receipt
        // proves that simply clearing power offsets restores startup IQK.
        if self.iqk_changed {
            return Err(Error::Prerequisite);
        }
        let g = self.grant.clone();
        if !crate::rtw88::firmware_transport::enclosed(
            |op| a.run(op),
            io.station_power_tracking_begin(&g, true),
        )
        .await?
        {
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
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| base.invoke_base(op), async {
                io.write8(0x522, 255).await?;
                let rx = read(io, dma_stop::RXPKT_NUM).await?;
                io.write32(dma_stop::RXPKT_NUM, rx | dma_stop::RW_RELEASE)
                    .await
            })
            .await
        })
        .await?;
        let mut idle = false;
        for _ in 0..1000 {
            if crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
                crate::rtw88::firmware_transport::enclosed(|op| base.invoke_base(op), async {
                    Ok(read(io, dma_stop::RXPKT_NUM).await? & dma_stop::RXDMA_IDLE != 0)
                })
                .await
            })
            .await?
            {
                idle = true;
                break;
            }
            io.delay_us(10).await;
        }
        if !idle
            || !crate::rtw88::firmware_transport::enclosed(
                |op| a.run(|| base.invoke_base(op)),
                io.station_power_tracking_quiet(),
            )
            .await?
        {
            return Err(Error::Timeout);
        }
        crate::rtw88::firmware_transport::enclosed(|op| a.run(op), async {
            crate::rtw88::firmware_transport::enclosed(|op| base.invoke_base(op), async {
                mask(io, 0xc94, 0x7e, 0).await?;
                mask(
                    io,
                    0xc1c,
                    0xffe00000,
                    u32::from(SCALE[usize::from(g.initial)]),
                )
                .await?;
                io.station_power_tracking_finish(None).await
            })
            .await
        })
        .await?;
        a.retire_receive()?;
        attempt.armed = false;
        Ok(true)
    }
}
