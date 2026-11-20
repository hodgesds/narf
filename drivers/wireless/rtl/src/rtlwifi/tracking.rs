// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2009-2013 Realtek Corporation.
//! Separately signed EE TXAGC thermal continuation. No board samples supplied.
//! Linux rtl8188ee/dm.c uses TXAGC, not the alternative BBSWING method.
use super::{
    channel_power::{Calibration, Permission},
    firmware_transport::{Identity, Io},
    ht,
    prepare::Error,
    protection,
};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const HEADER: usize = 256;
const LENGTH: usize = HEADER + 64 * 10 * 128;
const UNKNOWN: i16 = i16::MAX;
const PERIOD_MS: u64 = 2000; // RTL_WATCHDOG_TIME.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
fn geometry(channel: u8, ht: Option<&ht::Grant>) -> [u8; 6] {
    ht.and_then(ht::Grant::geometry)
        .map_or([channel, 20, 1, 1, 0, channel], |g| {
            [channel, 40, 1, 1, g.secondary(), g.center()]
        })
}
pub(super) fn request(
    base: &Calibration,
    firmware: Identity,
    channel: u8,
    ht: Option<&ht::Grant>,
    protection: Option<&protection::Grant>,
) -> Request {
    let f = base.factory();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8188EE NETH1 thermal full-program TXAGC continuation");
    hash.update(&super::radio::factory_identity(f));
    hash.update(&base.digest);
    hash.update(&firmware.digest);
    hash.update(&geometry(channel, ht));
    hash.update(&ht.map_or([0; 32], ht::Grant::measurement_digest));
    hash.update(&protection.map_or([0; 32], protection::Grant::measurement_digest));
    hash.update(&[f.logical[0xba]]);
    hash.update(b"Linux7.2 rtl8188ee dm.c: watchdog2000ms alternating RF42[17:16]=3/read[15:10], nonzero average4, exact EFUSEba1..63 no erased default; delta_swing_table_idx/thermal_threshold, retained CCK1_13 original a24[0..3] index; rf.c CCK and OFDM both type1 CCK TXAGC offset, signed component arithmetic no cross-byte carry/wrap, clamp to original qualified per-rate program, no scan turbo or BBSWING; IQK/LCK average drift>=8 actual calibrated readback+restore; idle full SCH_TX_CMD, pauseff MAC TXRX0 during gain/IQK/LCK, preserve RF18/RF0 width/security/DMA OWN; every original and new current capability encloses every poll and publication; full raw thermal0..63 x CCK/OFDM/MCS0..7 x gain0..63 conducted upper bounds covering all supply/static antenna, SGI20 HT20/40 fallback, all preceding response/retry/protection/BA and IQK/LCK emissions and all intermediate thermal/averaging/gain/calibration states; all64 temperatures must be known at every admitted index, no interpolation or sample-gap RF authority, unknown refuses; external board measurements required");
    let g = geometry(channel, ht);
    Request {
        name: format!(
            "rtlwifi/rtl8188ee-thermal-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}-h{}-r{}.bin",
            f.mac[0],
            f.mac[1],
            f.mac[2],
            f.mac[3],
            f.mac[4],
            f.mac[5],
            channel,
            g[4],
            if ht.is_none() {
                0
            } else if g[1] == 40 {
                4
            } else if channel == 1 {
                2
            } else {
                3
            },
            u8::from(protection.is_some()),
        ),
        binding: hash.finalize(),
    }
}
/// The thermal continuation may reduce and restore these actual indices,
/// never exceed the original current measured/factory program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Gains {
    pub cck: [u8; 4],
    pub ofdm: [u8; 8],
    pub mcs: [u8; 8],
}
impl Gains {
    pub(super) fn nominal(
        ht: Option<&ht::Grant>,
        domain: &RegulatoryDomain,
        permission: Permission,
    ) -> Result<Self, Error> {
        let (cck, ofdm) = permission.gains();
        Ok(Self {
            cck,
            ofdm,
            mcs: ht
                .map(|h| h.gains(domain, permission))
                .transpose()?
                .unwrap_or([0; 8]),
        })
    }
    fn reduce(self, delta: u8) -> Self {
        Self {
            cck: self.cck.map(|g| g.saturating_sub(delta)),
            ofdm: self.ofdm.map(|g| g.saturating_sub(delta)),
            mcs: self.mcs.map(|g| g.saturating_sub(delta)),
        }
    }
}
pub(crate) struct Grant {
    base: Arc<Calibration>,
    ht: Option<Arc<ht::Grant>>,
    protection: Option<Arc<protection::Grant>>,
    firmware: Identity,
    cap: Cap<FirmwareBlob, Read>,
    channel: u8,
    antenna: i16,
    ceiling: i16,
    // Column maxima over all64 signed thermal rows. Unknown in ANY row
    // keeps that index unknown, including between watchdog observations.
    worst: [[i16; 64]; 10],
    measurement: [u8; 32],
}
impl Grant {
    pub(super) fn measurement_digest(&self) -> [u8; 32] {
        self.measurement
    }
    pub(super) fn program_limits(&self) -> (i16, i16) {
        (self.ceiling, self.antenna)
    }
    pub(super) fn registered(
        base: Arc<Calibration>,
        firmware: Identity,
        channel: u8,
        ht: Option<Arc<ht::Grant>>,
        protection: Option<Arc<protection::Grant>>,
    ) -> Result<Option<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source = match crate::firmware_asset::load(
            &authority,
            &request(
                &base,
                firmware,
                channel,
                ht.as_deref(),
                protection.as_deref(),
            )
            .name,
            LENGTH,
            true,
        ) {
            Ok(s) => s,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Power(super::channel_power::Error::Firmware(e))),
        };
        Self::parse(
            base,
            firmware,
            channel,
            ht,
            protection,
            &source.bytes,
            source.signer,
            source.cap,
        )
        .map(|q| Some(Arc::new(q)))
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn parse(
        base: Arc<Calibration>,
        firmware: Identity,
        channel: u8,
        ht: Option<Arc<ht::Grant>>,
        protection: Option<Arc<protection::Grant>>,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        let bad = || Error::Power(super::channel_power::Error::Format);
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        let f = base.factory();
        if !(1..=63).contains(&f.logical[0xba])
            || !(1..=11).contains(&channel)
            || b.len() != LENGTH
            || b[..4] != *b"NETH"
            || b[4..8] != [1, 0, 0, 1]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48]
                != request(
                    &base,
                    firmware,
                    channel,
                    ht.as_deref(),
                    protection.as_deref(),
                )
                .binding
            || b[48..80] != super::radio::factory_identity(f)
            || b[80..112] != base.digest
            || b[112..118] != f.mac
            || b[118..124] != geometry(channel, ht.as_deref())
            || b[128..160] != ht.as_ref().map_or([0; 32], |q| q.measurement_digest())
            || b[160..192]
                != protection
                    .as_ref()
                    .map_or([0; 32], |q| q.measurement_digest())
            || b[192..196] != [f.logical[0xba], 64, 10, 64]
            || b[196..HEADER] != [0; 60]
            || ht.as_ref().is_some_and(|q| !q.matches(&base))
            || protection
                .as_ref()
                .is_some_and(|q| !q.matches(&base, ht.as_ref(), channel))
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(b[124..126].try_into().unwrap());
        let ceiling = i16::from_le_bytes(b[126..128].try_into().unwrap());
        let minimum_antenna = base
            .antenna()
            .max(ht.as_ref().map_or(0, |q| q.program_limits().1))
            .max(protection.as_ref().map_or(0, |q| q.program_limits().1));
        if !(minimum_antenna..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(bad());
        }
        let mut worst = [[-512; 64]; 10];
        for thermal in b[HEADER..].chunks_exact(10 * 128) {
            for (row, peaks) in thermal.chunks_exact(128).zip(&mut worst) {
                for (bytes, peak) in row.chunks_exact(2).zip(peaks) {
                    let value = i16::from_le_bytes(bytes.try_into().unwrap());
                    if value != UNKNOWN && !(-512..=256).contains(&value) {
                        return Err(bad());
                    }
                    *peak = (*peak).max(value);
                }
            }
        }
        let q = Self {
            base,
            ht,
            protection,
            firmware,
            cap,
            channel,
            antenna,
            ceiling,
            worst,
            measurement: {
                let mut hash = narf_crypto::sha256::Sha256::new();
                hash.update(b);
                hash.finalize()
            },
        };
        q.invoke(|| Ok(()))?;
        Ok(q)
    }
    pub(super) fn matches(
        &self,
        base: &Arc<Calibration>,
        ht: Option<&Arc<ht::Grant>>,
        protection: Option<&Arc<protection::Grant>>,
        channel: u8,
    ) -> bool {
        self.channel == channel
            && Arc::ptr_eq(&self.base, base)
            && self.ht.as_ref().map(Arc::as_ptr) == ht.map(Arc::as_ptr)
            && self.protection.as_ref().map(Arc::as_ptr) == protection.map(Arc::as_ptr)
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        let current = || {
            self.cap
                .invoke(Live(operation))
                .map_err(|_| Error::Power(super::channel_power::Error::Authority))?
        };
        self.firmware.invoke(|| {
            if let Some(protection) = &self.protection {
                protection.invoke(current)
            } else if let Some(ht) = &self.ht {
                ht.invoke(current)
            } else {
                self.base.with_current(current)
            }
        })
    }
    pub(super) fn check_sources(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
    ) -> Result<(), Error> {
        let gains = Gains::nominal(self.ht.as_deref(), domain, permission)?;
        self.check(domain, permission, gains)
    }
    pub(super) fn check(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
        actual: Gains,
    ) -> Result<(), Error> {
        self.check_extension(domain, permission, actual, self.ceiling, self.antenna)
    }
    pub(super) fn check_extension(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
        actual: Gains,
        extension_limit: i16,
        extension_antenna: i16,
    ) -> Result<(), Error> {
        self.invoke(|| {
            let antenna = self.antenna.max(extension_antenna);
            if self
                .base
                .permission(domain, self.channel)
                .map_err(Error::Power)?
                != permission
            {
                return Err(Error::State);
            }
            let nominal = Gains::nominal(self.ht.as_deref(), domain, permission)?;
            if actual.cck.iter().zip(nominal.cck).any(|(g, n)| *g > n)
                || actual.ofdm.iter().zip(nominal.ofdm).any(|(g, n)| *g > n)
                || actual.mcs.iter().zip(nominal.mcs).any(|(g, n)| *g > n)
            {
                return Err(Error::Power(super::channel_power::Error::FactoryPower));
            }
            let full_span = self
                .ht
                .as_ref()
                .and_then(|q| q.geometry())
                .map(|g| g.ceiling(domain))
                .transpose()?
                .unwrap_or(80);
            let limit = self
                .ceiling
                .min(extension_limit)
                .min(permission.eirp_limit_qdbm())
                .min(full_span)
                .min(self.ht.as_ref().map_or(80, |q| q.program_limits().0))
                .min(
                    self.protection
                        .as_ref()
                        .map_or(80, |q| q.program_limits().0),
                );
            let selected = permission.with_gains(actual.cck, actual.ofdm);
            if !self.base.within(selected, limit, antenna) {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            if let Some(ht) = &self.ht {
                ht.check_selected(domain, permission, selected, actual.mcs, limit, antenna)?;
            }
            if let Some(protection) = &self.protection {
                protection
                    .check_selected(domain, permission, selected, actual.mcs, limit, antenna)?;
            }
            let fits = |row: usize, gain: u8| {
                gain < 64
                    && self.worst[row][usize::from(gain)] != UNKNOWN
                    && i32::from(self.worst[row][usize::from(gain)]) + i32::from(antenna)
                        <= i32::from(limit)
            };
            if actual.cck.iter().any(|g| !fits(0, *g))
                || actual.ofdm.iter().any(|g| !fits(1, *g))
                || self.ht.is_some() && actual.mcs.iter().enumerate().any(|(m, g)| !fits(m + 2, *g))
            {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            Ok(())
        })
    }
}
/// Actual nonzero samples are averaged4. No sample authorizes a temperature
/// gap: the signed all64-temperature bound above covers every applied point.
pub(crate) struct State {
    pub grant: Arc<Grant>,
    pub applied: Gains,
    nominal: Gains,
    factory: u8,
    cck_base: u8,
    average: [u8; 4],
    cursor: usize,
    pub lck: Option<u8>,
    pub iqk: Option<u8>,
    next: u64,
    triggered: bool,
}
pub(super) struct Update {
    pub gains: Gains,
    pub lck: bool,
    pub iqk: bool,
    pub average: u8,
}
impl State {
    pub(super) fn new(
        grant: Arc<Grant>,
        domain: &RegulatoryDomain,
        permission: Permission,
        io: &impl Io,
    ) -> Result<Self, Error> {
        let nominal = Gains::nominal(grant.ht.as_deref(), domain, permission)?;
        grant.check(domain, permission, nominal)?;
        // Linux compares a24's four filter bytes against table columns2..5.
        let filter = io.read32(0xa24)?;
        let cck_base = CCK_FILTER
            .iter()
            .position(|value| *value == filter)
            .ok_or(Error::Radio(super::radio::Error::Calibration))? as u8;
        let factory = grant.base.factory().logical[0xba];
        Ok(Self {
            grant,
            applied: nominal,
            nominal,
            factory,
            cck_base,
            average: [0; 4],
            cursor: 0,
            lck: None,
            iqk: None,
            next: 0,
            triggered: false,
        })
    }
    pub(super) fn due(&self, now: u64) -> bool {
        now >= self.next
    }
    pub(super) fn triggered(&mut self, now: u64) -> Result<(), Error> {
        self.next = now.checked_add(PERIOD_MS).ok_or(Error::State)?;
        self.triggered = true;
        Ok(())
    }
    pub(super) fn needs_sample(&self) -> bool {
        self.triggered
    }
    pub(super) fn sample(&mut self, raw: u8, now: u64) -> Result<Update, Error> {
        if !(1..=63).contains(&raw) || !self.triggered {
            return Err(Error::Radio(super::radio::Error::Calibration));
        }
        self.triggered = false;
        self.next = now.checked_add(PERIOD_MS).ok_or(Error::State)?;
        self.average[self.cursor] = raw;
        self.cursor = (self.cursor + 1) % 4;
        let (sum, count) = self
            .average
            .iter()
            .filter(|v| **v != 0)
            .fold((0u16, 0u16), |(sum, count), v| {
                (sum + u16::from(*v), count + 1)
            });
        let average = (sum / count) as u8;
        let lck = self.lck.is_some_and(|old| old.abs_diff(average) >= 8);
        let iqk = self.iqk.is_some_and(|old| old.abs_diff(average) >= 8);
        self.lck.get_or_insert(raw);
        self.iqk.get_or_insert(raw);
        let delta = average.abs_diff(self.factory);
        let direction = usize::from(average > self.factory);
        let offset = THRESHOLD[direction]
            .iter()
            .position(|v| delta < *v)
            .map_or(14, |i| i.saturating_sub(1));
        let swing = (i16::from(self.cck_base) + i16::from(SWING[direction][offset])).clamp(0, 32);
        // rf.c uses CCK(type1) for both families. Hotter positive boosts are
        // limited by the preceding signed original program, so only a cold
        // decrease (and later restoration) can move the retained indices.
        let reduction = (swing - i16::from(self.cck_base)).max(0) as u8;
        Ok(Update {
            gains: self.nominal.reduce(reduction),
            lck,
            iqk,
            average,
        })
    }
}
const SWING: [[i8; 15]; 2] = [
    [0, 0, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11],
    [0, 0, -1, -2, -3, -4, -4, -4, -4, -5, -7, -8, -9, -9, -10],
];
const THRESHOLD: [[u8; 15]; 2] = [
    [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 27],
    [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 25, 25, 25],
];
// Realtek CCK columns2..5, source dm.c cck_tbl_ch1_13.
const CCK_FILTER: [u32; 33] = [
    0x121c252e, 0x111a232b, 0x10192129, 0x0f181f27, 0x0e161e25, 0x0d151c22, 0x0d141b21, 0x0c13191f,
    0x0b11181d, 0x0811161b, 0x0a10151a, 0x0a0f1418, 0x090e1317, 0x090d1216, 0x080c1115, 0x080c1013,
    0x070b0f12, 0x070b0e11, 0x060a0d10, 0x06090c0f, 0x06090c0f, 0x05080b0e, 0x05080b0d, 0x05080a0c,
    0x05070a0c, 0x0407090b, 0x0406090a, 0x0406080a, 0x04060809, 0x03050709, 0x03050708, 0x03050608,
    0x03040607,
];
impl State {
    pub(super) fn nominal(&self) -> Gains {
        self.nominal
    }
}
/// Every poll that may access RF/IQK/TXAGC repeats current host policy and
/// encloses that actual poll in every retained source capability invocation.
pub(super) async fn wait<T, F: core::future::Future<Output = Result<T, Error>>>(
    grant: Arc<Grant>,
    antenna: Option<Arc<super::antenna::Grant>>,
    permission: Permission,
    environment: &impl super::prepare::station::Environment,
    future: F,
) -> Result<T, Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            if environment.preparation_failed()
                || environment
                    .admission()
                    .is_some_and(|a| a.closed.load(core::sync::atomic::Ordering::Acquire))
            {
                return Err(Error::State);
            }
            let domain = environment
                .domain()
                .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
            grant.check_sources(&domain, permission)?;
            if let Some(antenna) = &antenna {
                antenna.check_sources(&domain, permission)?;
            }
            Ok(future.as_mut().poll(cx))
        };
        (if let Some(antenna) = &antenna {
            antenna.invoke(operation)
        } else {
            grant.invoke(operation)
        })
        .unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
    })
    .await
}
pub(super) fn readback(io: &impl Io, gains: Gains) -> Result<(), Error> {
    if (io.read32(0xe08)? >> 8) & 255 != u32::from(gains.cck[0])
        || io.read32(0x86c)? >> 8
            != u32::from(gains.cck[1])
                | (u32::from(gains.cck[2]) << 8)
                | (u32::from(gains.cck[3]) << 16)
    {
        return Err(Error::Readback);
    }
    for (reg, row) in [0xe00, 0xe04].into_iter().zip(gains.ofdm.chunks_exact(4)) {
        if io.read32(reg)? != u32::from_le_bytes(row.try_into().unwrap()) {
            return Err(Error::Readback);
        }
    }
    for (reg, row) in [0xe10, 0xe14].into_iter().zip(gains.mcs.chunks_exact(4)) {
        if io.read32(reg)? != u32::from_le_bytes(row.try_into().unwrap()) {
            return Err(Error::Readback);
        }
    }
    if io.read32(0xe18)? != 0 || io.read32(0xe1c)? != 0 {
        return Err(Error::Readback);
    }
    Ok(())
}
pub(super) fn program(io: &impl Io, gains: Gains) -> Result<(), Error> {
    let old = io.read32(0xe08)?;
    io.write32(0xe08, (old & !0xff00) | (u32::from(gains.cck[0]) << 8))?;
    let old = io.read32(0x86c)?;
    io.write32(
        0x86c,
        (old & 255)
            | (u32::from(gains.cck[1]) << 8)
            | (u32::from(gains.cck[2]) << 16)
            | (u32::from(gains.cck[3]) << 24),
    )?;
    for (reg, row) in [0xe00, 0xe04].into_iter().zip(gains.ofdm.chunks_exact(4)) {
        io.write32(reg, u32::from_le_bytes(row.try_into().unwrap()))?;
    }
    for (reg, row) in [0xe10, 0xe14].into_iter().zip(gains.mcs.chunks_exact(4)) {
        io.write32(reg, u32::from_le_bytes(row.try_into().unwrap()))?;
    }
    readback(io, gains)
}
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn artifact(
    base: &Calibration,
    firmware: Identity,
    channel: u8,
    ht: Option<&ht::Grant>,
    protection: Option<&protection::Grant>,
) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0; LENGTH];
    b[..4].copy_from_slice(b"NETH");
    b[4..8].copy_from_slice(&[1, 0, 0, 1]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
    b[16..48].copy_from_slice(&request(base, firmware, channel, ht, protection).binding);
    b[48..80].copy_from_slice(&super::radio::factory_identity(base.factory()));
    b[80..112].copy_from_slice(&base.digest);
    b[112..118].copy_from_slice(&base.factory().mac);
    b[118..124].copy_from_slice(&geometry(channel, ht));
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&80i16.to_le_bytes());
    b[128..160].copy_from_slice(&ht.map_or([0; 32], ht::Grant::measurement_digest));
    b[160..192].copy_from_slice(&protection.map_or([0; 32], protection::Grant::measurement_digest));
    b[192..196].copy_from_slice(&[base.factory().logical[0xba], 64, 10, 64]);
    for thermal in b[HEADER..].chunks_exact_mut(10 * 128) {
        for row in thermal.chunks_exact_mut(128) {
            for (gain, peak) in row.chunks_exact_mut(2).enumerate() {
                peak.copy_from_slice(&(gain as i16 * 2).to_le_bytes());
            }
        }
    }
    b
}
