// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2009-2013 Realtek Corporation.
//! NEAN full-program per-mux/thermal EE antenna diversity continuation.
use super::{
    channel_power::{Calibration, Permission},
    firmware_transport::{Identity, Io},
    ht,
    prepare::Error,
    protection,
    tracking::{self, Gains},
};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
#[path = "antenna_hw.rs"]
mod hardware;
pub(super) use hardware::State;
const HEADER: usize = 320;
const LENGTH: usize = HEADER + 2 * 64 * 10 * 128;
const UNKNOWN: i16 = i16::MAX;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
#[derive(Clone)]
pub(crate) struct Program {
    pub base: Arc<Calibration>,
    pub firmware: Identity,
    pub channel: u8,
    pub ht: Option<Arc<ht::Grant>>,
    pub protection: Option<Arc<protection::Grant>>,
    pub tracking: Option<Arc<tracking::Grant>>,
}
impl Program {
    fn kind(&self) -> Result<u8, Error> {
        let kind = self.base.factory().logical[0xc9];
        if matches!(kind, 1 | 2 | 4) {
            Ok(kind)
        } else {
            Err(Error::Power(super::channel_power::Error::Identity))
        }
    }
    fn geometry(&self) -> Result<[u8; 6], Error> {
        Ok(self.ht.as_ref().and_then(|q| q.geometry()).map_or(
            [self.channel, 20, 1, self.kind()?, 0, self.channel],
            |g| {
                [
                    self.channel,
                    40,
                    1,
                    self.base.factory().logical[0xc9],
                    g.secondary(),
                    g.center(),
                ]
            },
        ))
    }
    fn digests(&self) -> [[u8; 32]; 3] {
        [
            self.ht.as_ref().map_or([0; 32], |q| q.measurement_digest()),
            self.protection
                .as_ref()
                .map_or([0; 32], |q| q.measurement_digest()),
            self.tracking
                .as_ref()
                .map_or([0; 32], |q| q.measurement_digest()),
        ]
    }
    fn invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.firmware.invoke(|| {
            if let Some(q) = &self.tracking {
                q.invoke(operation)
            } else if let Some(q) = &self.protection {
                q.invoke(operation)
            } else if let Some(q) = &self.ht {
                q.invoke(operation)
            } else {
                self.base.with_current(operation)
            }
        })
    }
    pub(super) fn matches(&self, other: &Self) -> bool {
        self.channel == other.channel
            && Arc::ptr_eq(&self.base, &other.base)
            && self.firmware.digest == other.firmware.digest
            && self.ht.as_ref().map(Arc::as_ptr) == other.ht.as_ref().map(Arc::as_ptr)
            && self.protection.as_ref().map(Arc::as_ptr)
                == other.protection.as_ref().map(Arc::as_ptr)
            && self.tracking.as_ref().map(Arc::as_ptr) == other.tracking.as_ref().map(Arc::as_ptr)
    }
}
pub(super) fn request(program: &Program) -> Result<Request, Error> {
    let f = program.base.factory();
    let g = program.geometry()?;
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8188EE NEAN1 exact full-program automatic antenna diversity");
    hash.update(&super::radio::factory_identity(f));
    hash.update(&program.base.digest);
    hash.update(&program.firmware.digest);
    hash.update(&g);
    for digest in program.digests() {
        hash.update(&digest);
    }
    hash.update(b"Linux7.2 rtl8188ee dm.c hw.c phy.c trx.c/h: factory c9 type1 CG_TRX_HW,2 CGCS_RX_HW,4 SMART with actual ant_combination2 mapping914=0201; type1 MAINmux1/AUX0, type2 MAINmux0/AUX1; force first actual init and code by factory type, never alias prior logical idle-ant with type constant; MAC4c23/25 pin8708/9 RX86410 LNA b2c22/31 OFDMca4a0 CCKa74.7 a0c.4; linked c50.7 a00.15 andtype1 80c.21; hardware RX8643..8 type1 defaultTX86012..14 response6d86..7; PHY27bits7/6/0 actual mux, BSSID/to-self-qualified PWDB averages and tie/current,2s decision; SMART7b0/7b4 own-MAC target, actual RX864 combination1 means two muxes0/1 only, e08.16+c50.7 training for real2s, own-directed native samples only, no samples preserves TX and clears training; TXD2 antsel24/25 andD7antsel29 actual byte order and OWN/source fences; type2 no per-descriptor TX override; actual MAC/scheduler quiescence readback, IQK/LCK/gains/RF/keys/BA/native DMA owners retained; full supplied physical mux0/1 x thermal0..63 x CCK OFDM MCS0..7 x gain0..63 upper bounds cover hardware/autonomous switches, all responses/retries/PPDUs and IQK/LCK plus all init/training/antenna/thermal/rawgain/restore transition states and supply range; per-mux antenna bounds at least all preceding static bounds; no inferred board map, peak or measurement; each admitted gain known in every temperature on both physical muxes; preceding leisurePS/IPS/recovery transitions and all awake/firmware-response states; no NEFB composition, no new manual set_antenna callback");
    Ok(Request { name: format!("rtlwifi/rtl8188ee-antenna-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}-h{}-r{}-t{}-a{}.bin",
        f.mac[0],f.mac[1],f.mac[2],f.mac[3],f.mac[4],f.mac[5],program.channel,g[4],
        if program.ht.is_none() {0} else if g[1]==40 {4} else if program.channel==1 {2} else {3},
        u8::from(program.protection.is_some()),u8::from(program.tracking.is_some()),g[3]), binding:hash.finalize() })
}
pub(crate) struct Grant {
    program: Program,
    cap: Cap<FirmwareBlob, Read>,
    antenna: [i16; 2],
    ceiling: i16,
    worst: [[[i16; 64]; 10]; 2],
}
impl Grant {
    pub(super) fn registered(program: Program) -> Result<Option<Arc<Self>>, Error> {
        // Unknown/fixed/software-only factory types retain their preceding
        // static program; they cannot accidentally adopt an erased default.
        if program.kind().is_err() {
            return Ok(None);
        }
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source =
            match crate::firmware_asset::load(&authority, &request(&program)?.name, LENGTH, true) {
                Ok(s) => s,
                Err(FirmwareError::NotFound) => return Ok(None),
                Err(e) => return Err(Error::Power(super::channel_power::Error::Firmware(e))),
            };
        Self::parse(program, &source.bytes, source.signer, source.cap).map(|q| Some(Arc::new(q)))
    }
    pub(super) fn parse(
        program: Program,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        let bad = || Error::Power(super::channel_power::Error::Format);
        let f = program.base.factory();
        let digests = program.digests();
        if !(1..=11).contains(&program.channel)
            || b.len() != LENGTH
            || b[..4] != *b"NEAN"
            || b[4..8] != [1, 0, 64, 1]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48] != request(&program)?.binding
            || b[48..80] != super::radio::factory_identity(f)
            || b[80..112] != program.base.digest
            || b[112..118] != f.mac
            || b[118..124] != program.geometry()?
            || b[130..136] != [2, 64, 10, 64, 0, 0]
            || b[136..168] != digests[0]
            || b[168..200] != digests[1]
            || b[200..232] != digests[2]
            || b[232..HEADER] != [0; 88]
            || program
                .ht
                .as_ref()
                .is_some_and(|q| !q.matches(&program.base))
            || program
                .protection
                .as_ref()
                .is_some_and(|q| !q.matches(&program.base, program.ht.as_ref(), program.channel))
            || program.tracking.as_ref().is_some_and(|q| {
                !q.matches(
                    &program.base,
                    program.ht.as_ref(),
                    program.protection.as_ref(),
                    program.channel,
                )
            })
        {
            return Err(bad());
        }
        let antenna = [
            i16::from_le_bytes(b[124..126].try_into().unwrap()),
            i16::from_le_bytes(b[126..128].try_into().unwrap()),
        ];
        let ceiling = i16::from_le_bytes(b[128..130].try_into().unwrap());
        let minimum = program
            .base
            .antenna()
            .max(program.ht.as_ref().map_or(0, |q| q.program_limits().1))
            .max(
                program
                    .protection
                    .as_ref()
                    .map_or(0, |q| q.program_limits().1),
            )
            .max(
                program
                    .tracking
                    .as_ref()
                    .map_or(0, |q| q.program_limits().1),
            );
        if antenna.iter().any(|a| !(minimum..=128).contains(a)) || !(-512..=80).contains(&ceiling) {
            return Err(bad());
        }
        let mut worst = [[[-512; 64]; 10]; 2];
        for (physical, peaks) in b[HEADER..].chunks_exact(64 * 10 * 128).zip(&mut worst) {
            for thermal in physical.chunks_exact(10 * 128) {
                for (row, maxima) in thermal.chunks_exact(128).zip(peaks.iter_mut()) {
                    for (bytes, peak) in row.chunks_exact(2).zip(maxima) {
                        let value = i16::from_le_bytes(bytes.try_into().unwrap());
                        if value != UNKNOWN && !(-512..=256).contains(&value) {
                            return Err(bad());
                        }
                        *peak = (*peak).max(value);
                    }
                }
            }
        }
        let q = Self {
            program,
            cap,
            antenna,
            ceiling,
            worst,
        };
        q.invoke(|| Ok(()))?;
        Ok(q)
    }
    pub(super) fn matches(&self, program: &Program) -> bool {
        self.program.matches(program)
    }
    pub(super) fn kind(&self) -> u8 {
        self.program.base.factory().logical[0xc9]
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
        self.program.invoke(|| {
            self.cap
                .invoke(Live(operation))
                .map_err(|_| Error::Power(super::channel_power::Error::Authority))?
        })
    }
    pub(super) fn nominal(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
    ) -> Result<Gains, Error> {
        Gains::nominal(self.program.ht.as_deref(), domain, permission)
    }
    pub(super) fn check_sources(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
    ) -> Result<(), Error> {
        self.check(domain, permission, self.nominal(domain, permission)?)
    }
    pub(super) fn check(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
        actual: Gains,
    ) -> Result<(), Error> {
        self.invoke(|| {
            if self
                .program
                .base
                .permission(domain, self.program.channel)
                .map_err(Error::Power)?
                != permission
            {
                return Err(Error::State);
            }
            let nominal = self.nominal(domain, permission)?;
            if actual.cck.iter().zip(nominal.cck).any(|(g, n)| *g > n)
                || actual.ofdm.iter().zip(nominal.ofdm).any(|(g, n)| *g > n)
                || actual.mcs.iter().zip(nominal.mcs).any(|(g, n)| *g > n)
            {
                return Err(Error::Power(super::channel_power::Error::FactoryPower));
            }
            let span = self
                .program
                .ht
                .as_ref()
                .and_then(|q| q.geometry())
                .map(|g| g.ceiling(domain))
                .transpose()?
                .unwrap_or(80);
            let limit = self
                .ceiling
                .min(span)
                .min(permission.eirp_limit_qdbm())
                .min(
                    self.program
                        .ht
                        .as_ref()
                        .map_or(80, |q| q.program_limits().0),
                )
                .min(
                    self.program
                        .protection
                        .as_ref()
                        .map_or(80, |q| q.program_limits().0),
                )
                .min(
                    self.program
                        .tracking
                        .as_ref()
                        .map_or(80, |q| q.program_limits().0),
                );
            for (antenna, peaks) in self.antenna.into_iter().zip(&self.worst) {
                let selected = permission.with_gains(actual.cck, actual.ofdm);
                if let Some(q) = &self.program.tracking {
                    q.check_extension(domain, permission, actual, limit, antenna)?;
                } else {
                    if !self.program.base.within(selected, limit, antenna) {
                        return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                    }
                    if let Some(q) = &self.program.ht {
                        q.check_selected(domain, permission, selected, actual.mcs, limit, antenna)?;
                    }
                    if let Some(q) = &self.program.protection {
                        q.check_selected(domain, permission, selected, actual.mcs, limit, antenna)?;
                    }
                }
                let fits = |row: usize, gain: u8| {
                    gain < 64
                        && peaks[row][usize::from(gain)] != UNKNOWN
                        && i32::from(peaks[row][usize::from(gain)]) + i32::from(antenna)
                            <= i32::from(limit)
                };
                if actual.cck.iter().any(|g| !fits(0, *g))
                    || actual.ofdm.iter().any(|g| !fits(1, *g))
                    || self.program.ht.is_some()
                        && actual.mcs.iter().enumerate().any(|(m, g)| !fits(m + 2, *g))
                {
                    return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                }
            }
            Ok(())
        })
    }
}
pub(super) async fn wait<T, F: core::future::Future<Output = Result<T, Error>>>(
    grant: Arc<Grant>,
    permission: Permission,
    environment: &impl super::prepare::station::Environment,
    future: F,
) -> Result<T, Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        grant
            .invoke(|| {
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
                Ok(future.as_mut().poll(cx))
            })
            .unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
    })
    .await
}
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn artifact(program: &Program) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut b = alloc::vec![0;LENGTH];
    b[..4].copy_from_slice(b"NEAN");
    b[4..8].copy_from_slice(&[1, 0, 64, 1]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
    b[16..48].copy_from_slice(&request(program)?.binding);
    b[48..80].copy_from_slice(&super::radio::factory_identity(program.base.factory()));
    b[80..112].copy_from_slice(&program.base.digest);
    b[112..118].copy_from_slice(&program.base.factory().mac);
    b[118..124].copy_from_slice(&program.geometry()?);
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&8i16.to_le_bytes());
    b[128..130].copy_from_slice(&80i16.to_le_bytes());
    b[130..136].copy_from_slice(&[2, 64, 10, 64, 0, 0]);
    for (at, digest) in [136, 168, 200].into_iter().zip(program.digests()) {
        b[at..at + 32].copy_from_slice(&digest);
    }
    for plane in b[HEADER..].chunks_exact_mut(128) {
        for (gain, peak) in plane.chunks_exact_mut(2).enumerate() {
            peak.copy_from_slice(&(gain as i16 * 2).to_le_bytes());
        }
    }
    Ok(b)
}
impl Grant {
    pub(super) fn matches_owners(
        &self,
        base: &Arc<Calibration>,
        ht: Option<&Arc<ht::Grant>>,
        protection: Option<&Arc<protection::Grant>>,
        tracking: Option<&Arc<tracking::Grant>>,
        channel: u8,
    ) -> bool {
        self.program.channel == channel
            && Arc::ptr_eq(&self.program.base, base)
            && self.program.ht.as_ref().map(Arc::as_ptr) == ht.map(Arc::as_ptr)
            && self.program.protection.as_ref().map(Arc::as_ptr) == protection.map(Arc::as_ptr)
            && self.program.tracking.as_ref().map(Arc::as_ptr) == tracking.map(Arc::as_ptr)
    }
}
/// No descriptor is retired or re-labelled. A native host receipt plus
/// actual scheduler idle precedes all physical selection/training changes.
#[allow(clippy::too_many_arguments)]
pub(super) async fn quiesce<F: core::future::Future<Output = Result<(), Error>>>(
    io: &impl Io,
    expected_rf: u32,
    gains: Gains,
    ht: Option<&ht::Grant>,
    timing: bool,
    width: Option<ht::Geometry>,
    operation: F,
) -> Result<(), Error> {
    let pause = io.read8(0x522)?;
    io.write8(0x522, 0xff)?;
    if io.read8(0x522)? != 0xff {
        return Err(Error::Readback);
    }
    let mut idle = false;
    for _ in 0..101 {
        if io.read32(0x5f8)? == 0 {
            idle = true;
            break;
        }
        io.delay_us(10).await;
    }
    if !idle {
        return Err(Error::PacketTimeout);
    }
    let cr = io.read8(0x100)?;
    if cr & 0xc0 != 0xc0 {
        return Err(Error::State);
    }
    io.write8(0x100, cr & !0xc0)?;
    if io.read8(0x100)? & 0xc0 != 0 {
        return Err(Error::Readback);
    }
    if super::radio::rf_read(io, 0x18)
        .await
        .map_err(Error::Radio)?
        != expected_rf
    {
        return Err(Error::Readback);
    }
    operation.await?;
    tracking::readback(io, gains)?;
    if let Some(ht) = ht {
        ht.readback_width(io, gains.mcs, timing, width)?;
    }
    if super::radio::rf_read(io, 0x18)
        .await
        .map_err(Error::Radio)?
        != expected_rf
    {
        return Err(Error::Readback);
    }
    io.write8(0x100, cr)?;
    io.write8(0x522, pause)?;
    if io.read8(0x100)? != cr || io.read8(0x522)? != pause {
        return Err(Error::Readback);
    }
    Ok(())
}
