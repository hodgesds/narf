// SPDX-License-Identifier: GPL-2.0-or-later
//! NERT full-program RTS/CTS continuation; measured board data stays external.
use super::{
    channel_power::{Calibration, Permission},
    firmware_transport::Identity,
    ht,
    prepare::Error,
};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const HEADER: usize = 192;
const LENGTH: usize = HEADER + 10 * 128;
const UNKNOWN: i16 = i16::MAX;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    #[default]
    None,
    RtsCts,
    CtsToSelf,
}
impl Mode {
    pub(super) fn fields(self) -> u32 {
        match self {
            Self::None => 0,
            Self::RtsCts => 8 | (1 << 12),
            Self::CtsToSelf => 8 | (1 << 11),
        }
    }
}
/// mac80211 ERP Use_Protection; reject ambiguous/truncated control facts.
pub(super) fn erp(mut ies: &[u8]) -> Result<bool, Error> {
    let mut erp = None;
    while !ies.is_empty() {
        let head = ies.get(..2).ok_or(Error::Packet)?;
        let end = 2 + usize::from(head[1]);
        let body = ies.get(2..end).ok_or(Error::Packet)?;
        if head[0] == 42 && (body.len() != 1 || erp.replace(body[0] & 2 != 0).is_some()) {
            return Err(Error::Packet);
        }
        ies = &ies[end..];
    }
    Ok(erp.unwrap_or(false))
}
/// RTS threshold is disabled by default. Actual MPDU/FCS length supplies
/// use_rts; ERP requests CTS for OFDM/HT, leaving CCK long-preamble DATA alone.
pub(super) fn select(erp: bool, threshold: Option<u16>, length: usize, rate: u8) -> Mode {
    if threshold.is_some_and(|limit| length.saturating_add(4) > usize::from(limit)) {
        Mode::RtsCts
    } else if erp && rate >= 4 {
        Mode::CtsToSelf
    } else {
        Mode::None
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
fn geometry(channel: u8, ht: Option<&ht::Grant>) -> [u8; 6] {
    ht.and_then(ht::Grant::geometry)
        .map_or([channel, 20, 1, 3, 0, channel], |g| {
            [channel, 40, 1, 3, g.secondary(), g.center()]
        })
}
pub(super) fn request(
    base: &Calibration,
    firmware: Identity,
    channel: u8,
    ht: Option<&ht::Grant>,
) -> Request {
    let f = base.factory();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8188EE NERT1 exact unchanged full-program RTS CTS-to-self");
    hash.update(&super::radio::factory_identity(f));
    hash.update(&base.digest);
    hash.update(&firmware.digest);
    hash.update(&geometry(channel, ht));
    hash.update(&ht.map_or([0; 32], ht::Grant::measurement_digest));
    hash.update(b"Linux7.2 rtlwifi base.c _rtl_query_protection_mode: ERP Use_Protection for OFDM/MCS => CTS; explicit per-device threshold MPDU+FCS => RTS; data only; DW4 RTS_RATE8 OFDM24 CTS11 xor RTS12 HW_RTS13=0 RTS_SHORT26=0 RTS_BW27=0 RTS_SC28-29=0 RTS_STBC30-31=0; existing RTS fallback limit15 and unchanged DATA/RA/BA/OWN; all automatic RTS CTS retry rates included in CCK/OFDM peaks; full legacy and actual measured NEHT20/40, SGI20,7935RX, static antenna IQK LCK supply thermal0..63; exact original raw gains only, no tracking RTS overrides or default curve; current policy sources every poll, capture, DMA publication and callback; no board measurements supplied");
    let g = geometry(channel, ht);
    Request {
        name: format!(
            "rtlwifi/rtl8188ee-rts-cts-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}-h{}.bin",
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
            }
        ),
        binding: hash.finalize(),
    }
}
pub(crate) struct Grant {
    base: Arc<Calibration>,
    ht: Option<Arc<ht::Grant>>,
    firmware: Identity,
    cap: Cap<FirmwareBlob, Read>,
    channel: u8,
    antenna: i16,
    ceiling: i16,
    curves: [[i16; 64]; 10],
    measurement: [u8; 32],
}
impl Grant {
    pub(super) fn measurement_digest(&self) -> [u8; 32] {
        self.measurement
    }
    pub(super) fn program_limits(&self) -> (i16, i16) {
        (self.ceiling, self.antenna)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check_selected(
        &self,
        domain: &RegulatoryDomain,
        nominal: Permission,
        selected: Permission,
        mcs: [u8; 8],
        limit: i16,
        antenna: i16,
    ) -> Result<(), Error> {
        self.invoke(|| {
            self.check(domain, nominal)?;
            let limit = limit.min(self.ceiling);
            let antenna = antenna.max(self.antenna);
            let fits = |row: usize, gain: u8| {
                gain < 64
                    && self.curves[row][usize::from(gain)] != UNKNOWN
                    && i32::from(self.curves[row][usize::from(gain)]) + i32::from(antenna)
                        <= i32::from(limit)
            };
            let (cck, ofdm) = selected.gains();
            if cck.iter().any(|g| !fits(0, *g))
                || ofdm.iter().any(|g| !fits(1, *g))
                || self.ht.is_some() && mcs.iter().enumerate().any(|(m, g)| !fits(m + 2, *g))
            {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            Ok(())
        })
    }
    pub(super) fn registered(
        base: Arc<Calibration>,
        firmware: Identity,
        channel: u8,
        ht: Option<Arc<ht::Grant>>,
    ) -> Result<Option<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source = match crate::firmware_asset::load(
            &authority,
            &request(&base, firmware, channel, ht.as_deref()).name,
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
            &source.bytes,
            source.signer,
            source.cap,
        )
        .map(|g| Some(Arc::new(g)))
    }
    pub(super) fn parse(
        base: Arc<Calibration>,
        firmware: Identity,
        channel: u8,
        ht: Option<Arc<ht::Grant>>,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        let bad = || Error::Power(super::channel_power::Error::Format);
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        if !(1..=11).contains(&channel)
            || b.len() != LENGTH
            || b[..4] != *b"NERT"
            || b[4..8] != [1, 0, 192, 0]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48] != request(&base, firmware, channel, ht.as_deref()).binding
            || b[48..80] != super::radio::factory_identity(base.factory())
            || b[80..112] != base.digest
            || b[112..118] != base.factory().mac
            || b[118..124] != geometry(channel, ht.as_deref())
            || b[128..160] != ht.as_ref().map_or([0; 32], |g| g.measurement_digest())
            || b[160..192] != [0; 32]
            || ht.as_ref().is_some_and(|g| !g.matches(&base))
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(b[124..126].try_into().unwrap());
        let ceiling = i16::from_le_bytes(b[126..128].try_into().unwrap());
        let minimum = ht
            .as_ref()
            .map_or(base.antenna(), |g| g.program_limits().1.max(base.antenna()));
        if !(minimum..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(bad());
        }
        let curves: [[i16; 64]; 10] = core::array::from_fn(|row| {
            core::array::from_fn(|gain| {
                i16::from_le_bytes(
                    b[HEADER + row * 128 + gain * 2..HEADER + row * 128 + gain * 2 + 2]
                        .try_into()
                        .unwrap(),
                )
            })
        });
        if curves
            .iter()
            .flatten()
            .any(|p| *p != UNKNOWN && !(-512..=256).contains(p))
        {
            return Err(bad());
        }
        let grant = Self {
            base,
            ht,
            firmware,
            cap,
            channel,
            antenna,
            ceiling,
            curves,
            measurement: {
                let mut hash = narf_crypto::sha256::Sha256::new();
                hash.update(b);
                hash.finalize()
            },
        };
        grant.invoke(|| Ok(()))?;
        Ok(grant)
    }
    pub(super) fn matches(
        &self,
        base: &Arc<Calibration>,
        ht: Option<&Arc<ht::Grant>>,
        channel: u8,
    ) -> bool {
        Arc::ptr_eq(base, &self.base)
            && channel == self.channel
            && match (&self.ht, ht) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
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
        let op = || {
            self.cap
                .invoke(Live(operation))
                .map_err(|_| Error::Power(super::channel_power::Error::Authority))?
        };
        self.firmware.invoke(|| {
            if let Some(ht) = &self.ht {
                ht.invoke(op)
            } else {
                self.base.with_current(op)
            }
        })
    }
    pub(super) fn check(
        &self,
        domain: &RegulatoryDomain,
        permission: Permission,
    ) -> Result<(), Error> {
        self.invoke(|| {
            if self
                .base
                .permission(domain, self.channel)
                .map_err(Error::Power)?
                != permission
            {
                return Err(Error::State);
            }
            let full_span = self
                .ht
                .as_ref()
                .and_then(|g| g.geometry())
                .map(|g| g.ceiling(domain))
                .transpose()?
                .unwrap_or(80);
            let limit = self
                .ceiling
                .min(permission.eirp_limit_qdbm())
                .min(full_span)
                .min(self.ht.as_ref().map_or(80, |g| g.program_limits().0));
            if !self.base.within(permission, limit, self.antenna) {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            let fits = |row: usize, gain: u8| {
                self.curves[row][usize::from(gain)] != UNKNOWN
                    && i32::from(self.curves[row][usize::from(gain)]) + i32::from(self.antenna)
                        <= i32::from(limit)
            };
            let (cck, ofdm) = permission.gains();
            if cck.iter().any(|g| !fits(0, *g)) || ofdm.iter().any(|g| !fits(1, *g)) {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            if let Some(ht) = &self.ht {
                for (row, gain) in ht.gains(domain, permission)?.into_iter().enumerate() {
                    if !fits(row + 2, gain) {
                        return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                    }
                }
            }
            Ok(())
        })
    }
}
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn artifact(
    base: &Calibration,
    firmware: Identity,
    channel: u8,
    ht: Option<&ht::Grant>,
) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0;LENGTH];
    b[..4].copy_from_slice(b"NERT");
    b[4..8].copy_from_slice(&[1, 0, 192, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x79, 0x81]);
    b[16..48].copy_from_slice(&request(base, firmware, channel, ht).binding);
    b[48..80].copy_from_slice(&super::radio::factory_identity(base.factory()));
    b[80..112].copy_from_slice(&base.digest);
    b[112..118].copy_from_slice(&base.factory().mac);
    b[118..124].copy_from_slice(&geometry(channel, ht));
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&80i16.to_le_bytes());
    b[128..160].copy_from_slice(&ht.map_or([0; 32], ht::Grant::measurement_digest));
    for row in b[HEADER..].chunks_exact_mut(128) {
        for (gain, peak) in row.chunks_exact_mut(2).enumerate() {
            peak.copy_from_slice(&(gain as i16 * 2).to_le_bytes());
        }
    }
    b
}
