// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE-only parked HT20/LGI+SGI program. Linux rtl8188ee/{hw,phy,rf,trx}.c.
//! The optional signed measurement extends the exact retained legacy record;
//! no factory gain, reporting dBm estimate or elapsed wait is a measurement.
use super::{
    channel_power::{Calibration, Permission},
    firmware_transport::Io,
    prepare::Error,
};
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::{
    association::phy::{LocalHt, LocalPhy},
    reg::RegulatoryDomain,
};
#[path = "ht40.rs"]
mod wide;
pub(super) use wide::{
    capability as wide_capability, local as local_wide, request as wide_request, Geometry,
};
const HEADER: usize = 160;
const LENGTH: usize = HEADER + 8 * 128;
const UNKNOWN: i16 = i16::MAX;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub binding: [u8; 32],
}
pub(super) fn request(
    base: &Calibration,
    firmware: super::firmware_transport::Identity,
) -> Request {
    request_on_channel(base, firmware, 1)
}
pub(super) fn request_on_channel(
    base: &Calibration,
    firmware: super::firmware_transport::Identity,
    channel: u8,
) -> Request {
    let f = base.factory();
    let mut h = narf_crypto::sha256::Sha256::new();
    if channel == 1 {
        h.update(b"NARF RTL8188EE PCI8179 HT20 LGI+SGI20 1T1R MCS0-7 channel1 program v2");
    } else {
        h.update(b"NARF RTL8188EE PCI8179 HT20 LGI+SGI20 1T1R MCS0-7 exact-channel program v3");
        h.update(&[channel]);
    }
    h.update(&super::radio::factory_identity(f));
    h.update(&base.digest);
    h.update(super::fw::FW_8188EE.as_bytes());
    h.update(&firmware.digest);
    if channel == 1 {
        h.update(b"EFUSE1b signed high nibble; BW40base16; pathA PG8-row groups; TXAGCe10/e14; unusede18/e1c0; BW603.2=1 BB800/900.0=0 RF18 preserveupper+c01; SIFS14 EDCA16+9*AIFSN; fixedTXD5c..13 LGI USE_RATE DISFB QOS TID0-7 AC rings/QSEL=TID; QoS DATA peer AMPDU_DENSITY, AGG_EN+MAX_AGG_NUM0x14 only on operational originator BA TID (rtl_tx_status start after cnt_after_linked3, timeout5000TU, noRTS); softwareCCMP CAM0 rawRX7935 RXslots9100 HT_MAX_AMSDU; atomic full-body validation before PN; bound HT45/61/WMM; ADDBA37 nativeOWN; noRTS CTS tracking PM");
    } else {
        h.update(b"source hw.c _rtl88e_get_chnl_group channel<3/6/9/12 selects EFUSE BW40base16+group; EFUSE1b signed high nibble; rf.c per-regulatory pathA PGgroup rows4/5; TXAGCe10/e14 unused2SS0; RF18 exact current NEPC channel; BW20; SIFS14 EDCA16+9*AIFSN; MCS0..7 LGI/SGI; source-backed QoS/CCMP A-MSDU BA/TX A-MPDU and receive/copy/key epochs unchanged; noHT40 RTS CTS tracking");
    }
    h.update(b"full static factory antenna/IQK/LCK/thermal0..63 supply envelope; all legacy+automaticresponse+decline and8MCS conducted peaks; no measured data supplied; exact capture/key/IPC/callback epochs");
    h.update(b"HT SGI20 local RX; native RXD3 SPLCP8 and PHYsgi27.1 before PN; actual peer RX_SGI20 offer+response gates DATA TXD5.6 on MCS1..7, MCS0 LGI per rtl88ee_tx_fill_desc; H2C RA_MASK byte4 SGI5, no mixed-GI fallback under NEFBv1; each measured MCS peak covers LGI and SGI, all BA/protection/response/transient emissions");
    Request {
        name: if channel == 1 {
            format!(
                "rtlwifi/rtl8188ee-ht20-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                f.mac[0], f.mac[1], f.mac[2], f.mac[3], f.mac[4], f.mac[5]
            )
        } else {
            format!(
                "rtlwifi/rtl8188ee-ht20-v3-ch{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                channel, f.mac[0], f.mac[1], f.mac[2], f.mac[3], f.mac[4], f.mac[5]
            )
        },
        binding: h.finalize(),
    }
}
pub(super) fn local() -> LocalPhy {
    LocalPhy::ht20(LocalHt::siso20(true, true).with_rx_amsdu_7935(true))
        .expect("fixed mandatory HT20 MCS0..7 profile")
}
pub(crate) struct Grant {
    channel: u8,
    base: Arc<Calibration>,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    curves: [[i16; 64]; 8],
    firmware: super::firmware_transport::Identity,
    wide: Option<wide::Qualification>,
    measurement: [u8; 32],
}
impl Grant {
    pub(super) fn measurement_digest(&self) -> [u8; 32] {
        self.measurement
    }
    pub(super) fn program_limits(&self) -> (i16, i16) {
        (self.ceiling, self.antenna)
    }
    pub(super) fn matches(&self, base: &Arc<Calibration>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }
    pub(super) fn registered(
        base: Arc<Calibration>,
        firmware: super::firmware_transport::Identity,
        channel: u8,
    ) -> Result<Option<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source = match crate::firmware_asset::load(
            &authority,
            &request_on_channel(&base, firmware, channel).name,
            LENGTH,
            true,
        ) {
            Ok(s) => s,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Power(super::channel_power::Error::Firmware(e))),
        };
        Self::parse(base, firmware, &source.bytes, source.signer, source.cap)
            .map(|g| Some(Arc::new(g)))
    }
    pub(super) fn parse(
        base: Arc<Calibration>,
        firmware: super::firmware_transport::Identity,
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        if b.get(4..6) == Some(&[4, 0]) {
            return wide::parse(base, firmware, b, signer, cap);
        }
        let bad = || Error::Power(super::channel_power::Error::Format);
        let f = base.factory();
        let channel = *b.get(118).ok_or_else(bad)?;
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        if b.len() != LENGTH
            || b[..4] != *b"NEHT"
            || !(1..=11).contains(&channel)
            || b[4..8] != [if channel == 1 { 2 } else { 3 }, 0, HEADER as u8, 0]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48] != request_on_channel(&base, firmware, channel).binding
            || b[48..80] != super::radio::factory_identity(f)
            || b[80..112] != base.digest
            || b[112..118] != f.mac
            || b[118..124] != [channel, 20, 1, 1, 0, 0]
            || b[128..HEADER] != [0; 32]
        {
            return Err(bad());
        }
        let antenna = i16::from_le_bytes(b[124..126].try_into().unwrap());
        let ceiling = i16::from_le_bytes(b[126..128].try_into().unwrap());
        if !(base.antenna()..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(bad());
        }
        let curves = core::array::from_fn(|m| {
            core::array::from_fn(|i| {
                i16::from_le_bytes(
                    b[HEADER + m * 128 + i * 2..HEADER + m * 128 + i * 2 + 2]
                        .try_into()
                        .unwrap(),
                )
            })
        });
        if curves
            .iter()
            .flatten()
            .any(|v| *v != UNKNOWN && !(-512..=256).contains(v))
        {
            return Err(bad());
        }
        let grant = Self {
            channel,
            base,
            cap,
            antenna,
            ceiling,
            curves,
            firmware,
            wide: None,
            measurement: digest(b),
        };
        grant.invoke(|| Ok(()))?;
        Ok(grant)
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
        self.firmware.invoke(|| {
            self.base.with_current(|| {
                self.cap
                    .invoke(Live(operation))
                    .map_err(|_| Error::Power(super::channel_power::Error::Authority))?
            })
        })
    }
    pub(super) fn gains(
        &self,
        domain: &RegulatoryDomain,
        legacy: Permission,
    ) -> Result<[u8; 8], Error> {
        self.invoke(|| {
            if self
                .base
                .permission(domain, self.channel)
                .map_err(Error::Power)?
                != legacy
            {
                return Err(Error::State);
            }
            let limit = if let Some(wide) = &self.wide {
                wide.geometry
                    .ceiling(domain)?
                    .min(legacy.eirp_limit_qdbm())
                    .min(self.ceiling)
            } else {
                legacy.eirp_limit_qdbm().min(self.ceiling)
            };
            if !self.base.within(legacy, limit, self.antenna) {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            let mut maximum = factory_gains(self.base.factory(), self.channel)?;
            if let Some(wide) = &self.wide {
                let (cck, ofdm) = legacy.gains();
                let (wide_cck, wide_ofdm) = super::channel_power::factory_gains(
                    self.base.factory(),
                    wide.geometry.center(),
                )
                .map_err(Error::Power)?;
                for (row, (selected, caps)) in [
                    (cck.as_slice(), wide_cck.as_slice()),
                    (ofdm.as_slice(), wide_ofdm.as_slice()),
                ]
                .into_iter()
                .enumerate()
                {
                    if selected.iter().zip(caps).any(|(gain, cap)| {
                        gain > cap
                            || wide.legacy[row][usize::from(*gain)] == UNKNOWN
                            || i32::from(wide.legacy[row][usize::from(*gain)])
                                + i32::from(self.antenna)
                                > i32::from(limit)
                    }) {
                        return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                    }
                }
                for (max, cap) in maximum.iter_mut().zip(factory_gains_inner(
                    self.base.factory(),
                    wide.geometry.center(),
                    false,
                )?) {
                    *max = (*max).min(cap);
                }
            }
            let mut indices = [0; 8];
            for ((i, max), curve) in indices.iter_mut().zip(maximum).zip(&self.curves) {
                *i = (0..=max)
                    .rev()
                    .find(|i| {
                        curve[usize::from(*i)] != UNKNOWN
                            && i32::from(curve[usize::from(*i)]) + i32::from(self.antenna)
                                <= i32::from(limit)
                    })
                    .ok_or(Error::Power(super::channel_power::Error::NoMeasuredGain))?;
            }
            Ok(indices)
        })
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
            let maxima = self.gains(domain, nominal)?;
            let limit = limit.min(self.ceiling).min(nominal.eirp_limit_qdbm()).min(
                self.wide
                    .as_ref()
                    .map(|q| q.geometry.ceiling(domain))
                    .transpose()?
                    .unwrap_or(80),
            );
            let antenna = antenna.max(self.antenna);
            if !self.base.within(selected, limit, antenna)
                || mcs.iter().zip(maxima).any(|(g, max)| *g > max)
            {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            for (row, gain) in self.curves.iter().zip(mcs) {
                if row[usize::from(gain)] == UNKNOWN
                    || i32::from(row[usize::from(gain)]) + i32::from(antenna) > i32::from(limit)
                {
                    return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                }
            }
            if let Some(wide) = &self.wide {
                let limit = limit.min(wide.geometry.ceiling(domain)?);
                let (cck, ofdm) = selected.gains();
                for (row, indices) in wide.legacy.iter().zip([cck.as_slice(), ofdm.as_slice()]) {
                    if indices.iter().any(|g| {
                        row[usize::from(*g)] == UNKNOWN
                            || i32::from(row[usize::from(*g)]) + i32::from(antenna)
                                > i32::from(limit)
                    }) {
                        return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
                    }
                }
            }
            Ok(())
        })
    }
    pub(super) fn program(&self, io: &impl Io, indices: [u8; 8]) -> Result<(), Error> {
        self.invoke(|| {
            super::radio::parked(io).map_err(Error::Radio)?;
            for (reg, row) in [0xe10, 0xe14].into_iter().zip(indices.chunks_exact(4)) {
                io.write32(reg, u32::from_le_bytes(row.try_into().unwrap()))?;
            }
            self.readback(io, indices, false)?;
            super::radio::parked(io).map_err(Error::Radio)
        })
    }
    pub(super) fn readback(
        &self,
        io: &impl Io,
        indices: [u8; 8],
        timing: bool,
    ) -> Result<(), Error> {
        self.readback_width(io, indices, timing, None)
    }
    pub(super) fn readback_width(
        &self,
        io: &impl Io,
        indices: [u8; 8],
        timing: bool,
        width: Option<Geometry>,
    ) -> Result<(), Error> {
        if width.is_some() && width != self.geometry() {
            return Err(Error::State);
        }
        self.invoke(|| {
            for (reg, row) in [0xe10, 0xe14].into_iter().zip(indices.chunks_exact(4)) {
                if io.read32(reg)? != u32::from_le_bytes(row.try_into().unwrap()) {
                    return Err(Error::Readback);
                }
            }
            if io.read32(0xe18)? != 0
                || io.read32(0xe1c)? != 0
                || (io.read8(0x603)? & 4 == 0) != width.is_some()
                || (io.read32(0x800)? & 1 != 0) != width.is_some()
                || (io.read32(0x900)? & 1 != 0) != width.is_some()
            {
                return Err(Error::Readback);
            }
            if let Some(g) = width {
                g.readback(io)?;
            }
            if timing
                && [0x515, 0x517, 0x429, 0x63b]
                    .into_iter()
                    .any(|r| io.read8(r) != Ok(14))
            {
                return Err(Error::Readback);
            }
            Ok(())
        })
    }
}
/// hw.c::_rtl88ee_read_power_value_fromprom + phy.c::handle_path_a +
/// rf.c::_rtl88e_get_txpower_writeval_by_regulatory, pathA/channels1..11/20MHz.
/// Erased/default board data cannot establish a factory bound here.
pub(super) fn factory_gains(f: &super::efuse::Factory, channel: u8) -> Result<[u8; 8], Error> {
    factory_gains_inner(f, channel, true)
}
fn factory_gains_inner(
    f: &super::efuse::Factory,
    channel: u8,
    twenty: bool,
) -> Result<[u8; 8], Error> {
    let b = &f.logical;
    let bad = || Error::Power(super::channel_power::Error::FactoryPower);
    let group = match channel {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        _ => return Err(bad()),
    };
    if b[0x16 + group] > 63 || b[0x1b] == 255 {
        return Err(bad());
    }
    let n = i16::from(b[0x1b] >> 4);
    let delta = if n & 8 != 0 { n - 16 } else { n };
    let base = i16::from(b[0x16 + group]) + if twenty { delta } else { 0 };
    if !(0..=63).contains(&base) {
        return Err(bad());
    }
    let mode = if b[0xc1] == 255 { 0 } else { b[0xc1] & 7 };
    if mode > 3 {
        return Err(bad());
    }
    // Regulatory1 uses the channel group; 0/3 use group0, and 2 uses no PG.
    // On EE the rows are
    // OFDM0/1, CCK2/3, MCS0..3 row4, MCS4..7 row5, unused2SS6/7.
    let pg_group = if mode == 1 { group } else { 0 };
    let pg = &super::radio::power_groups()[pg_group * 8..pg_group * 8 + 8];
    Ok(core::array::from_fn(|i| {
        let offset = if matches!(mode, 2 | 3) {
            0
        } else {
            (pg[4 + i / 4][2].to_le_bytes()[i % 4] & 127) as u16
        };
        (base as u16 + offset).min(63) as u8
    }))
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "ht_tests.rs"]
pub(crate) mod tests;

/// Every poll of a retained native command earns the same current sources
/// and policy. A credit/mailbox wait cannot resume into an unqualified write.
pub(super) async fn wait<F: core::future::Future<Output = Result<(), Error>>>(
    base: Arc<Calibration>,
    ht: Option<Arc<Grant>>,
    protection: Option<Arc<super::protection::Grant>>,
    tracking: Option<Arc<super::tracking::Grant>>,
    permission: Permission,
    environment: &impl super::prepare::station::Environment,
    future: F,
) -> Result<(), Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let mut operation = || {
            let domain = environment
                .domain()
                .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
            if base
                .permission(&domain, permission.channel())
                .map_err(Error::Power)?
                != permission
            {
                return Err(Error::State);
            }
            if let Some(ht) = &ht {
                ht.gains(&domain, permission)?;
            }
            if let Some(protection) = &protection {
                protection.check(&domain, permission)?;
            }
            if let Some(tracking) = &tracking {
                tracking.check_sources(&domain, permission)?;
                tracking.invoke(|| Ok(future.as_mut().poll(cx)))
            } else {
                Ok(future.as_mut().poll(cx))
            }
        };
        let protected = || {
            if let Some(protection) = &protection {
                protection.invoke(operation)
            } else {
                operation()
            }
        };
        let checked = if let Some(ht) = &ht {
            ht.invoke(protected)
        } else {
            base.with_current(protected)
        };
        checked.unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
    })
    .await
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(bytes);
    h.finalize()
}
