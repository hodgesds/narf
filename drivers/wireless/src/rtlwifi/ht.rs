// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE-only parked HT20/LGI program. Linux rtl8188ee/{hw,phy,rf,trx}.c.
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
    let f = base.factory();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTL8188EE PCI8179 HT20 LGI 1T1R MCS0-7 channel1 program v1");
    h.update(&super::radio::factory_identity(f));
    h.update(&base.digest);
    h.update(super::fw::FW_8188EE.as_bytes());
    h.update(&firmware.digest);
    h.update(b"EFUSE1b signed high nibble; BW40base16; pathA PG8-row groups; TXAGCe10/e14; unusede18/e1c0; BW603.2=1 BB800/900.0=0 RF18 preserveupper+c01; SIFS14 EDCA16+9*AIFSN; fixedTXD5c..13 LGI USE_RATE DISFB QOS TID0-7 AC rings/QSEL=TID; QoS DATA peer AMPDU_DENSITY, AGG_EN+MAX_AGG_NUM0x14 only on operational originator BA TID (rtl_tx_status start after cnt_after_linked3, timeout5000TU, noRTS); softwareCCMP CAM0 rawRX3839; bound HT45/61/WMM; ADDBA37 nativeOWN; noRTS CTS tracking PM");
    h.update(b"full static factory antenna/IQK/LCK/thermal0..63 supply envelope; all legacy+automaticresponse+decline and8MCS conducted peaks; no measured data supplied; exact capture/key/IPC/callback epochs");
    Request {
        name: format!(
            "rtlwifi/rtl8188ee-ht20-lgi-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            f.mac[0], f.mac[1], f.mac[2], f.mac[3], f.mac[4], f.mac[5]
        ),
        binding: h.finalize(),
    }
}
pub(super) fn local() -> LocalPhy {
    LocalPhy::ht20(LocalHt::siso20(false, false)).expect("fixed mandatory HT20 MCS0..7 profile")
}
pub(crate) struct Grant {
    base: Arc<Calibration>,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    curves: [[i16; 64]; 8],
    firmware: super::firmware_transport::Identity,
}
impl Grant {
    pub(super) fn matches(&self, base: &Arc<Calibration>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }
    pub(super) fn registered(
        base: Arc<Calibration>,
        firmware: super::firmware_transport::Identity,
    ) -> Result<Option<Arc<Self>>, Error> {
        let authority = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Power(super::channel_power::Error::Authority))?;
        let source = match crate::firmware_asset::load(
            &authority,
            &request(&base, firmware).name,
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
        let bad = || Error::Power(super::channel_power::Error::Format);
        let f = base.factory();
        if signer.is_none() {
            return Err(Error::Power(super::channel_power::Error::Unsigned));
        }
        if b.len() != LENGTH
            || b[..4] != *b"NEHT"
            || b[4..8] != [1, 0, HEADER as u8, 0]
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize != LENGTH
            || b[12..16] != [0xec, 0x10, 0x79, 0x81]
            || b[16..48] != request(&base, firmware).binding
            || b[48..80] != super::radio::factory_identity(f)
            || b[80..112] != base.digest
            || b[112..118] != f.mac
            || b[118..124] != [1, 20, 1, 0, 0, 0]
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
            base,
            cap,
            antenna,
            ceiling,
            curves,
            firmware,
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
            if self.base.permission(domain, 1).map_err(Error::Power)? != legacy {
                return Err(Error::State);
            }
            let limit = legacy.eirp_limit_qdbm().min(self.ceiling);
            if !self.base.within(legacy, limit, self.antenna) {
                return Err(Error::Power(super::channel_power::Error::NoMeasuredGain));
            }
            let maximum = factory_gains(self.base.factory())?;
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
        self.invoke(|| {
            for (reg, row) in [0xe10, 0xe14].into_iter().zip(indices.chunks_exact(4)) {
                if io.read32(reg)? != u32::from_le_bytes(row.try_into().unwrap()) {
                    return Err(Error::Readback);
                }
            }
            if io.read32(0xe18)? != 0
                || io.read32(0xe1c)? != 0
                || io.read8(0x603)? & 4 == 0
                || io.read32(0x800)? & 1 != 0
                || io.read32(0x900)? & 1 != 0
            {
                return Err(Error::Readback);
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
/// rf.c::_rtl88e_get_txpower_writeval_by_regulatory, pathA/ch1/20MHz only.
/// Erased/default board data cannot establish a factory bound here.
pub(super) fn factory_gains(f: &super::efuse::Factory) -> Result<[u8; 8], Error> {
    let b = &f.logical;
    let bad = || Error::Power(super::channel_power::Error::FactoryPower);
    if b[0x16] > 63 || b[0x1b] == 255 {
        return Err(bad());
    }
    let n = i16::from(b[0x1b] >> 4);
    let delta = if n & 8 != 0 { n - 16 } else { n };
    let base = i16::from(b[0x16]) + delta;
    if !(0..=63).contains(&base) {
        return Err(bad());
    }
    let mode = if b[0xc1] == 255 { 0 } else { b[0xc1] & 7 };
    // ch1 selects PGgroup0 in every regulatory mode. On EE the rows are
    // OFDM0/1, CCK2/3, MCS0..3 row4, MCS4..7 row5, unused2SS6/7.
    let pg = &super::radio::power_groups()[..8];
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
    permission: Permission,
    environment: &impl super::prepare::station::Environment,
    future: F,
) -> Result<(), Error> {
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        let operation = || {
            let domain = environment
                .domain()
                .map_err(|_| Error::Power(super::channel_power::Error::Policy))?;
            if base.permission(&domain, 1).map_err(Error::Power)? != permission {
                return Err(Error::State);
            }
            if let Some(ht) = &ht {
                ht.gains(&domain, permission)?;
            }
            Ok(future.as_mut().poll(cx))
        };
        let checked = if let Some(ht) = &ht {
            ht.invoke(operation)
        } else {
            base.with_current(operation)
        };
        checked.unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
    })
    .await
}
