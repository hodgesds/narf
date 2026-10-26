// SPDX-License-Identifier: GPL-2.0-or-later
//! Parked C21 operating-power preparation. TXAGC layout: rtw8821c.c;
//! RFE power-path substitution: read_efuse; RRSR_INIT_2G: main.h/phy.c.
//! Explicit measured indices replace no measurement with a factory dBm guess.
use super::{
    calibration8821c,
    efuse::Factory8821c,
    firmware_transport::{Error, Io},
    radio8821c,
};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::{RegFlags, RegulatoryDomain};
type QError = calibration8821c::Error;
fn denied(error: QError) -> Error {
    Error::Calibration8821c(error)
}
const REGISTERS: [u16; 8] = [
    0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub indices: [u8; 12],
    pub thermal: u8,
    pub response_rates: u16,
    pub identity: [u8; 32],
}
pub(super) fn request(
    calibration: calibration8821c::Request,
    receipt: radio8821c::Info,
) -> Request {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8821CE parked legacy operating-power v1 ch1/20 RF-A; no station grant");
    hash.update(&calibration.identity);
    hash.update(&[receipt.channel, receipt.bandwidth_mhz]);
    hash.update(&receipt.swing.to_le_bytes());
    // Actual meter/status receipts gate the owner, not stable board identity:
    // one qualified temperature envelope must survive a different valid sample.
    hash.update(b"same-owner completed IQK; current meter in both signed thermal intervals");
    hash.update(b"RF42[17:16]=3; source2000000us conversion then actualRF42[15:10]");
    hash.update(b"explicit measured per-rate indices<=factory CCK/OFDM base; no gain tracking; MCS zero; RRSR15f; closed CR TXPAUSE DMA IRQ");
    for reg in REGISTERS {
        hash.update(&reg.to_le_bytes());
    }
    let m = calibration.mac;
    Request {
        identity: hash.finalize(),
        mac: m,
        filename: format!(
            "rtw88/rtw8821ce-power-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ),
    }
}
pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
pub(super) struct Envelope {
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    calibration: Arc<calibration8821c::Envelope>,
    indices: [u8; 12],
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 14],
    thermal: [u8; 2],
}
fn factory_limits(factory: &Factory8821c) -> Result<[u8; 2], QError> {
    // Original C21 BTG RFE2/4 substitutes pathB's 2G record for physical RF-A.
    let path = u8::from(matches!(factory.rfe(), 2 | 4));
    let raw = factory.power_path(path).ok_or(QError::Factory)?;
    if raw[0] > 63 || raw[6] > 63 || raw[11] == 255 {
        return Err(QError::Factory);
    }
    let nibble = i16::from(raw[11] & 15);
    let ofdm = i16::from(raw[6]) + if nibble & 8 != 0 { nibble - 16 } else { nibble };
    if ofdm < 0 {
        return Err(QError::Factory);
    }
    Ok([raw[0], ofdm.min(63) as u8]) // C21 factor1, channel1 group0, max_power_index0x3f.
}
impl Source {
    pub(super) fn load(
        self,
        request: Request,
        factory: &Factory8821c,
        calibration: Arc<calibration8821c::Envelope>,
    ) -> Result<Envelope, Error> {
        let limits = factory_limits(factory).map_err(denied)?;
        struct Decode<'a> {
            request: Request,
            calibration: Arc<calibration8821c::Envelope>,
            limits: &'a [u8; 2],
        }
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Envelope, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Envelope::decode(
                        view.bytes,
                        view.signer,
                        *cap,
                        self.request,
                        self.calibration,
                        *self.limits,
                    )
                })())
            }
        }
        match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|cap| cap.derive::<Read>().ok())
                    .ok_or_else(|| denied(QError::Authority))?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode {
                    request,
                    calibration,
                    limits: &limits,
                })
                .map_err(|_| denied(QError::Authority))?
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Envelope::decode(&bytes, signer, cap, request, calibration, limits)
            }
        }
    }
}
impl Envelope {
    pub(super) fn temperature(&self, value: u8) -> Result<(), Error> {
        self.calibration.temperature(value).map_err(denied)?;
        if (self.thermal[0]..=self.thermal[1]).contains(&value) {
            Ok(())
        } else {
            Err(denied(QError::Thermal))
        }
    }
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        request: Request,
        calibration: Arc<calibration8821c::Envelope>,
        limits: [u8; 2],
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| denied(QError::Authority))?;
        signer.ok_or_else(|| denied(QError::Unsigned))?;
        if raw.len() != 160
            || &raw[..4] != b"N21P"
            || raw[4..8] != [1, 0, 160, 0]
            || raw[8..12] != 160u32.to_le_bytes()
            || raw[12..16] != [0xec, 0x10, 0x21, 0xc8]
            || raw[54..56] != [1, 20]
            || &raw[66..68] != b"US"
            || raw[104..] != [0; 56]
        {
            return Err(denied(QError::Format));
        }
        if raw[16..48] != request.identity || raw[48..54] != request.mac {
            return Err(denied(QError::Identity));
        }
        let signed = |at| i16::from_le_bytes([raw[at], raw[at + 1]]);
        let (antenna, ceiling) = (signed(56), signed(58));
        let indices: [u8; 12] = raw[68..80].try_into().unwrap();
        let mut peaks = [0; 14];
        peaks[0] = signed(60);
        peaks[1] = signed(62);
        for (i, peak) in peaks[2..].iter_mut().enumerate() {
            *peak = signed(80 + 2 * i);
        }
        let thermal = [raw[64], raw[65]];
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&ceiling)
            || peaks.iter().any(|peak| !(-512..=256).contains(peak))
            || peaks[1..].iter().any(|peak| *peak > peaks[0])
            || thermal[0] > thermal[1]
            || thermal[1] > 63
            || indices
                .iter()
                .enumerate()
                .any(|(i, &index)| index > 63 || index > limits[usize::from(i >= 4)])
        {
            return Err(denied(QError::Format));
        }
        Ok(Self {
            request,
            cap,
            calibration,
            indices,
            antenna,
            ceiling,
            peaks,
            thermal,
        })
    }
    pub(super) fn matches(&self, request: &Request) -> bool {
        &self.request == request
    }
    fn policy(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.calibration.validate(domain).map_err(denied)?;
        if domain.country_code != *b"US" {
            return Err(denied(QError::Policy));
        }
        let mut limit = self.ceiling.min(80);
        let mut covering = false;
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz >= rule.freq_end_mhz
                || rule.max_bandwidth_mhz < 20
                || rule.flags.bits() & !RegFlags::NO_P2P.bits() != 0
            {
                return Err(denied(QError::Policy));
            }
            covering |= rule.freq_start_mhz <= 2402 && rule.freq_end_mhz >= 2422;
            limit = limit.min(i16::from(rule.max_power_dbm) * 4);
        }
        if !covering || self.peaks.iter().any(|&peak| peak + self.antenna > limit) {
            return Err(denied(QError::Policy));
        }
        Ok(())
    }
    pub(super) fn invoke<T>(
        &self,
        policy: &impl Fn() -> Result<RegulatoryDomain, Error>,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Invoke<'a, P, F> {
            envelope: &'a Envelope,
            policy: &'a P,
            operation: F,
        }
        impl<T, P: Fn() -> Result<RegulatoryDomain, Error>, F: FnOnce() -> Result<T, Error>>
            CapOp<FirmwareBlob, Read> for Invoke<'_, P, F>
        {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.envelope.policy(&(self.policy)()?)?;
                    (self.operation)()
                })())
            }
        }
        self.calibration.invoke(policy, || {
            self.cap
                .invoke(Invoke {
                    envelope: self,
                    policy,
                    operation,
                })
                .map_err(|_| denied(QError::Authority))?
        })
    }
    pub(super) async fn prepare(
        &self,
        io: &mut impl Io,
        policy: impl Fn() -> Result<RegulatoryDomain, Error>,
    ) -> Result<Info, Error> {
        self.invoke(&policy, || {
            io.begin_operating8821c()?;
            let old = io.read32(0x2908)?;
            if old == u32::MAX {
                return Err(Error::Gone);
            }
            io.write32(0xc90, (0x42 << 20) | (old & 0xcffff) | 0x30000)
        })?;
        io.delay_us(13).await;
        io.delay_us(2_000_000).await;
        let thermal = self.invoke(&policy, || {
            let value = io.read32(0x2908)?;
            if value == u32::MAX {
                return Err(Error::Gone);
            }
            let thermal = ((value >> 10) & 63) as u8;
            self.calibration.temperature(thermal).map_err(denied)?;
            if !(self.thermal[0]..=self.thermal[1]).contains(&thermal)
                || io.read32(0x2820)? & 0xfffff != 0
                || io.read32(0x1bf0)? & 0x100ff != 0
            {
                return Err(denied(QError::Thermal));
            }
            Ok(thermal)
        })?;
        for (i, reg) in REGISTERS.into_iter().enumerate() {
            let value = if i < 3 {
                u32::from_le_bytes(self.indices[i * 4..i * 4 + 4].try_into().unwrap())
            } else {
                0
            };
            self.invoke(&policy, || {
                io.write32(reg, value)?;
                if io.read32(reg)? != value {
                    return Err(Error::Prerequisite);
                }
                Ok(())
            })?;
            // Cooperative ownership boundary, not an invented radio settle/done bit.
            narf_scheduler::yield_now().await;
        }
        self.invoke(&policy, || {
            io.write32(0x440, 0x15f)?;
            if io.read32(0x440)? != 0x15f {
                return Err(Error::Prerequisite);
            }
            io.finish_operating8821c()?;
            Ok(Info {
                indices: self.indices,
                thermal,
                response_rates: 0x15f,
                identity: self.request.identity,
            })
        })
    }
}
