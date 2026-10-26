// SPDX-License-Identifier: GPL-2.0-or-later
//! C21 full awake legacy station qualification, distinct from parked N21P.
//! No asset or physical power/response measurement is supplied by this driver.
use super::{calibration8821c::Error as QError, firmware_transport::Error, operating8821c};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::{RegFlags, RegulatoryDomain};
fn denied(error: QError) -> Error {
    Error::Calibration8821c(error)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(power: operating8821c::Info, mac: [u8; 6]) -> Request {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8821CE full awake ch1/20 RF-A native PCI STA legacy CCK1 v1");
    hash.update(&power.identity);
    hash.update(&power.indices);
    hash.update(&power.response_rates.to_le_bytes());
    hash.update(&0x1fu32.to_le_bytes()); // station response mask, distinct from parked15f
    hash.update(b"static awake measured peaks cover all six-bit thermal values 0..63; no adaptive compensation");
    // Literal native program identity, including automatic response policy,
    // thermal trigger/wait, original CAM32 commands and fresh wake handshake.
    // A changed emitting sequence requires a changed externally signed grant.
    for word in [
        0x42u32, 0x30000, 13, 2_000_000, 0x440, 0x1f, 0x670, 0x674, 32, 0x80010000, 8, 1000, 10,
        0x100, 0x200, 0x680, 0xcf, 0x608, 0x630493c0, 0x9000040f, 0x3d9, 0x3da, 0x80, 0x40, 150,
        100, 0x383, 0x10, 0x550, 8, 0x303, 0xf7, 0x100, 0xff, 0x522, 0, 0x610, 0x618, 0x6a8,
        0xa532,
    ] {
        hash.update(&word.to_le_bytes());
    }
    hash.update(b"source C21 channel/RFE/swing; freshRF42; RPWM3d9/CPWM3da fresh toggle; CAM32 invalidate; host CCMP no HW keys; source US static PHY; noC22 DACK/trims/DPD");
    hash.update(b"shared rtw88 PCI TXDESC48 TXBD16 RXDESC24 RXBD8; MGMT128 BE256 RX512; CCX terminal SSN; native FCS/PHY/raw; same-owner completed beacon disarm while parked");
    hash.update(b"port0 MAC610 BSSID618 AID6a8; default awake/RA-onlyCCK1; H2C20 ACTIVE/3 keepalive off/4 disconnect off/40 RA/1 media; EDCA conservative DCF; no HT QoS aggregation autonomous keepalive");
    Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw8821ce-station-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
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
        policy: Arc<narf_wireless::reg::db::Database>,
    },
}
pub(super) struct Grant {
    digest: [u8; 32],
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    power: Arc<operating8821c::Envelope>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 3],
    thermal: [u8; 2],
    #[cfg(any(test, feature = "kernel-test"))]
    model: Option<Arc<narf_wireless::reg::db::Database>>,
}
impl Source {
    pub(super) fn load(
        self,
        request: Request,
        power: Arc<operating8821c::Envelope>,
    ) -> Result<Arc<Grant>, Error> {
        struct Decode {
            request: Request,
            power: Arc<operating8821c::Envelope>,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(view.bytes, view.signer, *cap, self.request, self.power)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|cap| cap.derive::<Read>().ok())
                    .ok_or_else(|| denied(QError::Authority))?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode { request, power })
                    .map_err(|_| denied(QError::Authority))??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified {
                bytes,
                signer,
                cap,
                policy,
            } => {
                let mut grant = Grant::decode(&bytes, signer, cap, request, power)?;
                grant.model = Some(policy);
                grant
            }
        };
        grant.check()?;
        Ok(Arc::new(grant))
    }
}
impl Grant {
    pub(super) fn ht_facts(&self) -> Option<super::ht::Facts> {
        self.power.ht_facts()
    }
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        request: Request,
        power: Arc<operating8821c::Envelope>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| denied(QError::Authority))?;
        signer.ok_or_else(|| denied(QError::Unsigned))?;
        if raw.len() != 128
            || &raw[..4] != b"N21S"
            || raw[4..8] != [1, 0, 128, 0]
            || raw[8..12] != 128u32.to_le_bytes()
            || raw[12..16] != [0xec, 0x10, 0x21, 0xc8]
            || raw[54..56] != [1, 20]
            || &raw[68..70] != b"US"
            || raw[70..] != [0; 58]
        {
            return Err(denied(QError::Format));
        }
        if raw[16..48] != request.identity || raw[48..54] != request.mac {
            return Err(denied(QError::Identity));
        }
        let signed = |at| i16::from_le_bytes([raw[at], raw[at + 1]]);
        let (antenna, ceiling) = (signed(56), signed(58));
        let peaks = [signed(60), signed(62), signed(64)];
        let thermal = [raw[66], raw[67]];
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&ceiling)
            || peaks.iter().any(|p| !(-512..=256).contains(p))
            // This initial static awake profile has no continuous conversion
            // watchdog. A narrow initial sample cannot authorize indefinite
            // firmware automatic responses: the awake measured envelope must
            // cover every possible six-bit meter value, including drift.
            || thermal != [0,63]
        {
            return Err(denied(QError::Format));
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(raw);
        Ok(Self {
            digest: hash.finalize(),
            request,
            cap,
            power,
            antenna,
            ceiling,
            peaks,
            thermal,
            #[cfg(any(test, feature = "kernel-test"))]
            model: None,
        })
    }
    pub(super) fn matches(&self, request: &Request) -> bool {
        &self.request == request
    }
    pub(super) fn own(&self) -> [u8; 6] {
        self.request.mac
    }
    pub(super) fn identity(&self) -> [u8; 32] {
        self.request.identity
    }
    pub(super) fn indices(&self) -> [u8; 12] {
        self.power.indices()
    }
    pub(super) fn extension_request(&self) -> super::station_profile::Request {
        super::station_profile::request_c21(
            self.request.identity,
            self.digest,
            self.indices(),
            self.own(),
        )
    }
    pub(super) fn extension_limit(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        self.power
            .invoke(&|| Ok(domain.clone()), || self.policy_limit(domain))
    }
    fn domain(&self) -> Result<RegulatoryDomain, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(db) = &self.model {
            return db
                .snapshot()
                .map(|d| d.as_ref().clone())
                .ok_or_else(|| denied(QError::Policy));
        }
        narf_wireless::reg::db::get_domain().ok_or_else(|| denied(QError::Policy))
    }
    fn policy(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.policy_limit(domain).map(|_| ())
    }
    fn policy_limit(&self, domain: &RegulatoryDomain) -> Result<i16, Error> {
        if domain.country_code != *b"US" {
            return Err(denied(QError::Policy));
        }
        let mut limit = self.ceiling.min(80);
        let mut covering = false;
        for r in &domain.rules {
            if r.freq_start_mhz >= 2422 || r.freq_end_mhz <= 2402 {
                continue;
            }
            if r.freq_start_mhz >= r.freq_end_mhz
                || r.max_bandwidth_mhz < 20
                || r.flags.bits() & !RegFlags::NO_P2P.bits() != 0
            {
                return Err(denied(QError::Policy));
            }
            covering |= r.freq_start_mhz <= 2402 && r.freq_end_mhz >= 2422;
            limit = limit.min(i16::from(r.max_power_dbm) * 4);
        }
        if !covering || self.peaks.iter().any(|&p| p + self.antenna > limit) {
            return Err(denied(QError::Policy));
        }
        Ok(limit)
    }
    pub(super) fn temperature(&self, value: u8) -> Result<(), Error> {
        self.power.temperature(value)?;
        if (self.thermal[0]..=self.thermal[1]).contains(&value) {
            Ok(())
        } else {
            Err(denied(QError::Thermal))
        }
    }
    /// Every actual operation is enclosed in all three exact source invokes;
    /// installed policy is sampled inside, without a live bootstrap fallback.
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<'a, F> {
            grant: &'a Grant,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.grant.policy(&self.grant.domain()?)?;
                    (self.operation)()
                })())
            }
        }
        self.power.invoke(&|| self.domain(), || {
            self.cap
                .invoke(Live {
                    grant: self,
                    operation,
                })
                .map_err(|_| denied(QError::Authority))?
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
}
