// SPDX-License-Identifier: GPL-2.0-or-later
//! Optional C22 legacy-rate/WMM recipe qualification. No measured asset is
//! supplied. The original N22Cv2 calibration alone never authorizes this path.
use super::{
    firmware_transport::Error,
    power_policy::{self, Gate},
};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::RegulatoryDomain;
fn denied(e: power_policy::Error) -> Error {
    Error::Power(e)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(
    board: [u8; 32],
    calibration: [u8; 32],
    gains: [u8; 2],
    mac: [u8; 6],
) -> Request {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTL8822CE ch1/20 TX-A static legacy12 data + response-bound WMM BE/TID0 v1");
    h.update(&board);
    h.update(&calibration);
    h.update(&gains);
    h.update(b"N22Cv2 retained CCKrefs; OFDMref0; legacydiff0; source phy_get_rrsr_mask(selected_rate)&15f=1f/5f/15f; no new RF calibration or compensation");
    h.update(b"actual bound legacy12 intersection; rateID B8/BG6/G7; H2C40 init1 PTdisabled mask12; fixed highest IEEE kbps data USE_RATE DISDATAFB; mgmt/EAPOL1M");
    h.update(b"WMM1 strict singleton Param; no UAPSD ACM BE; AP-response parameters; source EDCA 500/504/508/50c; SIFS10 slot9/20; BE AIFSN>=3 CWmin>=31 CWmax>=1023 TXOP0; no HT AMPDU BA");
    h.update(b"TXDESC48 TXBD16 RXDESC24 RXBD8; BE queue3a8; raw QoS26 TID0 before software CCMP; security EAPOL24; current signed sources and host policy within publication");
    Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw8822ce-legacy-wmm-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
    request: Request,
    base: power_policy::CalibratedBase,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 14],
    rates: u16,
    wmm: bool,
    #[cfg(any(test, feature = "kernel-test"))]
    model: Option<Arc<narf_wireless::reg::db::Database>>,
}
impl Source {
    pub(super) fn load(self, base: Gate) -> Result<Arc<Grant>, Error> {
        let base = base.calibrated_base().ok_or(Error::Unsupported)?;
        let request = base.request();
        struct Decode {
            base: power_policy::CalibratedBase,
            request: Request,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.request, self.base)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(denied(power_policy::Error::Authority))?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode { base, request })
                    .map_err(|_| denied(power_policy::Error::Authority))??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified {
                bytes,
                signer,
                cap,
                policy,
            } => {
                let mut g = Grant::decode(&bytes, signer, cap, request, base)?;
                g.model = Some(policy);
                g
            }
        };
        grant.check()?;
        Ok(Arc::new(grant))
    }
}
impl Grant {
    fn decode(
        raw: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        request: Request,
        base: power_policy::CalibratedBase,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp)
            .map_err(|_| denied(power_policy::Error::Authority))?;
        signer.ok_or(denied(power_policy::Error::Unsigned))?;
        if raw.len() != 128
            || &raw[..4] != b"N22L"
            || raw[4..8] != [1, 0, 128, 0]
            || raw[8..12] != 128u32.to_le_bytes()
            || raw[12..16] != [0xec, 0x10, 0x22, 0xc8]
            || raw[54..56] != [1, 20]
            || raw[90] & !1 != 0
            || raw[91..] != [0; 37]
        {
            return Err(denied(power_policy::Error::Format));
        }
        if raw[16..48] != request.identity || raw[48..54] != request.mac {
            return Err(denied(power_policy::Error::Identity));
        }
        let signed = |i| i16::from_le_bytes([raw[i], raw[i + 1]]);
        let antenna = signed(56);
        let ceiling = signed(58);
        let peaks = core::array::from_fn(|i| signed(60 + i * 2));
        let rates = u16::from_le_bytes([raw[88], raw[89]]);
        if !(0..=128).contains(&antenna)
            || !(-512..=256).contains(&ceiling)
            || rates & 1 == 0
            || rates & !0xfff != 0
            || peaks
                .iter()
                .enumerate()
                .any(|(i, &v)| (i < 2 || rates & (1 << (i - 2)) != 0) && !(-512..=256).contains(&v))
        {
            return Err(denied(power_policy::Error::Format));
        }
        Ok(Self {
            request,
            base,
            cap,
            antenna,
            ceiling,
            peaks,
            rates,
            wmm: raw[90] != 0,
            #[cfg(any(test, feature = "kernel-test"))]
            model: None,
        })
    }
    pub(super) fn rates(&self) -> u16 {
        self.rates
    }
    pub(super) fn wmm(&self) -> bool {
        self.wmm
    }
    pub(super) fn matches(&self, gate: &Gate) -> bool {
        gate.extension_request().as_ref() == Some(&self.request)
    }
    fn domain(&self) -> Result<RegulatoryDomain, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(d) = &self.model {
            return d
                .snapshot()
                .map(|d| d.as_ref().clone())
                .ok_or(denied(power_policy::Error::Policy));
        }
        narf_wireless::reg::db::get_domain().ok_or(denied(power_policy::Error::Policy))
    }
    fn policy(&self, domain: &RegulatoryDomain) -> Result<(), Error> {
        self.base.current(domain).map_err(denied)?;
        let limit = self.base.eirp().min(self.ceiling);
        if self.peaks.iter().enumerate().any(|(i, &p)| {
            (i < 2 || self.rates & (1 << (i - 2)) != 0)
                && i32::from(p) + i32::from(self.antenna) > i32::from(limit)
        }) {
            return Err(denied(power_policy::Error::Policy));
        }
        Ok(())
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<'a, F> {
            g: &'a Grant,
            op: F,
        }
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    self.g.policy(&self.g.domain()?)?;
                    (self.op)()
                })())
            }
        }
        self.base.invoke(&self.domain()?, || {
            self.cap
                .invoke(Live {
                    g: self,
                    op: operation,
                })
                .map_err(|_| denied(power_policy::Error::Authority))?
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
}
