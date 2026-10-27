// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact qualified source RTS descriptor program; no CTS-to-self inference.
use super::{firmware_transport::Error, ht, rx_ba_power, tx_ba_power};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicU32, Ordering};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;

#[derive(Clone)]
pub(super) enum Base {
    H(Arc<ht::Grant>),
    R(Arc<rx_ba_power::Grant>),
    T(Arc<tx_ba_power::Grant>),
}
impl Base {
    pub(super) fn ht(&self) -> Arc<ht::Grant> {
        match self {
            Self::H(h) => h.clone(),
            Self::R(r) => r.ht(),
            Self::T(t) => t.ht(),
        }
    }
    fn limit(&self) -> Result<i16, Error> {
        match self {
            Self::H(h) => h.rx_ba_limit(),
            Self::R(r) => r.limit(),
            Self::T(t) => t.limit(),
        }
    }
    fn within(&self, limit: i16) -> bool {
        match self {
            Self::H(h) => h.within(limit),
            Self::R(r) => r.within(limit),
            Self::T(t) => t.within(limit),
        }
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        match self {
            Self::H(h) => h.invoke(op),
            Self::R(r) => r.invoke(op),
            Self::T(t) => t.invoke(op),
        }
    }
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::H(a), Self::H(b)) => Arc::ptr_eq(a, b),
            (Self::R(a), Self::R(b)) => Arc::ptr_eq(a, b),
            (Self::T(a), Self::T(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &Base) -> Result<Request, Error> {
    base.invoke(|| Ok(()))?;
    let h = base.ht();
    let (recipe, digest, did) = h.rx_ba_identity();
    let mac = h.request().mac;
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTW88 exact-chip retained HT20 source RTS threshold v1");
    hash.update(&did.to_le_bytes());
    hash.update(&recipe);
    hash.update(&digest);
    match base {
        Base::H(_) => hash.update(b"H no BA"),
        Base::R(r) => {
            let (id, d) = r.tx_identity();
            hash.update(b"R recipient");
            hash.update(&id);
            hash.update(&d);
        }
        Base::T(t) => {
            let (id, d) = t.protection_identity();
            hash.update(b"T originator over exact H/R");
            hash.update(&id);
            hash.update(&d);
        }
    }
    hash.update(b"source tx.c fixed RTS24M8 W3USE_RTSbit12 W4RTSRATE28:24 W5DATA_RTS_SHORTbit12; eligible ordinary DATA only MPDUlen>configured threshold; actual negotiated24M support; initialdisabled; actual retained queue MACquiet and source invokes before setting; original QoS/header/CCMP/sequence unchanged; static thermal0..63 supply/antenna/BT/transient/retry/RTS/CTS/automatic response envelope; no CTS-to-self or HT protection-mode inference");
    hash.update(b"mgmt/control/private EAPOL never RTS; single RTS DATA requests exact native CCX plus PCI consumption and original DMA-byte comparison; actual BE+MGMT FIFO quiet bounded1s before next TX/key/setting; T burst retains each MPDU CCX and same exact source BAR20/DELBA/R readbacks; held/cancel/error pins all published DMA");
    Ok(Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw882{}ce-rts-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            if did == 0xc821 { 1 } else { 2 },
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ),
    })
}
pub(super) fn registered_base(gate: &super::power_policy::Gate) -> Result<Base, Error> {
    if let Some(base) = gate.protection_base() {
        return Ok(base);
    }
    let l = match gate.ht_base() {
        Some(l) => l,
        None => super::station_profile::Source::Registered.load(gate.clone())?,
    };
    let h = ht::Source::Registered.load(l)?;
    let tbase = match rx_ba_power::Source::Registered.load(h.clone()).ok() {
        Some(r) => tx_ba_power::Base::R(r),
        None => tx_ba_power::Base::H(h),
    };
    match tx_ba_power::Source::Registered.load(tbase.clone()).ok() {
        Some(t) => Ok(Base::T(t)),
        None => Ok(match tbase {
            tx_ba_power::Base::H(h) => Base::H(h),
            tx_ba_power::Base::R(r) => Base::R(r),
        }),
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
pub(super) struct Grant {
    base: Base,
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 4],
    minimum: u16,
    threshold: AtomicU32,
}
impl Source {
    pub(super) fn load(self, base: Base) -> Result<Arc<Grant>, Error> {
        let request = request(&base)?;
        struct Decode {
            base: Base,
            request: Request,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(view.bytes, view.signer, *cap, self.base, self.request)
                })())
            }
        }
        let g = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode { base, request })
                    .map_err(|_| Error::Access)??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Grant::decode(&bytes, signer, cap, base, request)?
            }
        };
        g.check()?;
        Ok(Arc::new(g))
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Base,
        request: Request,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let did = base.ht().rx_ba_identity().2;
        if signer.is_none()
            || b.len() != 128
            || b[..4] != *if did == 0xc821 { b"N21X" } else { b"N22X" }
            || b[4..8] != [1, 0, 128, 0]
            || b[8..12] != 128u32.to_le_bytes()
            || b[12..14] != [0xec, 0x10]
            || b[14..16] != did.to_le_bytes()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[68..70] != [0, 63]
            || b[72..] != [0; 56]
        {
            return Err(Error::Prerequisite);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let g = Self {
            base,
            request,
            cap,
            antenna: signed(56),
            ceiling: signed(58),
            peaks: core::array::from_fn(|i| signed(60 + i * 2)),
            minimum: u16::from_le_bytes([b[70], b[71]]),
            threshold: AtomicU32::new(u32::MAX),
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.peaks.iter().any(|p| !(-512..=256).contains(p))
            || g.peaks[1..].iter().any(|p| *p > g.peaks[0])
            || g.minimum > 2347
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    pub(super) fn matches(&self, base: &Base) -> bool {
        self.base.same(base) && request(base).as_ref() == Ok(&self.request)
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let limit = self.0.base.limit()?.min(self.0.ceiling);
                    if !self.0.base.within(limit)
                        || self
                            .0
                            .peaks
                            .iter()
                            .any(|&p| i32::from(p) + i32::from(self.0.antenna) > i32::from(limit))
                    {
                        return Err(Error::Prerequisite);
                    }
                    (self.1)()
                })())
            }
        }
        self.base
            .invoke(|| self.cap.invoke(Live(self, op)).map_err(|_| Error::Access)?)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn threshold(&self) -> u32 {
        self.threshold.load(Ordering::Acquire)
    }
    /// Caller holds the retained station/packet owner and proves native idle.
    pub(super) fn set(&self, threshold: u32, rates: u16) -> Result<(), Error> {
        self.invoke(|| {
            if threshold != u32::MAX
                && (!(u32::from(self.minimum)..=2347).contains(&threshold) || rates & (1 << 8) == 0)
            {
                return Err(Error::Unsupported);
            }
            self.threshold.store(threshold, Ordering::Release);
            Ok(())
        })
    }
}
/// Only the current native Port supplies this separately qualified setting.
pub(super) fn descriptor(d: &mut [u8; 48], length: usize, threshold: Option<u32>) {
    if threshold.is_some_and(|n| length as u64 > u64::from(n)) {
        for (at, bits) in [(12, 1 << 12), (16, 8 << 24), (20, 1 << 12)] {
            let old = u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
            d[at..at + 4].copy_from_slice(&(old | bits).to_le_bytes());
        }
    }
}
