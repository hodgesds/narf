// SPDX-License-Identifier: GPL-2.0-or-later
//! Distinct measured originator/burst program. No real qualification is supplied.
use super::{firmware_transport::Error, ht, rx_ba_power};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;

/// Acyclic base: T -> optional R -> H -> L -> chip calibration. Never a Gate.
#[derive(Clone)]
pub(super) enum Base {
    H(Arc<ht::Grant>),
    R(Arc<rx_ba_power::Grant>),
}
impl Base {
    pub(super) fn ht(&self) -> Arc<ht::Grant> {
        match self {
            Self::H(h) => h.clone(),
            Self::R(r) => r.ht(),
        }
    }
    fn limit(&self) -> Result<i16, Error> {
        match self {
            Self::H(h) => h.rx_ba_limit(),
            Self::R(r) => r.limit(),
        }
    }
    fn within(&self, limit: i16) -> bool {
        match self {
            Self::H(h) => h.within(limit),
            Self::R(r) => r.within(limit),
        }
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        match self {
            Self::H(h) => h.invoke(op),
            Self::R(r) => r.invoke(op),
        }
    }
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::H(a), Self::H(b)) => Arc::ptr_eq(a, b),
            (Self::R(a), Self::R(b)) => Arc::ptr_eq(a, b),
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
    hash.update(b"NARF RTW88 exact-chip originator HT20 BE/TID0 BA/burst v1");
    hash.update(&did.to_le_bytes());
    hash.update(&recipe);
    hash.update(&digest);
    match base {
        Base::H(_) => hash.update(b"RX decline H alone"),
        Base::R(r) => {
            let (identity, digest) = r.tx_identity();
            hash.update(b"RX BA R retained");
            hash.update(&identity);
            hash.update(&digest);
        }
    }
    hash.update(b"four independent parked-allocated DMA slots; immutable original QoS26/CCMP before native BD; one bounded BE WP batch; source W2 AGGEN12/DEN20; W3 MAXAGG3 factor0; noTXAMSDU; fixed qualified MCS/GI and nofallback; original per-TID SSN before crypto; actual ADDBA request CCX plus bound peer dialog/TID/window/timeout and RXidle; each MPDU actual requested CCX plus PCI; after acknowledged burst and MACquiet BAR20 at actual next QoS SN with native CCX; DELBA native control CCX; no invented BA bitmap or H2C ACK");
    hash.update(b"source coex MAC retry0808 and AMPDUtime20 exact writes/readbacks; BARretry0801; actual chip TXDMA_PQ_MAP and 16bit FIFO reserved/available proof plus PCI consumed prefix before next burst/key/control; max4MPDU/8191bytes/conservative HT symbol airtime<=4000us; full static thermal0..63/supply/antenna/BT/retry/transient/automatic-response envelope");
    Ok(Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw882{}ce-tx-ba-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
    digest: [u8; 32],
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 20],
    count: u8,
    window: u8,
    bytes: u16,
    airtime: u16,
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
                    let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.base, self.request)
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
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    pub(super) fn allows(&self, c: super::packet_format::Aggregation) -> bool {
        c.valid()
            && usize::from(c.count) <= self.count()
            && c.bytes <= self.bytes
            && c.airtime <= self.airtime
    }
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
            || b.len() != 192
            || b[..4] != *if did == 0xc821 { b"N21T" } else { b"N22T" }
            || b[4..8] != [1, 0, 192, 0]
            || b[8..12] != 192u32.to_le_bytes()
            || b[12..14] != [0xec, 0x10]
            || b[14..16] != did.to_le_bytes()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[68..70] != [0, 63]
            || !(2..=4).contains(&b[70])
            || !(1..=64).contains(&b[71])
            || b[108..] != [0; 84]
        {
            return Err(Error::Prerequisite);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let peaks =
            core::array::from_fn(|i| signed(if i < 4 { 60 + i * 2 } else { 76 + (i - 4) * 2 }));
        let g = Self {
            base,
            request,
            digest: {
                let mut hash = narf_crypto::sha256::Sha256::new();
                hash.update(b);
                hash.finalize()
            },
            cap,
            antenna: signed(56),
            ceiling: signed(58),
            peaks,
            count: b[70],
            window: b[71],
            bytes: u16::from_le_bytes([b[72], b[73]]),
            airtime: u16::from_le_bytes([b[74], b[75]]),
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.peaks.iter().any(|p| !(-512..=256).contains(p))
            || g.peaks[1..].iter().any(|&p| p > g.peaks[0])
            || !(1560..=8191).contains(&g.bytes)
            || !(2500..=4000).contains(&g.airtime)
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    pub(super) fn matches(&self, base: &Base) -> bool {
        self.base.same(base) && request(base).as_ref() == Ok(&self.request)
    }
    pub(super) fn count(&self) -> usize {
        usize::from(self.count)
    }
    pub(super) fn window(&self) -> u8 {
        self.window
    }
    pub(super) fn limits(&self) -> (u16, u16) {
        (self.bytes, self.airtime)
    }
    pub(super) fn protection_identity(&self) -> ([u8; 32], [u8; 32]) {
        (self.request.identity, self.digest)
    }
    pub(super) fn ht(&self) -> Arc<ht::Grant> {
        self.base.ht()
    }
    pub(super) fn limit(&self) -> Result<i16, Error> {
        Ok(self.base.limit()?.min(self.ceiling))
    }
    pub(super) fn within(&self, limit: i16) -> bool {
        self.base.within(limit)
            && self
                .peaks
                .iter()
                .all(|&p| i32::from(p) + i32::from(self.antenna) <= i32::from(limit))
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
}
