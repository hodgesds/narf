// SPDX-License-Identifier: GPL-2.0-or-later
//! Distinct exact-H recipient BA emission authority. No measured asset is supplied.
use super::{firmware_transport::Error, ht};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &ht::Grant) -> Result<Request, Error> {
    base.check()?;
    let (recipe, digest, did) = base.rx_ba_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTW88 exact-chip recipient RX BA v1");
    h.update(&did.to_le_bytes());
    h.update(&recipe);
    h.update(&digest);
    h.update(b"native AP ADDBA success/raw33/CCX+RXidle; bounded opaque postpublication pending prefix tied exact proposal/peer/TID/SSN/capture key+receive epoch; no preproposal or closed capture; request+response AMSDU bit1 required; TID0..7 window<=64 actualSSN; host originalRAW reorder before CCMP/PN; BAR20 compressed; DELBA30;100ms holes/TU inactivity; whole original3839 AMSDUinAMPDU; standalone3839 retained; key/receive epochs; TX AGG0; no BA H2C or CAM ACK");
    h.update(b"unchanged exact-chip MAC/PHY/RCR RAW+PHYST+FCS+VHTDACK/softwarecrypto/noBASSN, chip RXFLTMAP1, BAR retry0801, C22 BAparseroff/ACKtype5 readbacks; measured success/DELBA/automatic compressedBA response and whole transition peaks; full thermal0..63 supply/antenna/BT envelope");
    h.update(b"post-original-MAC-table RXFLTMAP1=ffff on C21 and C22; C21 initial mac_init0fff is overwritten by source MAC table6a2ff/6a3ff; no new filter write");
    let mac = base.request().mac;
    Ok(Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw882{}ce-rx-ba-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
    request: Request,
    digest: [u8; 32],
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    ceiling: i16,
    peaks: [i16; 3],
    window: u8,
    tids: u8,
}
impl Source {
    pub(super) fn load(self, base: Arc<ht::Grant>) -> Result<Arc<Grant>, Error> {
        let request = request(&base)?;
        struct Decode {
            base: Arc<ht::Grant>,
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
        base: Arc<ht::Grant>,
        request: Request,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let did = base.rx_ba_identity().2;
        if signer.is_none()
            || b.len() != 128
            || b[..4] != *if did == 0xc821 { b"N21R" } else { b"N22R" }
            || b[4..8] != [1, 0, 128, 0]
            || b[8..12] != 128u32.to_le_bytes()
            || b[12..14] != [0xec, 0x10]
            || b[14..16] != did.to_le_bytes()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[66..68] != [0, 63]
            || !(1..=64).contains(&b[68])
            || b[69] == 0
            || b[70..] != [0; 58]
        {
            return Err(Error::Prerequisite);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let g = Self {
            request,
            digest: {
                let mut h = narf_crypto::sha256::Sha256::new();
                h.update(b);
                h.finalize()
            },
            base,
            cap,
            antenna: signed(56),
            ceiling: signed(58),
            peaks: [signed(60), signed(62), signed(64)],
            window: b[68],
            tids: b[69],
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.peaks.iter().any(|p| !(-512..=256).contains(p))
            || g.peaks[1..].iter().any(|&p| p > g.peaks[0])
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    pub(super) fn matches(&self, base: &ht::Grant) -> bool {
        core::ptr::eq(self.base.as_ref(), base) && request(base).as_ref() == Ok(&self.request)
    }
    pub(super) fn tx_identity(&self) -> ([u8; 32], [u8; 32]) {
        (self.request.identity, self.digest)
    }
    pub(super) fn ht(&self) -> Arc<ht::Grant> {
        self.base.clone()
    }
    pub(super) fn limit(&self) -> Result<i16, Error> {
        Ok(self.base.rx_ba_limit()?.min(self.ceiling))
    }
    pub(super) fn within(&self, limit: i16) -> bool {
        self.base.within(limit)
            && self
                .peaks
                .iter()
                .all(|&p| i32::from(p) + i32::from(self.antenna) <= i32::from(limit))
    }
    pub(super) fn window(&self, tid: u8) -> Option<u8> {
        (tid < 8 && self.tids & (1 << tid) != 0).then_some(self.window)
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let limit = self.0.limit()?;
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
        self.base.invoke(|| {
            self.cap
                .invoke(Live(self, operation))
                .map_err(|_| Error::Access)?
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
}
