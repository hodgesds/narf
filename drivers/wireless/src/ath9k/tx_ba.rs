// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285-only measured two-MPDU sender BA. Air protocol and original
//! ownership precede native descriptor publication; no firmware offload exists.
use super::{
    ht,
    packet::{Error, Port},
};
#[cfg(feature = "kernel-test")]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
#[path = "tx_ba/protocol.rs"]
mod protocol;
pub(super) use protocol::{Action, Owner, PairPermit};
pub(super) const MAX_AIR: usize = 4095;
pub(super) const RETRIES: u8 = 3;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF AR9285 N85T measured two-MPDU HT20 LGI sender BA v1");
    h.update(&identity);
    h.update(&digest);
    h.update(&mac);
    h.update(b"same rev2 EEPROM/calibration/power/chain1 profile; noSGI20 noLDPC noTXSTBC; actual offered+response min AMPDU factor/max density and WMM/protection; TID0 actual nextQoS SSN, fresh dialog, native ADDBA ACK+RXidle and exact air response, window4..64, TU1024us inactivity; two original QoS26 CCMP packets then DMApad2, first linked to real tail NULL; firstIsAggrMoreAggr AggrLen and PadDelim, lastIsAggr zero rates/tries, first owns duration36+4ceil((8air+22)/NDBPS); max2 frames1550+FCS each/4095air/4ms, min256 padding plus actual density, AR9285 ent_mode0 noOTP60; tailTxDone+queueidle immutable bothDMA and descriptor proofs; actual BAflag/TID/SSN/64bitmap, wrongTID retries all, noBA TxOK terminalmute; max3 immutable original software retries normalACK samePN/SC with Retrybit only; compressed native20 BAR actual TXtail BAflag TID0 SSN TxDone ACK queueidle RXidle before hole advance; genuine senderDELBA; key receive epoch fences, rekey old-keyWaitM3 semantics preserved; stop/cancel/source failure retains published DMA; no checked-in measurements");
    h.update(b"complete static temperature/supply/antenna/BT/posture envelope including every two-frame rate/retry/protection/BAR/DELBA/automatic response and mode transient peak");
    Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-txba-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    }
}
pub(super) struct Grant {
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    peak: i16,
    ceiling: i16,
    window: u8,
}
pub(super) enum Source {
    Registered,
    #[cfg(feature = "kernel-test")]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    pub(super) fn load(self, base: Arc<ht::Grant>) -> Result<Arc<Grant>, Error> {
        struct Decode(Arc<ht::Grant>);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.0)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap = narf_firmware::open(&request(&base).filename, &loader)
                    .map_err(|_| Error::Access)?;
                cap.invoke(Decode(base)).map_err(|_| Error::Access)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, base)?,
        };
        grant.check()?;
        Ok(Arc::new(grant))
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<ht::Grant>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let r = request(&base);
        if signer.is_none()
            || b.len() != 96
            || b[..8] != [b'N', b'8', b'5', b'T', 1, 0, 96, 0]
            || b[8..12] != 96u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, 0x2b, 0]
            || b[16..48] != r.identity
            || b[48..54] != r.mac
            || b[54..58] != [1, 20, 1, 2]
            || !(4..=64).contains(&b[60])
            || b[61] != RETRIES
            || b[64..] != [0; 32]
        {
            return Err(Error::Packet);
        }
        let g = Self {
            base,
            cap,
            peak: i16::from_le_bytes([b[58], b[59]]),
            ceiling: i16::from_le_bytes([b[62], b[63]]),
            window: b[60],
        };
        if !(-512..=256).contains(&g.peak) || !(-512..=256).contains(&g.ceiling) {
            return Err(Error::Packet);
        }
        Ok(g)
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let (antenna, base) = self.0.base.ba_limit();
                    let mut limit = self.0.ceiling.min(base);
                    let d = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    for r in &d.rules {
                        if r.freq_start_mhz < 2422 && r.freq_end_mhz > 2402 {
                            limit = limit.min(i16::from(r.max_power_dbm) * 2);
                        }
                    }
                    if i32::from(self.0.peak) + i32::from(antenna) > i32::from(limit) {
                        return Err(Error::Access);
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
    pub(super) fn readback(&self, io: &impl Port) -> Result<(), Error> {
        self.check()?;
        self.base.readback(io)?;
        if io.read(0x803c)? & !0x400 != 0x17 {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
    pub(super) fn window(&self) -> u8 {
        self.window
    }
}
#[cfg(feature = "kernel-test")]
#[path = "tx_ba/tests.rs"]
pub(super) mod tests;
