// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact-chip static HT20/1SS qualification and native gain programming.
//! Sources: rtw88/{rtw8821c,rtw8822c,phy,tx,fw,mac80211}.c. No asset is supplied.
use super::{
    firmware_transport::{Error, Io},
    hardware::Features,
    packet_format::DataProfile,
    station_control::Admission,
    station_profile,
};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub hardware: Features,
    pub maximum: u8,
    pub legacy: [u8; 12],
    pub cck: [u8; 2],
}
impl Facts {
    pub(super) fn capability(self) -> Option<[u8; 26]> {
        self.local()?;
        let mut rx = [0; 10];
        rx[0] = 255;
        LocalHt::new(
            rx,
            rx,
            HtWidth::Twenty,
            HtGi {
                rx20: true,
                tx20: true,
                rx40: false,
                tx40: false,
            },
            0,
            4,
        )
        .ok()
        .map(|h| h.capability_body())
    }
    pub(super) fn local(self) -> Option<LocalPhy> {
        // Source chips implement HT; the actual report may only narrow paths.
        // The initial implementation owns a single stream even on C22 RX-AB.
        (self.hardware.antennas != 0 && self.hardware.streams != 0 && self.hardware.protocol == 3)
            .then(|| local(255, true, 0, 0))
            .flatten()
    }
}
/// `did`/`coding` select the RX/TX coding of `main.c::rtw_init_ht_cap`;
/// did 0 (beacon observation only) advertises no coding.
fn local(tx: u8, sgi: bool, did: u16, coding: u8) -> Option<LocalPhy> {
    let mut rx = [0; 10];
    rx[0] = 255;
    let mut transmit = [0; 10];
    transmit[0] = tx;
    LocalHt::new(
        rx,
        rx,
        HtWidth::Twenty,
        HtGi {
            rx20: true,
            tx20: sgi,
            rx40: false,
            tx40: false,
        },
        0,
        4,
    )
    .map(|h| {
        h.with_ldpc(
            super::coding::rx_ldpc(did),
            coding & super::coding::LDPC != 0,
        )
        .with_rx_stbc(did != 0)
        .with_tx_stbc(coding & super::coding::STBC != 0)
    })
    .and_then(|h| h.with_tx_selection(transmit))
    .ok()
    .and_then(|h| LocalPhy::ht20(h).ok())
}
pub(super) fn factory_limit(p: &[u8], factor: i16, max: u8) -> Option<u8> {
    let base = *p.get(6)?;
    let diff = *p.get(11)?;
    if base > max || diff == 255 {
        return None;
    }
    let n = i16::from(diff >> 4);
    let value = i16::from(base) + (if n & 8 != 0 { n - 16 } else { n }) * factor;
    (value >= 0).then_some(value.min(i16::from(max)) as u8)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &station_profile::Grant) -> Result<Request, Error> {
    let f = base
        .ht_facts()
        .filter(|f| f.local().is_some())
        .ok_or(Error::Unsupported)?;
    if !base.wmm() {
        return Err(Error::Unsupported);
    }
    let (recipe, digest) = base.ht_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF RTW88 exact-chip static HT20 one-stream MCS0..7 LGI/SGI20 v1");
    h.update(&base.did().to_le_bytes());
    h.update(&recipe);
    h.update(&digest);
    h.update(&f.hardware.raw);
    h.update(&[f.maximum]);
    h.update(&f.legacy);
    h.update(&f.cck);
    h.update(if base.did()==0xc821 { b"C21 RF-A absolute1d0c/10; retained legacy12; unusedHT/VHTzero; RF18/RF08/IQK; RF42 SIPIc90 maskfffff trigger30000 wait13+2000000us actualread2908" } else { b"C22 TX-A RX-AB equalOFDMrefs=MCS7; source signed7bit per-rate difference; minAB; unusedrates effective0; retainedCCKrefs" });
    h.update(b"RX PHYST exact32 at24+shift; C21 RXSC/RFMODE no channel; C22 RXSC/current20/reportedchannel1; absentPHY None plus RXD facts; receive epoch fences callbacks and IPC across actual key/reply/close");
    h.update(b"full static raw thermal0..63 supply/antenna/BT envelope; exact source gain writes/readbacks; no tracking or fabricated calibration; transient/response+legacy+8LGI+8SGI measured peaks");
    h.update(b"bound original HT45/61/WMM response; generated localHT20 MCSff RX/TX SGI20 default3839AMSDU; BGN20_1SS3 RA mask12..19 PTdisabled; fixedDATA12..19 USE_RATE DISDATAFB BW0 SGIbit4; BE/TID0 QoS26 before softwareCCMP; originalRAW AMSDU authenticated once; ADDBA status37 nativeCCX; noTXBA");
    let mac = base.own();
    Ok(Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw882{}ce-ht20-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            if base.did() == 0xc821 { 1 } else { 2 },
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
    base: Arc<station_profile::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    facts: Facts,
    indices: [u8; 8],
    peaks: [i16; 30],
    antenna: i16,
    ceiling: i16,
    mcs: u8,
    sgi: bool,
}
impl Source {
    pub(super) fn load(self, base: Arc<station_profile::Grant>) -> Result<Arc<Grant>, Error> {
        let r = request(&base)?;
        struct Decode {
            base: Arc<station_profile::Grant>,
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
                let cap = narf_firmware::open(&r.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode { base, request: r })
                    .map_err(|_| Error::Access)??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, base, r)?,
        };
        g.check()?;
        Ok(Arc::new(g))
    }
}
impl Grant {
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<station_profile::Grant>,
        request: Request,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let facts = base.ht_facts().ok_or(Error::Unsupported)?;
        if signer.is_none()
            || b.len() != 192
            || b[..4]
                != *if base.did() == 0xc821 {
                    b"N21H"
                } else {
                    b"N22H"
                }
            || b[4..8] != [1, 0, 192, 0]
            || b[8..12] != 192u32.to_le_bytes()
            || b[12..14] != [0xec, 0x10]
            || b[14..16] != base.did().to_le_bytes()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [1, 20]
            || b[64..66] != [0, 63]
            || b[66] == 0
            || b[67] & !1 != 0
            || b[132..] != [0; 60]
        {
            return Err(Error::Prerequisite);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let indices = b[68..76].try_into().map_err(|_| Error::Prerequisite)?;
        let peaks = core::array::from_fn(|i| {
            signed(if i < 2 {
                60 + i * 2
            } else if i < 18 {
                76 + (i - 2) * 2
            } else {
                108 + (i - 18) * 2
            })
        });
        let g = Self {
            request,
            digest: {
                let mut h = narf_crypto::sha256::Sha256::new();
                h.update(b);
                h.finalize()
            },
            base,
            cap,
            facts,
            indices,
            peaks,
            antenna: signed(56),
            ceiling: signed(58),
            mcs: b[66],
            sgi: b[67] != 0,
        };
        if !(0..=128).contains(&g.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.indices.iter().any(|&i| i > facts.maximum)
            || g.peaks.iter().any(|&p| !(-512..=256).contains(&p))
            || g.peaks[1..].iter().any(|&p| p > g.peaks[0])
            || g.base.did() == 0xc822
                && (g.indices[7] > 64
                    || g.indices
                        .iter()
                        .any(|&v| !(-64..=63).contains(&(i16::from(v) - i16::from(g.indices[7])))))
        {
            return Err(Error::Prerequisite);
        }
        Ok(g)
    }
    pub(super) fn local(&self) -> LocalPhy {
        self.local_coded(0)
    }
    /// Base RX coding plus the separately qualified N2xC TX `coding` flags.
    pub(super) fn local_coded(&self, coding: u8) -> LocalPhy {
        local(self.mcs, self.sgi, self.base.did(), coding).expect("validated native HT facts")
    }
    pub(super) fn profile(&self, rates: u16, mcs: u8, sgi: bool) -> Result<DataProfile, Error> {
        let p = DataProfile {
            rates,
            qos: true,
            mcs,
            sgi,
            ldpc: false,
            stbc: false,
            acs: 0,
        };
        if !self.allows(p) {
            return Err(Error::Unsupported);
        }
        Ok(p)
    }
    pub(super) fn allows(&self, p: DataProfile) -> bool {
        // TX coding is admitted separately by the bound N2xC continuation.
        p.valid()
            && p.qos
            && !p.ldpc
            && !p.stbc
            && p.rates & !self.base.rates() == 0
            && p.mcs != 0
            && p.mcs & !self.mcs == 0
            && (!p.sgi || self.sgi)
    }
    pub(super) fn mcs(&self) -> u8 {
        self.mcs
    }
    pub(super) fn sgi(&self) -> bool {
        self.sgi
    }
    pub(super) fn matches(&self, b: &station_profile::Grant) -> bool {
        request(b).as_ref() == Ok(&self.request)
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let d = self.0.base.current_domain()?;
                    let limit = self.0.base.ht_limit(&d)?.min(self.0.ceiling);
                    if self
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
    pub(super) fn rx_ba_identity(&self) -> ([u8; 32], [u8; 32], u16) {
        (self.request.identity, self.digest, self.base.did())
    }
    pub(super) fn rx_ba_limit(&self) -> Result<i16, Error> {
        let domain = self.base.current_domain()?;
        Ok(self.base.ht_limit(&domain)?.min(self.ceiling))
    }
    pub(super) fn within(&self, limit: i16) -> bool {
        self.peaks
            .iter()
            .all(|&p| i32::from(p) + i32::from(self.antenna) <= i32::from(limit))
    }
    fn words(&self) -> [u32; 16] {
        let mut bytes = [0; 64];
        let reference = i16::from(self.indices[7]);
        for (rate, b) in bytes.iter_mut().enumerate() {
            let index = if (12..20).contains(&rate) {
                i16::from(self.indices[rate - 12])
            } else {
                0
            };
            *b = if rate < 4 {
                0
            } else {
                ((index - reference) as i8 as u8) & 127
            };
        }
        core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
    }
    pub(super) fn readback(
        &self,
        mut read: impl FnMut(u16) -> Result<u32, Error>,
    ) -> Result<(), Error> {
        if self.base.did() == 0xc821 {
            return super::radio8821c::operating_readback_ht(read, self.facts.legacy, self.indices);
        }
        for (r, v) in [0x18a0, 0x41a0].into_iter().zip(self.facts.cck) {
            if read(r)? >> 16 & 127 != u32::from(v) {
                return Err(Error::Prerequisite);
            }
        }
        for r in [0x18e8, 0x41e8] {
            if read(r)? & 0x1fc00 != u32::from(self.indices[7]) << 10 {
                return Err(Error::Prerequisite);
            }
        }
        for (i, v) in self.words().into_iter().enumerate() {
            if read(0x3a00 + i as u16 * 4)? != v {
                return Err(Error::Prerequisite);
            }
        }
        if read(0x100)? & 0x200 != 0 || read(0x680)? & 0xcf != 0 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    pub(super) async fn program(
        &self,
        io: &mut impl Io,
        admission: &Admission,
    ) -> Result<(), Error> {
        self.check()?;
        // Call only after the retained gate encloses this NEW complete program.
        // C21's actual fresh RF42 conversion is required, never a factory byte.
        if self.base.did() == 0xc821 {
            admission.run(|| {
                io.station_allowed()?;
                let old = io.read32(0x2908)?;
                if old == u32::MAX {
                    return Err(Error::Gone);
                }
                io.write32(0xc90, (0x42 << 20) | (old & 0xfffff & !0x30000) | 0x30000)
            })?;
            io.delay_us(13).await;
            io.delay_us(2_000_000).await;
            admission.run(|| {
                io.station_allowed()?;
                let meter = io.read32(0x2908)?;
                if meter == u32::MAX {
                    return Err(Error::Gone);
                }
                self.base.temperature(((meter >> 10) & 63) as u8)
            })?;
            for (i, chunk) in self.indices.chunks_exact(4).enumerate() {
                let v = u32::from_le_bytes(chunk.try_into().unwrap());
                admission.run(|| {
                    io.station_allowed()?;
                    io.write32(0x1d0c + i as u16 * 4, v)
                })?;
                narf_scheduler::yield_now().await;
            }
        } else {
            for r in [0x18e8, 0x41e8] {
                admission.run(|| {
                    io.station_allowed()?;
                    super::radio::mask(io, 0x1c90, 1 << 15, 0)?;
                    super::radio::mask(io, r, 0x1fc00, u32::from(self.indices[7]))
                })?;
                narf_scheduler::yield_now().await;
            }
            for (i, v) in self.words().into_iter().enumerate() {
                admission.run(|| {
                    io.station_allowed()?;
                    super::radio::mask(io, 0x1c90, 1 << 15, 0)?;
                    io.write32(0x3a00 + i as u16 * 4, v)
                })?;
                narf_scheduler::yield_now().await;
            }
        }
        admission.run(|| {
            io.station_allowed()?;
            self.readback(|r| io.read32(r))
        })
    }
}
/// Bound normal-ACK immediate single-TID ADDBA request. No BA agreement is
/// created by the reply; its actual DMA/radio receipt is still mandatory.
pub(super) fn decline(frame: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() != 33
        || frame[..2] != [0xd0, 0]
        || frame[4..10] != own
        || frame[10..16] != ap
        || frame[16..22] != ap
        || frame[22] & 15 != 0
        || frame[24..26] != [3, 0]
    {
        return None;
    }
    let parameter = u16::from_le_bytes([frame[27], frame[28]]);
    if parameter & 2 == 0 || u16::from_le_bytes([frame[31], frame[32]]) & 15 != 0 {
        return None;
    }
    let mut out = alloc::vec![0xd0, 0, 0, 0];
    out.extend_from_slice(&ap);
    out.extend_from_slice(&own);
    out.extend_from_slice(&ap);
    out.extend_from_slice(&[0, 0, 3, 1, frame[26], 37, 0]);
    out.extend_from_slice(&((parameter & 0x3c) | 2).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    Some(out)
}
