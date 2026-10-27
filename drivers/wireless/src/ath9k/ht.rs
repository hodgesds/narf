// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285-only optional measured HT20/1SS long-GI qualification.
//! No measurement or signed asset is supplied by this implementation.
use super::{
    calibration::{Permission, Report},
    identity::{BringUpError, Identity},
    packet::{Error, Port},
    phy::{self, Prepared},
    EEPROM_4K_BYTES,
};
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy, Negotiated, Offer, Width};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone)]
pub(super) struct Facts {
    request: Request,
    pub report: Report,
    pub powers: [(u64, u32); 7],
    antenna: u8,
}
impl Facts {
    pub(super) fn new(
        device: narf_bus::BusDevice,
        id: Identity,
        base: Prepared,
        report: Report,
        image: &[u8; EEPROM_4K_BYTES],
    ) -> Result<Self, BringUpError> {
        // EEPROM disable flags are negative capabilities, not positive HT bits.
        if device.id.vendor != 0x168c
            || device.id.device != 0x002b
            || id.revision != 2
            || id.tx_chainmask != 1
            || id.rx_chainmask != 1
            || !id.ht20(image)
            || base.reference_frequency != 2412
            || report.frequency_mhz != 2412
        {
            return Err(BringUpError::BadIdentity);
        }
        let powers = phy::rates::checked_plan(image, report.max_power_half_dbm)?.registers;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF AR9285 N85H measured static HT20 LGI one-chain v1");
        h.update(b"AR9285 rev2 source RX STBC1 only; exact advertised local HT RX_STBC1 and actual AP TX_STBC offer/response bind per-MPDU native AR_STBC; chain1 TX STBC stays zero; no SGI20");
        h.update(b"native HT/ERP protection: exact offer+response and later current AP beacon, sticky RTS/CTS required, negotiated CCK basic long preamble, ctl0 RTS bit22 and first series RTSCTSQual bit15 with native packet duration, no simultaneous CTS-only; current native ownership unchanged");
        h.update(b"independent Open/secured QoS TID sequence spaces across key replies; legacy management sequence is separate; current receive authorization independent of ordinary TX credit");
        for v in [
            device.id.vendor,
            device.id.device,
            device.id.subsystem_vendor,
            device.id.subsystem_id,
            id.eeprom_version,
        ] {
            h.update(&v.to_le_bytes());
        }
        h.update(&[id.revision, image[6], id.rx_chainmask, id.tx_chainmask]);
        h.update(&id.mac);
        h.update(image);
        h.update(&[u8::from(base.high_power_gain), u8::from(base.xe2_gain)]);
        h.update(&base.ini_writes.to_le_bytes());
        h.update(&report.country);
        h.update(&[
            report.max_power_half_dbm,
            report.pa_offset.unwrap_or(255),
            report.iq_i,
            report.iq_q as u8,
        ]);
        h.update(&report.measured_noise_dbm.to_le_bytes());
        h.update(&report.noise_dbm.to_le_bytes());
        for (r, v) in powers {
            h.update(&r.to_le_bytes());
            h.update(&v.to_le_bytes());
        }
        h.update(&local(255).expect("constant local HT").1);
        h.update(b"AR9002 complete RAW3839; QoS26 CCMP original then DMApad2; FCS4; fixedMCS0..7 code80..87 widthGIzero chain1 duration36+4ceil((8wire+22)/NDBPS); legacycontrol/retry preserved; original keycacheinvalid; noBA noAMPDU noTXAMSDU; ADDBA37 nativeACK-idle; BE EDCA CW<=1023 AIFS<=15 TXOP0; nonEDMA nulltail bufhold 4092 RX IRQmasked1ms; receive-time port and monotonic reply/callback epoch");
        h.update(b"complete static temperature/supply/antenna/BT/posture envelope; calibration+legacy+responses+8MCS+retry/transient peaks; no fabricated tracking");
        let request = Request {
            identity: h.finalize(),
            mac: id.mac,
            filename: format!(
                "ath9k/ar9285-ht20-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                id.mac[0], id.mac[1], id.mac[2], id.mac[3], id.mac[4], id.mac[5]
            ),
        };
        Ok(Self {
            request,
            report,
            powers,
            antenna: image[60],
        })
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
}
fn local(mask: u8) -> Option<(LocalPhy, [u8; 26])> {
    let mut m = [0; 10];
    m[0] = 255;
    let mut selected = [0; 10];
    selected[0] = mask;
    // hw.c only grants SGI20 to AR9287+/AR9271, never AR9285.
    let ht = LocalHt::new(m, m, HtWidth::Twenty, HtGi::default(), 0, 6)
        .ok()?
        .with_rx_stbc(true)
        .with_tx_selection(selected)
        .ok()?;
    Some((LocalPhy::ht20(ht).ok()?, ht.capability_body()))
}
pub(super) struct Grant {
    facts: Facts,
    cap: Cap<FirmwareBlob, Read>,
    peaks: [i16; 21],
    antenna: i16,
    ceiling: i16,
    mcs: u8,
    digest: [u8; 32],
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
    pub(super) fn load(self, facts: Facts) -> Result<Arc<Grant>, Error> {
        struct Decode(Facts);
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
                let cap = narf_firmware::open(&facts.request.filename, &loader)
                    .map_err(|_| Error::Access)?;
                cap.invoke(Decode(facts)).map_err(|_| Error::Access)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, facts)?,
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
        facts: Facts,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        if signer.is_none()
            || b.len() != 160
            || b[..8] != [b'N', b'8', b'5', b'H', 1, 0, 160, 0]
            || b[8..12] != 160u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, 0x2b, 0]
            || b[16..48] != facts.request.identity
            || b[48..54] != facts.request.mac
            || b[54..58] != [1, 20, 1, 0]
            || b[62] == 0
            || b[63] != 0
            || b[106..] != [0; 54]
        {
            return Err(Error::Packet);
        }
        let signed = |at| i16::from_le_bytes([b[at], b[at + 1]]);
        let g = Self {
            digest: {
                let mut hash = narf_crypto::sha256::Sha256::new();
                hash.update(b);
                hash.finalize()
            },
            facts,
            cap,
            antenna: signed(58),
            ceiling: signed(60),
            mcs: b[62],
            peaks: core::array::from_fn(|i| signed(64 + i * 2)),
        };
        if !(0..=128).contains(&g.antenna)
            || g.antenna < i16::from(g.facts.antenna)
            || !(-512..=256).contains(&g.ceiling)
            || g.peaks.iter().any(|p| !(-512..=256).contains(p))
            || g.peaks[1..].iter().any(|p| *p > g.peaks[0])
        {
            return Err(Error::Packet);
        }
        Ok(g)
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
                    let d = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    let p = Permission::from_domain(&d).map_err(|_| Error::Access)?;
                    if !p.allows_report(self.0.facts.report) {
                        return Err(Error::Access);
                    }
                    let mut ceiling = self.0.ceiling;
                    for r in &d.rules {
                        if r.freq_start_mhz < 2422 && r.freq_end_mhz > 2402 {
                            ceiling = ceiling.min(i16::from(r.max_power_dbm) * 2);
                        }
                    }
                    if self
                        .0
                        .peaks
                        .iter()
                        .any(|p| i32::from(*p) + i32::from(self.0.antenna) > i32::from(ceiling))
                    {
                        return Err(Error::Access);
                    }
                    (self.1)()
                })())
            }
        }
        self.cap
            .invoke(Live(self, operation))
            .map_err(|_| Error::Access)?
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn local(&self) -> LocalPhy {
        local(self.mcs).expect("validated HT mask").0
    }
    pub(super) fn mcs(&self) -> u8 {
        self.mcs
    }
    pub(super) fn ba_identity(&self) -> ([u8; 32], [u8; 32], [u8; 6]) {
        (
            self.facts.request.identity,
            self.digest,
            self.facts.request.mac,
        )
    }
    pub(super) fn ba_limit(&self) -> (i16, i16) {
        (self.antenna, self.ceiling)
    }
    pub(super) fn readback(&self, io: &impl Port) -> Result<(), Error> {
        self.check()?;
        for (r, v) in self.facts.powers {
            if io.read(r)? != v {
                return Err(Error::Descriptor);
            }
        }
        for (r, mask, v) in [
            (0x9804, 0x7ff, 0x3c0),
            (0x99a4, u32::MAX, 1),
            (0xa39c, u32::MAX, 1),
            (0x832c, u32::MAX, 1),
            (0xa200, u32::MAX, 4),
            (0x24, 1, 0),
            (0x8114, u32::MAX, 0x200),
            (0x8340, u32::MAX, 0x380),
        ] {
            if io.read(r)? & mask != v {
                return Err(Error::Descriptor);
            }
        }
        for entry in 0..128u64 {
            if io.read(0x8800 + entry * 32 + 28)? & 0x8000 != 0 {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) struct Profile {
    mcs: u8,
    be: narf_wireless::wmm::Ac,
    rx_stbc: bool,
    rts: bool,
}
impl Profile {
    pub(super) fn mcs(self) -> u8 {
        self.mcs
    }
    pub(super) fn be(self) -> narf_wireless::wmm::Ac {
        self.be
    }
    pub(super) fn rx_stbc(self) -> bool {
        self.rx_stbc
    }
    pub(super) fn rts(self) -> bool {
        self.rts
    }
    pub(super) fn observe(
        mut self,
        offer: &Offer,
        ies: &[u8],
        basic: usize,
    ) -> Result<Self, Error> {
        if offer.width() != Width::Twenty
            || offer.ht().operation().secondary().is_some()
            || contention(ies)? != self.be
            || self.mcs & !offer.ht().tx_mcs()[0] != 0
        {
            return Err(Error::Packet);
        }
        self.rts |= offer.ht().operation().protection() != 0 || erp_protection(ies)?;
        if self.rts && basic >= 4 {
            return Err(Error::Packet);
        }
        self.rx_stbc &= offer.ht().peer_capability() & 0x80 != 0;
        Ok(self)
    }
}
pub(super) fn response(
    offer: &Offer,
    n: &Negotiated,
    offer_ies: &[u8],
    ies: &[u8],
    basic: usize,
) -> Result<Profile, Error> {
    if n.width() != Width::Twenty
        || n.ht().operation().secondary().is_some()
        || n.ht().tx_sgi20()
        || n.ht().rx_sgi20()
    {
        return Err(Error::Packet);
    }
    let be = contention(ies)?;
    let tx = n.ht().tx_mcs();
    if tx[0] == 0 || tx[1..].iter().any(|v| *v != 0) {
        return Err(Error::Packet);
    }
    let rts = offer.ht().operation().protection() != 0
        || n.ht().operation().protection() != 0
        || erp_protection(offer_ies)?
        || erp_protection(ies)?;
    // A CCK basic control rate makes the whole RTS/CTS exchange visible to
    // non-ERP members. Do not silently use an OFDM-only protection exchange.
    if rts && basic >= 4 {
        return Err(Error::Packet);
    }
    Ok(Profile {
        mcs: tx[0],
        be,
        rx_stbc: n.ht().rx_stbc()
            && offer.ht().peer_capability() & n.ht().peer_capability() & 0x80 != 0,
        rts,
    })
}
pub(super) fn contention(ies: &[u8]) -> Result<narf_wireless::wmm::Ac, Error> {
    erp_protection(ies)?;
    let w = narf_wireless::wmm::Parameters::parse(ies)
        .map_err(|_| Error::Packet)?
        .ok_or(Error::Packet)?;
    let be = w.ac[0];
    if w.uapsd || be.admission_control || be.cw_min() > 1023 || be.cw_max() > 1023 || be.txop != 0 {
        return Err(Error::Packet);
    }
    Ok(be)
}
fn erp_protection(ies: &[u8]) -> Result<bool, Error> {
    let mut remaining = ies;
    let mut erp = None;
    while !remaining.is_empty() {
        let length = 2 + usize::from(*remaining.get(1).ok_or(Error::Packet)?);
        let ie = remaining.get(..length).ok_or(Error::Packet)?;
        if ie[0] == 42 {
            if erp.is_some() || ie.len() != 3 || ie[2] & 0xf8 != 0 {
                return Err(Error::Packet);
            }
            erp = Some(ie[2] & 2 != 0);
        }
        remaining = &remaining[length..];
    }
    Ok(erp.unwrap_or(false))
}
pub(super) fn decline(f: &[u8], own: [u8; 6], ap: [u8; 6]) -> Option<Vec<u8>> {
    if f.len() != 33
        || f[..2] != [0xd0, 0]
        || f[4..10] != own
        || f[10..16] != ap
        || f[16..22] != ap
        || f[22] & 15 != 0
        || f[24..26] != [3, 0]
    {
        return None;
    }
    let p = u16::from_le_bytes([f[27], f[28]]);
    if p & 2 == 0 || u16::from_le_bytes([f[31], f[32]]) & 15 != 0 {
        return None;
    }
    let mut out = alloc::vec![0xd0, 0, 0, 0];
    out.extend_from_slice(&ap);
    out.extend_from_slice(&own);
    out.extend_from_slice(&ap);
    out.extend_from_slice(&[0, 0, 3, 1, f[26], 37, 0]);
    out.extend_from_slice(&((p & 0x3c) | 2).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    Some(out)
}

#[cfg(feature = "kernel-test")]
#[path = "ht/tests.rs"]
pub(super) mod tests;
