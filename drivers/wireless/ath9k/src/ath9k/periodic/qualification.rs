// SPDX-License-Identifier: GPL-2.0-or-later
//! Distinct N85P1 global full-program periodic-calibration qualification.
//! No signed production asset or measured board values are supplied.
use super::super::ht;
use super::Error;
#[cfg(feature = "kernel-test")]
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
pub(in crate::ath9k) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF AR9285 N85P full20/40 periodic calibration and ANI v1");
    hash.update(&identity);
    hash.update(&digest);
    hash.update(&mac);
    hash.update(&[base.version()]);
    hash.update(&base.geometry().body());
    for child in [
        super::super::rx_ba::request(base).identity,
        super::super::tx_ba::request(base).identity,
        super::super::tx_ba::large_request(base).identity,
        super::super::qos::request(base).identity,
    ] {
        hash.update(&child);
    }
    hash.update(b"exact current raw factory/calibration/full H body/primary+extension+center and full occupied span, immutable initial receipt never rewritten; one native current dynamic receipt with exact actual IQ/ADC/PA/NF/ANI readbacks, current source+PCI+RFsilent+power before every actual MMIO/DMA/copy; optional RXBA/TBA1..8 and QOS fourAC eightTID retain independent original current sources, per-original PN/SC/key/peer/capture epoch/terminal DMA owners");
    hash.update(b"Linux7.2 link.c/ar9002_calib.c/calib.c/ani.c/ar5008_phy.c/common hw.c: actual station short1000ms until complete, long30000ms or noise-interference1000ms, ANI1000ms, restartvalid1200000ms; admitted P1 always-awake actualRTC_ON2, noS1 or live clock wake authority, existing suspend retires this whole generation; source single-sample log10 measurement, ADCgain/DC only40 ordered gain/DC/IQ, actual DO_CAL running and completion, bounded30s timeout clears bit with no fresh correction; source native u32/signed arithmetic and exact enabled coefficient readback");
    hash.update(b"actual one-chain control and40-extension NF measurement, source9bit sanitize[-127,-108]/nominal-118, actual five-sample history/initial5unfiltered then median, no-update NF measure then actual median load completion before maxCCA-50, bounded222000us failure terminal; actual AR9285 PA7bit comparator program/restores with highpower factory TXGAIN skip, unchanged-offset exponential skip1..8 retains old receipt without fabricating new measurement; ANI actual MIB/PHY/listen counters, bound peer RSSI, source OFDM/CCK level/register transitions and actual receive sensitivity readbacks required, not periodic fixed INI replay");
    hash.update(b"externally measured global conducted upper bound across the complete program, all temperature0..63/supply/static antenna/BT/posture points, all source-possible PAoffset0..127, IQI0..63/Q-16..15, ADC even/odd gain/DC and all source ANI states, during every calibration/median/load/host restore/automatic response/retry/BA/control/PPDU transient; actual per-rate transmit powers remain factory/host/full-span limited; neither a nominal peak nor initial H measurement authorizes dynamic state");
    hash.update(b"asynchronous hardware measurements keep immutable prior coefficients explicitly current until actual host completion; host coefficient/PA/ANI mutations require actual native TX/control idle and RX/MAC quiescence, retain all published DMA and rearm actual same geometry before normal copy/publication; timeout/revocation/cancel/peer/generation loss closes CPU authority and quarantines unproven DMA; no new key, receipt or hardware success from scheduler intent; strict noN85S1 composition, default static programs unchanged when P absent, future qualified PS successor required");
    Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-periodic-v1-ch{}-ext{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            base.channel(),
            base.geometry().secondary().unwrap_or(0),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ),
    }
}
pub(in crate::ath9k) struct Grant {
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    peak: i16,
    ceiling: i16,
}
pub(in crate::ath9k) enum Source {
    Registered,
    #[cfg(feature = "kernel-test")]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    pub fn load(self, base: Arc<ht::Grant>) -> Result<Arc<Grant>, Error> {
        struct Decode(Arc<ht::Grant>);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::parse(self.0, view.bytes, view.signer, *cap)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|cap| cap.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap = narf_firmware::open(&request(&base).filename, &loader)
                    .map_err(|_| Error::Access)?;
                cap.invoke(Decode(base)).map_err(|_| Error::Access)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::parse(base, &bytes, signer, cap)?,
        };
        grant.check()?;
        Ok(Arc::new(grant))
    }
}
impl Grant {
    fn parse(
        base: Arc<ht::Grant>,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let r = request(&base);
        if signer.is_none()
            || bytes.len() != 160
            || bytes[..8] != [b'N', b'8', b'5', b'P', 1, 0, 160, 0]
            || bytes[8..12] != 160u32.to_le_bytes()
            || bytes[12..16] != [0x8c, 0x16, 0x2b, 0]
            || bytes[16..48] != r.identity
            || bytes[48..54] != r.mac
            || bytes[54..58] != base.geometry().body()
            || bytes[88..92] != [base.version(), 1, 0, 0]
            || bytes[92..124] != base.ba_identity().1
            || bytes[124..128] != [10, 1, 64, 128]
            || bytes[128..] != [0; 32]
        {
            return Err(Error::Packet);
        }
        for (at, value) in [
            (64, 1000u32),
            (68, 30000),
            (72, 1200000),
            (76, 1000),
            (80, 30000000),
            (84, 222000),
        ] {
            if bytes[at..at + 4] != value.to_le_bytes() {
                return Err(Error::Packet);
            }
        }
        let signed = |at| i16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let grant = Self {
            base,
            cap,
            antenna: signed(58),
            peak: signed(60),
            ceiling: signed(62),
        };
        if !(0..=128).contains(&grant.antenna)
            || grant.antenna < grant.base.ba_limit().0
            || !(-512..=256).contains(&grant.peak)
            || !(-512..=256).contains(&grant.ceiling)
        {
            return Err(Error::Packet);
        }
        Ok(grant)
    }
    pub fn invoke<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.invoke_under(self.ceiling, operation)
    }
    /// The concrete native owner intersects every actually installed B/T/Q
    /// signed ceiling and retains those independent current invocations around
    /// the same operation. A child's old static peak cannot stand in for the
    /// new complete periodic program's measured upper bound.
    pub fn invoke_under<T>(
        &self,
        installed_ceiling: i16,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Current<'a, F>(&'a Grant, i16, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Current<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let (_, base) = self.0.base.ba_limit();
                    let mut limit = base.min(self.0.ceiling).min(self.1);
                    let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    for rule in &domain.rules {
                        if rule.freq_start_mhz < self.0.base.span().1
                            && rule.freq_end_mhz > self.0.base.span().0
                        {
                            limit = limit.min(i16::from(rule.max_power_dbm) * 2);
                        }
                    }
                    if i32::from(self.0.peak) + i32::from(self.0.antenna) > i32::from(limit) {
                        return Err(Error::Access);
                    }
                    (self.2)()
                })())
            }
        }
        self.base.invoke(|| {
            self.cap
                .invoke(Current(self, installed_ceiling, operation))
                .map_err(|_| Error::Access)?
        })
    }
    pub fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub fn for_base(&self, base: &Arc<ht::Grant>) -> bool {
        Arc::ptr_eq(&self.base, base)
    }
}
