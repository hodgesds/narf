// SPDX-License-Identifier: GPL-2.0-or-later
//! Distinct measured AR9285 NETWORK_SLEEP program. No signed measurements
//! are supplied. Legacy programs remain awake without this exact source.
use super::{
    ht,
    packet::{Error, Port},
};
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
#[path = "ps/hardware.rs"]
pub(super) mod hardware;
#[path = "ps/owner.rs"]
mod owner;
#[path = "ps/tim.rs"]
pub(super) mod tim;
pub(super) use owner::{Action, Owner};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF AR9285 N85S exact20/40 host station NETWORK_SLEEP v1");
    hash.update(&identity);
    hash.update(&digest);
    hash.update(&mac);
    hash.update(&[base.version()]);
    hash.update(&base.geometry().body());
    for child in [
        super::rx_ba::request(base).identity,
        super::tx_ba::request(base).identity,
        super::tx_ba::large_request(base).identity,
        super::qos::request(base).identity,
    ] {
        hash.update(&child);
    }
    hash.update(b"full actual factory/calibration/rate/CTL/occupied span and fixed selected power unchanged; global measured complete temperature/supply/antenna/BT/posture static envelope includes every1..8MPDU/64BAW/3retry/fourAC/eightTID optional source program, management/control/PMNull/PSPoll/automatic response plus actual AWAKE<->NETWORK_SLEEP clock/RXabort/timer/IRQ transients; noFULL_SLEEP no invented physical data");
    hash.update(b"AR9285 noAUTOSLEEP: actual source current+PCI invoke before RTC wake, forcewakeEN+50us and bounded2ms actualON2, rejectSHUTDOWN no coldreset preservation fiction; clearSTA_PWR_SAV before normal MAC/DMA/payload/copy; all actual synth/mode/powers/ADC/IQ/RFsilent/source gates after wake; failure terminal/quarantine retains published DMA");
    hash.update(b"actual TIM wake/IRQcause path: installed MSI vector or existing1ms poll with PCI INTxdisabled; full original current BSSID beacon TIM unique bounded IE/AIDbitmap/DTIMperiod+count/TSF and current primary validation, HWTSF64 stable snapshot, source2+6TU nextTBTT and DTIM alignment,100ms roundup sleep clamp,3TU slop,CABtimeout80,nonauto beaconTimeout1,bmiss10,TSFOOR4240; TSFresync/epoch/peer loss never fabricate sleep");
    hash.update(b"DONT_ENCRYPT supported nonQoS24 ToDS PMNull branch, shared plain nonQoS SC owner WPA2/Open counter, noCCMPPN or key; genuine native ACK+TXidle+RXidle before AP PMstate commit; 16byte PSPoll PM1 durationAID|c000 nativeFrameType2 DurUpdateoff, current own/AP/AID and noPN; actual ACK+authenticated current unfragmented unicast response/MoreData and CAB MoreData/nextbeacon, max8polls per fresh beacon bounded wait");
    hash.update(b"ordinary original DATA/security replies set PM only under current S after independent shared crypto (CCMPAAD masksPM); no shared Null/control crypto widening; PMnotice/PSPoll/security/rekey/BA/originalDMA/copy flags keep awake; source/host/PHY/IRQ loss terminal; setter owns desired config continuation not completed sleep, survives caller return/cancel; old netdev/key/BA/capture generation cannot reopen");
    hash.update(b"bounded8 unpublished recipientBA replies behind actual PS native receipt; drain current key/peer RX to real idle without early BA publication or activation; keyepoch drops queued CPU authority, actual peer DELBA withdraws sameTID reply even if owner created after raw RXcopy; current source/publication/native ACK+RXidle still required; queuedcontrols blockDATA andsleep");
    Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-sta-ps-v1-ch{}-ext{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
pub(super) struct Grant {
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    antenna: i16,
    peak: i16,
    ceiling: i16,
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
                    let view = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(view.bytes, view.signer, *cap, self.0)
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
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<ht::Grant>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let r = request(&base);
        if signer.is_none()
            || bytes.len() != 128
            || bytes[..8] != [b'N', b'8', b'5', b'S', 1, 0, 128, 0]
            || bytes[8..12] != 128u32.to_le_bytes()
            || bytes[12..16] != [0x8c, 0x16, 0x2b, 0]
            || bytes[16..48] != r.identity
            || bytes[48..54] != r.mac
            || bytes[54..58] != base.geometry().body()
            || bytes[64..80]
                != [
                    1,
                    0,
                    0,
                    4,
                    255,
                    8,
                    0xd0,
                    7,
                    0,
                    4,
                    base.version(),
                    1,
                    0,
                    0,
                    0,
                    0,
                ]
            || bytes[80..112] != base.ba_identity().1
            || bytes[112..] != [0; 16]
        {
            return Err(Error::Packet);
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
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        struct Current<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Current<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let (_, base) = self.0.base.ba_limit();
                    let mut limit = base.min(self.0.ceiling);
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
                    (self.1)()
                })())
            }
        }
        self.base.invoke(|| {
            self.cap
                .invoke(Current(self, operation))
                .map_err(|_| Error::Access)?
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn readback(&self, io: &impl Port) -> Result<(), Error> {
        self.check()?;
        self.base.readback(io)
    }
}

pub(super) fn null(own: [u8; 6], ap: [u8; 6], sequence: u16, on: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0x48, if on { 0x11 } else { 1 }, 0, 0];
    bytes.extend_from_slice(&ap);
    bytes.extend_from_slice(&own);
    bytes.extend_from_slice(&ap);
    bytes.extend_from_slice(&((sequence & 4095) << 4).to_le_bytes());
    bytes
}
pub(super) fn poll(own: [u8; 6], ap: [u8; 6], aid: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0xa4, 0x10];
    bytes.extend_from_slice(&(aid | 0xc000).to_le_bytes());
    bytes.extend_from_slice(&ap);
    bytes.extend_from_slice(&own);
    bytes
}
#[cfg(feature = "kernel-test")]
#[path = "ps/tests.rs"]
pub(super) mod tests;
