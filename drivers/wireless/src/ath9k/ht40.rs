// SPDX-License-Identifier: GPL-2.0-or-later
//! N85H v3 exact20/40 full-program qualification. No signed board data is
//! supplied. The expected40 receipt comes from the external signer; actual
//! fresh calibration must match it before any40 packet owner is exposed.
use super::{
    calibration::{wide::WideReport, Report},
    channel_width::{Geometry, Permission},
    ht,
    identity::{BringUpError, Identity},
    packet::{Error, Port},
    phy::{
        rates::wide::{wide_plan, WidePlan},
        Prepared,
    },
    EEPROM_4K_BYTES,
};
#[cfg(feature = "kernel-test")]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::association::phy::{HtGi, HtWidth, LocalHt, LocalPhy};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
#[derive(Clone)]
pub(super) struct Facts {
    request: Request,
    base: Arc<ht::Grant>,
    geometry: Geometry,
    report: Report,
    powers: WidePlan,
}
impl Facts {
    pub(super) fn new(
        device: narf_bus::BusDevice,
        identity: Identity,
        prepared: Prepared,
        report: Report,
        image: &[u8; EEPROM_4K_BYTES],
        base: Arc<ht::Grant>,
        geometry: Geometry,
    ) -> Result<Self, BringUpError> {
        if !geometry.is_wide()
            || geometry.control() != report.frequency_mhz
            || image[6] & 8 != 0
            || base.version() > 2
            || base.channel() != geometry.primary()
        {
            return Err(BringUpError::BadIdentity);
        }
        // Reconstruct actual current nominal20 facts; an arbitrary H1/2 cap
        // or a previous calibration report cannot seed a40 transition.
        let current = ht::Facts::new(device, identity, prepared, report, image)?;
        let (base_identity, base_digest, mac) = base.ba_identity();
        if current.request().identity != base_identity {
            return Err(BringUpError::BadIdentity);
        }
        let powers = wide_plan(image, geometry, report.max_power_half_dbm)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF AR9285 N85H complete20/40 exact primary/secondary LGI/SGI40 v3");
        hash.update(&base_identity);
        hash.update(&base_digest);
        hash.update(&mac);
        hash.update(image);
        hash.update(&geometry.body());
        hash.update(&prepared.ini_writes.to_le_bytes());
        hash.update(&[
            u8::from(prepared.high_power_gain),
            u8::from(prepared.xe2_gain),
        ]);
        hash.update(&[powers.increment]);
        for (register, value) in powers.registers {
            hash.update(&register.to_le_bytes());
            hash.update(&value.to_le_bytes());
        }
        hash.update(b"actual cold full reset, identical EEPROM/silicon, INI col3 and modal swSettleHt40, primary20/extension legacy plus RF-center HT40 CTLs/targets/detector, exact PDADC increment no6bitwrap; synth/delta slope/wide spur, turboDYN2040+PRI_CH and joinedEXTCCA");
        hash.update(b"current preflight/full-span source before40 calibration; native40 carrier leakage without20 parallel phase, PA, both NF planes, actual ADC gain/DC and IQ complete, exact signer-supplied actual receipt digest before packet/DMA; no inherited20 receipt authorizes40");
        hash.update(b"management/control20, oneSS HT20LGI/HT40LGI/qualified directionalSGI40, neverSGI20 LDPC TXSTBC; actual RX width/GI/STBC status admission and TX serieswidth/GI, NDBPS40[54,108,162,216,324,432,486,540] duration36+symbols4us orceil3.6us; retry/automatic responses/fullstatic envelope included");
        hash.update(b"peer20 response beforeM2 or DATA: close/capture/key/BA/DMA retire, real full20 reset/calibration, fresh directed discovery+forced20 association; no host width substitute/no reused packet/copy token/no recursion to40; coldnewname/disconnect; all source caps and current host/radio readbacks gate every poll TX/copy");
        hash.update(b"base program noBA noAMPDU noTXAMSDU; distinct B/T/Q3 required and bound to complete H3 body+full40span for recipientBA bounded2MPDUsenderBA fourAC8TID; all preceding v1/v2 exact byte recipes unchanged");
        let request = Request {
            identity: hash.finalize(),
            mac,
            filename: format!(
                "ath9k/ar9285-ht40-v3-ch{}-{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                geometry.primary(),
                if geometry.extension() > geometry.control() {
                    "above"
                } else {
                    "below"
                },
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            ),
        };
        Ok(Self {
            request,
            base,
            geometry,
            report,
            powers,
        })
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    #[cfg(feature = "kernel-test")]
    pub(in crate::ath9k) fn base_digest(&self) -> [u8; 32] {
        self.base.ba_identity().1
    }
}
pub(super) struct Grant {
    facts: Facts,
    cap: Cap<FirmwareBlob, Read>,
    expected: [u8; 32],
    digest: [u8; 32],
    antenna: i16,
    ceiling: i16,
    mcs: u8,
    gi: u8,
    peaks: [i16; 64],
}
impl core::fmt::Debug for Grant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Ht40Grant")
            .field("geometry", &self.facts.geometry)
            .finish_non_exhaustive()
    }
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
                    let view = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(view.bytes, view.signer, *cap, self.0)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|cap| cap.derive::<Read>().ok())
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
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        facts: Facts,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        if signer.is_none()
            || bytes.len() != 384
            || bytes[..8] != [b'N', b'8', b'5', b'H', 3, 0, 0, 1]
            || bytes[8..12] != 384u32.to_le_bytes()
            || bytes[12..16] != [0x8c, 0x16, 0x2b, 0]
            || bytes[16..48] != facts.request.identity
            || bytes[48..54] != facts.request.mac
            || bytes[54..58] != facts.geometry.body()
            || bytes[62] == 0
            || bytes[62] & !facts.base.mcs() != 0
            || bytes[63] & !3 != 0
            || bytes[64..96] == [0; 32]
            || bytes[96..128] != facts.base.ba_identity().1
            || bytes[128..256] != [0; 128]
        {
            return Err(Error::Packet);
        }
        let signed = |at| i16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let grant = Self {
            facts,
            cap,
            expected: bytes[64..96].try_into().unwrap(),
            digest: {
                let mut hash = narf_crypto::sha256::Sha256::new();
                hash.update(bytes);
                hash.finalize()
            },
            antenna: signed(58),
            ceiling: signed(60),
            mcs: bytes[62],
            gi: bytes[63],
            peaks: core::array::from_fn(|index| signed(256 + index * 2)),
        };
        let (antenna, _) = grant.facts.base.ba_limit();
        if !(0..=128).contains(&grant.antenna)
            || grant.antenna < antenna
            || !(-512..=256).contains(&grant.ceiling)
            || grant.peaks.iter().any(|p| !(-512..=256).contains(p))
            || grant.peaks[56..59] != [0; 3]
            || grant.gi & 1 == 0 && grant.peaks[48..56] != [0; 8]
            || grant.peaks.iter().enumerate().any(|(index, p)| {
                !((56..59).contains(&index) || grant.gi & 1 == 0 && (48..56).contains(&index))
                    && *p > grant.peaks[0]
            })
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
                    let domain = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    let current = Permission::from_domain(&domain, self.0.facts.geometry)
                        .map_err(|_| Error::Access)?;
                    // This fixed full program uses the same nominal budget in
                    // both modes. Different20/40 ceilings retain real20 only.
                    if current.country != self.0.facts.report.country
                        || current.ceiling < self.0.facts.report.max_power_half_dbm
                    {
                        return Err(Error::Access);
                    }
                    let (_, base_limit) = self.0.facts.base.ba_limit();
                    let limit = self
                        .0
                        .ceiling
                        .min(base_limit)
                        .min(i16::from(current.ceiling));
                    if i32::from(self.0.peaks[0]) + i32::from(self.0.antenna) > i32::from(limit) {
                        return Err(Error::Access);
                    }
                    (self.1)()
                })())
            }
        }
        self.facts.base.invoke(|| {
            self.cap
                .invoke(Current(self, operation))
                .map_err(|_| Error::Access)?
        })
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn request(&self) -> Request {
        self.facts.request()
    }
    pub(super) fn budget(&self) -> u8 {
        self.facts.report.max_power_half_dbm
    }
    pub(super) fn geometry(&self) -> Geometry {
        self.facts.geometry
    }
    pub(super) fn base(&self) -> Arc<ht::Grant> {
        self.facts.base.clone()
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
        (self.antenna, self.ceiling.min(self.facts.base.ba_limit().1))
    }
    pub(super) fn local(&self) -> LocalPhy {
        let mut mcs = [0; 10];
        mcs[0] = 255;
        let mut selected = [0; 10];
        selected[0] = self.mcs;
        let ht = LocalHt::new(
            mcs,
            mcs,
            HtWidth::TwentyForty,
            HtGi {
                rx20: false,
                tx20: false,
                rx40: self.gi & 2 != 0,
                tx40: self.gi & 1 != 0,
            },
            0,
            6,
        )
        .expect("fixed AR9285 one-chain40")
        .with_rx_stbc(true)
        .with_tx_selection(selected)
        .expect("validated v3 TX subset");
        LocalPhy::ht40(ht).expect("fixed AR9285 full20/40")
    }
    pub(super) fn accept(&self, actual: WideReport) -> Result<(), Error> {
        self.check()?;
        if actual.geometry != self.facts.geometry
            || actual.powers.geometry != self.facts.geometry
            || actual.report.country != self.facts.report.country
            || actual.report.max_power_half_dbm != self.facts.report.max_power_half_dbm
            || actual.powers != self.facts.powers
            || actual.digest() != self.expected
        {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
    pub(super) fn readback(&self, io: &impl Port, actual: WideReport) -> Result<(), Error> {
        self.accept(actual)?;
        for (register, value) in actual.powers.registers {
            if io.read(register)? != value {
                return Err(Error::Descriptor);
            }
        }
        for (register, mask, expected) in [
            (0x9804, 0x7ff, actual.geometry.turbo()),
            (0x8318, u32::MAX, 1),
            (
                0x9874,
                0x3fff_ffff,
                0x3000_0000 | (u32::from(actual.geometry.center()) * 0x10000 / 15),
            ),
            (0x99a4, u32::MAX, 1),
            (0xa39c, u32::MAX, 1),
            (0x832c, u32::MAX, 1),
            (0xa200, u32::MAX, 4),
            (0x24, 1, 0),
            (0x99b4, u32::MAX, actual.adc),
            (
                0x9920,
                0xfff,
                0x800 | (u32::from(actual.report.iq_i) << 5) | (actual.report.iq_q as u32 & 31),
            ),
            (0x8114, u32::MAX, 0x200),
            (0x8340, u32::MAX, 0x380),
        ] {
            if io.read(register)? & mask != expected {
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
