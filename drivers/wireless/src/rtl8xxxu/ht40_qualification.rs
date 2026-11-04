// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed v2 full-program qualification. Neither this parser nor selected gains
//! prove that a native receiver has programmed a40MHz RF/BB state or cut RX.
use super::ht40_geometry::Geometry;
use super::{Error, Executable, Proof, Request};
use crate::rtl8xxxu::device_init::Factory;
use alloc::{format, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};

pub(super) const HEADER: usize = 192;
pub(super) const ROWS: usize = 10;
pub(super) const LENGTH: usize = HEADER + ROWS * 64 * 2;
const UNKNOWN: i16 = i16::MAX;

/// This binds the unchanged v1 RECIPE, not a fabricated copy of v1 measured
/// data. V2 owns explicit full-program bounds for both20/40MHz LGI states;
/// no v1 measured-data file is required merely to parse a new v2 record.
pub(in crate::rtl8xxxu) fn request(
    base: &Proof,
    executable: Executable,
    geometry: Geometry,
) -> Request {
    let (factory, legacy_digest, _) = base.calibration().binding();
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8188EU USB HT20+40 LGI SISO full-program2");
    hash.update(&factory);
    hash.update(&legacy_digest);
    hash.update(&executable.digest);
    hash.update(&geometry.binding_bytes());
    hash.update(&super::request(base, executable).binding);
    hash.update(b"primary factory group; EU zero HT20/HT40/OFDM diffs; BW603.2=0; FPGA800/900.0=1; RRSR440.21/22; CCKa00.4; OFDMd00.10/11; FPGA818.26/27; RF18 center primary+/-2 BW400; native readback and real old RXDMA/USB/MAC-FIFO retirement even same primary; v3 QoS BW25 prime20/21, LGI, host SN/RA/PT/fallback, software CCMP; current complete40 span and exact native receive/callback owner; v2 CCK/OFDM peaks plus8MCS peaks cover20+40 states, legacy/autonomous responses, antenna, static LC/IQK supply thermal0..63; no tracking, SGI,2SS or inferred dBm");
    let mac = &factory[8..14];
    Request {
        name: format!(
            "rtl8xxxu/rtl8188eu-ht40-lgi-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-p{}-s{}.bin",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            geometry.primary(),
            geometry.secondary(),
        ),
        binding: hash.finalize(),
    }
}

/// Opaque selected dimensions, NOT an actual native programming receipt.
/// Native wiring must retain this exact qualification and physical epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtl8xxxu) struct Gains {
    geometry: Geometry,
    record: [u8; 32],
    cck: u8,
    ofdm: u8,
    mcs: [u8; 8],
}
impl Gains {
    pub(in crate::rtl8xxxu) fn cck(&self) -> u8 {
        self.cck
    }
    pub(in crate::rtl8xxxu) fn ofdm(&self) -> u8 {
        self.ofdm
    }
    pub(in crate::rtl8xxxu) fn mcs(&self) -> [u8; 8] {
        self.mcs
    }
}

pub(in crate::rtl8xxxu) struct Qualification {
    base: Arc<Proof>,
    executable: Executable,
    cap: Cap<FirmwareBlob, Read>,
    factory: Factory,
    geometry: Geometry,
    record: [u8; 32],
    antenna: i16,
    ceiling: i16,
    curves: [[i16; 64]; ROWS],
}
impl Qualification {
    pub(in crate::rtl8xxxu) fn registered(
        base: Arc<Proof>,
        executable: Executable,
        factory: Factory,
        geometry: Geometry,
    ) -> Result<Option<Arc<Self>>, Error> {
        if base.permission().channel() != geometry.primary() {
            return Err(Error::State);
        }
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
            .ok_or(Error::Policy)?;
        let source = match crate::firmware_asset::load(
            &loader,
            &request(&base, executable, geometry).name,
            LENGTH,
            true,
        ) {
            Ok(source) => source,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(error) => {
                return Err(Error::Control(
                    crate::rtl8xxxu::firmware_transport::Error::Firmware(error),
                ))
            }
        };
        Self::parse(
            base,
            executable,
            factory,
            geometry,
            &source.bytes,
            source.signer,
            source.cap,
        )
        .map(|qualification| Some(Arc::new(qualification)))
    }
    pub(in crate::rtl8xxxu) fn parse(
        base: Arc<Proof>,
        executable: Executable,
        factory: Factory,
        geometry: Geometry,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        let (identity, legacy_digest, minimum_antenna) = base.calibration().binding();
        let vid = u16::from_le_bytes([identity[0], identity[1]]);
        let pid = u16::from_le_bytes([identity[2], identity[3]]);
        if signer.is_none()
            || bytes.len() != LENGTH
            || base.permission().channel() != geometry.primary()
            || crate::rtl8xxxu::power_policy::factory_bytes(factory, vid, pid) != identity
            || bytes[..4] != *b"N8HT"
            || bytes[4..8] != [2, 0, 192, 0]
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize != LENGTH
            || bytes[12..16] != identity[..4]
            || bytes[16..48] != request(&base, executable, geometry).binding
            || bytes[48..77] != identity
            || bytes[77..80] != [0; 3]
            || bytes[80..112] != legacy_digest
            || bytes[112..118] != identity[8..14]
            || bytes[118..124] != geometry.binding_bytes()
            || bytes[128..160] != super::request(&base, executable).binding
            || bytes[160..HEADER] != [0; 32]
        {
            return Err(Error::State);
        }
        let group = geometry.primary_factory_group();
        if factory.cck_power[group] > 63 || factory.ht40_power[group] > 63 {
            return Err(Error::State);
        }
        let antenna = i16::from_le_bytes(bytes[124..126].try_into().unwrap());
        let ceiling = i16::from_le_bytes(bytes[126..128].try_into().unwrap());
        if !(minimum_antenna..=128).contains(&antenna) || !(-512..=80).contains(&ceiling) {
            return Err(Error::Policy);
        }
        let curves = core::array::from_fn(|row| {
            core::array::from_fn(|gain| {
                let at = HEADER + row * 128 + gain * 2;
                i16::from_le_bytes([bytes[at], bytes[at + 1]])
            })
        });
        if curves
            .iter()
            .flatten()
            .any(|peak| *peak != UNKNOWN && !(-512..=256).contains(peak))
        {
            return Err(Error::State);
        }
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        let record = digest.finalize();
        let qualification = Self {
            base,
            executable,
            cap,
            factory,
            geometry,
            record,
            antenna,
            ceiling,
            curves,
        };
        qualification.gains()?;
        Ok(qualification)
    }
    fn with_sources<T>(&self, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Current<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Current<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.executable
            .invoke(|| {
                self.base.invoke(|| {
                    self.cap
                        .invoke(Current(operation))
                        .map_err(|_| Error::Policy)
                })
            })
            .map_err(Error::Control)???
    }
    fn current_limits(&self) -> Result<(i16, u8, u8, u8), Error> {
        let domain = self.base.domain()?;
        let permission = self
            .base
            .calibration()
            .permission(&domain, self.geometry.primary())
            .map_err(Error::Power)?;
        if permission != self.base.permission() {
            return Err(Error::Policy);
        }
        let ceiling = self
            .geometry
            .ceiling(&domain)?
            .min(permission.eirp_limit_qdbm())
            .min(self.ceiling);
        // Keep the actual existing legacy gain pair. V2 separately bounds its
        // changed40MHz RF/BB peaks; lower raw indices are not presumed monotonic.
        if !self
            .base
            .calibration()
            .within(permission, ceiling, self.antenna)
        {
            return Err(Error::Policy);
        }
        let (identity, _, _) = self.base.calibration().binding();
        let (cck, ofdm) = permission
            .gains(
                self.factory,
                u16::from_le_bytes([identity[0], identity[1]]),
                u16::from_le_bytes([identity[2], identity[3]]),
                self.geometry.primary(),
            )
            .map_err(Error::Power)?;
        let maximum = self.factory.ht40_power[self.geometry.primary_factory_group()];
        Ok((ceiling, cck, ofdm, maximum))
    }
    fn peak_fits(&self, row: usize, gain: u8, ceiling: i16) -> bool {
        self.curves[row][usize::from(gain)] != UNKNOWN
            && i32::from(self.curves[row][usize::from(gain)]) + i32::from(self.antenna)
                <= i32::from(ceiling)
    }
    pub(in crate::rtl8xxxu) fn gains(&self) -> Result<Gains, Error> {
        self.with_sources(|| {
            let (ceiling, cck, ofdm, maximum) = self.current_limits()?;
            if !self.peak_fits(0, cck, ceiling) || !self.peak_fits(1, ofdm, ceiling) {
                return Err(Error::Policy);
            }
            let mut mcs = [0; 8];
            for (index, gain) in mcs.iter_mut().enumerate() {
                *gain = (0..=maximum)
                    .rev()
                    .find(|gain| self.peak_fits(index + 2, *gain, ceiling))
                    .ok_or(Error::Policy)?;
            }
            Ok(Gains {
                geometry: self.geometry,
                record: self.record,
                cck,
                ofdm,
                mcs,
            })
        })
    }
    pub(in crate::rtl8xxxu) fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub(super) fn factory(&self) -> Factory {
        self.factory
    }
    fn validate_gains(&self, gains: Gains) -> Result<(), Error> {
        let (ceiling, cck, ofdm, maximum) = self.current_limits()?;
        if gains.geometry != self.geometry
            || gains.record != self.record
            || gains.cck != cck
            || gains.ofdm != ofdm
            || !self.peak_fits(0, cck, ceiling)
            || !self.peak_fits(1, ofdm, ceiling)
            || gains
                .mcs
                .iter()
                .enumerate()
                .any(|(index, gain)| *gain > maximum || !self.peak_fits(index + 2, *gain, ceiling))
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    pub(super) fn invoke<T>(
        &self,
        gains: Gains,
        operation: impl FnOnce() -> T,
    ) -> Result<T, Error> {
        self.with_sources(|| {
            self.validate_gains(gains)?;
            Ok(operation())
        })
    }
}
