// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured full B radio recipe, separate from basic-calibration v1.
use super::{factory::Factory, radio_assets::Assets, radio_power::Plan};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
const LENGTH: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Policy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    device: u16,
}
impl Board {
    pub fn new(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
    ) -> Result<Self, Error> {
        let base = super::calibration_policy::Board::new(factory, device, assets)
            .map_err(|_| Error::Identity)?;
        let identity = factory.identity().ok_or(Error::Identity)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(b"NARF RTL8852B initial full RF ch1 legacy20 awake WLAN-only v2;TX-A1M,RX-AB;all automatic CCK/OFDM response paths;no hardwarecrypto;onefreshPCI lifecycle");
        phycap.initial_profile().map_err(|_| Error::Identity)?;
        h.update(&base.identity());
        h.update(&phycap.fingerprint());
        for recipe in [
            super::radio_full::RECIPE,
            super::rfk_tables::RECIPE,
            super::coex_native::RECIPE,
            super::channel_bb::RECIPE,
            super::channel_rf::RECIPE,
            super::channel_transition::RECIPE,
            super::radio_trim::RECIPE,
            super::radio_power::RECIPE,
            super::iqk::RECIPE,
            super::tssi::RECIPE,
            super::dpk::RECIPE,
            super::station_control::profile_fingerprint(),
        ] {
            h.update(&recipe);
        }
        power.bind(&mut h);
        // Actual MAC source profile enables CCK+OFDM automatic rate selection and
        // source20MHz response RSC. TX-A CCTL cannot imply autonomous path-A only.
        h.update(b"c090:RRSR_RATE_EN=3;cc08:RESP_REF_RATE_SEL=0,RESP_RSC=2;all reachable ACK/CTS paths A/B/AB measured;BB3/RF2/MAC1 source units;ref0 both paths");
        Ok(Self {
            identity: h.finalize(),
            mac: identity.mac(),
            device: device.device,
        })
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub(super) fn wmm(mut self) -> Self {
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B WMM BE/TID0 legacy12 optional operating recipe v2");
        hash.update(&self.identity);
        hash.update(&super::station_control::wmm_fingerprint());
        self.identity = hash.finalize();
        self
    }
}
struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
pub(super) struct Qualification {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    antenna_qdb: i16,
    ceiling_qdbm: i16,
    peaks_qdbm: [i16; 3],
    wmm: bool,
    #[cfg(any(test, feature = "kernel-test"))]
    model_domain: Option<narf_wireless::reg::RegulatoryDomain>,
    #[cfg(any(test, feature = "kernel-test"))]
    model_revoke_before_publication: bool,
}
struct Decode(Board);
impl CapOp<FirmwareBlob, Read> for Decode {
    type Output = Result<Qualification, Error>;
    fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((|| {
            let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
            Qualification::from_verified(v.bytes, v.signer, self.0, *cap)
        })())
    }
}
impl Qualification {
    pub fn load(board: Board) -> Result<Self, Error> {
        let m = board.mac;
        let name = format!(
            "rtw89/rtw8852b-radio-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = narf_firmware::open(&name, &loader).map_err(Error::Firmware)?;
        let qualification = cap.invoke(Decode(board)).map_err(|_| Error::Authority)??;
        if qualification.wmm {
            narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?;
        }
        Ok(qualification)
    }
    fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        signer.ok_or(Error::Unsigned)?;
        if bytes.len() != LENGTH
            || &bytes[..4] != b"N52B"
            || bytes[4..8] != [2, 0, 128, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..57] != [1, 20, 1]
            || !matches!(bytes[57], 3 | 7)
            || bytes[68..] != [0; 60]
        {
            return Err(Error::Format);
        }
        let wmm = bytes[57] == 7;
        let board = if wmm { board.wmm() } else { board };
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let signed = |at| i16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let antenna_qdb = signed(58);
        let ceiling_qdbm = signed(60);
        let peaks_qdbm = [signed(62), signed(64), signed(66)];
        if !(0..=256).contains(&antenna_qdb)
            || !(-512..=256).contains(&ceiling_qdbm)
            || peaks_qdbm.iter().any(|v| !(-512..=256).contains(v))
        {
            return Err(Error::Format);
        }
        Ok(Self {
            board,
            authority,
            antenna_qdb,
            ceiling_qdbm,
            peaks_qdbm,
            wmm,
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
            #[cfg(any(test, feature = "kernel-test"))]
            model_revoke_before_publication: false,
        })
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == if self.wmm { board.wmm() } else { board }
    }
    pub(super) fn wmm_allowed(&self) -> Result<bool, Error> {
        self.current()?;
        Ok(self.wmm)
    }
    pub fn current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(domain) = self.model_domain.as_ref() {
            return self.check(domain);
        }
        let domain = if self.wmm {
            narf_wireless::reg::db::get_domain().ok_or(Error::Policy)?
        } else {
            narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?
        };
        self.check(&domain)
    }
    /// Keep actual publication inside this exact signed capability invocation.
    /// Metadata/current-policy sampling alone cannot authorize later MMIO.
    pub fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        // Deterministic inert-model interleaving: prior metadata/current()
        // succeeds, then revocation occurs at the actual publication boundary.
        #[cfg(any(test, feature = "kernel-test"))]
        if self.model_revoke_before_publication {
            self.authority.revoke();
        }
        struct Invoke<'a, F> {
            qualification: &'a Qualification,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, super::power::Error>> CapOp<FirmwareBlob, Read> for Invoke<'_, F> {
            type Output = Result<T, super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    #[cfg(any(test, feature = "kernel-test"))]
                    if let Some(domain) = self.qualification.model_domain.as_ref() {
                        self.qualification
                            .check(domain)
                            .map_err(|_| super::power::Error::Access)?;
                        return (self.operation)();
                    }
                    let domain = if self.qualification.wmm {
                        narf_wireless::reg::db::get_domain().ok_or(super::power::Error::Access)?
                    } else {
                        narf_wireless::reg::db::ensure_domain()
                            .map_err(|_| super::power::Error::Access)?
                    };
                    self.qualification
                        .check(&domain)
                        .map_err(|_| super::power::Error::Access)?;
                    (self.operation)()
                })())
            }
        }
        self.authority
            .invoke(Invoke {
                qualification: self,
                operation,
            })
            .map_err(|_| super::power::Error::Access)?
    }
    fn check(&self, domain: &narf_wireless::reg::RegulatoryDomain) -> Result<(), Error> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let mut ceiling = None;
        for rule in &domain.rules {
            if rule.freq_start_mhz >= 2422 || rule.freq_end_mhz <= 2402 {
                continue;
            }
            if rule.freq_start_mhz > 2402
                || rule.freq_end_mhz < 2422
                || rule.max_bandwidth_mhz < 20
                || rule.flags.bits() & !narf_wireless::reg::RegFlags::NO_P2P.bits() != 0
            {
                return Err(Error::Policy);
            }
            let p = i16::from(rule.max_power_dbm) * 4;
            ceiling = Some(ceiling.map_or(p, |old: i16| old.min(p)));
        }
        let ceiling = ceiling.ok_or(Error::Policy)?.min(self.ceiling_qdbm);
        if self
            .peaks_qdbm
            .iter()
            .any(|p| i32::from(*p) + i32::from(self.antenna_qdb) > i32::from(ceiling))
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy/tests.rs"]
pub(super) mod tests;
