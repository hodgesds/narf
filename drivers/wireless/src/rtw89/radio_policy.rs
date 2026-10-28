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
/// Optional operating programs layered on the signed full-radio record.
///
/// Profile byte57 carries the base flags (3) plus one bit per program. Each
/// enabled program extends the board identity in the fixed `ALL` order, so a
/// signed record authorizes exactly the emitter programs it was measured
/// with: enabling another program on an old record fails identity. A program
/// may require earlier ones (all-AC QoS builds on WMM).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Program {
    /// WMM BE/TID0 with negotiated legacy rates (recipe revision2).
    Wmm,
    /// All four ACs / TID0..7 on ACH0..3 with host strict-priority service.
    QosAll,
    /// Firmware rate adaptation and hardware retry fallback (H2C RA).
    FirmwareRa,
    /// HT20 station: HT capability IE, firmware RA over MCS0..7 TX,
    /// MCS0..15 RX.
    Ht,
    /// HE20 station on top of HT20: HE capability IE, firmware RA over
    /// HE-MCS0..11 NSS1 TX with firmware GI/LTF selection, HE SU/ER SU/MU
    /// RX on any GI/LTF.
    He,
}
impl Program {
    pub(super) const ALL: [Self; 5] = [
        Self::Wmm,
        Self::QosAll,
        Self::FirmwareRa,
        Self::Ht,
        Self::He,
    ];
    pub(super) const BASE: u8 = 3;
    pub(super) fn bit(self) -> u8 {
        match self {
            Self::Wmm => 1 << 2,
            Self::QosAll => 1 << 3,
            Self::FirmwareRa => 1 << 4,
            Self::Ht => 1 << 5,
            Self::He => 1 << 6,
        }
    }
    fn requires(self) -> u8 {
        match self {
            Self::Wmm => 0,
            Self::QosAll | Self::FirmwareRa => Self::Wmm.bit(),
            Self::Ht => Self::Wmm.bit() | Self::FirmwareRa.bit(),
            Self::He => Self::Wmm.bit() | Self::FirmwareRa.bit() | Self::Ht.bit(),
        }
    }
    /// Base flags plus `self` and everything it requires.
    pub(super) fn flags(self) -> u8 {
        Self::BASE | self.bit() | self.requires()
    }
    /// Valid profile flag byte: base set, only known bits, dependencies met.
    pub(super) fn valid(flags: u8) -> bool {
        let known = Self::ALL.iter().fold(Self::BASE, |m, p| m | p.bit());
        flags & Self::BASE == Self::BASE
            && flags & !known == 0
            && Self::ALL
                .iter()
                .all(|p| flags & p.bit() == 0 || flags & p.requires() == p.requires())
    }
    fn extend(self, identity: [u8; 32]) -> [u8; 32] {
        let mut hash = narf_crypto::sha256::Sha256::new();
        match self {
            Self::Wmm => {
                hash.update(b"NARF RTL8852B WMM BE/TID0 legacy12 optional operating recipe v2");
                hash.update(&identity);
                hash.update(&super::station_control::wmm_fingerprint());
            }
            Self::QosAll => {
                hash.update(b"NARF RTL8852B WMM all-AC TID0..7 optional operating recipe v1");
                hash.update(&identity);
                hash.update(&super::station_control::qos_all_fingerprint());
            }
            Self::FirmwareRa => {
                hash.update(b"NARF RTL8852B firmware RA legacy optional operating recipe v1");
                hash.update(&identity);
                hash.update(&super::station_control::firmware_ra_fingerprint());
            }
            Self::Ht => {
                hash.update(b"NARF RTL8852B HT20 optional operating recipe v1");
                hash.update(&identity);
                hash.update(&super::station_control::ht_fingerprint());
            }
            Self::He => {
                hash.update(b"NARF RTL8852B HE20 optional operating recipe v1");
                hash.update(&identity);
                hash.update(&super::station_control::he_fingerprint());
            }
        }
        hash.finalize()
    }
}
/// Which observed-FLR PCI lifecycle of this boot the radio runs in. The
/// measured v2 qualification binds "one fresh PCI lifecycle": the first
/// observed FLR after boot. Any later generation (SER L2-style reset or a
/// resume from system suspend) repeats the FLR but follows an earlier
/// operating generation or a platform power transition, so it carries its
/// own identity and needs its own signed measured record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Lifecycle {
    #[default]
    Initial,
    Repeat,
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
    /// `Board::new` bound to the observed-FLR lifecycle. `Initial` keeps the
    /// existing identity unchanged.
    pub(super) fn new_for(
        lifecycle: Lifecycle,
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
    ) -> Result<Self, Error> {
        Self::new(factory, device, assets, power, phycap).map(|board| board.lifecycle(lifecycle))
    }
    pub(super) fn lifecycle(mut self, lifecycle: Lifecycle) -> Self {
        if lifecycle == Lifecycle::Repeat {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(b"NARF RTL8852B repeat observed-FLR PCI lifecycle v1;SER-L2 reset or S3 resume;same boot");
            h.update(&self.identity);
            self.identity = h.finalize();
        }
        self
    }
    pub(super) fn wmm(self) -> Self {
        self.with_programs(Program::Wmm.flags())
    }
    /// Extend the identity by every program enabled in `flags`.
    pub(super) fn with_programs(mut self, flags: u8) -> Self {
        for program in Program::ALL {
            if flags & program.bit() != 0 {
                self.identity = program.extend(self.identity);
            }
        }
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
    flags: u8,
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
            || !Program::valid(bytes[57])
            || bytes[68..] != [0; 60]
        {
            return Err(Error::Format);
        }
        let flags = bytes[57];
        let wmm = flags & Program::Wmm.bit() != 0;
        let board = board.with_programs(flags);
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
            flags,
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
            #[cfg(any(test, feature = "kernel-test"))]
            model_revoke_before_publication: false,
        })
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board.with_programs(self.flags)
    }
    /// Current signed authorization for one optional operating program.
    pub(super) fn allows(&self, program: Program) -> Result<bool, Error> {
        self.current()?;
        Ok(self.flags & program.bit() != 0)
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
