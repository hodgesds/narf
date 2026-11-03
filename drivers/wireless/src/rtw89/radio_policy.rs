// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured full B radio recipe, separate from basic-calibration v1.
use super::{factory::Factory, radio_assets::Assets, radio_power::Plan};
use alloc::format;
use alloc::sync::Arc;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const LENGTH: usize = 128;
#[path = "amsdu_policy.rs"]
mod amsdu;
#[path = "channel_policy.rs"]
mod channel;
#[path = "fragment_policy.rs"]
mod fragment;
#[path = "lps_policy.rs"]
mod lps;
#[path = "rf_tracking_policy.rs"]
mod rf_tracking;

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
    /// Originator Block Ack with TX A-MPDU on top of HT20: ADDBA request
    /// emitter, TXWD AGG_EN/MAX_AGGNUM/AMPDU_DENSITY, RA aggregation limit
    /// and up to `packet_core::AGG_WINDOW` data frames in flight.
    Ampdu,
}
impl Program {
    pub(super) const ALL: [Self; 6] = [
        Self::Wmm,
        Self::QosAll,
        Self::FirmwareRa,
        Self::Ht,
        Self::He,
        Self::Ampdu,
    ];
    pub(super) const BASE: u8 = 3;
    pub(super) fn bit(self) -> u8 {
        match self {
            Self::Wmm => 1 << 2,
            Self::QosAll => 1 << 3,
            Self::FirmwareRa => 1 << 4,
            Self::Ht => 1 << 5,
            Self::He => 1 << 6,
            Self::Ampdu => 1 << 7,
        }
    }
    fn requires(self) -> u8 {
        match self {
            Self::Wmm => 0,
            Self::QosAll | Self::FirmwareRa => Self::Wmm.bit(),
            Self::Ht => Self::Wmm.bit() | Self::FirmwareRa.bit(),
            Self::He | Self::Ampdu => Self::Wmm.bit() | Self::FirmwareRa.bit() | Self::Ht.bit(),
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
                hash.update(b"NARF RTL8852B HE20 optional operating recipe v2");
                hash.update(&identity);
                hash.update(&super::station_control::he_fingerprint());
            }
            Self::Ampdu => {
                hash.update(b"NARF RTL8852B originator BA TX A-MPDU optional operating recipe v1");
                hash.update(&identity);
                hash.update(&super::station_control::ampdu_fingerprint());
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
        // Preserve v2's exact channel1 meaning. Noninitial plans require their
        // own typed full-program constructor/record, never an old header alias.
        if power.channel() != super::operating_channel::Profile::INITIAL {
            return Err(Error::Identity);
        }
        Self::compose(
            factory,
            device,
            assets,
            power,
            phycap,
            b"NARF RTL8852B initial full RF ch1 legacy20 awake WLAN-only v2;TX-A1M,RX-AB;all automatic CCK/OFDM response paths;no hardwarecrypto;onefreshPCI lifecycle",
        )
    }
    /// Identity of the same full program retuned to one noninitial primary
    /// (2..=13): the identical factory/PHY_CAP/recipe composition over the
    /// plan's per-channel Linux power rows and typed SCO/FIR/TSSI profile,
    /// domain-separated from v2. Only a signed N52C record admits it.
    pub(super) fn new_noninitial(
        lifecycle: Lifecycle,
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
    ) -> Result<Self, Error> {
        if !channel::admissible(power.channel()) {
            return Err(Error::Identity);
        }
        Self::compose(
            factory,
            device,
            assets,
            power,
            phycap,
            if power.channel().width() != super::operating_channel::Width::Mhz20 {
                b"NARF RTL8852B wide full RF 40/80MHz HT/VHT/HE-wide awake WLAN-only v1;TX-A1M,RX-AB;automatic response paths (CCK only on 2.4GHz);no hardwarecrypto;retuned from Ready ch1 program; actual primary/center/width bound by the plan"
            } else if power.channel().is_5ghz() {
                b"NARF RTL8852B 5GHz full RF 20MHz legacy-OFDM20 awake WLAN-only v1;TX-A1M,RX-AB;automatic OFDM response paths, no CCK;no hardwarecrypto;retuned across band from Ready ch1 program"
            } else {
                b"NARF RTL8852B noninitial full RF 2.4GHz20 legacy20 awake WLAN-only v1;TX-A1M,RX-AB;all automatic CCK/OFDM response paths;no hardwarecrypto;retuned from Ready ch1 program"
            },
        )
        .map(|board| board.lifecycle(lifecycle))
    }
    fn compose(
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
        domain: &[u8],
    ) -> Result<Self, Error> {
        let base = super::calibration_policy::Board::new(factory, device, assets)
            .map_err(|_| Error::Identity)?;
        let identity = factory.identity().ok_or(Error::Identity)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(domain);
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
/// Signed power envelope gating publications on one occupied span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Envelope {
    span: (u32, u32),
    antenna_qdb: i16,
    ceiling_qdbm: i16,
    peaks_qdbm: [i16; 3],
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
    record_digest: [u8; 32],
    record_signer: [u8; 32],
    amsdu: Option<amsdu::Amsdu>,
    rf_tracking: Option<rf_tracking::Tracking>,
    lps: Option<lps::Sleep>,
    fragments: Option<fragment::Fragments>,
    /// Signed noninitial per-channel full-program records (N52C).
    channels: alloc::vec::Vec<channel::Channel>,
    /// Operating channel whose envelope gates every publication, as
    /// [`profile_key`] (primary | width << 8 | center << 16); channel1/20MHz
    /// is the base N52B.
    active: core::sync::atomic::AtomicU32,
    /// Station TX grant on a passive-only (DFS / NO_IR) primary: the
    /// primary and the exact policy snapshot under which the station
    /// client's `narf_wireless::reg::witness::BeaconWitness` admitted it.
    passive_tx: narf_lib::sync::IrqSafeSpinLock<Option<(u8, Arc<RegulatoryDomain>)>>,
    #[cfg(any(test, feature = "kernel-test"))]
    model_domain: Option<Arc<RegulatoryDomain>>,
    #[cfg(any(test, feature = "kernel-test"))]
    model_revoke_before_publication: bool,
    #[cfg(any(test, feature = "kernel-test"))]
    model_native_before_publication: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
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
        let mut qualification = cap.invoke(Decode(board)).map_err(|_| Error::Authority)??;
        if qualification.wmm {
            narf_wireless::reg::db::ensure_domain().map_err(|_| Error::Policy)?;
        }
        qualification.amsdu = amsdu::Amsdu::optional(&qualification)?;
        qualification.rf_tracking = rf_tracking::Tracking::optional(&qualification)?;
        if qualification.amsdu.is_some() || qualification.rf_tracking.is_some() {
            qualification.current()?;
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
        let record_signer = signer.ok_or(Error::Unsigned)?;
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
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        Ok(Self {
            board,
            authority,
            record_digest: digest.finalize(),
            record_signer,
            amsdu: None,
            rf_tracking: None,
            lps: None,
            fragments: None,
            channels: alloc::vec::Vec::new(),
            active: core::sync::atomic::AtomicU32::new(profile_key(
                super::operating_channel::Profile::INITIAL,
            )),
            passive_tx: narf_lib::sync::IrqSafeSpinLock::new(None),
            antenna_qdb,
            ceiling_qdbm,
            peaks_qdbm,
            wmm,
            flags,
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
            #[cfg(any(test, feature = "kernel-test"))]
            model_revoke_before_publication: false,
            #[cfg(any(test, feature = "kernel-test"))]
            model_native_before_publication: None,
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
    pub(super) fn amsdu_allowed(&self) -> Result<bool, Error> {
        self.current()?;
        Ok(self.amsdu.is_some())
    }
    pub(super) fn load_sleep(&mut self, assets: &Assets) -> Result<(), Error> {
        let profile = super::lps_wire::Profile::from_assets(assets).ok_or(Error::Identity)?;
        self.lps = lps::Sleep::optional(self, profile)?;
        self.current()
    }
    pub(super) fn load_fragments(&mut self) -> Result<(), Error> {
        self.fragments = fragment::Fragments::optional(self)?;
        self.current()
    }
    pub(super) fn fragments_allowed(&self) -> Result<bool, Error> {
        self.current()?;
        Ok(self.fragments.is_some())
    }
    pub(super) fn sleep_profile(&self) -> Result<Option<super::lps_wire::Profile>, Error> {
        self.current()?;
        Ok(self.lps.as_ref().map(lps::Sleep::profile))
    }
    fn invoke_programs<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        let operation = || match &self.fragments {
            Some(program) => program.invoke(operation),
            None => operation(),
        };
        let operation = || match &self.lps {
            Some(program) => program.invoke(operation),
            None => operation(),
        };
        let operation = || match &self.rf_tracking {
            Some(program) => program.invoke(operation),
            None => operation(),
        };
        let operation = || match &self.amsdu {
            Some(program) => program.invoke(operation),
            None => operation(),
        };
        match self.active_profile() {
            None => operation(),
            Some(profile) => match self.channel(profile) {
                Some(record) => record.invoke(operation),
                None => Err(super::power::Error::Access),
            },
        }
    }
    pub(super) fn rf_tracking_window(&self) -> Result<Option<super::rf_tracking::Window>, Error> {
        self.current()?;
        self.rf_tracking
            .as_ref()
            .map(rf_tracking::Tracking::window)
            .transpose()
    }
    pub(super) fn wmm_allowed(&self) -> Result<bool, Error> {
        self.current()?;
        Ok(self.wmm)
    }
    pub fn current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        if let Some(program) = &self.amsdu {
            program.current()?;
        }
        if let Some(program) = &self.rf_tracking {
            program.current()?;
        }
        if let Some(program) = &self.lps {
            program.current()?;
        }
        if let Some(program) = &self.fragments {
            program.current()?;
        }
        self.check(&*self.policy()?).map(|_| ())
    }
    /// The host regulatory snapshot every envelope check runs against (the
    /// installed shared policy, bootstrapped from the signed default unless
    /// WMM-qualified; the inert model in tests). Its `Arc` identity scopes
    /// station beacon witnesses and passive TX grants.
    pub(super) fn policy(&self) -> Result<Arc<RegulatoryDomain>, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(domain) = self.model_domain.as_ref() {
            return Ok(domain.clone());
        }
        if self.wmm {
            narf_wireless::reg::db::snapshot().ok_or(Error::Policy)
        } else {
            narf_wireless::reg::db::ensure_snapshot().map_err(|_| Error::Policy)
        }
    }
    /// Grant (or with `None` withdraw) station TX on the passive-only
    /// primary `grant.0`, which the station client admitted under its beacon
    /// witness taken under exactly the policy `grant.1`. Only the station
    /// association / CSA path grants; `select` of any other primary drops it.
    pub(super) fn grant_passive_tx(&self, grant: Option<(u8, Arc<RegulatoryDomain>)>) {
        let retired = core::mem::replace(&mut *self.passive_tx.lock(), grant);
        drop(retired);
    }
    /// `current` plus the frame-TX rule: on a passive-only (DFS / NO_IR)
    /// active span a frame may be published only under a passive TX grant
    /// for this exact primary and current policy snapshot (mac80211 never
    /// probes there; a station transmits only to an AP it heard).
    pub(super) fn tx_current(&self) -> Result<(), Error> {
        self.current()?;
        let policy = self.policy()?;
        if !self.check(&policy)? {
            return Ok(());
        }
        let active = self.active();
        match &*self.passive_tx.lock() {
            Some((primary, granted)) if *primary == active && Arc::ptr_eq(granted, &policy) => {
                Ok(())
            }
            _ => Err(Error::Policy),
        }
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
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(effect) = self.model_native_before_publication.as_ref() {
            effect();
        }
        struct Invoke<'a, F> {
            qualification: &'a Qualification,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, super::power::Error>> CapOp<FirmwareBlob, Read> for Invoke<'_, F> {
            type Output = Result<T, super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let domain = self
                        .qualification
                        .policy()
                        .map_err(|_| super::power::Error::Access)?;
                    self.qualification
                        .check(&domain)
                        .map_err(|_| super::power::Error::Access)?;
                    self.qualification.invoke_programs(self.operation)
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
    /// Envelope of the active primary: base N52B over 2402..2422 for channel1,
    /// otherwise the current signed N52C record over its occupied span.
    fn envelope(&self) -> Result<Envelope, Error> {
        let Some(active) = self.active_profile() else {
            return Ok(Envelope {
                span: (2402, 2422),
                antenna_qdb: self.antenna_qdb,
                ceiling_qdbm: self.ceiling_qdbm,
                peaks_qdbm: self.peaks_qdbm,
            });
        };
        let record = self.channel(active).ok_or(Error::Policy)?;
        record.current()?;
        Ok(record.envelope())
    }
    /// The record of exactly this operating channel (primary, width and,
    /// for a 2.4GHz 40MHz channel, secondary side). A 20MHz record never
    /// admits a wider program on its primary, nor the reverse.
    fn channel(&self, profile: super::operating_channel::Profile) -> Option<&channel::Channel> {
        self.channels
            .iter()
            .find(|record| record.profile() == profile)
    }
    /// Load the optional N52C record for one noninitial primary. `board` is
    /// [`Board::new_noninitial`] for the same lifecycle; the base program
    /// flags are applied here. Call after every other companion is loaded.
    pub(super) fn load_channel(
        &mut self,
        profile: super::operating_channel::Profile,
        board: Board,
    ) -> Result<bool, Error> {
        let board = board.with_programs(self.flags);
        let record = channel::Channel::optional(self, profile, board)?;
        self.channels
            .retain(|existing| existing.profile() != profile);
        let loaded = record.is_some();
        if let Some(record) = record {
            self.channels.push(record);
        }
        Ok(loaded)
    }
    /// Current signed admission of `profile` (channel1 is the base record).
    pub(super) fn channel_allowed(
        &self,
        profile: super::operating_channel::Profile,
    ) -> Result<bool, Error> {
        self.current()?;
        if profile == super::operating_channel::Profile::INITIAL {
            return Ok(true);
        }
        let Some(record) = self.channel(profile) else {
            return Ok(false);
        };
        record.bound(self)?;
        if !profile.is_5ghz() && profile.width() == super::operating_channel::Width::Mhz20 {
            return Ok(true);
        }
        // A 5GHz record is only admitted while the current host rule over
        // its span passes the envelope (a DFS / NO_IR span is admitted as
        // passive-only: RX, passive scan, and station TX only under a
        // witness grant, `tx_current`), so a scan never retunes onto a
        // channel whose envelope `select` would refuse. A 40/80MHz record
        // is likewise checked over its whole occupied span (both bands).
        Ok(Self::check_envelope(&*self.policy()?, record.envelope()).is_ok())
    }
    /// The signed noninitial record was measured for exactly this freshly
    /// rebuilt identity (before program extension).
    pub(super) fn channel_matches(
        &self,
        profile: super::operating_channel::Profile,
        board: Board,
    ) -> bool {
        self.channel(profile)
            .is_some_and(|record| record.board() == board.with_programs(self.flags))
    }
    /// Switch the envelope gating every later publication to `profile`. The
    /// native retune owner selects the target before its first emission on
    /// the new primary, so the whole occupied span is under the current host
    /// rule. No register access happens here.
    pub(super) fn select(&self, profile: super::operating_channel::Profile) -> Result<(), Error> {
        if profile != super::operating_channel::Profile::INITIAL {
            self.channel(profile).ok_or(Error::Policy)?.bound(self)?;
        }
        {
            let mut grant = self.passive_tx.lock();
            if grant.as_ref().is_some_and(|(p, _)| *p != profile.primary()) {
                let retired = grant.take();
                drop(grant);
                drop(retired);
            }
        }
        let previous = self
            .active
            .swap(profile_key(profile), core::sync::atomic::Ordering::AcqRel);
        let result = self.current();
        if result.is_err() {
            self.active
                .store(previous, core::sync::atomic::Ordering::Release);
        }
        result
    }
    /// Primary of the active operating channel.
    pub(super) fn active(&self) -> u8 {
        self.active.load(core::sync::atomic::Ordering::Acquire) as u8
    }
    /// The active noninitial operating channel (`None` = base channel1/20MHz).
    pub(super) fn active_profile(&self) -> Option<super::operating_channel::Profile> {
        let key = self.active.load(core::sync::atomic::Ordering::Acquire);
        let profile = profile_from_key(key)?;
        (profile != super::operating_channel::Profile::INITIAL).then_some(profile)
    }
    /// `Ok(passive)`: the active envelope passes; `passive` when its span is
    /// passive-only (DFS / NO_IR).
    fn check(&self, domain: &RegulatoryDomain) -> Result<bool, Error> {
        Self::check_envelope(domain, self.envelope()?)
    }
    /// The host rule over the record's whole occupied span. NO_P2P, AUTO_BW
    /// and NO_160MHZ restrict nothing at 20MHz. DFS and NO_IR are accepted
    /// only on a 5GHz span and make it passive-only (`Ok(true)`, cfg80211
    /// `IEEE80211_CHAN_RADAR` / `NO_IR`): RX, monitor and passive scan; frame
    /// TX additionally needs the station's witness grant (`tx_current`).
    /// Every other (or unknown) flag refuses.
    fn check_envelope(domain: &RegulatoryDomain, envelope: Envelope) -> Result<bool, Error> {
        if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(Error::Policy);
        }
        let (low, high) = envelope.span;
        let mut ceiling = None;
        let mut passive = false;
        for (index, rule) in domain.rules.iter().enumerate() {
            if rule.freq_start_mhz >= high || rule.freq_end_mhz <= low {
                continue;
            }
            if rule.freq_start_mhz > low
                || rule.freq_end_mhz < high
                // cfg80211 reg_get_max_bandwidth (AUTO_BW run, NO_160MHZ
                // cap) must allow the whole occupied width (20/40/80MHz,
                // cfg80211 `reg_does_bw_fit`); NO_160MHZ restricts nothing
                // below 160MHz.
                || domain.max_bandwidth(index) < high - low
                || rule.flags.bits() & !(PLAIN_RULE_FLAGS | PASSIVE_RULE_FLAGS) != 0
            {
                return Err(Error::Policy);
            }
            if rule.flags.bits() & PASSIVE_RULE_FLAGS != 0 {
                if low < 5000 {
                    return Err(Error::Policy);
                }
                passive = true;
            }
            let p = i16::from(rule.max_power_dbm) * 4;
            ceiling = Some(ceiling.map_or(p, |old: i16| old.min(p)));
        }
        let ceiling = ceiling.ok_or(Error::Policy)?.min(envelope.ceiling_qdbm);
        if envelope
            .peaks_qdbm
            .iter()
            .any(|p| i32::from(*p) + i32::from(envelope.antenna_qdb) > i32::from(ceiling))
        {
            return Err(Error::Policy);
        }
        Ok(passive)
    }
}
/// The [`Qualification`] `active` key of an operating channel.
fn profile_key(profile: super::operating_channel::Profile) -> u32 {
    u32::from(profile.primary())
        | ((profile.width() as u32) << 8)
        | (u32::from(profile.center()) << 16)
}
fn profile_from_key(key: u32) -> Option<super::operating_channel::Profile> {
    use super::operating_channel::{Profile, Width};
    let (primary, center) = (key as u8, (key >> 16) as u8);
    let width = match (key >> 8) as u8 {
        0 => Width::Mhz20,
        1 => Width::Mhz40,
        2 => Width::Mhz80,
        _ => return None,
    };
    Profile::new_wide(primary, width, center > primary).filter(|p| p.center() == center)
}
/// Rule flags making a 5GHz span passive-only (never on 2.4GHz here).
const PASSIVE_RULE_FLAGS: u32 =
    narf_wireless::reg::RegFlags::DFS.bits() | narf_wireless::reg::RegFlags::NO_IR.bits();
/// Rule flags a plain 20MHz span may carry: NO_P2P, AUTO_BW, NO_160MHZ.
/// Every other (or unknown) bit but `PASSIVE_RULE_FLAGS` is refused.
const PLAIN_RULE_FLAGS: u32 = narf_wireless::reg::RegFlags::NO_P2P.bits()
    | narf_wireless::reg::RegFlags::AUTO_BW.bits()
    | narf_wireless::reg::RegFlags::NO_160MHZ.bits();
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy/tests.rs"]
pub(super) mod tests;
