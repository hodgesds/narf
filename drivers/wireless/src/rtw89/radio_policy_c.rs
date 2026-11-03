// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured full RTL8852C radio program records, the C counterpart of
//! `radio_policy` (B `N52B` v2 + `N52C`), with their own magics, names and
//! identities so no B record or identity ever admits C (or vice versa).
//!
//! * `N5CB` v2 (`rtw89/rtw8852c-radio-v2-<mac>.bin`, 128 bytes): the initial
//!   full program at core.c `rtw89_get_default_chandef` (2.4GHz channel 1,
//!   20MHz), measured over 2402..2422.
//! * `N5CC` v1 (`rtw89/rtw8852c-chan-v1-<band>g-ch<primary>-bw<width>-<mac>.bin`,
//!   128 bytes): one noninitial typed `operating_channel_c::Profile` (band,
//!   primary, width, centre). Every 2.4GHz 20MHz primary 2..=13, 2.4GHz HT40
//!   either side and every 5GHz 20/40/80/160MHz block may carry one; channel
//!   14 (CCK-only) and 6GHz (refused by `radio_power_c`) never do. Its
//!   binding covers the base record digest/signer, which must also sign it.
//!
//! Each record's peaks/antenna/ceiling are checked against the current host
//! rule over the profile's whole occupied span: every overlapping rule must
//! allow the profile width (`reg_get_max_bandwidth` incl. NO_160MHZ), the
//! overlapping rules must cover the span without a gap, and DFS/NO_IR are
//! accepted (passive-only, as the B family) only at 5GHz. No C station
//! program (WMM/QoS/RA/HT/HE/A-MPDU) or optional companion record (B
//! N52A/N52T/N52P/N52F) exists for C, so the profile flag byte must be the
//! base set exactly. These are formats only: NARF carries no C board value,
//! and an unprovisioned board stays unadmitted.
use super::operating_channel_c::{Band, Profile, Width};
use super::radio_policy::Lifecycle;
use super::{factory::Factory, radio_assets::Assets, radio_power_c::Plan};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const LENGTH: usize = 128;
/// Profile byte 57: the B base flags with no optional program bit.
const BASE_FLAGS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Firmware(FirmwareError),
    Authority,
    Unsigned,
    Format,
    Identity,
    Policy,
}

/// The full C program the identity measures (Linux 7.3-rc4 call chain).
const RECIPE: &[u8] = b"rtw8852c radio_c::Radio: rtw8852c_rfk_init, rtw8852c_set_txpwr_ctrl, rtw8852c_power_trim, rtw8852c_bb_cfg_txrx_path(RF_AB); core.c __rtw89_set_channel (rtw8852c_set_channel_help enter, rtw8852c_set_channel mac/bb/rf, rtw8852c_set_txpwr, help exit, btc switch band + rtw8852c_rfk_band_changed on a band change) then rtw8852c_rfk_channel (RX DCK, IQK, TSSI, DPK; RFK MCC V0 slot0); RF_GET_MCCCH V0";
fn domain(profile: Profile) -> &'static [u8] {
    if profile == Profile::INITIAL {
        b"NARF RTL8852C initial full RF ch1 20MHz awake WLAN-only v1;TX-A,RX-AB;no hardwarecrypto;onefreshPCI lifecycle"
    } else if profile.band() == Band::Ghz5 {
        b"NARF RTL8852C 5GHz full RF awake WLAN-only v1;TX-A,RX-AB;no CCK;no hardwarecrypto;retuned across band from Ready ch1 program"
    } else {
        b"NARF RTL8852C noninitial full RF 2.4GHz awake WLAN-only v1;TX-A,RX-AB;no hardwarecrypto;retuned from Ready ch1 program"
    }
}
fn width_mhz(width: Width) -> u8 {
    match width {
        Width::Mhz20 => 20,
        Width::Mhz40 => 40,
        Width::Mhz80 => 80,
        Width::Mhz160 => 160,
    }
}
/// Profiles a C record may admit: 2.4GHz and 5GHz typed profiles, never
/// channel 14 or 6GHz.
pub(super) fn admissible(profile: Profile) -> bool {
    match profile.band() {
        Band::Ghz2 => profile.primary() != 14,
        Band::Ghz5 => true,
        Band::Ghz6 => false,
    }
}
/// Every noninitial admissible profile, in a fixed order.
pub(super) fn noninitial() -> alloc::vec::Vec<Profile> {
    let mut out = alloc::vec::Vec::new();
    for primary in 1..=13 {
        out.extend(Profile::new20(Band::Ghz2, primary));
        for above in [true, false] {
            out.extend(Profile::new_2ghz_40(primary, above));
        }
    }
    for primary in super::operating_channel_c::GHZ5 {
        out.extend(Profile::new20(Band::Ghz5, primary));
        for width in [Width::Mhz40, Width::Mhz80, Width::Mhz160] {
            out.extend(Profile::new_wide(Band::Ghz5, primary, width));
        }
    }
    out.retain(|p| *p != Profile::INITIAL && admissible(*p));
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Board {
    identity: [u8; 32],
    mac: [u8; 6],
    device: u16,
    profile: Profile,
}
impl Board {
    /// Identity of the full C program on `power.channel()`: the C cold
    /// calibration identity, the C-bound firmware PHY-cap receipt, the
    /// recipe, the exact `radio_power_c` program and the profile geometry,
    /// domain-separated per lifecycle.
    pub fn new(
        lifecycle: Lifecycle,
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
    ) -> Result<Self, Error> {
        let profile = power.channel();
        if !admissible(profile) || !phycap.is_c() {
            return Err(Error::Identity);
        }
        phycap.initial_profile().map_err(|_| Error::Identity)?;
        let base = super::calibration_policy::Board::new_c(factory, device, assets)
            .map_err(|_| Error::Identity)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(domain(profile));
        h.update(&base.identity());
        h.update(&phycap.fingerprint());
        h.update(RECIPE);
        power.bind(&mut h);
        h.update(&[
            profile.band() as u8,
            profile.primary(),
            profile.center(),
            width_mhz(profile.width()),
        ]);
        let mut identity = h.finalize();
        if lifecycle == Lifecycle::Repeat {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(b"NARF RTL8852C repeat observed-FLR PCI lifecycle v1;SER-L2 reset or S3 resume;same boot");
            h.update(&identity);
            identity = h.finalize();
        }
        Ok(Self {
            identity,
            mac: base.mac(),
            device: device.device,
            profile,
        })
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Envelope {
    span: (u32, u32),
    width: u32,
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
fn envelope(bytes: &[u8], profile: Profile) -> Result<Envelope, Error> {
    let signed = |at: usize| i16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let e = Envelope {
        span: profile.occupied(),
        width: profile.width().mhz(),
        antenna_qdb: signed(58),
        ceiling_qdbm: signed(60),
        peaks_qdbm: [signed(62), signed(64), signed(66)],
    };
    if !(0..=256).contains(&e.antenna_qdb)
        || !(-512..=256).contains(&e.ceiling_qdbm)
        || e.peaks_qdbm.iter().any(|v| !(-512..=256).contains(v))
    {
        return Err(Error::Format);
    }
    Ok(e)
}
fn loader() -> Result<Cap<narf_firmware::FirmwareRegistry, Read>, Error> {
    narf_firmware::trusted_loader_authority()
        .and_then(|c| c.derive::<Read>().ok())
        .ok_or(Error::Authority)
}

/// One signed noninitial `N5CC` record.
struct Channel {
    authority: Cap<FirmwareBlob, Read>,
    board: Board,
    binding: [u8; 32],
    envelope: Envelope,
}
fn channel_recipe(profile: Profile) -> &'static [u8] {
    if profile.band() == Band::Ghz5 {
        b"RTL8852C 5GHz noninitial full operating program v1; __rtw89_set_channel with btc switch band and rtw8852c_tssi_scan on a band change, then rtw8852c_rfk_channel on a Ready owner; actual primary/width WW0 limits and RU limits, no CCK; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
    } else {
        b"RTL8852C 2.4GHz noninitial full operating program v1; __rtw89_set_channel then rtw8852c_rfk_channel on a Ready owner; same band, no band-change TSSI scan; actual primary/width WW0 CCK/OFDM limits, SCO CCK and TX shape; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
    }
}
fn binding(base: &Qualification, board: Board) -> Result<[u8; 32], Error> {
    let profile = board.profile;
    if profile == Profile::INITIAL
        || !admissible(profile)
        || board.mac != base.board.mac
        || board.device != base.board.device
    {
        return Err(Error::Identity);
    }
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTL8852C measured noninitial channel full program v1");
    hash.update(&[
        profile.band() as u8,
        profile.primary(),
        profile.center(),
        width_mhz(profile.width()),
    ]);
    hash.update(&board.identity);
    hash.update(&base.board.identity);
    hash.update(&base.record_digest);
    hash.update(&base.record_signer);
    hash.update(channel_recipe(profile));
    Ok(hash.finalize())
}
/// Firmware name of the `N5CC` record for `profile` on `mac`.
pub(super) fn channel_name(profile: Profile, mac: [u8; 6]) -> alloc::string::String {
    let m = mac;
    format!(
        "rtw89/rtw8852c-chan-v1-{}g-ch{:03}-bw{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        if profile.band() == Band::Ghz5 { 5 } else { 2 },
        profile.primary(),
        width_mhz(profile.width()),
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5]
    )
}
impl Channel {
    fn from_verified(
        base: &Qualification,
        board: Board,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        let binding = binding(base, board)?;
        if signer.ok_or(Error::Unsigned)? != base.record_signer {
            return Err(Error::Identity);
        }
        let p = board.profile;
        if bytes.len() != LENGTH
            || &bytes[..4] != b"N5CC"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, width_mhz(p.width()), p.primary(), BASE_FLAGS]
            || bytes[68..70] != [p.band() as u8, p.center()]
            || bytes[70..] != [0; 58]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        Ok(Self {
            authority,
            board,
            binding,
            envelope: envelope(bytes, p)?,
        })
    }
    fn current(&self) -> Result<(), Error> {
        self.authority.invoke(Current).map_err(|_| Error::Authority)
    }
    fn bound(&self, base: &Qualification) -> Result<(), Error> {
        self.current()?;
        if binding(base, self.board)? != self.binding {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, super::power::Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.authority
            .invoke(Live(operation))
            .map_err(|_| super::power::Error::Access)?
    }
}

/// The signed base `N5CB` v2 record plus every loaded `N5CC` record.
pub(super) struct Qualification {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    envelope: Envelope,
    record_digest: [u8; 32],
    record_signer: [u8; 32],
    channels: alloc::vec::Vec<Channel>,
    /// Profile whose envelope gates every publication.
    active: narf_lib::sync::IrqSafeSpinLock<Profile>,
    #[cfg(any(test, feature = "kernel-test"))]
    model_domain: Option<alloc::sync::Arc<RegulatoryDomain>>,
}
impl Qualification {
    /// Load the base record for `board` (which must be the initial-profile
    /// identity). A missing record is `Firmware(NotFound)`: unadmitted.
    pub fn load(board: Board) -> Result<Self, Error> {
        if board.profile != Profile::INITIAL {
            return Err(Error::Identity);
        }
        let m = board.mac;
        let name = format!(
            "rtw89/rtw8852c-radio-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        let cap = narf_firmware::open(&name, &loader()?).map_err(Error::Firmware)?;
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
        cap.invoke(Decode(board)).map_err(|_| Error::Authority)?
    }
    pub(super) fn from_verified(
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        board: Board,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        let record_signer = signer.ok_or(Error::Unsigned)?;
        if board.profile != Profile::INITIAL
            || bytes.len() != LENGTH
            || &bytes[..4] != b"N5CB"
            || bytes[4..8] != [2, 0, 128, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, BASE_FLAGS]
            || bytes[68..] != [0; 60]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != board.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let envelope = envelope(bytes, Profile::INITIAL)?;
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        Ok(Self {
            board,
            authority,
            envelope,
            record_digest: digest.finalize(),
            record_signer,
            channels: alloc::vec::Vec::new(),
            active: narf_lib::sync::IrqSafeSpinLock::new(Profile::INITIAL),
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
        })
    }
    pub fn matches(&self, board: Board) -> bool {
        self.board == board
    }
    /// Load the optional `N5CC` record for `board.profile()` (a noninitial
    /// identity from [`Board::new`]). Absent: `Ok(false)`, unadmitted.
    pub(super) fn load_channel(&mut self, board: Board) -> Result<bool, Error> {
        binding(self, board)?;
        let name = channel_name(board.profile, self.board.mac);
        let cap = match narf_firmware::open(&name, &loader()?) {
            Ok(cap) => cap,
            Err(FirmwareError::NotFound) => return Ok(false),
            Err(error) => return Err(Error::Firmware(error)),
        };
        struct Decode<'a>(&'a Qualification, Board);
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Channel, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Channel::from_verified(self.0, self.1, v.bytes, v.signer, *cap)
                })())
            }
        }
        let record = cap
            .invoke(Decode(self, board))
            .map_err(|_| Error::Authority)??;
        self.install(record);
        Ok(true)
    }
    fn install(&mut self, record: Channel) {
        let profile = record.board.profile;
        self.channels.retain(|c| c.board.profile != profile);
        self.channels.push(record);
    }
    fn channel(&self, profile: Profile) -> Option<&Channel> {
        self.channels.iter().find(|c| c.board.profile == profile)
    }
    /// The loaded record for `profile` was measured for exactly `board`.
    pub(super) fn channel_matches(&self, board: Board) -> bool {
        if board.profile == Profile::INITIAL {
            return self.matches(board);
        }
        self.channel(board.profile)
            .is_some_and(|record| record.board == board)
    }
    /// Current signed admission of `profile`: a record exists, is bound to
    /// this base, and the current host rule over its span passes.
    pub(super) fn channel_allowed(&self, profile: Profile) -> Result<bool, Error> {
        self.current()?;
        let envelope = if profile == Profile::INITIAL {
            self.envelope
        } else {
            let Some(record) = self.channel(profile) else {
                return Ok(false);
            };
            record.bound(self)?;
            record.envelope
        };
        Ok(check_envelope(&*self.policy()?, envelope).is_ok())
    }
    /// Switch the gating envelope to `profile` before its first emission.
    /// No register access happens here.
    pub(super) fn select(&self, profile: Profile) -> Result<(), Error> {
        if profile != Profile::INITIAL {
            self.channel(profile).ok_or(Error::Policy)?.bound(self)?;
        }
        let previous = core::mem::replace(&mut *self.active.lock(), profile);
        let result = self.current();
        if result.is_err() {
            *self.active.lock() = previous;
        }
        result
    }
    pub(super) fn active(&self) -> Profile {
        *self.active.lock()
    }
    fn active_envelope(&self) -> Result<Envelope, Error> {
        let active = self.active();
        if active == Profile::INITIAL {
            return Ok(self.envelope);
        }
        let record = self.channel(active).ok_or(Error::Policy)?;
        record.current()?;
        Ok(record.envelope)
    }
    fn policy(&self) -> Result<alloc::sync::Arc<RegulatoryDomain>, Error> {
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(domain) = self.model_domain.as_ref() {
            return Ok(domain.clone());
        }
        narf_wireless::reg::db::ensure_snapshot().map_err(|_| Error::Policy)
    }
    pub fn current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        check_envelope(&*self.policy()?, self.active_envelope()?).map(|_| ())
    }
    /// Keep actual publication inside this exact signed capability
    /// invocation (and the active channel record's).
    pub fn with_current<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        struct Invoke<'a, F> {
            qualification: &'a Qualification,
            operation: F,
        }
        impl<T, F: FnOnce() -> Result<T, super::power::Error>> CapOp<FirmwareBlob, Read> for Invoke<'_, F> {
            type Output = Result<T, super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let q = self.qualification;
                    let domain = q.policy().map_err(|_| super::power::Error::Access)?;
                    let envelope = q
                        .active_envelope()
                        .map_err(|_| super::power::Error::Access)?;
                    check_envelope(&domain, envelope).map_err(|_| super::power::Error::Access)?;
                    match q.active() {
                        active if active == Profile::INITIAL => (self.operation)(),
                        active => match q.channel(active) {
                            Some(record) => record.invoke(self.operation),
                            None => Err(super::power::Error::Access),
                        },
                    }
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
}
/// The host rules over the envelope's whole occupied span. `Ok(passive)`.
fn check_envelope(domain: &RegulatoryDomain, envelope: Envelope) -> Result<bool, Error> {
    if !domain.country_code.iter().all(u8::is_ascii_uppercase) {
        return Err(Error::Policy);
    }
    let (low, high) = envelope.span;
    let mut ceiling = None;
    let mut passive = false;
    // Overlapping rules in ascending order must cover low..high gaplessly.
    let mut covered = low;
    let mut rules: alloc::vec::Vec<usize> = (0..domain.rules.len())
        .filter(|&i| {
            let r = &domain.rules[i];
            r.freq_start_mhz < high && r.freq_end_mhz > low
        })
        .collect();
    rules.sort_by_key(|&i| domain.rules[i].freq_start_mhz);
    for index in rules {
        let rule = &domain.rules[index];
        if rule.freq_start_mhz > covered
            || domain.max_bandwidth(index) < envelope.width
            || rule.flags.bits() & !(PLAIN_RULE_FLAGS | PASSIVE_RULE_FLAGS) != 0
        {
            return Err(Error::Policy);
        }
        covered = covered.max(rule.freq_end_mhz);
        if rule.flags.bits() & PASSIVE_RULE_FLAGS != 0 {
            if low < 5000 {
                return Err(Error::Policy);
            }
            passive = true;
        }
        let p = i16::from(rule.max_power_dbm) * 4;
        ceiling = Some(ceiling.map_or(p, |old: i16| old.min(p)));
    }
    if covered < high {
        return Err(Error::Policy);
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
const PASSIVE_RULE_FLAGS: u32 =
    narf_wireless::reg::RegFlags::DFS.bits() | narf_wireless::reg::RegFlags::NO_IR.bits();
const PLAIN_RULE_FLAGS: u32 = narf_wireless::reg::RegFlags::NO_P2P.bits()
    | narf_wireless::reg::RegFlags::AUTO_BW.bits()
    | narf_wireless::reg::RegFlags::NO_160MHZ.bits();
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy_c/tests.rs"]
pub(super) mod tests;
