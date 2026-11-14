// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured full RTL8852A radio program records, the A counterpart of
//! `radio_policy_c` (C `N5CB` v2 + `N5CC`) and `radio_policy_51` (51 `N51B`
//! v2 + `N51C`), with their own magics, names and identities so no B, C or
//! 51 record or identity ever admits A (or vice versa).
//!
//! * `N5AB` v2 (`rtw89/rtw8852a-radio-v2-<mac>.bin`, 128 bytes): the initial
//!   full program at core.c `rtw89_get_default_chandef` (2.4GHz channel 1,
//!   20MHz), measured over 2402..2422.
//! * `N5AC` v1 (`rtw89/rtw8852a-chan-v1-<2|5>g-ch<primary>-c<center>-bw<width>-
//!   <mac>.bin`, 128 bytes): one noninitial typed `operating_channel::Profile`
//!   (rtw8852a.c `support_bands` 2.4/5GHz, `support_bandwidths`
//!   20/40/80MHz, `support_unii4` false). Every 2.4GHz 20MHz primary 2..=13,
//!   2.4GHz HT40 either side and every 5GHz 20/40/80MHz block may carry one;
//!   channel 14 (CCK-only) never does. The centre is part of the name, so the
//!   two 2.4GHz HT40 sides of one primary never share a file. Its binding
//!   covers the base record digest/signer, which must also sign it.
//! * `N5AF` v1 (`rtw89/rtw8852a-fragment-v1-<mac>.bin`, 128 bytes): the
//!   optional signed software-fragment companion ([`fragment`]).
//!
//! Each record's peaks/antenna/ceiling are checked against the current host
//! rule over the profile's whole occupied span exactly as the C family
//! (`radio_policy_c::check_envelope`: overlapping rules must cover the span
//! without a gap, each must allow the width incl. AUTO_BW/NO_160MHZ, and
//! DFS/NO_IR are accepted, passive-only, only at 5GHz). The base record's
//! profile flag byte may enable the RTL8852A station programs
//! (WMM/QoS/RA/HT/HE/A-MPDU, [`PROGRAMS`]), each extending the identity;
//! a 40/80MHz record binds the shared wide station capability. These are
//! formats only: NARF carries no RTL8852A board value, and an
//! unprovisioned board stays unadmitted.
//!
//! The A RF program itself (`radio_a::Radio`, the `preflight_radio_a` /
//! `prepare_radio_a` owner) does not exist yet: this module is the signed
//! program the owner will install, not the owner. Installing an
//! `OrdinaryGrant::A` without the owner having run the recipe would admit
//! ordinary TX without the measured RF program, so no production path
//! installs the grant from here.
use super::operating_channel::{Profile, Width};
pub(super) use super::radio_policy::Lifecycle;
use super::radio_policy::Program;
pub(super) use super::radio_policy_c::Error;
use super::radio_policy_c::{check_envelope, envelope_at, loader, Envelope};
use super::{factory::Factory, radio_assets::Assets, radio_power_c::Plan};
use alloc::format;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::{FirmwareBlob, FirmwareError};
use narf_wireless::reg::RegulatoryDomain;
const LENGTH: usize = 128;
/// Profile byte 57: the B base flags with no optional program bit.
const BASE_FLAGS: u8 = 3;
/// Optional operating programs an A base record may enable (byte 57, the
/// B `radio_policy::Program` bit layout and dependencies). All six have a
/// real A path (v0 TXWD station, A-MPDU and A-MSDU in `packet_core`).
pub(super) const PROGRAMS: [Program; 6] = [
    Program::Wmm,
    Program::QosAll,
    Program::FirmwareRa,
    Program::Ht,
    Program::He,
    Program::Ampdu,
];
fn programs_valid(flags: u8) -> bool {
    let known = PROGRAMS.iter().fold(BASE_FLAGS, |m, p| m | p.bit());
    Program::valid(flags) && flags & !known == 0
}
/// Extend an A identity by one enabled program (domain-separated from B's
/// `Program::extend` and C's `radio_policy_c::extend`; the station
/// H2C/TXWD programs are the common AX code the B fingerprints measure,
/// sent through the A v0 TXWD path).
fn extend(program: Program, identity: [u8; 32]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    match program {
        Program::Wmm => {
            hash.update(
                b"NARF RTL8852A WMM BE/TID0 legacy12 optional operating recipe v1;txwd_body_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::wmm_fingerprint());
        }
        Program::QosAll => {
            hash.update(b"NARF RTL8852A WMM all-AC TID0..7 optional operating recipe v1;txwd_body_v0;ach0..3_v0");
            hash.update(&identity);
            hash.update(&super::station_control::qos_all_fingerprint());
        }
        Program::FirmwareRa => {
            hash.update(
                b"NARF RTL8852A firmware RA legacy optional operating recipe v1;txwd_info0_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::firmware_ra_fingerprint());
        }
        Program::Ht => {
            hash.update(b"NARF RTL8852A HT20 optional operating recipe v1;rx_desc_v0;bacam_v0");
            hash.update(&identity);
            hash.update(&super::station_control::ht_fingerprint());
        }
        Program::He => {
            hash.update(
                b"NARF RTL8852A HE20 optional operating recipe v1;txwd_info0_v0 DATA_ER;rx_desc_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::he_fingerprint());
        }
        Program::Ampdu => {
            hash.update(b"NARF RTL8852A originator BA TX A-MPDU optional operating recipe v1;txwd_body3/info1/info2 v0 agg;max_tx_agg_num 128;max_amsdu 3500");
            hash.update(&identity);
            hash.update(&super::station_control::ampdu_fingerprint());
        }
    }
    hash.finalize()
}

/// The full RTL8852A program the identity measures (Linux 7.3-rc4).
const RECIPE: &[u8] = b"rtw8852a radio_a::Radio: rtw8852a_rfk_init (rck A/B, dack, rx_dck afe), rtw8852a_set_txpwr_ctrl, rtw8852a_power_trim, NO bb_cfg_txrx_path (.cfg_txrx_path NULL); core.c __rtw89_set_channel (rtw8852a_set_channel_help enter, rtw8852a_set_channel mac/bb/rf, rtw8852a_set_txpwr byrate/offset/limit/limit_ru, help exit, rtw8852a_rfk_band_changed on a band change) then rtw8852a_rfk_channel (RX DCK, IQK, TSSI, DPK); no RF_GET_MCCCH";
/// The RTL8852A TX power program a record measures (`Plan::visit_a`).
const POWER: &[u8] = b"RTL8852A Plan::visit_a: rtw8852a_set_txpwr byrate 2TX, offset, 2TX limit + RU pages, no shape; rtw8852a_set_txpwr_ref both paths";
fn domain(profile: Profile) -> &'static [u8] {
    if profile == Profile::INITIAL {
        b"NARF RTL8852A initial full RF ch1 20MHz awake WLAN-only v1;2T2R TX-A,RX-AB;no hardwarecrypto;onefreshPCI lifecycle"
    } else if profile.is_5ghz() {
        b"NARF RTL8852A 5GHz full RF awake WLAN-only v1;2T2R TX-A,RX-AB;no CCK;no hardwarecrypto;retuned across band from Ready ch1 program"
    } else {
        b"NARF RTL8852A noninitial full RF 2.4GHz awake WLAN-only v1;2T2R TX-A,RX-AB;no hardwarecrypto;retuned from Ready ch1 program"
    }
}
fn width_mhz(width: Width) -> u8 {
    width.mhz() as u8
}
/// Profiles an RTL8852A record may admit: rtw8852a.c 2.4/5GHz at
/// 20/40/80MHz (no 160MHz, no 2.4GHz 80MHz, no 6GHz), never channel 14.
pub(super) fn admissible(profile: Profile) -> bool {
    match profile.width() {
        Width::Mhz160 => false,
        Width::Mhz80 => profile.is_5ghz(),
        _ => profile.primary() != 14,
    }
}
/// Every noninitial admissible profile, in a fixed order.
pub(super) fn noninitial() -> alloc::vec::Vec<Profile> {
    let mut out = alloc::vec::Vec::new();
    for primary in 1..=13 {
        out.extend(Profile::new_wide(primary, Width::Mhz20, false));
        for above in [true, false] {
            out.extend(Profile::new_2ghz_40(primary, above));
        }
    }
    for primary in super::operating_channel::GHZ5 {
        for width in [Width::Mhz20, Width::Mhz40, Width::Mhz80] {
            out.extend(Profile::new_wide(primary, width, false));
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
    /// Identity of the full RTL8852A program on `power.channel()`
    /// (`profile`): the RTL8852A cold calibration identity, the
    /// RTL8852A-bound firmware PHY-cap receipt, the recipe, the exact
    /// `radio_power_c` program and the profile geometry, domain-separated
    /// per lifecycle.
    pub fn new(
        lifecycle: Lifecycle,
        factory: &Factory,
        device: narf_bus::DeviceId,
        assets: &Assets,
        profile: Profile,
        power: &Plan,
        phycap: &super::firmware_phycap::Receipt,
    ) -> Result<Self, Error> {
        let restated = power.channel();
        if !admissible(profile)
            || restated.primary() != profile.primary()
            || restated.center() != profile.center()
            || restated.width().mhz() != profile.width().mhz()
            || !phycap.is_a()
        {
            return Err(Error::Identity);
        }
        phycap.initial_profile().map_err(|_| Error::Identity)?;
        let base = super::calibration_policy::Board::new_a(factory, device, assets)
            .map_err(|_| Error::Identity)?;
        let mut h = narf_crypto::sha256::Sha256::new();
        h.update(domain(profile));
        h.update(&base.identity());
        h.update(&phycap.fingerprint());
        h.update(RECIPE);
        // A 40/80MHz record also binds the shared wide station capability
        // its channel lets the station offer (`station_control::wide_phy`).
        if matches!(profile.width(), Width::Mhz40 | Width::Mhz80) {
            h.update(&super::station_control::wide_fingerprint());
        }
        h.update(POWER);
        power.bind(&mut h);
        profile.bind(&mut h);
        h.update(&[
            profile.band_index(),
            profile.primary(),
            profile.center(),
            width_mhz(profile.width()),
        ]);
        let mut identity = h.finalize();
        if lifecycle == Lifecycle::Repeat {
            let mut h = narf_crypto::sha256::Sha256::new();
            h.update(b"NARF RTL8852A repeat observed-FLR PCI lifecycle v1;SER-L2 reset or S3 resume;same boot");
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
    /// Extend the identity by every RTL8852A program enabled in `flags`, in
    /// the fixed [`PROGRAMS`] order.
    pub(super) fn with_programs(mut self, flags: u8) -> Self {
        for program in PROGRAMS {
            if flags & program.bit() != 0 {
                self.identity = extend(program, self.identity);
            }
        }
        self
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
}

struct Current;
impl CapOp<FirmwareBlob, Read> for Current {
    type Output = ();
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<(), CapError> {
        Ok(())
    }
}
fn envelope(bytes: &[u8], profile: Profile) -> Result<Envelope, Error> {
    envelope_at(bytes, profile.occupied(), profile.width().mhz(), None)
}

/// One signed noninitial `N5AC` record.
struct Channel {
    authority: Cap<FirmwareBlob, Read>,
    board: Board,
    binding: [u8; 32],
    envelope: Envelope,
}
fn channel_recipe(profile: Profile) -> &'static [u8] {
    if profile.is_5ghz() {
        b"RTL8852A 5GHz noninitial full operating program v1; __rtw89_set_channel with btc switch band and rtw8852a_tssi_scan on a band change, then rtw8852a_rfk_channel on a Ready owner; actual primary/width WW0 2TX limits and RU limits, no CCK; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
    } else {
        b"RTL8852A 2.4GHz noninitial full operating program v1; __rtw89_set_channel then rtw8852a_rfk_channel on a Ready owner; same band, no band-change TSSI scan; actual primary/width WW0 CCK/OFDM 2TX limits, SCO CCK, no TX shape; worst-case peaks/antenna cover all calibration emissions on this profile under the current host rule over the whole occupied span"
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
    hash.update(b"NARF RTL8852A measured noninitial channel full program v1");
    hash.update(&[
        profile.band_index(),
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
/// Firmware name of the `N5AC` record for `profile` on `mac`.
pub(super) fn channel_name(profile: Profile, mac: [u8; 6]) -> alloc::string::String {
    let m = mac;
    format!(
        "rtw89/rtw8852a-chan-v1-{}g-ch{:03}-c{:03}-bw{}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
        if profile.is_5ghz() { 5 } else { 2 },
        profile.primary(),
        profile.center(),
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
            || &bytes[..4] != b"N5AC"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, width_mhz(p.width()), p.primary(), BASE_FLAGS]
            || bytes[68..70] != [p.band_index(), p.center()]
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

/// The signed base `N5AB` v2 record plus every loaded `N5AC` record and the
/// optional `N5AF` fragment companion.
pub(super) struct Qualification {
    board: Board,
    authority: Cap<FirmwareBlob, Read>,
    envelope: Envelope,
    record_digest: [u8; 32],
    record_signer: [u8; 32],
    /// Byte 57 of the base record: base flags plus enabled `PROGRAMS`.
    flags: u8,
    channels: alloc::vec::Vec<Channel>,
    fragments: Option<fragment::Fragments>,
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
            "rtw89/rtw8852a-radio-v2-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
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
            || &bytes[..4] != b"N5AB"
            || bytes[4..8] != [2, 0, 128, 0]
            || bytes[8..12] != (LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != board.device.to_le_bytes()
            || bytes[54..57] != [1, 20, 1]
            || !programs_valid(bytes[57])
            || bytes[68..] != [0; 60]
        {
            return Err(Error::Format);
        }
        let flags = bytes[57];
        let extended = board.with_programs(flags);
        if bytes[16..48] != extended.identity || bytes[48..54] != board.mac {
            return Err(Error::Identity);
        }
        let envelope = envelope(bytes, Profile::INITIAL)?;
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        Ok(Self {
            board: extended,
            authority,
            envelope,
            record_digest: digest.finalize(),
            record_signer,
            flags,
            channels: alloc::vec::Vec::new(),
            fragments: None,
            active: narf_lib::sync::IrqSafeSpinLock::new(Profile::INITIAL),
            #[cfg(any(test, feature = "kernel-test"))]
            model_domain: None,
        })
    }
    /// `board` is the program-free identity [`Board::new`] rebinds.
    pub fn matches(&self, board: Board) -> bool {
        self.board == board.with_programs(self.flags)
    }
    /// Whether the base record enables `program` (current authority only).
    pub(super) fn allows(&self, program: Program) -> Result<bool, Error> {
        self.current()?;
        Ok(self.flags & program.bit() != 0)
    }
    /// Load the optional `N5AC` record for `board.profile()` (a noninitial
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
        let key = record.board.profile;
        self.channels.retain(|c| c.board.profile != key);
        self.channels.push(record);
    }
    fn channel(&self, profile: Profile) -> Option<&Channel> {
        self.channels.iter().find(|c| c.board.profile == profile)
    }
    /// The loaded record for `board.profile()` was measured for exactly
    /// `board`.
    pub(super) fn channel_matches(&self, board: Board) -> bool {
        if board.profile == Profile::INITIAL {
            return self.matches(board);
        }
        self.channel(board.profile)
            .is_some_and(|record| record.board == board)
    }
    fn envelope_of(&self, profile: Profile) -> Result<Option<Envelope>, Error> {
        if profile == Profile::INITIAL {
            return Ok(Some(self.envelope));
        }
        let Some(record) = self.channel(profile) else {
            return Ok(None);
        };
        record.bound(self)?;
        Ok(Some(record.envelope))
    }
    /// Current signed admission of `profile`: a record exists, is bound to
    /// this base, and the current host rule over its span passes.
    pub(super) fn channel_allowed(&self, profile: Profile) -> Result<bool, Error> {
        self.current()?;
        let Some(envelope) = self.envelope_of(profile)? else {
            return Ok(false);
        };
        Ok(check_envelope(&*self.policy()?, envelope).is_ok())
    }
    /// `channel_allowed` restricted to spans the host rule leaves active
    /// (no DFS/NO_IR rule), where frame TX (`tx_current`) is admitted.
    pub(super) fn channel_active(&self, profile: Profile) -> Result<bool, Error> {
        self.current()?;
        let Some(envelope) = self.envelope_of(profile)? else {
            return Ok(false);
        };
        Ok(check_envelope(&*self.policy()?, envelope) == Ok(false))
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
        let active = *self.active.lock();
        if active == Profile::INITIAL {
            return Ok(self.envelope);
        }
        let record = self.channel(active).ok_or(Error::Policy)?;
        record.current()?;
        Ok(record.envelope)
    }
    pub(super) fn policy(&self) -> Result<alloc::sync::Arc<RegulatoryDomain>, Error> {
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
        if let Some(program) = &self.fragments {
            program.current()?;
        }
        check_envelope(&*self.policy()?, self.active_envelope()?).map(|_| ())
    }
    /// `current` plus the frame-TX rule: a passive-only (DFS / NO_IR) span
    /// may carry the signed calibration/tuning emissions the record covers,
    /// but no frame (RTL8852A has no beacon-witness passive TX grant).
    pub(super) fn tx_current(&self) -> Result<(), Error> {
        self.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        if check_envelope(&*self.policy()?, self.active_envelope()?)? {
            return Err(Error::Policy);
        }
        Ok(())
    }
    /// Keep actual publication inside this exact signed capability
    /// invocation (and the active channel record's, and the fragment
    /// companion's when one is loaded).
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
                    q.invoke_programs(self.operation)
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
    /// Load the optional `N5AF` fragment companion, if provisioned.
    /// Absent, the qualification admits ordinary TX but no fragmentation.
    pub(super) fn load_fragments(&mut self) -> Result<(), Error> {
        self.fragments = fragment::Fragments::optional(self)?;
        self.current()
    }
    pub(super) fn fragments_allowed(&self) -> Result<bool, Error> {
        self.current()?;
        Ok(self.fragments.is_some())
    }
    fn invoke_programs<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::power::Error>,
    ) -> Result<T, super::power::Error> {
        let operation = || match &self.fragments {
            Some(program) => program.invoke(operation),
            None => operation(),
        };
        let active = *self.active.lock();
        if active == Profile::INITIAL {
            return operation();
        }
        match self.channel(active) {
            Some(record) => record.invoke(operation),
            None => Err(super::power::Error::Access),
        }
    }
}
/// The optional signed software-fragment companion (`N5AF`).
#[path = "radio_policy_a/fragment.rs"]
pub(super) mod fragment;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy_a/tests.rs"]
pub(super) mod tests;
